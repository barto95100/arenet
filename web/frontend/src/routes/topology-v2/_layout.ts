
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

/**
 * Layout builder for the topology canvas.
 *
 * Pure function: takes the route list (whatever the live data feed
 * delivers — or a mock fixture during development) and returns
 * Svelte Flow nodes + edges with positions already computed.
 *
 * The Svelte Flow `fitView` prop will recenter / rescale at mount
 * time, so all we have to do here is keep the *relative* geometry
 * consistent (columns aligned, rows evenly spaced).
 */

import type {
        BackendClusterNodeData,
        CaddyHubNodeData,
        ConsumerNodeData,
        FlowEdgeData,
        FQDNNodeData,
        TopologyEdge,
        TopologyGraph,
        TopologyNode,
        TopologyRoute,
        TopologyUpstream,
} from './_types';

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

const COL_X = {
        CONSUMER: 0,
        FQDN: 300,
        CADDY: 600,
        BACKEND: 900,
} as const;

const ROW_SPACING_Y = 150;

const DEFAULT_CONSUMERS: ConsumerNodeData[] = [
        {
                kind: 'consumer',
                label: 'Web app',
                subtitle: 'desktop + tablette',
                meta: ['TLS 1.3 · Chrome / Firefox / Safari'],
        },
        {
                kind: 'consumer',
                label: 'Mobile app',
                subtitle: 'iOS / Android',
                meta: ['SwiftUI + Kotlin · WS 1.2k'],
        },
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Build the Vue Service → Backend graph from a route list.
 *
 *   col 0 (consumers)   placeholder fixtures (Phase 1)
 *   col 1 (FQDN)        primary host per route
 *   col 2 (caddy)       single central hub node
 *   col 3 (backends)    one BackendCluster per route, carrying its
 *                       full upstream pool so the node component
 *                       can render fairness bars per row
 *
 * Edges: consumer → FQDN (fan-out), FQDN → caddy, caddy → cluster.
 */
export function buildServiceToBackendGraph(routes: TopologyRoute[]): TopologyGraph {
        const nodes: TopologyNode[] = [];
        const edges: TopologyEdge[] = [];

        // --- Col 0: consumers ------------------------------------------
        const consumerYs = computeStackYs(DEFAULT_CONSUMERS.length);
        DEFAULT_CONSUMERS.forEach((data, i) => {
                nodes.push({
                        id: `consumer-${i}`,
                        type: 'consumer',
                        position: { x: COL_X.CONSUMER, y: consumerYs[i] },
                        data,
                });
        });

        // --- Col 1: FQDN ------------------------------------------------
        const fqdnYs = computeStackYs(routes.length);
        routes.forEach((route, i) => {
                const data: FQDNNodeData = {
                        kind: 'fqdn',
                        host: route.host,
                        protocols: route.tlsEnabled ? 'HTTPS · h2 · h3' : 'HTTP',
                        meta: `${formatRate(route.reqPerSec)} · ${aliasCountLabel(route)}`,
                };
                nodes.push({
                        id: `fqdn-${route.id}`,
                        type: 'fqdn',
                        position: { x: COL_X.FQDN, y: fqdnYs[i] },
                        data,
                });
        });

        // --- Col 2: Caddy hub ------------------------------------------
        const aggregateReqPerSec = routes.reduce((sum, r) => sum + r.reqPerSec, 0);
        const caddyData: CaddyHubNodeData = {
                kind: 'caddy',
                version: 'Caddy 2.8',
                instanceId: 'arenet-instance',
                aggregateReqPerSec,
                chips: deriveCaddyChips(routes),
        };
        nodes.push({
                id: 'caddy-hub',
                type: 'caddy',
                position: { x: COL_X.CADDY, y: 0 },
                data: caddyData,
        });

        // --- Col 3: Backend clusters -----------------------------------
        const clusterYs = computeStackYs(routes.length);
        routes.forEach((route, i) => {
                const healthyCount = route.upstreams.filter((u) => u.status === 'healthy').length;
                const data: BackendClusterNodeData = {
                        kind: 'backend-cluster',
                        clusterLabel: route.clusterLabel ?? deriveClusterLabel(route.host),
                        runtime: dominantRuntime(route.upstreams),
                        lbPolicy: route.lbPolicy,
                        upstreams: route.upstreams,
                        healthyCount,
                        totalCount: route.upstreams.length,
                        warning: deriveClusterWarning(route),
                };
                nodes.push({
                        id: `cluster-${route.id}`,
                        type: 'backend-cluster',
                        position: { x: COL_X.BACKEND, y: clusterYs[i] },
                        data,
                });
        });

        // --- Edges -----------------------------------------------------
        DEFAULT_CONSUMERS.forEach((_, ci) => {
                routes.forEach((route) => {
                        edges.push(makeFlowEdge(
                                `e-c${ci}-fqdn-${route.id}`,
                                `consumer-${ci}`,
                                `fqdn-${route.id}`,
                                {
                                        kind: 'flow',
                                        reqPerSec: route.reqPerSec / DEFAULT_CONSUMERS.length,
                                        p99LatencyMs: route.p99LatencyMs,
                                        errorRate5xx: route.errorRate5xx,
                                },
                        ));
                });
        });

        routes.forEach((route) => {
                edges.push(makeFlowEdge(
                        `e-fqdn-${route.id}-caddy`,
                        `fqdn-${route.id}`,
                        'caddy-hub',
                        {
                                kind: 'flow',
                                reqPerSec: route.reqPerSec,
                                p99LatencyMs: route.p99LatencyMs,
                                errorRate5xx: route.errorRate5xx,
                        },
                ));
        });

        routes.forEach((route) => {
                edges.push(makeFlowEdge(
                        `e-caddy-cluster-${route.id}`,
                        'caddy-hub',
                        `cluster-${route.id}`,
                        {
                                kind: 'flow',
                                reqPerSec: route.reqPerSec,
                                p99LatencyMs: route.p99LatencyMs,
                                errorRate5xx: route.errorRate5xx,
                        },
                ));
        });

        return { nodes, edges };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFlowEdge(
        id: string,
        source: string,
        target: string,
        data: FlowEdgeData,
): TopologyEdge {
        return { id, source, target, type: 'animated-flow', data };
}

function computeStackYs(count: number): number[] {
        if (count === 0) return [];
        const totalHeight = (count - 1) * ROW_SPACING_Y;
        const startY = -totalHeight / 2;
        return Array.from({ length: count }, (_, i) => startY + i * ROW_SPACING_Y);
}

function deriveClusterLabel(host: string): string {
        const parts = host.split('.');
        return parts[0] || host;
}

function dominantRuntime(upstreams: TopologyUpstream[]): string | undefined {
        if (upstreams.length === 0) return undefined;
        const counts = new Map<string, number>();
        upstreams.forEach((u) => {
                if (u.runtime) counts.set(u.runtime, (counts.get(u.runtime) ?? 0) + 1);
        });
        let best: { runtime: string; count: number } | undefined;
        counts.forEach((count, runtime) => {
                if (!best || count > best.count) best = { runtime, count };
        });
        return best?.runtime;
}

function deriveClusterWarning(route: TopologyRoute): string | undefined {
        const ups = route.upstreams;
        if (ups.length === 0) return 'Aucun upstream configuré';
        const healthy = ups.filter((u) => u.status === 'healthy').length;
        if (healthy === 0) return 'Tous les upstreams sont indisponibles';
        if (ups.length === 1) return "Pas de cluster — recommandé d'ajouter ≥ 2 réplicas";
        if (healthy < ups.length) return `${ups.length - healthy} upstream(s) hors-service`;
        return undefined;
}

function deriveCaddyChips(routes: TopologyRoute[]): CaddyHubNodeData['chips'] {
        const chips: CaddyHubNodeData['chips'] = ['L7-LB'];
        if (routes.some((r) => r.wafLevel === 'block' || r.wafLevel === 'detect')) chips.push('WAF');
        if (routes.some((r) => r.rateLimited)) chips.push('RATE');
        if (routes.some((r) => r.mtlsRequired)) chips.push('mTLS');
        return chips;
}

function aliasCountLabel(route: TopologyRoute): string {
        const n = (route.aliases?.length ?? 0) + 1;
        return n === 1 ? '1 host' : `${n} hosts`;
}

function formatRate(rps: number): string {
        if (rps >= 1000) return `${(rps / 1000).toFixed(1)} k req/s`;
        return `${Math.round(rps)} req/s`;
}