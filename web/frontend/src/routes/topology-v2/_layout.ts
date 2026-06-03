// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

/**
 * Layout builders for the topology canvas.
 *
 * Two pure functions, one per view mode:
 *   buildServiceToBackendGraph  4 columns: Consumer -> FQDN -> Caddy -> Cluster
 *   buildProtocolGraph          3 columns: EntryPoint -> Caddy -> Service
 *
 * Both share the same Caddy hub model and the same edge tier
 * resolution (resolveFlowTier from _types.ts). Helpers below are
 * shared across the two builders.
 *
 * `fitView` on <SvelteFlow> recenters at mount; switching views
 * after that does not refit automatically — that's intentional,
 * the user keeps their current zoom/pan when toggling.
 */

import type {
        BackendClusterNodeData,
        CaddyHubNodeData,
        ConsumerNodeData,
        EntryPointNodeData,
        FlowEdgeData,
        FQDNNodeData,
        ServiceNodeData,
        TopologyEdge,
        TopologyGraph,
        TopologyNode,
        TopologyRoute,
        TopologyUpstream,
} from './_types';

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

/** Vue B (service -> backend): 4 columns at 0/300/600/900. */
const COL_X_SERVICE = {
        CONSUMER: 0,
        FQDN: 300,
        CADDY: 600,
        BACKEND: 900,
} as const;

/** Vue A (protocol): 3 columns spread over the same 900px width
 *  so the canvas bounds stay roughly identical when toggling
 *  between views — less jarring visually. */
const COL_X_PROTOCOL = {
        ENTRY_POINT: 0,
        CADDY: 450,
        SERVICE: 900,
} as const;

const ROW_SPACING_Y = 150;

// ---------------------------------------------------------------------------
// Hardcoded fixtures — Phase 1 only.
// Will be replaced by data-driven derivation once the backend
// exposes the corresponding telemetry.
// ---------------------------------------------------------------------------

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

/** Entry-point fixtures for Vue A col 0. Numbers mirror the mock
 *  so the visual diff is easy to verify. Real values will come
 *  from Caddy's listener metrics in Phase 2. */
const DEFAULT_ENTRY_POINTS: EntryPointNodeData[] = [
        {
                kind: 'entry-point',
                protocol: ':443 HTTPS',
                subtitle: 'TLS 1.3 · ALPN h2',
                hosts: ['api.arenet.fr', 'admin.arenet.fr'],
                reqPerSec: 812,
        },
        {
                kind: 'entry-point',
                protocol: ':443 QUIC/HTTP3',
                subtitle: 'UDP · 0-RTT activé',
                hosts: ['app.arenet.fr'],
                reqPerSec: 386,
        },
        {
                kind: 'entry-point',
                protocol: ':80 HTTP',
                subtitle: 'redirect -> 443',
                hosts: ['tous les hôtes'],
                reqPerSec: 42,
        },
        {
                kind: 'entry-point',
                protocol: ':443 WebSocket',
                subtitle: 'Upgrade · proxy_protocol',
                hosts: ['ws.arenet.fr/socket'],
                reqPerSec: 84,
        },
        {
                kind: 'entry-point',
                protocol: ':443 admin (forward_auth)',
                subtitle: 'OIDC · IP allowlist',
                hosts: ['admin.arenet.fr'],
                reqPerSec: 8,
        },
];

// ===========================================================================
// Public API — Vue B (Service -> Backend)
// ===========================================================================

/**
 * Build the Vue Service -> Backend graph from a route list.
 *
 *   col 0 (consumers)   placeholder fixtures (Phase 1)
 *   col 1 (FQDN)        primary host per route
 *   col 2 (caddy)       single central hub node
 *   col 3 (backends)    one BackendCluster per route, carrying its
 *                       full upstream pool so the node component
 *                       can render fairness bars per row
 */
export function buildServiceToBackendGraph(routes: TopologyRoute[]): TopologyGraph {
        const nodes: TopologyNode[] = [];
        const edges: TopologyEdge[] = [];

        // Col 0 — consumers
        const consumerYs = computeStackYs(DEFAULT_CONSUMERS.length);
        DEFAULT_CONSUMERS.forEach((data, i) => {
                nodes.push({
                        id: `consumer-${i}`,
                        type: 'consumer',
                        position: { x: COL_X_SERVICE.CONSUMER, y: consumerYs[i] },
                        data,
                });
        });

        // Col 1 — FQDN
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
                        position: { x: COL_X_SERVICE.FQDN, y: fqdnYs[i] },
                        data,
                });
        });

        // Col 2 — Caddy hub
        nodes.push(buildCaddyNode(routes, COL_X_SERVICE.CADDY));

        // Col 3 — Backend clusters
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
                        position: { x: COL_X_SERVICE.BACKEND, y: clusterYs[i] },
                        data,
                });
        });

        // Edges: consumer -> FQDN fan-out, FQDN -> caddy, caddy -> cluster
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
                        routeFlowData(route),
                ));
        });

        routes.forEach((route) => {
                edges.push(makeFlowEdge(
                        `e-caddy-cluster-${route.id}`,
                        'caddy-hub',
                        `cluster-${route.id}`,
                        routeFlowData(route),
                ));
        });

        return { nodes, edges };
}

// ===========================================================================
// Public API — Vue A (Protocol)
// ===========================================================================

/**
 * Build the Vue Protocol graph from a route list.
 *
 *   col 0 (entry points)  hardcoded Caddy listeners (Phase 1)
 *   col 1 (caddy)         single central hub node (same as Vue B)
 *   col 2 (services)      one ServiceNode per route, derived from
 *                         the route's primary upstream
 *
 * Edges: each entry point -> Caddy with its own reqPerSec; Caddy ->
 * each service with the route's metrics. The entry-point side
 * focuses on inbound flow shape; the service side on per-route
 * health and latency.
 */
export function buildProtocolGraph(routes: TopologyRoute[]): TopologyGraph {
        const nodes: TopologyNode[] = [];
        const edges: TopologyEdge[] = [];

        // Col 0 — Entry points (fixtures)
        const epYs = computeStackYs(DEFAULT_ENTRY_POINTS.length);
        DEFAULT_ENTRY_POINTS.forEach((data, i) => {
                nodes.push({
                        id: `ep-${i}`,
                        type: 'entry-point',
                        position: { x: COL_X_PROTOCOL.ENTRY_POINT, y: epYs[i] },
                        data,
                });
        });

        // Col 1 — Caddy hub
        nodes.push(buildCaddyNode(routes, COL_X_PROTOCOL.CADDY));

        // Col 2 — Services (one per route)
        const serviceYs = computeStackYs(routes.length);
        routes.forEach((route, i) => {
                nodes.push({
                        id: `service-${route.id}`,
                        type: 'service',
                        position: { x: COL_X_PROTOCOL.SERVICE, y: serviceYs[i] },
                        data: deriveServiceFromRoute(route),
                });
        });

        // Edges: each entry point -> Caddy
        DEFAULT_ENTRY_POINTS.forEach((ep, i) => {
                edges.push(makeFlowEdge(
                        `e-ep${i}-caddy`,
                        `ep-${i}`,
                        'caddy-hub',
                        {
                                kind: 'flow',
                                reqPerSec: ep.reqPerSec,
                                p99LatencyMs: 0,  // listener-level latency not tracked
                                errorRate5xx: 0,
                        },
                ));
        });

        // Caddy -> each service
        routes.forEach((route) => {
                edges.push(makeFlowEdge(
                        `e-caddy-service-${route.id}`,
                        'caddy-hub',
                        `service-${route.id}`,
                        routeFlowData(route),
                ));
        });

        return { nodes, edges };
}

// ===========================================================================
// Shared helpers
// ===========================================================================

function buildCaddyNode(routes: TopologyRoute[], x: number): TopologyNode {
        const data: CaddyHubNodeData = {
                kind: 'caddy',
                version: 'Caddy 2.8',
                instanceId: 'arenet-instance',
                aggregateReqPerSec: routes.reduce((sum, r) => sum + r.reqPerSec, 0),
                chips: deriveCaddyChips(routes),
        };
        return {
                id: 'caddy-hub',
                type: 'caddy',
                position: { x, y: 0 },
                data,
        };
}

/** Derive a ServiceNodeData from a route's primary upstream. */
function deriveServiceFromRoute(route: TopologyRoute): ServiceNodeData {
        const primary = route.upstreams[0];
        const additionalUpstreamCount = Math.max(0, route.upstreams.length - 1);

        const state: ServiceNodeData['state'] =
                route.errorRate5xx > 0
                        ? 'bad'
                        : route.p99LatencyMs > 300
                        ? 'warn'
                        : 'healthy';

        const statusLine =
                route.errorRate5xx > 0
                        ? `5xx ${route.errorRate5xx}% · timeout 5s`
                        : route.p99LatencyMs > 300
                        ? `latence ↑ · p99 ${Math.round(route.p99LatencyMs)} ms`
                        : `healthy · p99 ${Math.round(route.p99LatencyMs)} ms`;

        return {
                kind: 'service',
                serviceName: route.clusterLabel ?? deriveClusterLabel(route.host),
                runtime: primary?.runtime,
                primaryAddress: primary?.url ?? '(no upstream)',
                additionalUpstreamCount: additionalUpstreamCount > 0 ? additionalUpstreamCount : undefined,
                statusLine,
                reqPerSec: route.reqPerSec,
                state,
        };
}

function routeFlowData(route: TopologyRoute): FlowEdgeData {
        return {
                kind: 'flow',
                reqPerSec: route.reqPerSec,
                p99LatencyMs: route.p99LatencyMs,
                errorRate5xx: route.errorRate5xx,
        };
}

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
