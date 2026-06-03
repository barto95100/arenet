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
        UpstreamNodeData,
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

/** Sub-flow cluster geometry (Vue B col 3). Children are positioned
 *  relative to the cluster group node — so x/y here is local. The
 *  group's width/height must accommodate header + N stacked upstream
 *  cards with the configured padding. Children stack vertically. */
// Cluster sized to fit "host.example.local:8443" (~22 chars at the
// upstream card's monospaced font) without truncation, plus the
// fairness bar + r/s readout below. Bumped from 260 → 300 in C6
// after the operator flagged mid-IP truncation of "http://192.168…"
// (Critique 7). Both views' col 3 is rightmost so the widening
// only pushes the canvas a bit further right — no other column
// needs to move.
const CLUSTER_WIDTH = 300;
const CLUSTER_HEADER_HEIGHT = 56;
const CLUSTER_PADDING_TOP = CLUSTER_HEADER_HEIGHT + 4;
const CLUSTER_PADDING_BOTTOM = 8;
const CLUSTER_WARNING_FOOTER_HEIGHT = 34;
const UPSTREAM_HEIGHT = 56;
const UPSTREAM_GAP_Y = 6;
const UPSTREAM_X_INSET = 8;          // inset from cluster left edge
const UPSTREAM_INNER_WIDTH = CLUSTER_WIDTH - UPSTREAM_X_INSET * 2;

/** Vertical extent occupied by N upstream cards (no padding). */
function upstreamsBlockHeight(n: number): number {
        if (n === 0) return 0;
        return n * UPSTREAM_HEIGHT + (n - 1) * UPSTREAM_GAP_Y;
}

/** Total cluster group height for N upstream children. When a warning
 *  is present, reserve extra bottom space so the absolute-positioned
 *  warning footer in BackendClusterNode doesn't overlap the last
 *  upstream card. */
function clusterTotalHeight(n: number, hasWarning: boolean): number {
        const base = CLUSTER_PADDING_TOP + upstreamsBlockHeight(n) + CLUSTER_PADDING_BOTTOM;
        return hasWarning ? base + CLUSTER_WARNING_FOOTER_HEIGHT : base;
}

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
                        // C17a (2026-06-04): drop the mock "h2 · h3" suffix.
                        // The backend doesn't expose real ALPN protocols yet
                        // — surfacing fake ones lied about HTTP/2 / HTTP/3
                        // availability. See #R-TOPO-alpn for the real-data
                        // follow-up.
                        protocols: route.tlsEnabled ? 'HTTPS' : 'HTTP',
                        meta: `${formatRate(route.reqPerSec)} · ${aliasCountLabel(route)}`,
                        aliases: route.aliases,
                        wafLevel: route.wafLevel ?? 'off',
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

        // Col 3 — Backend clusters as sub-flow groups + N upstream children
        //
        // Each cluster is a group node sized to fit its upstream pool.
        // Cluster Ys are computed so the *centers* of variable-height
        // groups remain evenly spaced (mirrors the protocol view's
        // visual rhythm and prevents overlap when one route has many
        // upstreams). Children carry parentId + extent: 'parent' so
        // Svelte Flow keeps them inside the group when the user drags
        // either the parent or a child.
        const clusterWarnings = routes.map(deriveClusterWarning);
        const clusterHeights = routes.map((r, i) =>
                clusterTotalHeight(r.upstreams.length, clusterWarnings[i] !== undefined),
        );
        const clusterYs = computeStackYsForHeights(clusterHeights);
        routes.forEach((route, i) => {
                const healthyCount = route.upstreams.filter((u) => u.status === 'healthy').length;
                const unhealthyCount = route.upstreams.filter((u) => u.status === 'unhealthy').length;
                const totalCount = route.upstreams.length;
                const clusterId = `cluster-${route.id}`;
                const clusterData: BackendClusterNodeData = {
                        kind: 'backend-cluster',
                        clusterLabel: route.clusterLabel ?? deriveClusterLabel(route.host),
                        runtime: dominantRuntime(route.upstreams),
                        lbPolicy: route.lbPolicy,
                        healthyCount,
                        unhealthyCount,
                        totalCount,
                        hasHealthCheck: route.hasHealthCheck,
                        warning: clusterWarnings[i],
                };
                nodes.push({
                        id: clusterId,
                        type: 'backend-cluster',
                        position: { x: COL_X_SERVICE.BACKEND, y: clusterYs[i] },
                        width: CLUSTER_WIDTH,
                        height: clusterHeights[i],
                        data: clusterData,
                });

                // Upstream children. Position is local to the parent.
                route.upstreams.forEach((upstream, ui) => {
                        const childY = CLUSTER_PADDING_TOP + ui * (UPSTREAM_HEIGHT + UPSTREAM_GAP_Y);
                        const { displayUrl, wasHttps } = formatUpstreamUrl(upstream.url);
                        const childData: UpstreamNodeData = {
                                kind: 'upstream',
                                upstreamId: upstream.id,
                                url: upstream.url,
                                displayUrl,
                                wasHttps,
                                runtime: upstream.runtime,
                                status: upstream.status,
                                healthCheckConfigured: upstream.healthCheckConfigured,
                                reqPerSec: upstream.reqPerSec,
                                p99LatencyMs: upstream.p99LatencyMs,
                                fairnessRatio: upstream.fairnessRatio,
                        };
                        nodes.push({
                                id: `upstream-${route.id}-${upstream.id}`,
                                type: 'upstream',
                                position: { x: UPSTREAM_X_INSET, y: childY },
                                width: UPSTREAM_INNER_WIDTH,
                                height: UPSTREAM_HEIGHT,
                                parentId: clusterId,
                                extent: 'parent',
                                draggable: false,
                                selectable: false,
                                data: childData,
                        });
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

        // Caddy hub -> each upstream child (N edges per cluster).
        //
        // Pre-restructure (one edge per cluster) hid per-upstream flow
        // shape — the operator couldn't tell which replica was hot. We
        // now emit one edge per upstream, carrying that upstream's
        // own reqPerSec / p99 / a synthesized 5xx (route-level — we
        // don't have per-upstream error rates yet, see Stage B).
        //
        // Falls back to a single edge to the cluster group when the
        // route has 0 upstreams (degenerate route): the cluster node
        // still renders its empty-pool warning, and the edge lets the
        // operator see the route exists.
        routes.forEach((route) => {
                if (route.upstreams.length === 0) {
                        edges.push(makeFlowEdge(
                                `e-caddy-cluster-${route.id}`,
                                'caddy-hub',
                                `cluster-${route.id}`,
                                routeFlowData(route),
                        ));
                        return;
                }
                route.upstreams.forEach((upstream) => {
                        edges.push(makeFlowEdge(
                                `e-caddy-upstream-${route.id}-${upstream.id}`,
                                'caddy-hub',
                                `upstream-${route.id}-${upstream.id}`,
                                {
                                        kind: 'flow',
                                        reqPerSec: upstream.reqPerSec,
                                        p99LatencyMs: upstream.p99LatencyMs,
                                        // Per-upstream 5xx not yet instrumented (Stage B
                                        // — #R-TOPO-upstream-metrics). Route-level rate is
                                        // the closest signal: if the route is bleeding 5xx,
                                        // surfacing it on every upstream edge is honest about
                                        // the lack of per-replica visibility.
                                        errorRate5xx: route.errorRate5xx,
                                },
                        ));
                });
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

/** Stack variable-height blocks vertically with a constant gap
 *  between them, centered around y=0. Returns the TOP-Y of each
 *  block (Svelte Flow positions nodes by their top-left corner).
 *
 *  Used for backend clusters whose height grows with the number
 *  of upstreams — a fixed-row stacker would overlap a tall
 *  cluster with its neighbour. */
function computeStackYsForHeights(heights: number[]): number[] {
        if (heights.length === 0) return [];
        const totalHeight =
                heights.reduce((sum, h) => sum + h, 0) +
                (heights.length - 1) * ROW_SPACING_Y;
        const startTop = -totalHeight / 2;
        const ys: number[] = [];
        let cursor = startTop;
        for (const h of heights) {
                ys.push(cursor);
                cursor += h + ROW_SPACING_Y;
        }
        return ys;
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
        // Three-state aware (Regression A, 2026-06-03). v1.1.0 emits
        // 'unknown' for every upstream — "no probe data yet, not the
        // same as bad". The warning must fire ONLY for STRICTLY
        // unhealthy upstreams. Previously this fired whenever
        // healthyCount === 0, which is true in the all-unknown case
        // too → red "Tous les upstreams sont indisponibles" on every
        // route in the canvas.
        const unhealthy = ups.filter((u) => u.status === 'unhealthy').length;
        if (unhealthy === ups.length) return 'Tous les upstreams sont indisponibles';
        if (unhealthy > 0) return `${unhealthy} upstream(s) hors-service`;
        // All upstreams unknown OR all healthy OR a mix without any
        // strictly-unhealthy → no warning. The header surfaces the
        // count breakdown for those cases.
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

/** Strip http://, https://, h2://, h2c:// from an upstream URL for
 *  display, and report whether the original used a TLS-bearing scheme.
 *
 *  The original full URL stays in TopologyUpstream.url for tooltips
 *  and future copy actions; this just produces the short label for
 *  the UpstreamNode card.
 *
 *  Why not surface scheme as a separate field from the backend? The
 *  Caddy reverse_proxy upstream string is what the operator typed —
 *  storage doesn't decompose it. Doing the split client-side avoids
 *  a backend types change and keeps the wire shape backwards
 *  compatible.
 */
const SCHEME_RX = /^(https?|h2c?):\/\//i;
function formatUpstreamUrl(rawUrl: string): { displayUrl: string; wasHttps: boolean } {
        const m = rawUrl.match(SCHEME_RX);
        if (!m) return { displayUrl: rawUrl, wasHttps: false };
        const scheme = m[1].toLowerCase();
        const wasHttps = scheme === 'https' || scheme === 'h2';
        return { displayUrl: rawUrl.slice(m[0].length), wasHttps };
}
