// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

/**
 * Layout builder for the topology canvas.
 *
 * Single pure function `buildTopologyGraph(routes)` that emits a
 * three-column graph:
 *
 *   col 0 (FQDN)        primary host per route
 *   col 1 (Caddy hub)   single central hub node
 *   col 2 (backends)    one BackendCluster group per route with N
 *                       UpstreamNode children inside (sub-flow);
 *                       caddy-hub fans out to one edge per upstream
 *
 * C6b-i (2026-06-04) simplified this module: the previous
 * "Vue protocole" entry-point layout and the consumer column on
 * the service view were Phase-1 mock leakage — entry-point and
 * consumer fixtures were hardcoded constants, the view toggle
 * exposed a second canvas that carried no real data. Dropping
 * both views collapses the layout to a single source-of-truth
 * builder reading only from the live route list.
 */

import type {
        BackendClusterNodeData,
        CaddyHubNodeData,
        FlowEdgeData,
        FQDNNodeData,
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

/** Three-column layout: FQDN → Caddy hub → BackendCluster. The
 *  cluster column was 900px in the four-column service view; with
 *  the consumer column removed (C6b-i) everything shifts left,
 *  the canvas occupies 0..800 horizontally instead of 0..900. */
const COL_X = {
        FQDN: 0,
        CADDY: 400,
        BACKEND: 800,
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

// ===========================================================================
// Public API — buildTopologyGraph
// ===========================================================================

/**
 * Build the topology graph from the live route list. Single source
 * of truth — no fixtures, no view variants.
 *
 *   col 0 (FQDN)        primary host per route
 *   col 1 (Caddy hub)   single central hub node
 *   col 2 (backends)    one BackendCluster group per route with N
 *                       UpstreamNode children inside (sub-flow);
 *                       caddy-hub fans out to one edge per upstream
 */
export function buildTopologyGraph(routes: TopologyRoute[]): TopologyGraph {
        const nodes: TopologyNode[] = [];
        const edges: TopologyEdge[] = [];

        // C14b (2026-06-04): UpstreamNode bar width is a
        // global-relative ratio reqPerSec / globalMax. Compute once
        // up front so every upstream's data carries its own
        // pre-divided loadRatio. Falls back to 0 across the board
        // when nothing has traffic — avoids divide-by-zero and keeps
        // all bars empty at idle for a clean baseline.
        let globalMaxReqPerSec = 0;
        for (const r of routes) {
                for (const u of r.upstreams) {
                        if (u.reqPerSec > globalMaxReqPerSec) globalMaxReqPerSec = u.reqPerSec;
                }
        }

        // Col 0 — FQDN
        const fqdnYs = computeStackYs(routes.length);
        routes.forEach((route, i) => {
                const data: FQDNNodeData = {
                        kind: 'fqdn',
                        host: route.host,
                        protocols: formatProtocols(route),
                        meta: formatFQDNMeta(route),
                        aliases: route.aliases,
                        wafLevel: route.wafLevel ?? 'off',
                };
                nodes.push({
                        id: `fqdn-${route.id}`,
                        type: 'fqdn',
                        position: { x: COL_X.FQDN, y: fqdnYs[i] },
                        data,
                });
        });

        // Col 1 — Caddy hub
        nodes.push(buildCaddyNode(routes, COL_X.CADDY));

        // Col 2 — Backend clusters as sub-flow groups + N upstream children
        //
        // Each cluster is a group node sized to fit its upstream pool.
        // Cluster Ys are computed so the *centers* of variable-height
        // groups remain evenly spaced and prevent overlap when one
        // route has many upstreams. Children carry parentId +
        // extent: 'parent' so Svelte Flow keeps them inside the group
        // when the user drags either the parent or a child.
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
                        position: { x: COL_X.BACKEND, y: clusterYs[i] },
                        width: CLUSTER_WIDTH,
                        height: clusterHeights[i],
                        data: clusterData,
                });

                // Upstream children. Position is local to the parent.
                route.upstreams.forEach((upstream, ui) => {
                        const childY = CLUSTER_PADDING_TOP + ui * (UPSTREAM_HEIGHT + UPSTREAM_GAP_Y);
                        const { displayUrl, wasHttps } = formatUpstreamUrl(upstream.url);
                        const loadRatio =
                                globalMaxReqPerSec > 0
                                        ? upstream.reqPerSec / globalMaxReqPerSec
                                        : 0;
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
                                loadRatio,
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

        // Edges: FQDN -> caddy, caddy -> upstream (fan-out per cluster)
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
// Helpers
// ===========================================================================

function buildCaddyNode(routes: TopologyRoute[], x: number): TopologyNode {
        // C21 (2026-06-04) trimmed the visible content of the hub
        // to "Caddy" + aggregate req/s; version + instanceId now
        // surface only as a hover tooltip in the component.
        const data: CaddyHubNodeData = {
                kind: 'caddy',
                version: 'Caddy 2.8',
                instanceId: 'arenet-instance',
                aggregateReqPerSec: routes.reduce((sum, r) => sum + r.reqPerSec, 0),
        };
        return {
                id: 'caddy-hub',
                type: 'caddy',
                position: { x, y: 0 },
                data,
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

/** FQDN protocols label.
 *
 *  C18 (2026-06-04): renders "HTTP → HTTPS" when the route has
 *  TLS enabled AND http→https redirect configured, otherwise just
 *  "HTTPS" / "HTTP". The arrow communicates "plain-HTTP requests
 *  get bounced", which the operator can't otherwise see from the
 *  canvas. tlsEnabled === false short-circuits to "HTTP" (you
 *  can't redirect to a non-existent HTTPS endpoint).
 *
 *  C17a (2026-06-04 same commit): the previous "HTTPS · h2 · h3"
 *  mock suffix is gone — the backend doesn't expose real ALPN
 *  yet (#R-TOPO-alpn).
 */
function formatProtocols(route: TopologyRoute): string {
        if (!route.tlsEnabled) return 'HTTP';
        if (route.httpRedirect) return 'HTTP → HTTPS';
        return 'HTTPS';
}

/** FQDN meta line.
 *
 *  Always shows the current req/s. C17b + C19 (2026-06-04):
 *  appends an alias count ONLY when the route actually has
 *  aliases. The label uses "alias(es)" terminology so the
 *  primary FQDN (already shown above) isn't counted in the
 *  number — operator's mental model is "the FQDN plus how
 *  many additional hosts", and "1 host" for a route with no
 *  aliases was confusing noise.
 */
function formatFQDNMeta(route: TopologyRoute): string {
        const rate = formatRate(route.reqPerSec);
        const aliasCount = route.aliases?.length ?? 0;
        if (aliasCount === 0) return rate;
        if (aliasCount === 1) return `${rate} · 1 alias`;
        return `${rate} · ${aliasCount} aliases`;
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
