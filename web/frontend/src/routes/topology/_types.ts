// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

/**
 * Topology view domain types.
 *
 * Frontend-only shapes describing what the topology canvas needs
 * to render. Decoupled from the backend storage.Route to keep the
 * canvas hackable in isolation while the live data feed is being
 * wired up.
 *
 * Important: Svelte Flow constrains `Node<T>` and `Edge<T>` data
 * payloads to extend `Record<string, unknown>`. Each *NodeData /
 * FlowEdgeData type alias is therefore declared as the intersection
 * of the strict shape with Record<string, unknown> — object
 * literals carrying the strict fields then satisfy the intersection
 * directly (no `as` cast needed at the call site).
 */

import type { Node, Edge } from '@xyflow/svelte';

// ---------------------------------------------------------------------------
// Domain enums
// ---------------------------------------------------------------------------

export type LBPolicy =
        | 'round_robin'
        | 'weighted_round_robin'
        | 'least_conn'
        | 'ip_hash'
        | 'random'
        | 'first';

export type HealthStatus = 'healthy' | 'unhealthy' | 'draining' | 'unknown';

export type FlowTier = 'dead' | 'idle' | 'low' | 'mid' | 'high' | 'warn' | 'bad';

// ---------------------------------------------------------------------------
// Domain types — input
// ---------------------------------------------------------------------------

export interface TopologyRoute {
        id: string;
        host: string;
        aliases?: string[];

        upstreams: TopologyUpstream[];
        lbPolicy: LBPolicy;

        reqPerSec: number;
        p99LatencyMs: number;
        errorRate5xx: number;            // 0-100

        tlsEnabled: boolean;
        wafLevel?: 'off' | 'detect' | 'block';
        rateLimited?: boolean;
        mtlsRequired?: boolean;

        // True when storage.Route.HealthCheck.Enabled is true on
        // the backend. Drives the per-upstream shield indicator
        // (#R-TOPO-health-coherence v1.1.0). NOT optional — the
        // backend always emits the field.
        hasHealthCheck: boolean;

        clusterLabel?: string;
}

export interface TopologyUpstream {
        id: string;
        url: string;
        runtime?: string;
        status: HealthStatus;

        // Mirrors the parent route's hasHealthCheck — denormalised
        // by the backend so the UpstreamNode component doesn't have
        // to thread the route in. True ⇒ render a small "monitored"
        // shield next to the URL.
        healthCheckConfigured: boolean;

        reqPerSec: number;
        p99LatencyMs: number;
        fairnessRatio: number;           // 0-1
}

// ---------------------------------------------------------------------------
// Node data payloads — `& Record<string, unknown>` to satisfy
// Svelte Flow's Node<T> constraint.
// ---------------------------------------------------------------------------

/** Col 0 — primary host serving a route.
 *
 *  C16 (2026-06-03): `wafLevel` carries route-level WAF state —
 *  rendered as a Lucide Shield/ShieldCheck glyph next to the host.
 *
 *  C17 (2026-06-04): `aliases` is the additional-hosts list for
 *  the route, used to populate the "X hosts" subline tooltip with
 *  real hostnames. `protocols` is now derived strictly from
 *  TLS-enabled (HTTPS / HTTP) until the backend exposes the real
 *  ALPN list — the previous "HTTPS · h2 · h3" was mock leakage.
 *  See `#R-TOPO-alpn` in docs/backlog-step-r.md. */
export type FQDNNodeData = {
        kind: 'fqdn';
        host: string;
        protocols: string;
        meta: string;
        aliases?: string[];
        wafLevel: 'off' | 'detect' | 'block';
} & Record<string, unknown>;

/** Both views — the single central Caddy hub. */
export type CaddyHubNodeData = {
        kind: 'caddy';
        version: string;
        instanceId: string;
        aggregateReqPerSec: number;
        chips: ('WAF' | 'RATE' | 'mTLS' | 'L7-LB')[];
} & Record<string, unknown>;

/** Vue B col 3 — group container for a route's upstream pool.
 *
 *  Sub-flow restructure (2026-06-03): the cluster used to render
 *  one card with N upstream rows AND a single inbound edge from
 *  caddy-hub. The N edges critique called this out — the operator
 *  couldn't see per-upstream flow shape. We now emit:
 *    - one BackendClusterNode group (this payload, no upstreams[])
 *    - N UpstreamNode children with parentId + extent: 'parent'
 *    - N edges from caddy-hub to each child
 *
 *  The cluster node itself only carries header metadata; the
 *  per-upstream rendering moved to UpstreamNode. `lbPolicy` is
 *  still surfaced in the header but hidden by the component when
 *  totalCount === 1 (round_robin over 1 target is meaningless). */
export type BackendClusterNodeData = {
        kind: 'backend-cluster';
        clusterLabel: string;
        runtime?: string;
        lbPolicy: LBPolicy;
        healthyCount: number;
        // Strictly status === 'unhealthy'. Distinct from
        // `totalCount - healthyCount` because 'unknown' is its own
        // third state in v1.1.0 — see Critique 9 / Regression A.
        unhealthyCount: number;
        totalCount: number;
        // Mirrors the parent route's hasHealthCheck. Drives the
        // header's "monitored" framing: when false we can't talk
        // about "sains" because nothing is being probed.
        hasHealthCheck: boolean;
        warning?: string;
} & Record<string, unknown>;

/** Vue B col 3 child — one upstream inside a cluster group.
 *
 *  Rendered as a sibling of the cluster header in Svelte Flow's
 *  sub-flow layout (parentId points at `cluster-${routeId}` on
 *  the Node, NOT on this data payload). Carries everything the
 *  presentation needs from the source TopologyUpstream plus a
 *  pre-computed flow tier — the parent's data no longer holds an
 *  upstreams[] array, so each child must be self-sufficient. */
export type UpstreamNodeData = {
        kind: 'upstream';
        upstreamId: string;
        url: string;
        runtime?: string;
        status: HealthStatus;
        healthCheckConfigured: boolean;
        // Whether the original url started with https/h2 (or any
        // TLS-bearing scheme). Surfaced as a tiny lock glyph next to
        // the displayDisplayed URL so we don't lose the TLS info when
        // stripping the scheme.
        wasHttps: boolean;
        // Url with scheme stripped for display (http://, https://,
        // h2://, h2c:// removed). The original is preserved on `url`
        // for tooltips and any future copy-to-clipboard action.
        displayUrl: string;
        reqPerSec: number;
        p99LatencyMs: number;
        // Load ratio relative to the busiest upstream across the
        // whole canvas (C14b, 2026-06-04). Pre-computed at layout
        // time so the bar width is a simple `loadRatio * 100%`.
        // Single source of comparison — all upstream bars share the
        // same scale, the eye spots hot upstreams regardless of
        // which cluster they belong to. globalMax === 0 yields 0
        // here (clean empty bars at idle).
        //
        // Replaces the previous `fairnessRatio` which was a
        // per-cluster weight share — meaningless on single-upstream
        // clusters (always 1.0) and not comparable across clusters.
        loadRatio: number;               // 0-1
} & Record<string, unknown>;

export type TopologyNodeData =
        | FQDNNodeData
        | CaddyHubNodeData
        | BackendClusterNodeData
        | UpstreamNodeData;

// ---------------------------------------------------------------------------
// Edge data
// ---------------------------------------------------------------------------

export type FlowEdgeData = {
        kind: 'flow';
        reqPerSec: number;
        p99LatencyMs: number;
        errorRate5xx: number;
} & Record<string, unknown>;

// ---------------------------------------------------------------------------
// Output shape
// ---------------------------------------------------------------------------

export type TopologyNode = Node<TopologyNodeData>;
export type TopologyEdge = Edge<FlowEdgeData>;

export interface TopologyGraph {
        nodes: TopologyNode[];
        edges: TopologyEdge[];
}

// ---------------------------------------------------------------------------
// Tier resolution — single source of truth for AnimatedFlowEdge
// and the legend in the right sidebar.
//
// Precedence:
//   1. errorRate5xx > 0  → 'bad'  (red, dashed)
//   2. p99LatencyMs > 300 → 'warn' (amber)
//   3. reqPerSec brackets matching the mock legend exactly:
//        ≥ 400 req/s → 'high'
//        150–400     → 'mid'
//        20–150      → 'low'
//        (0, 20)     → 'idle' (pale particles)
//        exactly 0   → 'dead' (no particles, line only)
//
// The 'dead' tier (added 2026-06-03) carves out exactly-zero
// traffic from 'idle'. Browser smoke surfaced the confusion:
// 'idle' rendered two pale particles even when the route was
// truly silent (reqPerSec === 0), reading as "a trickle of
// traffic where there is none". 'dead' keeps the edge line
// drawn so the operator still sees the route exists, but skips
// the particle animation so silent routes look silent.
// ---------------------------------------------------------------------------

export function resolveFlowTier(data: FlowEdgeData): FlowTier {
        if (data.errorRate5xx > 0) return 'bad';
        if (data.p99LatencyMs > 300) return 'warn';
        if (data.reqPerSec >= 400) return 'high';
        if (data.reqPerSec >= 150) return 'mid';
        if (data.reqPerSec >= 20) return 'low';
        // Exactly-zero traffic gets its own tier so AnimatedFlowEdge
        // can suppress the particle render. Any positive sub-20
        // value still falls into 'idle' (pale particles).
        if (data.reqPerSec > 0) return 'idle';
        return 'dead';
}
