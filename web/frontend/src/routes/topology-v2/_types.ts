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

export type FlowTier = 'idle' | 'low' | 'mid' | 'high' | 'warn' | 'bad';

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

        clusterLabel?: string;
}

export interface TopologyUpstream {
        id: string;
        url: string;
        runtime?: string;
        status: HealthStatus;

        reqPerSec: number;
        p99LatencyMs: number;
        fairnessRatio: number;           // 0-1
}

// ---------------------------------------------------------------------------
// Node data payloads — `& Record<string, unknown>` to satisfy
// Svelte Flow's Node<T> constraint.
// ---------------------------------------------------------------------------

export type EntryPointNodeData = {
        kind: 'entry-point';
        protocol: string;
        subtitle: string;
        hosts: string[];
        reqPerSec: number;
} & Record<string, unknown>;

export type ConsumerNodeData = {
        kind: 'consumer';
        label: string;
        subtitle: string;
        meta: string[];
} & Record<string, unknown>;

export type FQDNNodeData = {
        kind: 'fqdn';
        host: string;
        protocols: string;
        meta: string;
} & Record<string, unknown>;

export type CaddyHubNodeData = {
        kind: 'caddy';
        version: string;
        instanceId: string;
        aggregateReqPerSec: number;
        chips: ('WAF' | 'RATE' | 'mTLS' | 'L7-LB')[];
} & Record<string, unknown>;

export type BackendClusterNodeData = {
        kind: 'backend-cluster';
        clusterLabel: string;
        runtime?: string;
        lbPolicy: LBPolicy;
        upstreams: TopologyUpstream[];
        healthyCount: number;
        totalCount: number;
        warning?: string;
} & Record<string, unknown>;

export type TopologyNodeData =
        | EntryPointNodeData
        | ConsumerNodeData
        | FQDNNodeData
        | CaddyHubNodeData
        | BackendClusterNodeData;

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

export type TopologyViewMode = 'protocol' | 'service-to-backend';

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
//        < 20        → 'idle'
// ---------------------------------------------------------------------------

export function resolveFlowTier(data: FlowEdgeData): FlowTier {
        if (data.errorRate5xx > 0) return 'bad';
        if (data.p99LatencyMs > 300) return 'warn';
        if (data.reqPerSec >= 400) return 'high';
        if (data.reqPerSec >= 150) return 'mid';
        if (data.reqPerSec >= 20) return 'low';
        return 'idle';
}
