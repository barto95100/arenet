<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  BackendClusterNode — the richest custom node in the topology
  canvas. Renders a cluster of upstreams behind one route, with:

    - Header chip: cluster name + LB policy + health ratio
    - One row per upstream: address, runtime, p99, req/s, fairness bar
    - Optional warning footer (SPOF, partial outage, etc.)

  The single source of truth for what to render is the
  BackendClusterNodeData payload built in layout.ts. This component
  is pure presentation: no fetches, no stores, no side effects.
-->
<script lang="ts">
        import { Handle, Position, type NodeProps } from '@xyflow/svelte';
        import type {
                BackendClusterNodeData,
                HealthStatus,
                LBPolicy,
                TopologyUpstream,
        } from '../../_types';

        // Svelte Flow passes the node payload as `data`. We narrow
        // the union to BackendClusterNodeData here for type-safe field
        // access — layout.ts is the only place that constructs these
        // and tags them via `type: 'backend-cluster'`.
        let { data }: NodeProps & { data: BackendClusterNodeData } = $props();

        // Cluster-level health state, drives header color.
        let clusterState = $derived(deriveClusterState(data));

        function deriveClusterState(d: BackendClusterNodeData): 'healthy' | 'warn' | 'bad' {
                if (d.healthyCount === 0) return 'bad';
                if (d.healthyCount < d.totalCount) return 'warn';
                // Warning string can also force a 'warn' tint even when
                // all upstreams are healthy (e.g. SPOF on single replica).
                if (d.warning) return 'warn';
                return 'healthy';
        }

        function formatLBPolicy(p: LBPolicy): string {
                switch (p) {
                        case 'round_robin':
                                return 'ROUND ROBIN';
                        case 'weighted_round_robin':
                                return 'WEIGHTED RR';
                        case 'least_conn':
                                return 'LEAST CONN';
                        case 'ip_hash':
                                return 'IP HASH (sticky)';
                        case 'random':
                                return 'RANDOM';
                        case 'first':
                                return 'FIRST';
                }
        }

        function statusDotClass(s: HealthStatus): string {
                return `dot dot-${s}`;
        }

        function formatRate(rps: number): string {
                if (rps >= 1000) return `${(rps / 1000).toFixed(1)}k r/s`;
                return `${Math.round(rps)} r/s`;
        }

        // Stable id helper for the fairness bar inner — purely cosmetic,
        // lets CSS animations / future micro-interactions key on a real
        // DOM id without inventing one inline.
        function upstreamRowId(u: TopologyUpstream): string {
                return `up-${u.id}`;
        }
</script>

<div class="cluster-node" data-state={clusterState}>
        <!-- Inbound handle (Caddy -> cluster). We only declare the
             target side; clusters never source flow in our topology. -->
        <Handle type="target" position={Position.Left} />

        <!-- Header -->
        <header class="cluster-header">
                <div class="cluster-title">
                        <span class="cluster-label">{data.clusterLabel}</span>
                        {#if data.runtime}
                                <span class="cluster-runtime">({data.runtime})</span>
                        {/if}
                </div>
                <div class="cluster-meta">
                        <span class="lb-policy">{formatLBPolicy(data.lbPolicy)}</span>
                        <span class="sep">·</span>
                        <span class="health-ratio">
                                {data.healthyCount} sains / {data.totalCount}
                        </span>
                </div>
        </header>

        <!-- Upstream rows -->
        <ul class="upstream-list">
                {#each data.upstreams as upstream (upstream.id)}
                        <li class="upstream-row" id={upstreamRowId(upstream)} data-status={upstream.status}>
                                <div class="up-line-1">
                                        <span class={statusDotClass(upstream.status)} aria-hidden="true"></span>
                                        <span class="up-url">{upstream.url}</span>
                                        <span class="up-p99">p99 {Math.round(upstream.p99LatencyMs)} ms</span>
                                </div>
                                <div class="up-line-2">
                                        <div class="fairness-bar" aria-label="Fairness {Math.round(upstream.fairnessRatio * 100)}%">
                                                <div
                                                        class="fairness-fill"
                                                        style:width="{Math.round(upstream.fairnessRatio * 100)}%"
                                                ></div>
                                        </div>
                                        <span class="up-rps">{formatRate(upstream.reqPerSec)}</span>
                                </div>
                        </li>
                {/each}
        </ul>

        <!-- Optional warning footer -->
        {#if data.warning}
                <footer class="cluster-warning">
                        <svg class="warn-ico" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
                                <path d="M8 2 L14 13 L2 13 Z" />
                                <path d="M8 6 v3" stroke-linecap="round" />
                                <circle cx="8" cy="11" r="0.6" fill="currentColor" stroke="none" />
                        </svg>
                        <span>{data.warning}</span>
                </footer>
        {/if}
</div>

<style>
        .cluster-node {
                width: 260px;
                background: var(--surface, oklch(19% 0.006 250));
                border: 1px solid var(--border, oklch(28% 0.009 250));
                border-radius: 8px;
                overflow: hidden;
                font-family: var(--font-display, system-ui, sans-serif);
                color: var(--fg, oklch(96% 0.005 250));
                font-size: 12px;
                box-shadow: 0 1px 0 rgb(0 0 0 / 0.4);
        }

        /* State-dependent left border accent — quickly scannable
           when many clusters share the column. */
        .cluster-node[data-state='healthy'] {
                border-left: 2px solid var(--accent, oklch(68% 0.21 255));
        }
        .cluster-node[data-state='warn'] {
                border-left: 2px solid var(--warn, oklch(80% 0.14 85));
        }
        .cluster-node[data-state='bad'] {
                border-left: 2px solid var(--bad, oklch(66% 0.20 25));
        }

        /* ---------- Header ---------- */
        .cluster-header {
                padding: 10px 12px 8px 12px;
                border-bottom: 1px solid var(--border, oklch(28% 0.009 250));
                background: var(--surface-2, oklch(22% 0.007 250));
        }

        .cluster-title {
                display: flex;
                align-items: baseline;
                gap: 6px;
                margin-bottom: 4px;
        }

        .cluster-label {
                font-size: 13px;
                font-weight: 600;
                letter-spacing: 0.01em;
        }

        .cluster-runtime {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 11px;
                color: var(--fg-muted, oklch(68% 0.012 250));
        }

        .cluster-meta {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-muted, oklch(68% 0.012 250));
                letter-spacing: 0.03em;
                text-transform: uppercase;
        }

        .cluster-meta .sep {
                margin: 0 6px;
                color: var(--fg-dim, oklch(54% 0.011 250));
        }

        /* ---------- Upstream rows ---------- */
        .upstream-list {
                list-style: none;
                margin: 0;
                padding: 4px 0;
        }

        .upstream-row {
                padding: 7px 12px;
                display: flex;
                flex-direction: column;
                gap: 4px;
        }

        .upstream-row + .upstream-row {
                border-top: 1px solid var(--border, oklch(28% 0.009 250));
        }

        .up-line-1 {
                display: flex;
                align-items: center;
                gap: 8px;
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 11.5px;
        }

        .up-line-2 {
                display: flex;
                align-items: center;
                gap: 8px;
        }

        .up-url {
                flex: 1 1 auto;
                color: var(--fg, oklch(96% 0.005 250));
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
        }

        .up-p99 {
                flex: 0 0 auto;
                color: var(--fg-muted, oklch(68% 0.012 250));
                font-size: 10.5px;
        }

        .up-rps {
                flex: 0 0 auto;
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-muted, oklch(68% 0.012 250));
                min-width: 56px;
                text-align: right;
        }

        /* ---------- Status dot ---------- */
        .dot {
                flex: 0 0 auto;
                width: 7px;
                height: 7px;
                border-radius: 50%;
                background: var(--fg-dim, oklch(54% 0.011 250));
        }
        .dot-healthy {
                background: var(--ok, oklch(72% 0.16 150));
                box-shadow: 0 0 4px oklch(72% 0.16 150 / 0.55);
        }
        .dot-unhealthy {
                background: var(--bad, oklch(66% 0.20 25));
                box-shadow: 0 0 4px oklch(66% 0.20 25 / 0.6);
        }
        .dot-draining {
                background: var(--warn, oklch(80% 0.14 85));
        }
        .dot-unknown {
                background: var(--fg-dim, oklch(54% 0.011 250));
        }

        /* ---------- Fairness bar ---------- */
        .fairness-bar {
                flex: 1 1 auto;
                height: 4px;
                background: var(--border, oklch(28% 0.009 250));
                border-radius: 2px;
                overflow: hidden;
        }

        .fairness-fill {
                height: 100%;
                background: var(--accent, oklch(68% 0.21 255));
                border-radius: 2px;
                transition: width 0.6s ease;
        }

        /* Color the fill by the row status — a draining or unhealthy
           upstream's share is more striking when it's not blue. */
        .upstream-row[data-status='draining'] .fairness-fill {
                background: var(--warn, oklch(80% 0.14 85));
        }
        .upstream-row[data-status='unhealthy'] .fairness-fill {
                background: var(--bad, oklch(66% 0.20 25));
        }
        .upstream-row[data-status='unknown'] .fairness-fill {
                background: var(--fg-dim, oklch(54% 0.011 250));
        }

        /* ---------- Warning footer ---------- */
        .cluster-warning {
                display: flex;
                align-items: flex-start;
                gap: 6px;
                padding: 8px 12px;
                border-top: 1px solid var(--border, oklch(28% 0.009 250));
                background: oklch(22% 0.007 250 / 0.5);
                color: var(--warn, oklch(80% 0.14 85));
                font-size: 11px;
                line-height: 1.4;
        }

        .cluster-warning .warn-ico {
                flex: 0 0 auto;
                width: 12px;
                height: 12px;
                margin-top: 1px;
        }

        /* Bad-state warning has stronger color */
        .cluster-node[data-state='bad'] .cluster-warning {
                color: var(--bad, oklch(66% 0.20 25));
        }

        /* Svelte Flow injects its own .svelte-flow__node wrapper around
           our component. We don't need its default padding/box-shadow —
           override below. The :global selector targets the wrapper from
           inside our scoped component, which is the documented pattern
           in the Svelte Flow custom-nodes guide. */
        :global(.svelte-flow__node-backend-cluster) {
                padding: 0;
                background: transparent;
                border: none;
                box-shadow: none;
                color: inherit;
        }
</style>