<!--
  ServiceNode — Vue A col 2.

  Simplified upstream node showing service name, primary backend
  address, single-line status, and aggregate req/s. Used in the
  protocol view where the focus is the entry-point -> service flow
  shape, not the per-backend LB breakdown. For the richer cluster
  view with fairness bars, see BackendClusterNode (Vue B col 3).

  The visual `state` (left-border accent color) is pre-computed
  by the layout builder so the component stays pure presentation.
-->
<script lang="ts">
        import { Handle, Position, type NodeProps } from '@xyflow/svelte';
        import type { ServiceNodeData } from '../../_types';

        let { data }: NodeProps & { data: ServiceNodeData } = $props();

        function formatRate(rps: number): string {
                if (rps >= 1000) return `${(rps / 1000).toFixed(1)} k req/s`;
                return `${Math.round(rps)} req/s`;
        }
</script>

<div class="service-node" data-state={data.state}>
        <Handle type="target" position={Position.Left} />

        <div class="service-title">
                <span class="name">{data.serviceName}</span>
                {#if data.runtime}
                        <span class="runtime">({data.runtime})</span>
                {/if}
        </div>

        <div class="address">
                <span class="primary">{data.primaryAddress}</span>
                {#if data.additionalUpstreamCount && data.additionalUpstreamCount > 0}
                        <span class="more">+{data.additionalUpstreamCount}</span>
                {/if}
        </div>

        <div class="status">{data.statusLine}</div>

        {#if data.extraMeta}
                <div class="extra-meta">{data.extraMeta}</div>
        {/if}

        <div class="rate">{formatRate(data.reqPerSec)}</div>
</div>

<style>
        .service-node {
                width: 230px;
                padding: 10px 12px;
                background: var(--surface, oklch(19% 0.006 250));
                border: 1px solid var(--border, oklch(28% 0.009 250));
                border-radius: 8px;
                font-family: var(--font-display, system-ui, sans-serif);
                color: var(--fg, oklch(96% 0.005 250));
                font-size: 12px;
                box-shadow: 0 1px 0 rgb(0 0 0 / 0.4);
        }

        .service-node[data-state='healthy'] {
                border-left: 2px solid var(--accent, oklch(68% 0.21 255));
        }
        .service-node[data-state='warn'] {
                border-left: 2px solid var(--warn, oklch(80% 0.14 85));
        }
        .service-node[data-state='bad'] {
                border-left: 2px solid var(--bad, oklch(66% 0.20 25));
        }

        .service-title {
                display: flex;
                align-items: baseline;
                gap: 6px;
                margin-bottom: 3px;
        }

        .name {
                font-size: 13px;
                font-weight: 600;
        }

        .runtime {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 11px;
                color: var(--fg-muted, oklch(68% 0.012 250));
        }

        .address {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-muted, oklch(68% 0.012 250));
                margin-bottom: 4px;
        }

        .address .more {
                color: var(--fg-dim, oklch(54% 0.011 250));
                margin-left: 4px;
        }

        .status {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-muted, oklch(68% 0.012 250));
                margin-bottom: 3px;
        }

        .service-node[data-state='warn'] .status {
                color: var(--warn, oklch(80% 0.14 85));
        }
        .service-node[data-state='bad'] .status {
                color: var(--bad, oklch(66% 0.20 25));
        }

        .extra-meta {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-dim, oklch(54% 0.011 250));
                margin-bottom: 3px;
        }

        .rate {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 11px;
                color: var(--fg, oklch(96% 0.005 250));
                font-weight: 500;
                margin-top: 4px;
                padding-top: 5px;
                border-top: 1px solid var(--border, oklch(28% 0.009 250));
        }

        :global(.svelte-flow__node-service) {
                padding: 0;
                background: transparent;
                border: none;
                box-shadow: none;
                color: inherit;
        }
</style>
