<!--
  CaddyHubNode — Col 2 of both views. The single central hub.

  Shows the running Caddy version + Arenet instance id + aggregate
  inbound req/s, with chips for the active site-wide capabilities
  (WAF, rate-limit, mTLS, L7-LB). Pulse glow on the border keeps it
  visually anchored as the conversation piece of the topology.
-->
<script lang="ts">
        import { Handle, Position, type NodeProps } from '@xyflow/svelte';
        import type { CaddyHubNodeData } from '../../_types';

        let { data }: NodeProps & { data: CaddyHubNodeData } = $props();

        function formatRate(rps: number): string {
                if (rps >= 1000) return `${(rps / 1000).toFixed(1)} k req/s`;
                return `${Math.round(rps)} req/s`;
        }
</script>

<div class="caddy-node">
        <Handle type="target" position={Position.Left} />

        <div class="caddy-title">{data.version}</div>
        <div class="caddy-instance">{data.instanceId}</div>
        <div class="caddy-rate">{formatRate(data.aggregateReqPerSec)}</div>

        {#if data.chips.length > 0}
                <div class="chips">
                        {#each data.chips as chip (chip)}
                                <span class="chip">{chip}</span>
                        {/each}
                </div>
        {/if}

        <Handle type="source" position={Position.Right} />
</div>

<style>
        .caddy-node {
                width: 180px;
                padding: 14px 14px 10px 14px;
                background: var(--surface, oklch(19% 0.006 250));
                border: 1.5px solid var(--accent-line, oklch(68% 0.21 255 / 0.45));
                border-radius: 10px;
                font-family: var(--font-display, system-ui, sans-serif);
                color: var(--fg, oklch(96% 0.005 250));
                font-size: 12px;
                text-align: center;
                box-shadow: 0 0 18px oklch(68% 0.21 255 / 0.14);
        }

        .caddy-title {
                font-size: 14px;
                font-weight: 600;
                margin-bottom: 2px;
        }

        .caddy-instance {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-muted, oklch(68% 0.012 250));
                letter-spacing: 0.03em;
                text-transform: uppercase;
                margin-bottom: 6px;
        }

        .caddy-rate {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 11px;
                color: var(--accent, oklch(68% 0.21 255));
                font-weight: 500;
                margin-bottom: 8px;
        }

        .chips {
                display: flex;
                justify-content: center;
                flex-wrap: wrap;
                gap: 4px;
        }

        .chip {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 9.5px;
                padding: 2px 6px;
                border: 1px solid var(--border-hi, oklch(34% 0.011 250));
                border-radius: 4px;
                color: var(--fg-muted, oklch(68% 0.012 250));
                background: var(--surface-2, oklch(22% 0.007 250));
                letter-spacing: 0.04em;
        }

        :global(.svelte-flow__node-caddy) {
                padding: 0;
                background: transparent;
                border: none;
                box-shadow: none;
                color: inherit;
        }
</style>
