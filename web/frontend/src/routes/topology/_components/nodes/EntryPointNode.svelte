<!--
  EntryPointNode — Vue A col 0.

  Represents a Caddy listener entry point (port + transport +
  routing handler). Sources flow toward Caddy, so only a right
  Handle is declared.
-->
<script lang="ts">
        import { Handle, Position, type NodeProps } from '@xyflow/svelte';
        import type { EntryPointNodeData } from '../../_types';

        let { data }: NodeProps & { data: EntryPointNodeData } = $props();

        function formatRate(rps: number): string {
                if (rps >= 1000) return `${(rps / 1000).toFixed(1)} k req/s`;
                return `${Math.round(rps)} req/s`;
        }
</script>

<div class="entry-point-node">
        <div class="protocol">{data.protocol}</div>
        <div class="subtitle">{data.subtitle}</div>

        {#if data.hosts.length > 0}
                <ul class="hosts-list">
                        {#each data.hosts as host, i (i)}
                                <li>{host}</li>
                        {/each}
                </ul>
        {/if}

        <div class="rate">{formatRate(data.reqPerSec)}</div>

        <Handle type="source" position={Position.Right} />
</div>

<style>
        .entry-point-node {
                width: 210px;
                padding: 10px 12px;
                background: var(--surface, oklch(19% 0.006 250));
                border: 1px solid var(--border, oklch(28% 0.009 250));
                border-radius: 8px;
                font-family: var(--font-display, system-ui, sans-serif);
                color: var(--fg, oklch(96% 0.005 250));
                font-size: 12px;
                box-shadow: 0 1px 0 rgb(0 0 0 / 0.4);
        }

        .protocol {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 12px;
                font-weight: 500;
                color: var(--fg, oklch(96% 0.005 250));
                margin-bottom: 3px;
        }

        .subtitle {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-muted, oklch(68% 0.012 250));
                margin-bottom: 5px;
        }

        .hosts-list {
                list-style: none;
                margin: 0 0 5px 0;
                padding: 0;
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-dim, oklch(54% 0.011 250));
        }

        .hosts-list li {
                line-height: 1.45;
        }

        .rate {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 11px;
                color: var(--fg, oklch(96% 0.005 250));
                font-weight: 500;
                padding-top: 5px;
                border-top: 1px solid var(--border, oklch(28% 0.009 250));
        }

        :global(.svelte-flow__node-entry-point) {
                padding: 0;
                background: transparent;
                border: none;
                box-shadow: none;
                color: inherit;
        }
</style>
