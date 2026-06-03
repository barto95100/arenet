<!--
  CaddyHubNode — the single central routing focal point.

  C21 (2026-06-04) reshape: round container, content trimmed to
  "Caddy" label + aggregate req/s. Version + instanceId moved to a
  hover tooltip; the previous chip block (L7-LB / WAF / RATE / mTLS)
  is gone entirely. The round geometry visually distinguishes the
  hub from the rectangular FQDN and cluster nodes — "this is the
  routing center" without needing words.
-->
<script lang="ts">
        import { Handle, Position, type NodeProps } from '@xyflow/svelte';
        import type { CaddyHubNodeData } from '../../_types';

        let { data }: NodeProps & { data: CaddyHubNodeData } = $props();

        function formatRate(rps: number): string {
                if (rps >= 1000) return `${(rps / 1000).toFixed(1)} k req/s`;
                return `${Math.round(rps)} req/s`;
        }

        // Tooltip surfacing the static identifiers the visible label
        // used to show. Format: "<version> · <instanceId>".
        let hubTooltip = $derived(`${data.version} · ${data.instanceId}`);
</script>

<div class="caddy-node" title={hubTooltip}>
        <Handle type="target" position={Position.Left} />

        <div class="caddy-title">Caddy</div>
        <div class="caddy-rate">{formatRate(data.aggregateReqPerSec)}</div>

        <Handle type="source" position={Position.Right} />
</div>

<style>
        .caddy-node {
                /* Round 130x130 focal point. The accent border + soft
                   outer glow keep the hub the eye-catcher of the
                   canvas without adding any text decoration. */
                width: 130px;
                height: 130px;
                border-radius: 50%;
                box-sizing: border-box;
                background: var(--surface, oklch(19% 0.006 250));
                border: 1.5px solid var(--accent-line, oklch(68% 0.21 255 / 0.55));
                box-shadow: 0 0 22px oklch(68% 0.21 255 / 0.18);
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                gap: 4px;
                font-family: var(--font-display, system-ui, sans-serif);
                color: var(--fg, oklch(96% 0.005 250));
                font-size: 12px;
                text-align: center;
        }

        .caddy-title {
                font-size: 15px;
                font-weight: 600;
                letter-spacing: 0.01em;
        }

        .caddy-rate {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 12px;
                color: var(--accent, oklch(68% 0.21 255));
                font-weight: 500;
        }

        /* Svelte Flow wrapper override — keep the wrapper transparent
           so only our round .caddy-node paints. Without this the
           wrapper's default rectangular box would frame the circle. */
        :global(.svelte-flow__node-caddy) {
                padding: 0;
                background: transparent;
                border: none;
                box-shadow: none;
                color: inherit;
        }
</style>
