<!--
  FQDNNode — Col 1 of the Service→Backend view.

  Represents a primary host (api.arenet.fr, app.arenet.fr…) fed by
  upstream consumers and forwarding to Caddy. Declares both handles
  so edges can attach on the right protocol.
-->
<script lang="ts">
        import { Handle, Position, type NodeProps } from '@xyflow/svelte';
        import type { FQDNNodeData } from '../../_types';

        let { data }: NodeProps & { data: FQDNNodeData } = $props();
</script>

<div class="fqdn-node">
        <Handle type="target" position={Position.Left} />

        <div class="host">{data.host}</div>
        <div class="protocols">{data.protocols}</div>
        <div class="meta">{data.meta}</div>

        <Handle type="source" position={Position.Right} />
</div>

<style>
        .fqdn-node {
                width: 200px;
                padding: 10px 12px;
                background: var(--surface, oklch(19% 0.006 250));
                border: 1px solid var(--border, oklch(28% 0.009 250));
                border-radius: 8px;
                font-family: var(--font-display, system-ui, sans-serif);
                color: var(--fg, oklch(96% 0.005 250));
                font-size: 12px;
                box-shadow: 0 1px 0 rgb(0 0 0 / 0.4);
        }

        .host {
                font-size: 13px;
                font-weight: 600;
                margin-bottom: 3px;
        }

        .protocols {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-muted, oklch(68% 0.012 250));
                margin-bottom: 4px;
        }

        .meta {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-dim, oklch(54% 0.011 250));
        }

        :global(.svelte-flow__node-fqdn) {
                padding: 0;
                background: transparent;
                border: none;
                box-shadow: none;
                color: inherit;
        }
</style>
