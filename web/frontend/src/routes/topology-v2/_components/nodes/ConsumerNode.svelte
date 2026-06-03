<!--
  ConsumerNode — Col 0 of the Service→Backend view.

  Aggregated consumer source (web app, mobile app, B2B partners,
  internal tools…). Only emits flow rightward toward FQDN nodes,
  so we declare a source Handle on the right and no target.

  Carries fixture data for Phase 1 — see _layout.ts header comment.
-->
<script lang="ts">
        import { Handle, Position, type NodeProps } from '@xyflow/svelte';
        import type { ConsumerNodeData } from '../../_types';

        let { data }: NodeProps & { data: ConsumerNodeData } = $props();
</script>

<div class="consumer-node">
        <header>
                <div class="title">{data.label}</div>
                <div class="subtitle">{data.subtitle}</div>
        </header>

        {#if data.meta.length > 0}
                <ul class="meta-list">
                        {#each data.meta as line, i (i)}
                                <li>{line}</li>
                        {/each}
                </ul>
        {/if}

        <Handle type="source" position={Position.Right} />
</div>

<style>
        .consumer-node {
                width: 200px;
                padding: 10px 12px;
                background: var(--surface, oklch(19% 0.006 250));
                border: 1px solid var(--border, oklch(28% 0.009 250));
                border-left: 2px solid var(--accent, oklch(68% 0.21 255));
                border-radius: 8px;
                font-family: var(--font-display, system-ui, sans-serif);
                color: var(--fg, oklch(96% 0.005 250));
                font-size: 12px;
                box-shadow: 0 1px 0 rgb(0 0 0 / 0.4);
        }

        .title {
                font-size: 13px;
                font-weight: 600;
                margin-bottom: 2px;
        }

        .subtitle {
                color: var(--fg-muted, oklch(68% 0.012 250));
                font-size: 11px;
        }

        .meta-list {
                list-style: none;
                margin: 6px 0 0 0;
                padding: 6px 0 0 0;
                border-top: 1px solid var(--border, oklch(28% 0.009 250));
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-muted, oklch(68% 0.012 250));
                display: flex;
                flex-direction: column;
                gap: 2px;
        }

        :global(.svelte-flow__node-consumer) {
                padding: 0;
                background: transparent;
                border: none;
                box-shadow: none;
                color: inherit;
        }
</style>
