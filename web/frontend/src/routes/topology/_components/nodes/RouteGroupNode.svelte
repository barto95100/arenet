<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  RouteGroupNode — Sujet 1 Phase 3.c (2026-06-17). Subtle visual
  container wrapping the primary FQDN + its alias sub-nodes in
  col 0 so the operator reads "this whole stack is one route"
  at a glance.

  Pure visual: no handles, no metrics, no content. The size
  is dictated by `width` / `height` on the Node itself (set
  in _layout.ts at emit time, computed from the underlying
  routeCol0Height + lateral padding to cover the AliasNode
  indent + FQDN width).

  Z-order: SvelteFlow renders nodes in array order. The layout
  emits route-group nodes FIRST (per route) so they paint
  BEHIND the primary FQDN + alias cards. Without this the
  container would mask the cards instead of framing them.

  Pointer events: disabled so the container doesn't intercept
  drag / select on the FQDN + alias cards underneath. Operator
  interacts with the cards directly; the container is decoration.

  Palette: --accent-soft (transparent --accent at ~14%) for the
  fill and --border-dim with extra opacity for the stroke. Both
  tokens already exist in the design system and degrade
  gracefully via the inline fallbacks if a future palette shift
  drops them.
-->
<script lang="ts">
        import type { NodeProps } from '@xyflow/svelte';
        import type { RouteGroupNodeData } from '../../_types';

        let { data }: NodeProps & { data: RouteGroupNodeData } = $props();
</script>

<div
        class="route-group"
        role="presentation"
        aria-label={`Route group ${data.primaryHost}`}
></div>

<style>
        .route-group {
                width: 100%;
                height: 100%;
                background: var(
                        --accent-soft,
                        color-mix(in oklch, oklch(68% 0.21 255) 8%, transparent)
                );
                border: 1px dashed
                        color-mix(in oklch, var(--accent, oklch(68% 0.21 255)) 22%, transparent);
                border-radius: 12px;
                box-sizing: border-box;
                pointer-events: none;
        }

        /* SvelteFlow wraps every custom node in .svelte-flow__node-{type}
           with its own padding / border / shadow / background. The
           container is supposed to be invisible chrome; we strip the
           wrapper so only our subtle .route-group surface paints. */
        :global(.svelte-flow__node-route-group) {
                padding: 0;
                background: transparent;
                border: none;
                box-shadow: none;
                color: inherit;
                /* The container must NOT be selectable / focusable —
                   it carries no content the operator can act on. */
                pointer-events: none;
        }
</style>
