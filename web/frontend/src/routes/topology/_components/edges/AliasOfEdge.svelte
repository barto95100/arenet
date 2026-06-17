<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  AliasOfEdge — Semantic-only edge linking an alias node to its
  primary FQDN. Sujet 1 Phase 3.a (Topology Plan B frontend).

  Visual contract (different from AnimatedFlowEdge):
    - DASHED stroke. The dash pattern signals "this is not a
      traffic edge" so the operator's eye doesn't seek a flow
      shape along this line. Anchored by the same operator-mock
      convention used elsewhere in the canvas for non-flow
      relationships.
    - NO particles. Adding moving dots on alias→primary edges
      would visually double-count the route's traffic — the
      real flow already animates on the Caddy→Backend edges
      shared by every alias of the route. The dashed line
      reads as "alias-of" pure relationship, not data flow.
    - Muted, low-chroma color. The accent palette is reserved
      for traffic-bearing AnimatedFlowEdge in the same canvas;
      AliasOfEdge in --fg-dim sits visually behind any flow
      edge crossing the same screen space, so a 21-alias route
      doesn't drown out the real per-route traffic indicators.
    - Thin stroke-width (1px) — matches the visual weight of a
      hint, not a primary connection.

  Implementation mirrors AnimatedFlowEdge's BaseEdge wrapper +
  getBezierPath geometry helper. The lack of <animateMotion>
  particles is the only structural delta; the BaseEdge alone
  paints the dashed bezier and Svelte Flow handles drag/select
  state transparently.
-->
<script lang="ts">
        import { BaseEdge, getBezierPath, type EdgeProps } from '@xyflow/svelte';
        import type { AliasOfEdgeData } from '../../_types';

        type Props = EdgeProps & { data?: AliasOfEdgeData };

        let {
                id,
                sourceX,
                sourceY,
                targetX,
                targetY,
                sourcePosition,
                targetPosition,
                markerEnd,
        }: Props = $props();

        let pathTuple = $derived(
                getBezierPath({
                        sourceX,
                        sourceY,
                        targetX,
                        targetY,
                        sourcePosition,
                        targetPosition,
                }),
        );
        let edgePath = $derived(pathTuple[0]);

        // Visual constants — stroke style locked at module scope so
        // a future operator-driven theme tweak can be applied in one
        // place. The dash pattern (3 on, 4 off) is shorter than the
        // FlowEdge 'bad'-tier dash (4 on, 4 off) so the two read as
        // distinct visual languages when they happen to coexist on
        // the same canvas (rare but possible if a route is both
        // erroring at 5xx AND has aliases).
        const STROKE_STYLE =
                'stroke: var(--fg-dim, oklch(54% 0.011 250));' +
                ' stroke-opacity: 0.55;' +
                ' stroke-width: 1;' +
                ' stroke-dasharray: 3 4;';
</script>

<BaseEdge {id} path={edgePath} {markerEnd} style={STROKE_STYLE} />
