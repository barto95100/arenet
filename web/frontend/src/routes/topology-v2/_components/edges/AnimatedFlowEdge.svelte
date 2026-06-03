<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  AnimatedFlowEdge — custom Svelte Flow edge that paints a bezier
  path between two nodes and overlays animated SVG particles that
  follow the path via <mpath>. The particle count, size, glow, and
  the stroke color/style all derive from the FlowTier computed
  from this edge's live FlowEdgeData (req/s, p99, errorRate).

  Tier mapping is centralized in _types.ts -> resolveFlowTier so
  the legend in the right sidebar can use the exact same thresholds
  without drift.

  Implementation notes:
   - <BaseEdge> renders a <path id={id}> we can reference.
   - Each <circle> uses <animateMotion><mpath href="#{id}"/></animateMotion>
     to follow that path.
   - Particles are staggered by setting `begin` to a negative offset
     so they appear pre-distributed along the path at t=0 instead
     of all bunched up at the source.
-->
<script lang="ts">
        import { BaseEdge, getBezierPath, type EdgeProps } from '@xyflow/svelte';
        import { resolveFlowTier, type FlowEdgeData, type FlowTier } from '../../_types';

        type Props = EdgeProps & { data?: FlowEdgeData };

        let {
                id,
                sourceX,
                sourceY,
                targetX,
                targetY,
                sourcePosition,
                targetPosition,
                data,
                markerEnd,
        }: Props = $props();

        // -----------------------------------------------------------------
        // Geometry — Svelte Flow's bezier helper does the heavy lifting.
        // -----------------------------------------------------------------
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

        // -----------------------------------------------------------------
        // Tier resolution + visual config tables.
        //
        // Counts and durations are calibrated to the mock:
        //   - more traffic = more particles, faster
        //   - high tier gets larger radius + stronger glow
        //   - 'bad' tier additionally dashes the underlying stroke
        // -----------------------------------------------------------------
        let tier: FlowTier = $derived(data ? resolveFlowTier(data) : 'idle');

        type TierConfig = {
                count: number;
                durS: number;
                radius: number;
                opacity: number;
                glowPx: number;
        };

        function tierConfig(t: FlowTier): TierConfig {
                switch (t) {
                        case 'idle':
                                return { count: 2, durS: 6, radius: 1.4, opacity: 0.55, glowPx: 0 };
                        case 'low':
                                return { count: 3, durS: 4, radius: 1.8, opacity: 0.75, glowPx: 0 };
                        case 'mid':
                                return { count: 4, durS: 3, radius: 2.2, opacity: 0.95, glowPx: 3 };
                        case 'high':
                                return { count: 5, durS: 2, radius: 2.6, opacity: 1.0, glowPx: 5 };
                        case 'warn':
                                return { count: 3, durS: 3, radius: 2.0, opacity: 0.95, glowPx: 4 };
                        case 'bad':
                                return { count: 4, durS: 3, radius: 2.2, opacity: 1.0, glowPx: 4 };
                }
        }

        function tierColor(t: FlowTier): string {
                switch (t) {
                        case 'idle':
                                return 'oklch(60% 0.01 250)';
                        case 'low':
                        case 'mid':
                        case 'high':
                                return 'oklch(68% 0.21 255)';
                        case 'warn':
                                return 'oklch(80% 0.14 85)';
                        case 'bad':
                                return 'oklch(66% 0.20 25)';
                }
        }

        function tierStrokeStyle(t: FlowTier): string {
                const color = tierColor(t);
                const opacity = t === 'idle' ? 0.3 : t === 'bad' ? 0.6 : t === 'warn' ? 0.5 : 0.45;
                const dashed = t === 'bad' ? ' stroke-dasharray: 4 4;' : '';
                return `stroke: ${color}; stroke-opacity: ${opacity}; stroke-width: 1.5;${dashed}`;
        }

        let cfg = $derived(tierConfig(tier));
        let color = $derived(tierColor(tier));
        let strokeStyle = $derived(tierStrokeStyle(tier));
</script>

<!-- The path itself; id={id} so our <mpath> below can reference it. -->
<BaseEdge {id} path={edgePath} {markerEnd} style={strokeStyle} />

<!-- Particle trail. Each circle is staggered via negative `begin` so
     they appear spread along the path at t=0 instead of bunched up at
     the source. -->
{#each Array.from({ length: cfg.count }) as _, i (i)}
        <circle
                r={cfg.radius}
                fill={color}
                style:opacity={cfg.opacity}
                style:filter={cfg.glowPx > 0
                        ? `drop-shadow(0 0 ${cfg.glowPx}px ${color})`
                        : 'none'}
                style:pointer-events="none"
        >
                <animateMotion
                        dur="{cfg.durS}s"
                        repeatCount="indefinite"
                        begin="{-1 * (cfg.durS / cfg.count) * i}s"
                >
                        <mpath href={`#${id}`} />
                </animateMotion>
        </circle>
{/each}
