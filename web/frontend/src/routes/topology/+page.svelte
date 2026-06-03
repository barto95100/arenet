<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Topology v2 — Phase 1.3.

  Two-column page layout (canvas | sidebar) with a centered view
  toggle on top of the canvas that swaps between:

    - Vue protocole         entry-points -> Caddy -> services
    - Vue service -> backend  consumers -> FQDN -> Caddy -> clusters

  Both views share the Caddy hub and the AnimatedFlowEdge. The
  toggle does not refit the canvas; the user keeps their zoom/pan
  when switching, which is the right behavior when comparing the
  two perspectives side-by-side.
-->
<script lang="ts">
        import { SvelteFlow, Background, Controls, type NodeTypes, type EdgeTypes } from '@xyflow/svelte';
        import '@xyflow/svelte/dist/style.css';

        import { buildProtocolGraph, buildServiceToBackendGraph } from './_layout';
        import { mockRoutes } from './_mock-data';
        import type { TopologyViewMode } from './_types';

        // Custom node components — one per `kind` emitted by the layout builders.
        import EntryPointNode from './_components/nodes/EntryPointNode.svelte';
        import ConsumerNode from './_components/nodes/ConsumerNode.svelte';
        import FQDNNode from './_components/nodes/FQDNNode.svelte';
        import CaddyHubNode from './_components/nodes/CaddyHubNode.svelte';
        import ServiceNode from './_components/nodes/ServiceNode.svelte';
        import BackendClusterNode from './_components/nodes/BackendClusterNode.svelte';
        import AnimatedFlowEdge from './_components/edges/AnimatedFlowEdge.svelte';

        // Page-level UI
        import ViewToggle from './_components/ViewToggle.svelte';
        import TopologySidebar from './_components/TopologySidebar.svelte';

        const nodeTypes: NodeTypes = {
                'entry-point': EntryPointNode,
                consumer: ConsumerNode,
                fqdn: FQDNNode,
                caddy: CaddyHubNode,
                service: ServiceNode,
                'backend-cluster': BackendClusterNode,
        };

        const edgeTypes: EdgeTypes = {
                'animated-flow': AnimatedFlowEdge,
        };

        // Current view + initial graph. We default to Vue service -> backend
        // because it's the richest view (per-backend fairness bars) and is
        // what most operators will want to land on.
        let currentView = $state<TopologyViewMode>('service-to-backend');
        const initial = buildServiceToBackendGraph(mockRoutes);
        let nodes = $state.raw(initial.nodes);
        let edges = $state.raw(initial.edges);

        function switchView(view: TopologyViewMode): void {
                if (view === currentView) return;
                currentView = view;
                const graph = view === 'protocol'
                        ? buildProtocolGraph(mockRoutes)
                        : buildServiceToBackendGraph(mockRoutes);
                nodes = graph.nodes;
                edges = graph.edges;
        }
</script>

<svelte:head>
        <title>Topology v2 — Arenet</title>
</svelte:head>

<div class="topo-page">
        <header class="topo-header">
                <div class="eyebrow">TRAFIC · VUE FLUX</div>
                <h1>Topology</h1>
                <p class="lede">
                        Points d'entrée du reverse proxy à gauche, services en amont à droite.
                        L'épaisseur et la luminosité de chaque ligne reflètent le débit en temps
                        réel sur ce flux.
                </p>
        </header>

        <div class="topo-content">
                <div class="topo-canvas-wrap">
                        <div class="canvas-toolbar">
                                <ViewToggle value={currentView} onChange={switchView} />
                        </div>
                        <div class="canvas-frame">
                                <SvelteFlow
                                        bind:nodes
                                        bind:edges
                                        {nodeTypes}
                                        {edgeTypes}
                                        fitView
                                        nodesDraggable
                                        nodesConnectable={false}
                                        elementsSelectable
                                        proOptions={{ hideAttribution: true }}
                                >
                                        <Background />
                                        <Controls />
                                </SvelteFlow>
                        </div>
                </div>

                <TopologySidebar routes={mockRoutes} />
        </div>
</div>

<style>
        .topo-page {
                display: flex;
                flex-direction: column;
                height: 100%;
                min-height: 0;
                padding: 24px;
                gap: 18px;
                box-sizing: border-box;
        }

        .topo-header {
                flex: 0 0 auto;
        }

        .eyebrow {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 11px;
                color: var(--accent, oklch(68% 0.21 255));
                letter-spacing: 0.06em;
                margin-bottom: 8px;
        }

        h1 {
                font-size: 28px;
                font-weight: 600;
                margin: 0 0 4px 0;
        }

        .lede {
                color: var(--fg-muted, oklch(68% 0.012 250));
                font-size: 13px;
                margin: 0;
                max-width: 720px;
                line-height: 1.5;
        }

        .topo-content {
                flex: 1 1 auto;
                min-height: 0;
                display: flex;
                gap: 14px;
        }

        .topo-canvas-wrap {
                flex: 1 1 auto;
                min-width: 0;
                border: 1px solid var(--border, oklch(28% 0.009 250));
                border-radius: 8px;
                overflow: hidden;
                background: var(--bg, oklch(15% 0.005 250));
                display: flex;
                flex-direction: column;
        }

        .canvas-toolbar {
                flex: 0 0 auto;
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 10px 12px;
                border-bottom: 1px solid var(--border, oklch(28% 0.009 250));
                background: var(--surface-2, oklch(22% 0.007 250));
        }

        .canvas-frame {
                flex: 1 1 auto;
                min-height: 0;
                position: relative;
        }
</style>