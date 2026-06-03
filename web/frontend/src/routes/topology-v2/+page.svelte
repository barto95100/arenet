<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Topology v2 — Service → Backend view (Phase 1.2).

  Two-column layout under the page header:
    - canvas (Svelte Flow) takes the remaining width
    - right sidebar (Légende + Top flux + Actions rapides) is fixed 280px

  Pipeline: mock routes → _layout.ts → SvelteFlow with custom
  node/edge types. The sidebar reads the same mockRoutes to keep
  its Top flux ranking in sync with the canvas.
-->
<script lang="ts">
        import { SvelteFlow, Background, Controls, type NodeTypes, type EdgeTypes } from '@xyflow/svelte';
        import '@xyflow/svelte/dist/style.css';

        import { buildServiceToBackendGraph } from './_layout';
        import { mockRoutes } from './_mock-data';

        import ConsumerNode from './_components/nodes/ConsumerNode.svelte';
        import FQDNNode from './_components/nodes/FQDNNode.svelte';
        import CaddyHubNode from './_components/nodes/CaddyHubNode.svelte';
        import BackendClusterNode from './_components/nodes/BackendClusterNode.svelte';
        import AnimatedFlowEdge from './_components/edges/AnimatedFlowEdge.svelte';
        import TopologySidebar from './_components/TopologySidebar.svelte';

        const nodeTypes: NodeTypes = {
                consumer: ConsumerNode,
                fqdn: FQDNNode,
                caddy: CaddyHubNode,
                'backend-cluster': BackendClusterNode,
        };

        const edgeTypes: EdgeTypes = {
                'animated-flow': AnimatedFlowEdge,
        };

        const graph = buildServiceToBackendGraph(mockRoutes);
        let nodes = $state.raw(graph.nodes);
        let edges = $state.raw(graph.edges);
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
        }
</style>
