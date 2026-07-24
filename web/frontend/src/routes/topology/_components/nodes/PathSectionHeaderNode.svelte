<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  PathSectionHeaderNode — per-path section header rendered INSIDE a
  route's single backend cluster (v2.25.0 topology rework, Task 1).

  Previously (v2.24.0) each path-pool rendered as its own separate
  BackendClusterNode, carrying a `pathPrefix` chip in its header.
  v2.25.0 collapses a route back down to ONE backend cluster and
  renders each path-pool as a light section header + its upstream
  rows nested inside that single cluster instead. This node is that
  section header — a discreet "── /v1 ──" divider, not a card.

  The target handle is the anchor for the hub→section structural
  edge (Task 2): the edge lands here instead of on each individual
  upstream when a route has path pools.
-->
<script lang="ts">
	import { Handle, Position, type NodeProps } from '@xyflow/svelte';
	import type { PathSectionHeaderNodeData } from '../../_types';

	let { data }: NodeProps & { data: PathSectionHeaderNodeData } = $props();
</script>

<div class="path-section-header" data-testid="path-section-header">
	<!-- Target handle: the hub->section structural edge lands here (the
	     section header is the anchor for a path-pool's inbound line). -->
	<Handle type="target" position={Position.Left} />
	<span class="psh-rule">── </span>
	<span class="psh-prefix">{data.pathPrefix}</span>
	<span class="psh-rule"> ──</span>
</div>

<style>
	.path-section-header {
		display: flex;
		align-items: center;
		gap: 4px;
		width: 100%;
		height: 100%;
		box-sizing: border-box;
		font-family: var(--font-mono, ui-monospace, monospace);
		font-size: 11px;
		color: var(--fg-muted, oklch(68% 0.012 250));
		padding: 0 8px;
	}

	.psh-prefix {
		font-weight: 600;
		color: var(--fg, oklch(96% 0.005 250));
	}

	.psh-rule {
		opacity: 0.6;
		color: var(--fg-muted, oklch(68% 0.012 250));
	}

	/* Svelte Flow injects a wrapper around our component. We don't
	   want its default border/padding here — the wrapper is just a
	   positioning container. Same override pattern as UpstreamNode /
	   BackendClusterNode. */
	:global(.svelte-flow__node-path-section-header) {
		padding: 0;
		background: transparent;
		border: none;
		box-shadow: none;
		color: inherit;
	}
</style>
