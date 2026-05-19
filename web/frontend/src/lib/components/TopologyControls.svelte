<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  TopologyControls (Step F Chunk 4b.4 — new). Compact overlay panel
  with zoom-in / zoom-out / reset / fit-view buttons. Drives the
  viewport store directly; rendered as an absolute-positioned
  overlay over <TopologySvg>.

  The fit-view button needs to know the viewport's screen size to
  pass into viewport.fitView; the parent (TopologyDashboard or
  /topology page) supplies those via the `viewportSize` prop so
  this component doesn't reach into the DOM itself.

  Public API (add-only per §1.3):

    viewportSize  — { width: number; height: number } in CSS px
    routesCount   — number of routes currently rendered, used to
                    compute the matching bbox (same formula as
                    TopologySvg's onMount fitView so the button
                    reproduces the initial cadrage exactly).
    bbox          — optional explicit bbox override; if absent,
                    computed from routesCount via the shared
                    bounds module. Use only for non-standard
                    layouts (Phase 2 sub-graphs etc.).
-->
<script lang="ts">
	import Button from './Button.svelte';
	import Tooltip from './Tooltip.svelte';
	import { viewport, type BBox } from '$lib/topology/viewport.svelte';
	import { computeTopologyBBox } from '$lib/topology/bounds';

	interface Props {
		viewportSize: { width: number; height: number };
		routesCount: number;
		bbox?: BBox;
	}

	let { viewportSize, routesCount, bbox }: Props = $props();

	// Either the caller passed an explicit bbox or we derive one
	// from routesCount. Single source of truth via bounds.ts.
	const effectiveBBox = $derived(bbox ?? computeTopologyBBox(routesCount));

	const ZOOM_STEP = 1.25; // 25 % per click — fast enough to feel responsive.

	function zoomIn(): void {
		// Anchor at viewport center so the click-zoom feels natural.
		viewport.zoom(ZOOM_STEP, viewportSize.width / 2, viewportSize.height / 2);
	}

	function zoomOut(): void {
		viewport.zoom(1 / ZOOM_STEP, viewportSize.width / 2, viewportSize.height / 2);
	}

	function reset(): void {
		viewport.reset();
	}

	function fitView(): void {
		viewport.fitView(effectiveBBox, viewportSize.width, viewportSize.height, 40);
	}
</script>

<div class="topology-controls" role="toolbar" aria-label="Topology view controls">
	<Tooltip label="Zoom in" side="left">
		{#snippet children()}
			<Button variant="ghost" size="sm" onclick={zoomIn} aria-label="Zoom in">
				{#snippet children()}
					<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
						<!-- Lucide: zoom-in -->
						<circle cx="11" cy="11" r="8" />
						<line x1="21" x2="16.65" y1="21" y2="16.65" />
						<line x1="11" x2="11" y1="8" y2="14" />
						<line x1="8" x2="14" y1="11" y2="11" />
					</svg>
				{/snippet}
			</Button>
		{/snippet}
	</Tooltip>

	<Tooltip label="Zoom out" side="left">
		{#snippet children()}
			<Button variant="ghost" size="sm" onclick={zoomOut} aria-label="Zoom out">
				{#snippet children()}
					<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
						<!-- Lucide: zoom-out -->
						<circle cx="11" cy="11" r="8" />
						<line x1="21" x2="16.65" y1="21" y2="16.65" />
						<line x1="8" x2="14" y1="11" y2="11" />
					</svg>
				{/snippet}
			</Button>
		{/snippet}
	</Tooltip>

	<Tooltip label="Reset view" side="left">
		{#snippet children()}
			<Button variant="ghost" size="sm" onclick={reset} aria-label="Reset view">
				{#snippet children()}
					<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
						<!-- Lucide: refresh-cw -->
						<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" />
						<path d="M21 3v5h-5" />
						<path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" />
						<path d="M8 16H3v5" />
					</svg>
				{/snippet}
			</Button>
		{/snippet}
	</Tooltip>

	<Tooltip label="Fit to screen" side="left">
		{#snippet children()}
			<Button variant="ghost" size="sm" onclick={fitView} aria-label="Fit to screen">
				{#snippet children()}
					<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
						<!-- Lucide: maximize-2 -->
						<polyline points="15 3 21 3 21 9" />
						<polyline points="9 21 3 21 3 15" />
						<line x1="21" x2="14" y1="3" y2="10" />
						<line x1="3" x2="10" y1="21" y2="14" />
					</svg>
				{/snippet}
			</Button>
		{/snippet}
	</Tooltip>
</div>

<style>
	.topology-controls {
		display: inline-flex;
		flex-direction: column;
		gap: var(--space-2);
		padding: var(--space-2);
		background: var(--bg-surface);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-md);
	}
	.icon {
		width: 16px;
		height: 16px;
	}
</style>
