<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  TopologySvg (spec §6.1 / §6.2 / §6.3). Three-column SVG layout:
  Clients pillar (left), Routes column (center), Upstreams column
  (right). Each route draws two edges: Client→Route and
  Route→Upstream. Upstreams are deduplicated by URL — multiple
  routes sharing an upstream collapse onto a single upstream node
  but keep their own edges (spec §6.2).

  Reduced-motion is forwarded to TopologyEdge (which suppresses
  particles) and TopologyNode (which suppresses pulse animation).
-->
<script lang="ts">
	import { onMount, untrack } from 'svelte';
	import { fade, scale } from 'svelte/transition';
	import { cubicOut } from 'svelte/easing';
	import { prefersReducedMotion } from 'svelte/motion';
	import TopologyEdge from './TopologyEdge.svelte';
	import TopologyNode from './TopologyNode.svelte';
	import { isActive, isErrorSpike, type RouteState } from '$lib/stores/topology.svelte';
	import { viewport } from '$lib/topology/viewport.svelte';
	import {
		SVG_WIDTH,
		MIN_SVG_HEIGHT,
		NODE_HEIGHT,
		ROW_PITCH,
		TOP_PAD,
		BOTTOM_PAD,
		computeSvgHeight,
		computeTopologyBBox
	} from '$lib/topology/bounds';

	interface Props {
		routes: RouteState[];
		selectedRouteId: string | null;
		reducedMotion: boolean;
		onSelectRoute: (routeId: string) => void;
		/** Aggregate req/s across all routes — displayed in the Clients pillar. */
		totalReqPerSec: number;
	}

	let { routes, selectedRouteId, reducedMotion, onSelectRoute, totalReqPerSec }: Props = $props();

	// SVG root reference + cached client rect for pointer math.
	let svgEl: SVGSVGElement | undefined = $state();
	// `panning` drives the cursor style via class:panning, so it must
	// be reactive — Svelte 5 warns on non-$state mutations bound to
	// the template otherwise.
	let panning = $state(false);
	let panLastX = 0;
	let panLastY = 0;

	// Column-layout constants (X axis) — local to TopologySvg's
	// 3-column rendering. The vertical geometry constants
	// (NODE_HEIGHT, ROW_PITCH, TOP_PAD, BOTTOM_PAD, SVG_WIDTH,
	// MIN_SVG_HEIGHT, computeSvgHeight) live in lib/topology/bounds.ts
	// so TopologyControls + TopologySvg share the same source of
	// truth for fit-view bbox computation.
	const CLIENTS_X = 80;
	const CLIENTS_WIDTH = 120;
	const CLIENTS_RIGHT = CLIENTS_X + CLIENTS_WIDTH; // 200

	const ROUTES_X = 400;
	const ROUTES_WIDTH = 240;
	const ROUTES_RIGHT = ROUTES_X + ROUTES_WIDTH; // 640

	const UPSTREAMS_X = 900;
	const UPSTREAMS_WIDTH = 240;

	/** Compute the Y coordinate of route i (top of its box). */
	function routeY(i: number): number {
		return TOP_PAD + i * ROW_PITCH;
	}

	/** Vertical center of a route's box. Edges anchor here. */
	function routeCenterY(i: number): number {
		return routeY(i) + NODE_HEIGHT / 2;
	}

	// Total SVG height — delegated to the shared bounds module so
	// TopologyControls fit-view stays in sync with the initial mount
	// fit-view (same formula on both sides).
	const svgHeight = $derived(computeSvgHeight(routes.length));

	// Clients pillar spans the same Y range as the routes column.
	const pillarTop = TOP_PAD;
	const pillarBottom = $derived(
		routes.length > 0 ? routeY(routes.length - 1) + NODE_HEIGHT : MIN_SVG_HEIGHT - BOTTOM_PAD
	);
	const pillarHeight = $derived(pillarBottom - pillarTop);

	// Deduplicate upstreams by URL; preserve first-seen order. Each
	// upstream gets a Y assigned by averaging the Y of every route
	// that fans into it. That visually centers the upstream node
	// between its incoming edges.
	const upstreams = $derived.by(() => {
		type U = { url: string; routeIndices: number[] };
		const byUrl = new Map<string, U>();
		const orderedUrls: string[] = [];
		routes.forEach((r, i) => {
			let entry = byUrl.get(r.upstream);
			if (!entry) {
				entry = { url: r.upstream, routeIndices: [] };
				byUrl.set(r.upstream, entry);
				orderedUrls.push(r.upstream);
			}
			entry.routeIndices.push(i);
		});
		return orderedUrls.map((url, j) => {
			const u = byUrl.get(url)!;
			// Y = average of incoming route center Ys, snapped to the
			// row pitch grid. Index j is used as a fallback if we
			// want a deterministic packed layout instead — but
			// averaging avoids crossing edges in most cases.
			const avg = u.routeIndices.reduce((s, i) => s + routeCenterY(i), 0) / u.routeIndices.length;
			return {
				url,
				y: avg - NODE_HEIGHT / 2,
				routeIndices: u.routeIndices,
				index: j
			};
		});
	});

	/** Find the upstream node Y center for a given route. */
	function upstreamCenterYForRoute(routeIndex: number): number {
		for (const u of upstreams) {
			if (u.routeIndices.includes(routeIndex)) {
				return u.y + NODE_HEIGHT / 2;
			}
		}
		return TOP_PAD + NODE_HEIGHT / 2;
	}

	function stateForRoute(r: RouteState): 'active' | 'idle' | 'spike' {
		if (isErrorSpike(r)) return 'spike';
		if (isActive(r)) return 'active';
		return 'idle';
	}

	// Animation params for node add/remove (Step F Chunk 4b.3).
	// When the user prefers reduced motion, the durations collapse to
	// 0 so the transition is functional but invisible — Svelte's
	// transition machinery still runs (lifecycle hooks intact) but
	// no animation frames are produced.
	const addDuration = $derived(prefersReducedMotion.current ? 0 : 200);
	const removeDuration = $derived(prefersReducedMotion.current ? 0 : 150);

	// --- viewport interaction (Step F Chunk 4b.3) --------------------------

	// The SVG content sits inside an inner <g> that follows viewport.x/y/k.
	// All event coordinates below are in CSS-pixel space relative to the
	// SVG root; the viewport store handles the topology↔screen math.

	function onPointerDown(e: PointerEvent): void {
		// Left button only; ignore right-click and middle-click for now.
		if (e.button !== 0) return;
		panning = true;
		panLastX = e.clientX;
		panLastY = e.clientY;
		svgEl?.setPointerCapture(e.pointerId);
	}

	function onPointerMove(e: PointerEvent): void {
		if (!panning) return;
		const dx = e.clientX - panLastX;
		const dy = e.clientY - panLastY;
		panLastX = e.clientX;
		panLastY = e.clientY;
		viewport.pan(dx, dy);
	}

	function onPointerUp(e: PointerEvent): void {
		if (!panning) return;
		panning = false;
		svgEl?.releasePointerCapture(e.pointerId);
	}

	function onWheel(e: WheelEvent): void {
		// Trackpad pinch arrives with ctrlKey=true and a fine-grained
		// deltaY; mouse wheel arrives without ctrlKey and coarser deltaY.
		// Both feed the same zoom logic with a single tuning factor.
		e.preventDefault();
		const rect = svgEl?.getBoundingClientRect();
		if (!rect) return;
		const centerX = e.clientX - rect.left;
		const centerY = e.clientY - rect.top;
		// Wheel up (deltaY < 0) zooms in; wheel down zooms out.
		// 0.0015 makes pinch + scroll feel similar on a Mac trackpad.
		const factor = Math.exp(-e.deltaY * 0.0015);
		viewport.zoom(factor, centerX, centerY);
	}

	onMount(() => {
		// fitView on first paint to land on a sensible initial frame.
		// Uses the shared computeTopologyBBox so TopologyControls'
		// fit-view button reproduces the exact same cadrage on click.
		// Wrapped in untrack so the read doesn't subscribe this effect
		// to viewport state.
		untrack(() => {
			if (!svgEl) return;
			const rect = svgEl.getBoundingClientRect();
			viewport.fitView(
				computeTopologyBBox(routes.length),
				rect.width,
				rect.height,
				40
			);
		});
		return () => viewport.reset();
	});

</script>

<svg
	bind:this={svgEl}
	viewBox={`0 0 ${SVG_WIDTH} ${svgHeight}`}
	preserveAspectRatio="xMidYMid meet"
	class="topology-svg"
	class:panning
	role="img"
	aria-label="Topology of {routes.length} routes"
	onpointerdown={onPointerDown}
	onpointermove={onPointerMove}
	onpointerup={onPointerUp}
	onpointercancel={onPointerUp}
	onwheel={onWheel}
>
	<!-- Viewport content: pan/zoom transform applied to all topology
	     children. The math (translate then scale) is in CSS-pixel
	     space because the listeners feed deltas in client-pixel space.
	     The SVG viewBox stays static so the coordinate system the
	     children draw in doesn't change. -->
	<g class="viewport-content" transform="translate({viewport.x} {viewport.y}) scale({viewport.k})">
	<!-- Clients pillar (spec §6.2) -->
	<g class="clients-pillar">
		<rect
			x={CLIENTS_X}
			y={pillarTop}
			width={CLIENTS_WIDTH}
			height={pillarHeight}
			rx="6"
			class="pillar-box"
		/>
		<text
			x={CLIENTS_X + CLIENTS_WIDTH / 2}
			y={pillarTop + 24}
			text-anchor="middle"
			class="pillar-title"
		>
			Clients
		</text>
		<text
			x={CLIENTS_X + CLIENTS_WIDTH / 2}
			y={pillarTop + pillarHeight / 2}
			text-anchor="middle"
			dominant-baseline="middle"
			class="pillar-total"
		>
			{totalReqPerSec}
		</text>
		<text
			x={CLIENTS_X + CLIENTS_WIDTH / 2}
			y={pillarTop + pillarHeight / 2 + 16}
			text-anchor="middle"
			dominant-baseline="middle"
			class="pillar-unit"
		>
			req/s total
		</text>
	</g>

	<!-- Edges Client→Route -->
	{#each routes as r, i (r.id)}
		<TopologyEdge
			x1={CLIENTS_RIGHT}
			y1={routeCenterY(i)}
			x2={ROUTES_X}
			y2={routeCenterY(i)}
			reqPerSec={r.reqPerSec}
			errRate5xx={r.errRate5xx}
			{reducedMotion}
		/>
	{/each}

	<!-- Edges Route→Upstream -->
	{#each routes as r, i (r.id)}
		<TopologyEdge
			x1={ROUTES_RIGHT}
			y1={routeCenterY(i)}
			x2={UPSTREAMS_X}
			y2={upstreamCenterYForRoute(i)}
			reqPerSec={r.reqPerSec}
			errRate5xx={r.errRate5xx}
			{reducedMotion}
		/>
	{/each}

	<!-- Route nodes. Each is wrapped in a <g> that carries the
	     mount/unmount transitions; the <TopologyNode> component
	     produces its own <g> inside. SVG transforms compose, so the
	     wrapper's transition transforms layer on top of the
	     viewport's translate(x) scale(k) without collision. -->
	{#each routes as r, i (r.id)}
		<g
			in:scale={{ duration: addDuration, easing: cubicOut, start: 0.8 }}
			out:fade={{ duration: removeDuration, easing: cubicOut }}
		>
			<TopologyNode
				x={ROUTES_X}
				y={routeY(i)}
				width={ROUTES_WIDTH}
				height={NODE_HEIGHT}
				label={r.host}
				reqPerSec={r.reqPerSec}
				errRate5xx={r.errRate5xx}
				nodeState={stateForRoute(r)}
				selected={selectedRouteId === r.id}
				onClick={() => onSelectRoute(r.id)}
				{reducedMotion}
			/>
		</g>
	{/each}

	<!-- Upstream nodes. Same mount/unmount animation as Routes;
	     upstream dedup means add/remove fires only when a new URL
	     appears or the last route pointing at it disappears. -->
	{#each upstreams as u (u.url)}
		<g
			class="upstream-node"
			in:scale={{ duration: addDuration, easing: cubicOut, start: 0.8 }}
			out:fade={{ duration: removeDuration, easing: cubicOut }}
		>
			<rect
				x={UPSTREAMS_X}
				y={u.y}
				width={UPSTREAMS_WIDTH}
				height={NODE_HEIGHT}
				rx="6"
				class="upstream-box"
			/>
			<text
				x={UPSTREAMS_X + UPSTREAMS_WIDTH / 2}
				y={u.y + NODE_HEIGHT / 2 - 4}
				text-anchor="middle"
				dominant-baseline="middle"
				class="upstream-url"
			>
				{u.url}
			</text>
			{#if u.routeIndices.length > 1}
				<text
					x={UPSTREAMS_X + UPSTREAMS_WIDTH / 2}
					y={u.y + NODE_HEIGHT / 2 + 14}
					text-anchor="middle"
					dominant-baseline="middle"
					class="upstream-count"
				>
					← {u.routeIndices.length} routes
				</text>
			{/if}
		</g>
	{/each}
	</g>
</svg>

<style>
	.topology-svg {
		display: block;
		width: 100%;
		height: auto;
		cursor: grab;
		/* Block touch-action so pointermove events fire reliably for
		 * pan + wheel events aren't swallowed by browser scroll. */
		touch-action: none;
		user-select: none;
	}
	.topology-svg.panning {
		cursor: grabbing;
	}

	.pillar-box {
		fill: var(--bg-elevated);
		stroke: var(--border-default);
		stroke-width: 1;
	}
	.pillar-title {
		fill: var(--text-secondary);
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}
	.pillar-total {
		fill: var(--text-primary);
		font-family: var(--font-mono);
		font-size: var(--text-2xl);
		font-weight: 600;
	}
	.pillar-unit {
		fill: var(--text-secondary);
		font-family: var(--font-mono);
		font-size: var(--text-xs);
	}

	.upstream-box {
		fill: var(--bg-elevated);
		stroke: var(--border-default);
		stroke-width: 1.5;
	}
	.upstream-url {
		fill: var(--text-primary);
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		font-weight: 500;
	}
	.upstream-count {
		fill: var(--text-secondary);
		font-family: var(--font-sans);
		font-size: var(--text-xs);
	}
</style>
