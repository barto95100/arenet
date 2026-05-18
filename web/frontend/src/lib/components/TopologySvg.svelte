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
	import TopologyEdge from './TopologyEdge.svelte';
	import TopologyNode from './TopologyNode.svelte';
	import { isActive, isErrorSpike, type RouteState } from '$lib/stores/topology.svelte';

	interface Props {
		routes: RouteState[];
		selectedRouteId: string | null;
		reducedMotion: boolean;
		onSelectRoute: (routeId: string) => void;
		/** Aggregate req/s across all routes — displayed in the Clients pillar. */
		totalReqPerSec: number;
	}

	let { routes, selectedRouteId, reducedMotion, onSelectRoute, totalReqPerSec }: Props = $props();

	// Layout constants — single source for column geometry. Spec §6.2.
	const NODE_HEIGHT = 56;
	const NODE_GAP = 16;
	const ROW_PITCH = NODE_HEIGHT + NODE_GAP; // 72
	const TOP_PAD = 20;
	const BOTTOM_PAD = 20;

	const CLIENTS_X = 80;
	const CLIENTS_WIDTH = 120;
	const CLIENTS_RIGHT = CLIENTS_X + CLIENTS_WIDTH; // 200

	const ROUTES_X = 400;
	const ROUTES_WIDTH = 240;
	const ROUTES_RIGHT = ROUTES_X + ROUTES_WIDTH; // 640

	const UPSTREAMS_X = 900;
	const UPSTREAMS_WIDTH = 240;

	const SVG_WIDTH = 1200;
	const MIN_SVG_HEIGHT = 600;

	/** Compute the Y coordinate of route i (top of its box). */
	function routeY(i: number): number {
		return TOP_PAD + i * ROW_PITCH;
	}

	/** Vertical center of a route's box. Edges anchor here. */
	function routeCenterY(i: number): number {
		return routeY(i) + NODE_HEIGHT / 2;
	}

	// Total SVG height: at least MIN_SVG_HEIGHT, otherwise tall enough
	// to fit all routes.
	const svgHeight = $derived(
		Math.max(MIN_SVG_HEIGHT, TOP_PAD + routes.length * ROW_PITCH + BOTTOM_PAD)
	);

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
</script>

<svg
	viewBox={`0 0 ${SVG_WIDTH} ${svgHeight}`}
	preserveAspectRatio="xMidYMid meet"
	class="topology-svg"
	role="img"
	aria-label="Topology of {routes.length} routes"
>
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

	<!-- Route nodes -->
	{#each routes as r, i (r.id)}
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
	{/each}

	<!-- Upstream nodes -->
	{#each upstreams as u (u.url)}
		<g class="upstream-node">
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
</svg>

<style>
	.topology-svg {
		display: block;
		width: 100%;
		height: auto;
	}

	.pillar-box {
		fill: var(--bg-elevated);
		stroke: var(--border-default);
		stroke-width: 1;
	}
	.pillar-title {
		fill: var(--text-secondary);
		font-family: 'Inter', system-ui, sans-serif;
		font-size: 12px;
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}
	.pillar-total {
		fill: var(--text-primary);
		font-family: 'JetBrains Mono', ui-monospace, monospace;
		font-size: 22px;
		font-weight: 600;
	}
	.pillar-unit {
		fill: var(--text-secondary);
		font-family: 'JetBrains Mono', ui-monospace, monospace;
		font-size: 11px;
	}

	.upstream-box {
		fill: var(--bg-elevated);
		stroke: var(--border-default);
		stroke-width: 1.5;
	}
	.upstream-url {
		fill: var(--text-primary);
		font-family: 'JetBrains Mono', ui-monospace, monospace;
		font-size: 12px;
		font-weight: 500;
	}
	.upstream-count {
		fill: var(--text-secondary);
		font-family: 'Inter', system-ui, sans-serif;
		font-size: 10px;
	}
</style>
