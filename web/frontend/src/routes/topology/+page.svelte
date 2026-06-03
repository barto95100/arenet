<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Topology v2 — Phase 2.

  Phase 1 shipped the canvas + sidebar + view toggle against a
  static mock. Phase 2 replaces the mock import with a live data
  feed: fetchSnapshot on mount, then connectLiveStream subscribes
  to the WS push at /api/v1/topology/stream (default 2 s emit
  cadence, configurable via ARENET_TOPOLOGY_TICK_MS on the
  server).

  States:
    - loading       initial fetch in flight (centered spinner)
    - error         fetch failed (message + manual retry button)
    - connected     snapshot loaded, WS open or reconnecting
                    (canvas + sidebar render normally)

  The view toggle swaps between protocol and service-to-backend
  layouts; both consume the same `routes` state. WS ticks rebuild
  the graph in place — Svelte Flow keeps drag positions because
  the layout builders emit stable, deterministic node ids per
  route. Reconnect attempts run silently in the background with
  the backoff schedule documented in _api.ts; a small dot in the
  toolbar surfaces the disconnected state.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { SvelteFlow, Background, Controls, useSvelteFlow, type NodeTypes, type EdgeTypes, type Node, type Edge } from '@xyflow/svelte';
	import '@xyflow/svelte/dist/style.css';

	import { buildProtocolGraph, buildServiceToBackendGraph } from './_layout';
	import type { TopologyRoute, TopologyViewMode } from './_types';
	import { fetchSnapshot, connectLiveStream, TopologyFetchError } from './_api';

	// Custom node components — one per `kind` emitted by the layout builders.
	import EntryPointNode from './_components/nodes/EntryPointNode.svelte';
	import ConsumerNode from './_components/nodes/ConsumerNode.svelte';
	import FQDNNode from './_components/nodes/FQDNNode.svelte';
	import CaddyHubNode from './_components/nodes/CaddyHubNode.svelte';
	import ServiceNode from './_components/nodes/ServiceNode.svelte';
	import BackendClusterNode from './_components/nodes/BackendClusterNode.svelte';
	import UpstreamNode from './_components/nodes/UpstreamNode.svelte';
	import AnimatedFlowEdge from './_components/edges/AnimatedFlowEdge.svelte';
	import FlowApiBridge from './_components/FlowApiBridge.svelte';

	// Page-level UI
	import ViewToggle from './_components/ViewToggle.svelte';
	import TopologySidebar from './_components/TopologySidebar.svelte';
	import Spinner from '$lib/components/Spinner.svelte';

	type FlowApi = ReturnType<typeof useSvelteFlow<Node, Edge>>;

	const nodeTypes: NodeTypes = {
		'entry-point': EntryPointNode,
		consumer: ConsumerNode,
		fqdn: FQDNNode,
		caddy: CaddyHubNode,
		service: ServiceNode,
		'backend-cluster': BackendClusterNode,
		upstream: UpstreamNode,
	};

	const edgeTypes: EdgeTypes = {
		'animated-flow': AnimatedFlowEdge,
	};

	// View + graph state. routes is the live data; graph is the
	// builder output for the current view.
	let currentView = $state<TopologyViewMode>('service-to-backend');
	let routes = $state<TopologyRoute[]>([]);
	let nodes = $state.raw([] as ReturnType<typeof buildServiceToBackendGraph>['nodes']);
	let edges = $state.raw([] as ReturnType<typeof buildServiceToBackendGraph>['edges']);

	// Page-status state. 'loading' shows the centered spinner;
	// 'error' shows the error panel + retry button; 'connected'
	// shows the canvas.
	type PageStatus = 'loading' | 'error' | 'connected';
	let pageStatus = $state<PageStatus>('loading');
	let pageError = $state<string>('');

	// Live indicator — 'live' when the WS is connected, 'reconnecting'
	// when an automatic reconnect is in flight. The indicator is a
	// small dot in the canvas toolbar.
	type LiveStatus = 'live' | 'reconnecting';
	let liveStatus = $state<LiveStatus>('reconnecting');

	let closeStream: (() => void) | null = null;

	// Flow API captured from inside <SvelteFlow> via FlowApiBridge.
	// Null until the bridge mounts (first frame after <SvelteFlow>
	// renders). rebuildGraph's tick path requires it for the
	// updateNodeData / updateEdge calls — if it's still null on a
	// tick (extremely brief window during initial mount) we fall
	// back to the array-reassignment path, which works but remounts.
	let flowApi: FlowApi | null = null;

	// Live-tick reconciliation.
	//
	// Three invariants matter on every WS tick:
	//   1. User-dragged node positions must survive the rebuild
	//      (F1 — operator browser feedback 2026-06-03).
	//   2. Custom edge components (AnimatedFlowEdge) must NOT
	//      remount, so their SMIL <animateMotion> animations
	//      don't snap back to t=0 every tick (C4 — sawtooth
	//      jitter, 2026-06-03).
	//   3. Custom node components (UpstreamNode etc.) must
	//      observe live data updates — not just remain mounted.
	//      Regression B (2026-06-03): the earlier in-place
	//      `prev.data = fresh.data` mutation kept the wrapper
	//      mounted (good for SMIL continuity) but didn't cross
	//      the reactivity boundary into children that destructured
	//      `data` via $props(), so per-upstream req/s went stale.
	//
	// Solution: use Svelte Flow's first-class updateNodeData /
	// updateEdge APIs for ids present in both old and new graphs.
	// These mutate the internal store in a way the framework
	// observes AND propagate the new data into the rendered child
	// component without unmounting it. The same call also keeps
	// edge identity stable, so AnimatedFlowEdge's SMIL continues
	// uninterrupted.
	//
	// For ids that appear or disappear, we still need an array
	// reassignment (the API doesn't have a single add/remove
	// primitive that preserves the others' identity in one call),
	// so we do a partial reassignment only when the id set
	// actually changes between ticks.
	//
	// `preservePositions: false` (used by switchView) opts out of
	// position preservation — switching layouts is an intentional
	// re-layout. We then do a full array reassignment so the
	// builder's new positions land everywhere.
	function rebuildGraph(
		routesIn: TopologyRoute[],
		view: TopologyViewMode,
		preservePositions = true,
	): void {
		const graph = view === 'protocol'
			? buildProtocolGraph(routesIn)
			: buildServiceToBackendGraph(routesIn);

		// First call or view switch: reassign the full arrays. No
		// existing state to reconcile against. The builder's
		// positions are the truth.
		if (!preservePositions || nodes.length === 0 || flowApi === null) {
			nodes = graph.nodes;
			edges = graph.edges;
			return;
		}

		// Compare id sets. If add or remove happened, fall back to
		// array reassignment with position preservation (the F1
		// pattern from before the API rewrite). The data update
		// for surviving nodes still goes through updateNodeData
		// so child components react.
		const prevNodeIds = new Set<string>();
		for (const n of nodes) prevNodeIds.add(n.id);
		const nextNodeIds = new Set<string>();
		for (const n of graph.nodes) nextNodeIds.add(n.id);
		const prevEdgeIds = new Set<string>();
		for (const e of edges) prevEdgeIds.add(e.id);
		const nextEdgeIds = new Set<string>();
		for (const e of graph.edges) nextEdgeIds.add(e.id);

		const idsetEqual = (a: Set<string>, b: Set<string>): boolean => {
			if (a.size !== b.size) return false;
			for (const x of a) if (!b.has(x)) return false;
			return true;
		};

		const nodesIdsetEqual = idsetEqual(prevNodeIds, nextNodeIds);
		const edgesIdsetEqual = idsetEqual(prevEdgeIds, nextEdgeIds);

		if (nodesIdsetEqual && edgesIdsetEqual) {
			// Fast path: same id sets. Push data changes through
			// Svelte Flow's first-class APIs so children re-render
			// without the wrapper being unmounted.
			for (const fresh of graph.nodes) {
				flowApi.updateNodeData(fresh.id, fresh.data, { replace: true });
			}
			for (const fresh of graph.edges) {
				flowApi.updateEdge(fresh.id, { data: fresh.data });
			}
			return;
		}

		// Mixed: some ids added, some removed. Preserve drag
		// positions for ids that survived; emit fresh entries for
		// new ones; drop removed ones implicitly via the new
		// array. New entries land via array reassignment (Svelte
		// Flow handles their initial mount); survivors update via
		// updateNodeData *after* the reassignment to ensure their
		// child components see the new data prop too.
		const prevPositionsById = new Map<string, { x: number; y: number }>();
		for (const n of nodes) {
			if (n.position) prevPositionsById.set(n.id, { x: n.position.x, y: n.position.y });
		}
		const nextNodes = graph.nodes.map((fresh) => {
			const savedPos = prevPositionsById.get(fresh.id);
			if (savedPos) {
				return { ...fresh, position: savedPos };
			}
			return fresh;
		});
		nodes = nextNodes;
		edges = graph.edges;

		// Reactivity flush then data push for survivors. Without
		// this, ids that survived the membership change would
		// receive their fresh data via the array reassignment AND
		// the child render would unmount-remount because the
		// reassignment replaced the node object refs. The
		// updateNodeData call is idempotent — pushing the same
		// data we just put in the array — but it nudges the
		// framework into the no-remount data-only update path.
		for (const fresh of graph.nodes) {
			if (prevNodeIds.has(fresh.id)) {
				flowApi.updateNodeData(fresh.id, fresh.data, { replace: true });
			}
		}
	}

	function switchView(view: TopologyViewMode): void {
		if (view === currentView) return;
		currentView = view;
		// Intentional re-layout — discard preserved positions.
		// The two views have different column structures, so
		// preserved positions wouldn't make sense anyway (a node
		// dragged in service-to-backend's col 3 would land in
		// protocol's col 2 mid-air).
		rebuildGraph(routes, view, false);
	}

	async function loadInitial(): Promise<void> {
		pageStatus = 'loading';
		pageError = '';
		try {
			const snap = await fetchSnapshot();
			routes = snap.routes;
			rebuildGraph(routes, currentView);
			pageStatus = 'connected';
			// Now that we have the initial graph, open the live
			// stream. The WS handler's initial-emit-on-connect
			// means the FIRST tick arrives ~immediately and we'll
			// flip liveStatus to 'live' in the onTick callback.
			openStream();
		} catch (err) {
			const msg =
				err instanceof TopologyFetchError
					? err.message
					: err instanceof Error
						? err.message
						: String(err);
			pageError = msg;
			pageStatus = 'error';
		}
	}

	function openStream(): void {
		// Idempotent — if the page reloads or the user clicks
		// Retry mid-stream, close the previous handle first.
		if (closeStream !== null) {
			closeStream();
			closeStream = null;
		}
		closeStream = connectLiveStream(
			(nextRoutes) => {
				routes = nextRoutes;
				rebuildGraph(nextRoutes, currentView);
				liveStatus = 'live';
			},
			() => {
				// onDisconnect — the stream client is mid-reconnect.
				// We don't reset routes; the canvas keeps showing
				// the last-known state until the next successful
				// tick. The dot turns amber.
				liveStatus = 'reconnecting';
			}
		);
	}

	onMount(() => {
		void loadInitial();
		return () => {
			if (closeStream !== null) {
				closeStream();
				closeStream = null;
			}
		};
	});
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

	{#if pageStatus === 'loading'}
		<div class="topo-state-wrap">
			<Spinner size="lg" />
			<p class="state-text">Chargement de la topologie…</p>
		</div>
	{:else if pageStatus === 'error'}
		<div class="topo-state-wrap">
			<div class="error-box">
				<div class="error-title">Échec du chargement</div>
				<div class="error-msg">{pageError}</div>
				<button class="retry-btn" type="button" onclick={() => void loadInitial()}>
					Réessayer
				</button>
			</div>
		</div>
	{:else}
		<div class="topo-content">
			<div class="topo-canvas-wrap">
				<div class="canvas-toolbar">
					<ViewToggle value={currentView} onChange={switchView} />
					<div class="live-indicator" class:reconnecting={liveStatus === 'reconnecting'}>
						<span class="dot"></span>
						<span class="label">{liveStatus === 'live' ? 'live' : 'reconnecting…'}</span>
					</div>
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
						<FlowApiBridge onReady={(api) => (flowApi = api)} />
					</SvelteFlow>
				</div>
			</div>

			<TopologySidebar {routes} />
		</div>
	{/if}
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
		position: relative;
	}

	.canvas-frame {
		flex: 1 1 auto;
		min-height: 0;
		position: relative;
	}

	/* Loading / error states use the same outer wrap so the
	   page layout doesn't jump between states. */
	.topo-state-wrap {
		flex: 1 1 auto;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 14px;
		min-height: 0;
	}

	.state-text {
		color: var(--fg-muted, oklch(68% 0.012 250));
		font-size: 13px;
		margin: 0;
	}

	.error-box {
		max-width: 480px;
		padding: 20px 24px;
		background: var(--surface, oklch(19% 0.006 250));
		border: 1px solid color-mix(in oklch, var(--bad, oklch(66% 0.20 25)) 40%, transparent);
		border-radius: 8px;
		text-align: center;
	}

	.error-title {
		font-size: 14px;
		font-weight: 600;
		color: var(--bad, oklch(66% 0.20 25));
		margin-bottom: 6px;
	}

	.error-msg {
		font-family: var(--font-mono, ui-monospace, monospace);
		font-size: 12px;
		color: var(--fg-muted, oklch(68% 0.012 250));
		margin-bottom: 14px;
		word-break: break-word;
	}

	.retry-btn {
		padding: 6px 14px;
		font-size: 12.5px;
		font-weight: 500;
		color: var(--fg, oklch(96% 0.005 250));
		background: var(--surface-2, oklch(22% 0.007 250));
		border: 1px solid var(--border-hi, oklch(34% 0.011 250));
		border-radius: 6px;
		cursor: pointer;
	}

	.retry-btn:hover {
		background: var(--surface-hi, oklch(26% 0.008 250));
	}

	/* Live indicator — small absolute-positioned pill on the
	   right side of the toolbar. Doesn't shift the centered
	   ViewToggle. */
	.live-indicator {
		position: absolute;
		right: 14px;
		top: 50%;
		transform: translateY(-50%);
		display: inline-flex;
		align-items: center;
		gap: 6px;
		font-family: var(--font-mono, ui-monospace, monospace);
		font-size: 10.5px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--ok, oklch(72% 0.16 150));
		padding: 4px 10px;
		border-radius: 999px;
		background: color-mix(in oklch, var(--ok, oklch(72% 0.16 150)) 14%, transparent);
	}

	.live-indicator.reconnecting {
		color: var(--warn, oklch(80% 0.14 85));
		background: color-mix(in oklch, var(--warn, oklch(80% 0.14 85)) 14%, transparent);
	}

	.live-indicator .dot {
		width: 6px;
		height: 6px;
		border-radius: 50%;
		background: currentColor;
		box-shadow: 0 0 6px currentColor;
	}

	.live-indicator.reconnecting .dot {
		box-shadow: none;
	}
</style>
