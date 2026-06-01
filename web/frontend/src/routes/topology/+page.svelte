<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Topology page (spec §6.1). Wires the TopologyClient WebSocket
  lifecycle to the TopologyStore, then renders the SVG topology +
  optional detail panel.

  - Hard-auth is enforced by +layout.svelte; this page assumes
    auth.state === 'authenticated' at mount.
  - prefers-reduced-motion is observed and forwarded to TopologySvg.
  - On 401 handshake, the client redirects to /login (auth store
    clears in the layout).
-->
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { goto } from '$app/navigation';
	import { topology } from '$lib/stores/topology.svelte';
	import { viewport } from '$lib/topology/viewport.svelte';
	import { computeTopologyBBox } from '$lib/topology/bounds';
	import { shouldAutoFit } from '$lib/topology/auto-fit';
	import { TopologyClient, type Snapshot, type ConnectionStatus } from '$lib/api/topology';
	import TopologySvg from '$lib/components/TopologySvg.svelte';
	import TopologyControls from '$lib/components/TopologyControls.svelte';
	import TopologyDetailPanel from '$lib/components/TopologyDetailPanel.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import StatusDot from '$lib/components/StatusDot.svelte';

	let client: TopologyClient | null = null;

	// Selected route ID (detail panel open when non-null).
	let selectedRouteId = $state<string | null>(null);

	// prefers-reduced-motion gate (spec §6.6).
	let reducedMotion = $state(false);
	let motionMQ: MediaQueryList | null = null;

	// Live viewport dimensions of the .svg-wrap surface — bound via
	// the template below. Chunk 4b.4 TopologyControls reads these
	// for fit-view + zoom-to-center math.
	let wrapWidth = $state(0);
	let wrapHeight = $state(0);

	function onMotionChange(): void {
		if (motionMQ) reducedMotion = motionMQ.matches;
	}

	function handleSnapshot(snap: Snapshot): void {
		topology.apply(snap);
		// If the currently-selected route disappeared from the
		// snapshot, close the panel.
		if (selectedRouteId !== null && !topology.get(selectedRouteId)) {
			selectedRouteId = null;
		}
	}

	function handleStatus(s: ConnectionStatus): void {
		topology.setStatus(s);
	}

	function handleUnauthorized(): void {
		// Same flow as the rest of the API client (Step D): redirect
		// to /login. The auth store's bootstrap on the next load will
		// transition to anonymous.
		goto('/login');
	}

	function onSelectRoute(id: string): void {
		// Second click on the same node closes the panel
		// (spec §6.9).
		selectedRouteId = selectedRouteId === id ? null : id;
	}

	onMount(() => {
		// Reduced motion media query (spec §6.6).
		if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
			motionMQ = window.matchMedia('(prefers-reduced-motion: reduce)');
			reducedMotion = motionMQ.matches;
			motionMQ.addEventListener('change', onMotionChange);
		}

		// WS lifecycle.
		client = new TopologyClient({
			onSnapshot: handleSnapshot,
			onStatus: handleStatus,
			onUnauthorized: handleUnauthorized
		});
		client.attachVisibilityListener();
		client.connect();
	});

	onDestroy(() => {
		client?.destroy();
		client = null;
		if (motionMQ) {
			motionMQ.removeEventListener('change', onMotionChange);
			motionMQ = null;
		}
		// Don't clear the store on unmount — the user may navigate
		// back to /topology shortly; the store survives across
		// navigations until full page reload.
	});

	// EXPLICIT VERSION COUNTER subscription.
	//
	// Reading `topology.routes.values()` alone (whether via getter
	// or inline iteration) was empirically not enough to invalidate
	// these `$derived` blocks across the module boundary — see the
	// long doc-comment in topology.svelte.ts for the full saga.
	//
	// Pairing each read with `void topology.version` subscribes the
	// $derived to a plain $state(number) that IS reliably reactive
	// cross-module. Every mutator on the store bumps `version`, the
	// $derived invalidates, the closure re-runs, and the iteration
	// reads the now-current Map contents.
	//
	// The `void` cast discards the value — we only need the
	// subscription side-effect.
	const routesList = $derived.by(() => {
		void topology.version;
		return Array.from(topology.routes.values());
	});
	const totalReqPerSec = $derived.by(() => {
		void topology.version;
		let total = 0;
		for (const r of topology.routes.values()) total += r.reqPerSec;
		return total;
	});
	const selectedRoute = $derived(
		selectedRouteId !== null ? topology.get(selectedRouteId) : null
	);

	const statusLabel = $derived.by(() => {
		switch (topology.connectionStatus) {
			case 'connected':
				return 'connected';
			case 'reconnecting':
				return 'reconnecting…';
			case 'disconnected':
				return 'disconnected';
		}
	});
	const statusDot = $derived.by(() => {
		switch (topology.connectionStatus) {
			case 'connected':
				return 'up';
			case 'reconnecting':
				return 'warn';
			case 'disconnected':
				return 'down';
		}
	});

	const showWaitingForTick = $derived(
		topology.connectionStatus === 'connected' && topology.lastTickAt === null
	);

	// J.6 — auto-fit on the first non-empty data tick (Finding #10
	// from the Step I smoke). The naive "call fitView from onMount"
	// trap is that at mount the topology store is empty: nodes
	// arrive via the first WebSocket snapshot at ~1 Hz, so a fit
	// computed before that snapshot runs against zero nodes and
	// produces an identity (or NaN) transform.
	//
	// Correct trigger: watch `routesList.length` and fire fitView()
	// the first time it transitions from 0 to > 0. The local
	// `hasFit` flag guards against re-firing on every subsequent
	// tick — re-fitting on every snapshot would make the viewport
	// jump every second as routes appear/disappear, which would be
	// worse than the pre-J.6 behaviour.
	//
	// The fit also waits for the wrap to have measured a non-zero
	// viewport size (wrapWidth > 0, wrapHeight > 0); without this
	// guard the first $effect tick fires before bind:clientWidth/
	// Height has reported the rendered surface, and fitView would
	// divide by zero in viewport.fitView's clamp.
	let hasFit = $state(false);
	$effect(() => {
		if (
			!shouldAutoFit({
				hasFit,
				routesCount: routesList.length,
				viewportWidth: wrapWidth,
				viewportHeight: wrapHeight
			})
		) {
			return;
		}
		viewport.fitView(
			computeTopologyBBox(routesList.length),
			wrapWidth,
			wrapHeight,
			40
		);
		hasFit = true;
	});
</script>

<svelte:head>
	<title>Topology — Arenet</title>
</svelte:head>

<div class="page">
	<PageHeader
		eyebrow="Aperçu · Topology"
		title="Topology"
		subtitle="Live network visualization."
	>
		{#snippet actions()}
			{#if showWaitingForTick}
				<span class="waiting" aria-live="polite">Waiting for first tick…</span>
			{/if}
			<span class="status" aria-live="polite">
				<StatusDot status={statusDot} />
				{statusLabel}
			</span>
		{/snippet}
	</PageHeader>

	{#if routesList.length === 0 && topology.connectionStatus !== 'reconnecting'}
		<div class="card empty">
			<p>No routes configured yet.</p>
			<p class="dim">
				Visit <a class="link" href="/routes">Routes</a> to add one. Live ticks will appear here once the server has emitted them.
			</p>
		</div>
	{:else}
		<!-- bind:clientWidth/Height supplies the live viewport size
		     to TopologyControls so fit-view / zoom-to-center math
		     reads off the actual rendered surface rather than a
		     hardcoded guess. -->
		<div class="svg-wrap" bind:clientWidth={wrapWidth} bind:clientHeight={wrapHeight}>
			<TopologySvg
				routes={routesList}
				{selectedRouteId}
				{reducedMotion}
				{onSelectRoute}
				{totalReqPerSec}
			/>
			<div class="controls-overlay">
				<TopologyControls
					viewportSize={{ width: wrapWidth, height: wrapHeight }}
					routesCount={routesList.length}
				/>
			</div>
		</div>
	{/if}

	{#if selectedRoute}
		<TopologyDetailPanel route={selectedRoute} onClose={() => (selectedRouteId = null)} />
	{/if}
</div>

<style>
	.page {
		padding: 0;
	}
	.waiting {
		font-size: 11.5px;
		color: var(--fg-muted);
		font-family: var(--font-mono);
	}
	.status {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		font-size: 12.5px;
		color: var(--fg-muted);
	}

	/* .card.empty + .svg-wrap consume the R.4.1 primitives:
	   .card is the shared surface; .empty is a modifier that
	   re-uses the dashboard's empty-state pattern. */
	.card {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 14px 16px;
	}
	.card.empty {
		padding: 48px 32px;
		text-align: center;
	}
	.card.empty p {
		margin: 4px 0;
		color: var(--fg);
	}
	.dim {
		color: var(--fg-muted);
		font-size: 13px;
	}
	.link {
		color: var(--accent);
	}
	.link:hover {
		text-decoration: underline;
	}

	.svg-wrap {
		position: relative;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 16px;
		overflow: hidden;
	}
	.controls-overlay {
		position: absolute;
		top: 12px;
		right: 12px;
		z-index: 20;
		pointer-events: auto;
	}
</style>
