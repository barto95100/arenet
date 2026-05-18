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
	import { TopologyClient, type Snapshot, type ConnectionStatus } from '$lib/api/topology';
	import TopologySvg from '$lib/components/TopologySvg.svelte';
	import TopologyDetailPanel from '$lib/components/TopologyDetailPanel.svelte';

	let client: TopologyClient | null = null;

	// Selected route ID (detail panel open when non-null).
	let selectedRouteId = $state<string | null>(null);

	// prefers-reduced-motion gate (spec §6.6).
	let reducedMotion = $state(false);
	let motionMQ: MediaQueryList | null = null;

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

	const routesList = $derived(topology.list());
	const totalReqPerSec = $derived(topology.totalReqPerSec());
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
</script>

<svelte:head>
	<title>Topology — Arenet</title>
</svelte:head>

<div class="page">
	<header class="page-header">
		<div>
			<h1 class="title">Topology</h1>
			<p class="subtitle">Live network visualization.</p>
		</div>
		<div class="status-block">
			{#if showWaitingForTick}
				<span class="waiting" aria-live="polite">Waiting for first tick…</span>
			{/if}
			<span class="status" aria-live="polite">
				<span class="status-dot status-dot-{statusDot}" aria-hidden="true"></span>
				{statusLabel}
			</span>
		</div>
	</header>

	{#if routesList.length === 0 && topology.connectionStatus !== 'reconnecting'}
		<div class="empty">
			<p>No routes configured yet.</p>
			<p class="text-secondary">
				Visit <a class="link" href="/routes">Routes</a> to add one. Live ticks will appear here once the server has emitted them.
			</p>
		</div>
	{:else}
		<div class="svg-wrap">
			<TopologySvg
				routes={routesList}
				{selectedRouteId}
				{reducedMotion}
				{onSelectRoute}
				{totalReqPerSec}
			/>
		</div>
	{/if}

	{#if selectedRoute}
		<TopologyDetailPanel route={selectedRoute} onClose={() => (selectedRouteId = null)} />
	{/if}
</div>

<style>
	.page {
		padding: 1.5rem;
	}
	.page-header {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		margin-bottom: 1.5rem;
	}
	.title {
		font-family: 'Inter', system-ui, sans-serif;
		font-size: 1.5rem;
		font-weight: 600;
		color: var(--text-primary);
		margin: 0;
	}
	.subtitle {
		font-size: 0.875rem;
		color: var(--text-secondary);
		margin: 0.25rem 0 0;
	}
	.status-block {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}
	.waiting {
		font-size: 0.75rem;
		color: var(--text-secondary);
	}
	.status {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.875rem;
		color: var(--text-secondary);
	}
	.status-dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
		display: inline-block;
	}
	.status-dot-up {
		background: var(--status-up);
		box-shadow: 0 0 6px var(--status-up);
	}
	.status-dot-warn {
		background: var(--status-warn);
		box-shadow: 0 0 6px var(--status-warn);
	}
	.status-dot-down {
		background: var(--status-down);
	}

	.svg-wrap {
		background: var(--bg-base);
		border: 1px solid var(--border-subtle);
		border-radius: 8px;
		padding: 1rem;
		overflow: auto;
	}

	.empty {
		text-align: center;
		padding: 4rem 1rem;
		color: var(--text-primary);
	}
	.empty p {
		margin: 0.25rem 0;
	}
	.link {
		color: var(--accent-cyan);
	}
	.link:hover {
		text-decoration: underline;
	}
	.text-secondary {
		color: var(--text-secondary);
	}
</style>
