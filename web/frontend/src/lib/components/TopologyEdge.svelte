<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  TopologyEdge (spec §6.3 / §6.4). Renders a single bezier <path>
  between (x1,y1) and (x2,y2), and spawns TopologyParticle children
  at a rate proportional to reqPerSec (capped at particleDensityCap).
  Particle color is computed from errRate5xx per spec §6.4.

  When the reduced-motion media query matches, no particles are
  spawned; the edge displays its current reqPerSec as a midpoint
  text label instead (spec §6.6).
-->
<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import TopologyParticle from './TopologyParticle.svelte';
	import {
		COLOR_ERROR_THRESHOLD,
		PARTICLE_DENSITY_CAP
	} from '$lib/stores/topology-constants';
	import { topology } from '$lib/stores/topology.svelte';

	interface Props {
		x1: number;
		y1: number;
		x2: number;
		y2: number;
		reqPerSec: number;
		errRate5xx: number;
		/** When true, no particles spawn; a text label is shown. */
		reducedMotion: boolean;
	}

	let { x1, y1, x2, y2, reqPerSec, errRate5xx, reducedMotion }: Props = $props();

	// Hard cap on in-flight particles per edge. Defense against
	// pathological accumulation when onComplete is delayed (RAF
	// throttling in background tabs, browser sleep, etc.) — the
	// smoke session for v0.3.0-step-e observed 9000+ circles after
	// 5 s without load when the spawn timer continued firing but
	// the RAF that drives onComplete had been throttled by the
	// browser. A simple max prevents unbounded DOM growth.
	const MAX_PARTICLES_PER_EDGE = 100;

	// Bezier control points: horizontal pull toward the column gap.
	const cpDx = $derived(Math.max((x2 - x1) * 0.5, 40));
	const d = $derived(
		`M ${x1},${y1} C ${x1 + cpDx},${y1} ${x2 - cpDx},${y2} ${x2},${y2}`
	);
	const midX = $derived((x1 + x2) / 2);
	const midY = $derived((y1 + y2) / 2);

	// Color per current tick (spec §6.4).
	const color = $derived.by(() => {
		if (errRate5xx === 0) return 'var(--accent-cyan)';
		if (errRate5xx >= COLOR_ERROR_THRESHOLD) return 'var(--status-down)';
		return 'var(--status-warn)';
	});

	let pathEl = $state<SVGPathElement | null>(null);

	// --- particles -----------------------------------------------------------

	type Particle = { id: number; color: string };
	let nextId = 0;
	let particles = $state<Particle[]>([]);
	let spawnTimer: ReturnType<typeof setInterval> | null = null;

	function spawnOne(): void {
		// Safety cap: if particles aren't completing (RAF throttled,
		// tab hidden, etc.), stop spawning rather than leaking.
		if (particles.length >= MAX_PARTICLES_PER_EDGE) return;
		const id = nextId++;
		particles = [...particles, { id, color }];
	}

	function onParticleComplete(id: number): void {
		particles = particles.filter((p) => p.id !== id);
	}

	function restartSpawnTimer(): void {
		if (spawnTimer !== null) {
			clearInterval(spawnTimer);
			spawnTimer = null;
		}
		if (reducedMotion) return;
		// Pause spawning while the WebSocket is not connected (Step F
		// §7.2). reqPerSec values frozen at the moment of disconnect
		// would otherwise keep streaming particles for stale routes,
		// producing the misleading "everything looks fine" illusion
		// during an outage.
		if (topology.connectionStatus !== 'connected') return;
		// Skip spawning while the tab is hidden — the RAF that drives
		// particle completion is also throttled there, so spawning
		// would just inflate the cap with stuck circles.
		if (typeof document !== 'undefined' && document.hidden) return;
		const rate = Math.max(0, Math.min(reqPerSec, PARTICLE_DENSITY_CAP));
		if (rate <= 0) return;
		const intervalMs = 1000 / rate;
		spawnTimer = setInterval(spawnOne, intervalMs);
	}

	// Re-tune the spawn timer whenever any of its inputs change.
	// connectionStatus is a plain $state primitive in the topology
	// store — reactive cross-module per the version-counter doc
	// (topology.svelte.ts lines 199-220), no `void topology.version`
	// needed here.
	//
	// Regression test for the disconnect-pause behavior is deferred
	// to Chunk 7 — it needs @testing-library/svelte which installs
	// then. See MetricEdge.test.ts in that chunk.
	$effect(() => {
		// Read the dependencies to subscribe.
		void reqPerSec;
		void reducedMotion;
		void topology.connectionStatus;
		restartSpawnTimer();
	});

	onMount(() => {
		if (typeof document !== 'undefined') {
			document.addEventListener('visibilitychange', restartSpawnTimer);
		}
	});

	onDestroy(() => {
		if (typeof document !== 'undefined') {
			document.removeEventListener('visibilitychange', restartSpawnTimer);
		}
		if (spawnTimer !== null) {
			clearInterval(spawnTimer);
			spawnTimer = null;
		}
	});
</script>

<g class="edge">
	<path
		bind:this={pathEl}
		{d}
		stroke="var(--border-default)"
		stroke-width="1"
		fill="none"
		class="edge-path"
	/>

	{#if reducedMotion}
		<!-- Spec §6.6: static label with the current rate -->
		<text x={midX} y={midY - 6} text-anchor="middle" class="edge-label" fill={color}>
			{reqPerSec} req/s
		</text>
	{:else}
		{#each particles as p (p.id)}
			<TopologyParticle
				pathRef={pathEl}
				color={p.color}
				onComplete={() => onParticleComplete(p.id)}
			/>
		{/each}
	{/if}
</g>

<style>
	.edge-path {
		opacity: 0.5;
	}
	.edge-label {
		font-family: var(--font-mono);
		font-size: 11px;
		font-weight: 500;
		pointer-events: none;
	}
</style>
