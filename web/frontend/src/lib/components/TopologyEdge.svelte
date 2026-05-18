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
	import { onDestroy } from 'svelte';
	import TopologyParticle from './TopologyParticle.svelte';
	import {
		COLOR_ERROR_THRESHOLD,
		PARTICLE_DENSITY_CAP
	} from '$lib/stores/topology-constants';

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
		const rate = Math.max(0, Math.min(reqPerSec, PARTICLE_DENSITY_CAP));
		if (rate <= 0) return;
		const intervalMs = 1000 / rate;
		spawnTimer = setInterval(spawnOne, intervalMs);
	}

	// Re-tune the spawn timer whenever reqPerSec or reducedMotion changes.
	$effect(() => {
		// Read the dependencies to subscribe.
		void reqPerSec;
		void reducedMotion;
		restartSpawnTimer();
	});

	onDestroy(() => {
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
		font-family: 'JetBrains Mono', ui-monospace, monospace;
		font-size: 11px;
		font-weight: 500;
		pointer-events: none;
	}
</style>
