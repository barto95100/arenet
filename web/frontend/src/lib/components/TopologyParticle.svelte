<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  TopologyParticle (spec §6.3 / §6.4). A single <circle> that animates
  along a parent SVG <path> via requestAnimationFrame +
  getPointAtLength.

  Lifecycle: the parent edge spawns N particles per second; each
  particle independently travels the path in PARTICLE_TRAVEL_MS, then
  signals onComplete so the parent can drop it from the array. RAF
  is cancelled in onDestroy to avoid leaks on tab close or route
  change.
-->
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { PARTICLE_TRAVEL_MS } from '$lib/stores/topology-constants';

	interface Props {
		pathRef: SVGPathElement | null;
		color: string;
		/** Called when the particle reaches end-of-path. */
		onComplete: () => void;
	}

	let { pathRef, color, onComplete }: Props = $props();

	// Live position in user coordinates of the <svg>.
	let x = $state(0);
	let y = $state(0);
	let visible = $state(false);

	let startedAt = 0;
	let rafId: number | null = null;
	let totalLength = 0;

	function step(now: number): void {
		if (!pathRef || totalLength === 0) {
			rafId = null;
			onComplete();
			return;
		}
		const elapsed = now - startedAt;
		const progress = Math.min(elapsed / PARTICLE_TRAVEL_MS, 1);
		const point = pathRef.getPointAtLength(progress * totalLength);
		x = point.x;
		y = point.y;
		if (progress >= 1) {
			visible = false;
			rafId = null;
			onComplete();
			return;
		}
		rafId = requestAnimationFrame(step);
	}

	onMount(() => {
		if (!pathRef) {
			onComplete();
			return;
		}
		try {
			totalLength = pathRef.getTotalLength();
		} catch {
			// Path not yet laid out (rare race in StrictMode); skip.
			onComplete();
			return;
		}
		visible = true;
		startedAt = performance.now();
		rafId = requestAnimationFrame(step);
	});

	onDestroy(() => {
		if (rafId !== null) {
			cancelAnimationFrame(rafId);
			rafId = null;
		}
	});
</script>

{#if visible}
	<circle cx={x} cy={y} r="2.5" fill={color} class="particle" />
{/if}

<style>
	.particle {
		filter: drop-shadow(0 0 3px currentColor);
		pointer-events: none;
	}
</style>
