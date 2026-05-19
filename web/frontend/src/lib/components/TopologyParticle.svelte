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
	let fallbackTimer: ReturnType<typeof setTimeout> | null = null;
	let completed = false;

	function complete(): void {
		// Idempotent — RAF path and fallback timer may both race to
		// signal completion (e.g., when the tab becomes visible and
		// the throttled RAF catches up around the same time the
		// fallback timer fires).
		if (completed) return;
		completed = true;
		visible = false;
		if (rafId !== null) {
			cancelAnimationFrame(rafId);
			rafId = null;
		}
		if (fallbackTimer !== null) {
			clearTimeout(fallbackTimer);
			fallbackTimer = null;
		}
		onComplete();
	}

	function step(now: number): void {
		if (!pathRef || totalLength === 0) {
			complete();
			return;
		}
		const elapsed = now - startedAt;
		const progress = Math.min(elapsed / PARTICLE_TRAVEL_MS, 1);
		const point = pathRef.getPointAtLength(progress * totalLength);
		x = point.x;
		y = point.y;
		if (progress >= 1) {
			complete();
			return;
		}
		rafId = requestAnimationFrame(step);
	}

	onMount(() => {
		if (!pathRef) {
			complete();
			return;
		}
		try {
			totalLength = pathRef.getTotalLength();
		} catch {
			// Path not yet laid out (rare race in StrictMode); skip.
			complete();
			return;
		}
		visible = true;
		startedAt = performance.now();
		rafId = requestAnimationFrame(step);
		// Fallback timer: guarantees onComplete fires even if the
		// browser throttles RAF (background tab, sleep, etc.). The
		// extra 500 ms gives a healthy frame a chance to finish
		// naturally; only kicks in when RAF is genuinely stuck.
		// Without this, throttled RAF + a still-running spawn timer
		// in the parent edge let particles accumulate indefinitely
		// — observed during the v0.3.0-step-e smoke (9000+ circles
		// after 5 s).
		fallbackTimer = setTimeout(complete, PARTICLE_TRAVEL_MS + 500);
	});

	onDestroy(() => {
		if (rafId !== null) {
			cancelAnimationFrame(rafId);
			rafId = null;
		}
		if (fallbackTimer !== null) {
			clearTimeout(fallbackTimer);
			fallbackTimer = null;
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
