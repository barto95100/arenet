<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Decorative background for the /login page. Ports the 9-layer
  composition of docs/mocks/auth/signin.html into a standalone
  Svelte component:

      bg-stage      gradient base (HSL→OKLCH)
      bg-conic      slow rotating conic sweep (90s)
      bg-aurora     two drifting blobs (55s / 70s)
      bg-grid       64px grid masked by radial fade
      bg-ring       780px orbital ring + dashed inner ring
      bg-dots       26 ambient drifting particles (random vectors)
      card-halo     560px breathing glow centered on the card
      bg-vignette   center vignette to calm under the card
      bg-noise      SVG turbulence overlay at 4.5% opacity

  Mounted fixed in /login/+page.svelte; z-indexes 0-3 stay below
  the form (z-index 10).

  All animations are globally disabled under
  @media (prefers-reduced-motion: reduce). The mock disabled
  only the dots; the brief asked for all of them.
-->
<script lang="ts">
	import { onMount } from 'svelte';

	let dotsLayer: HTMLDivElement;

	onMount(() => {
		// Generate ambient drifting dots — port of the IIFE at the
		// bottom of the mock. Skip generation under reduced motion
		// (no point setting CSS vars for animations that won't run).
		if (!dotsLayer) return;
		const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
		const count = reduced ? 8 : 26;
		const sizes = ['s', '', 'l'];
		for (let i = 0; i < count; i++) {
			const d = document.createElement('div');
			const isViolet = Math.random() < 0.35;
			const size = sizes[Math.floor(Math.random() * sizes.length)];
			d.className = 'd' + (isViolet ? ' v' : '') + (size ? ' ' + size : '');
			const sx = Math.random() * 100;
			const sy = Math.random() * 100;
			const angle = Math.random() * Math.PI * 2;
			const dist = 120 + Math.random() * 220;
			const mx = Math.cos(angle) * dist;
			const my = Math.sin(angle) * dist;
			d.style.left = sx + '%';
			d.style.top = sy + '%';
			d.style.setProperty('--mx', mx.toFixed(0) + 'px');
			d.style.setProperty('--my', my.toFixed(0) + 'px');
			d.style.setProperty('--dur', (16 + Math.random() * 18).toFixed(1) + 's');
			d.style.setProperty('--delay', (-Math.random() * 20).toFixed(1) + 's');
			dotsLayer.appendChild(d);
		}
	});
</script>

<div class="bg-stage" aria-hidden="true"></div>
<div class="bg-conic" aria-hidden="true"></div>
<div class="bg-aurora" aria-hidden="true"></div>
<div class="bg-grid" aria-hidden="true"></div>
<div class="bg-ring" aria-hidden="true"></div>
<div class="bg-dots" bind:this={dotsLayer} aria-hidden="true"></div>
<div class="card-halo" aria-hidden="true"></div>
<div class="bg-vignette" aria-hidden="true"></div>
<div class="bg-noise" aria-hidden="true"></div>

<style>
	/* All tokens below are OKLCH, scoped to this component. The
	 * global tokens.css (HEX-based) is NOT modified. */

	.bg-stage {
		position: fixed;
		inset: 0;
		background:
			radial-gradient(110% 80% at 18% 12%, oklch(68% 0.21 255 / 0.10) 0%, transparent 55%),
			radial-gradient(80% 60% at 88% 88%, oklch(52% 0.22 265 / 0.10) 0%, transparent 55%),
			linear-gradient(180deg, var(--bg-login-grad-from) 0%, var(--bg-login-grad-to) 100%);
		z-index: 0;
	}

	.bg-conic {
		position: fixed;
		inset: -20%;
		background: conic-gradient(
			from 200deg at 50% 50%,
			transparent 0deg,
			oklch(68% 0.21 255 / 0.08) 60deg,
			transparent 130deg,
			oklch(52% 0.22 285 / 0.07) 220deg,
			transparent 320deg,
			transparent 360deg
		);
		filter: blur(40px);
		opacity: 0.85;
		z-index: 1;
		pointer-events: none;
		animation: conicSpin 90s linear infinite;
	}
	@keyframes conicSpin {
		to {
			transform: rotate(360deg);
		}
	}

	.bg-aurora {
		position: fixed;
		inset: -25%;
		pointer-events: none;
		z-index: 1;
		overflow: hidden;
	}
	.bg-aurora::before,
	.bg-aurora::after {
		content: '';
		position: absolute;
		width: 60vmax;
		height: 60vmax;
		border-radius: 50%;
		filter: blur(80px);
		opacity: 0.5;
		will-change: transform;
	}
	.bg-aurora::before {
		top: -15%;
		left: -10%;
		background: radial-gradient(circle, oklch(58% 0.18 255 / 0.45) 0%, transparent 65%);
		animation: auroraDriftA 55s ease-in-out infinite alternate;
	}
	.bg-aurora::after {
		bottom: -15%;
		right: -10%;
		background: radial-gradient(circle, oklch(50% 0.20 290 / 0.40) 0%, transparent 65%);
		animation: auroraDriftB 70s ease-in-out infinite alternate;
	}
	@keyframes auroraDriftA {
		0% {
			transform: translate(-8%, -5%) scale(1);
		}
		50% {
			transform: translate(25%, 18%) scale(1.15);
		}
		100% {
			transform: translate(8%, 30%) scale(0.95);
		}
	}
	@keyframes auroraDriftB {
		0% {
			transform: translate(10%, 5%) scale(1);
		}
		50% {
			transform: translate(-22%, -15%) scale(1.18);
		}
		100% {
			transform: translate(-5%, -28%) scale(0.92);
		}
	}

	.bg-grid {
		position: fixed;
		inset: 0;
		background-image:
			linear-gradient(to right, oklch(28% 0.009 250) 1px, transparent 1px),
			linear-gradient(to bottom, oklch(28% 0.009 250) 1px, transparent 1px);
		background-size: 64px 64px;
		opacity: 0.14;
		mask-image: radial-gradient(140% 100% at 50% 40%, #000 25%, transparent 80%);
		pointer-events: none;
		z-index: 2;
	}

	.bg-ring {
		position: fixed;
		top: 50%;
		left: 50%;
		width: 780px;
		height: 780px;
		transform: translate(-50%, -50%);
		border-radius: 50%;
		border: 1px solid oklch(68% 0.21 255 / 0.16);
		box-shadow:
			inset 0 0 80px oklch(68% 0.21 255 / 0.05),
			0 0 60px oklch(52% 0.22 285 / 0.08);
		pointer-events: none;
		z-index: 2;
		animation: ringPulse 12s ease-in-out infinite;
	}
	.bg-ring::before {
		content: '';
		position: absolute;
		inset: 60px;
		border-radius: 50%;
		border: 1px dashed oklch(68% 0.21 255 / 0.10);
		animation: ringSpin 80s linear infinite reverse;
	}
	@keyframes ringPulse {
		0%,
		100% {
			opacity: 0.55;
		}
		50% {
			opacity: 0.95;
		}
	}
	@keyframes ringSpin {
		to {
			transform: rotate(360deg);
		}
	}

	.bg-dots {
		position: fixed;
		inset: 0;
		pointer-events: none;
		z-index: 2;
		overflow: hidden;
	}
	.bg-dots :global(.d) {
		position: absolute;
		width: 3px;
		height: 3px;
		border-radius: 50%;
		background: oklch(68% 0.21 255);
		box-shadow:
			0 0 10px oklch(68% 0.21 255 / 0.6),
			0 0 22px oklch(68% 0.21 255 / 0.3);
		opacity: 0;
		animation: dotDrift var(--dur, 18s) linear infinite;
		animation-delay: var(--delay, 0s);
	}
	.bg-dots :global(.d.v) {
		background: oklch(64% 0.20 290);
		box-shadow:
			0 0 10px oklch(64% 0.20 290 / 0.55),
			0 0 22px oklch(64% 0.20 290 / 0.28);
	}
	.bg-dots :global(.d.s) {
		width: 2px;
		height: 2px;
	}
	.bg-dots :global(.d.l) {
		width: 4px;
		height: 4px;
	}
	@keyframes dotDrift {
		0% {
			transform: translate(0, 0) scale(0.6);
			opacity: 0;
		}
		10% {
			opacity: 0.85;
		}
		50% {
			transform: translate(var(--mx, 40px), var(--my, -60px)) scale(1);
			opacity: 1;
		}
		90% {
			opacity: 0.8;
		}
		100% {
			transform: translate(calc(var(--mx, 40px) * 2), calc(var(--my, -60px) * 2)) scale(0.6);
			opacity: 0;
		}
	}

	.card-halo {
		position: fixed;
		top: 50%;
		left: 50%;
		width: 560px;
		height: 560px;
		transform: translate(-50%, -50%);
		border-radius: 50%;
		background: radial-gradient(
			circle,
			oklch(68% 0.21 255 / 0.18) 0%,
			oklch(52% 0.22 265 / 0.08) 35%,
			transparent 70%
		);
		filter: blur(40px);
		pointer-events: none;
		z-index: 3;
		animation: cardBreathe 9s ease-in-out infinite;
	}
	@keyframes cardBreathe {
		0%,
		100% {
			transform: translate(-50%, -50%) scale(0.92);
			opacity: 0.7;
		}
		50% {
			transform: translate(-50%, -50%) scale(1.08);
			opacity: 1;
		}
	}

	.bg-vignette {
		position: fixed;
		inset: 0;
		background: radial-gradient(
			40% 30% at 50% 50%,
			color-mix(in oklch, var(--bg-login-grad-to) 55%, transparent) 0%,
			transparent 75%
		);
		pointer-events: none;
		z-index: 3;
	}

	.bg-noise {
		position: fixed;
		inset: 0;
		pointer-events: none;
		z-index: 3;
		opacity: 0.045;
		mix-blend-mode: overlay;
		background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='240' height='240'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='2' stitchTiles='stitch'/><feColorMatrix values='0 0 0 0 0.85   0 0 0 0 0.86   0 0 0 0 0.92   0 0 0 0.55 0'/></filter><rect width='100%' height='100%' filter='url(%23n)'/></svg>");
		background-size: 240px 240px;
	}

	/* Responsive tightening — mirror the mock breakpoints. */
	@media (max-width: 640px) {
		.bg-conic {
			filter: blur(60px);
			opacity: 0.5;
		}
		.bg-aurora::before,
		.bg-aurora::after {
			filter: blur(60px);
			opacity: 0.35;
		}
		.card-halo {
			width: 380px;
			height: 380px;
		}
		.bg-ring {
			width: 540px;
			height: 540px;
		}
	}
	@media (max-width: 480px) {
		.bg-conic {
			display: none;
		}
		.bg-ring {
			display: none;
		}
		.bg-dots :global(.d) {
			box-shadow: 0 0 8px oklch(68% 0.21 255 / 0.5);
		}
	}

	/* Reduced motion — kill ALL animations per the brief
	 * (mock only killed the dots). Layers stay visible static. */
	@media (prefers-reduced-motion: reduce) {
		.bg-conic,
		.bg-aurora::before,
		.bg-aurora::after,
		.card-halo,
		.bg-ring,
		.bg-ring::before {
			animation: none !important;
		}
		.bg-dots :global(.d) {
			animation: none !important;
			opacity: 0.6;
		}
	}
</style>
