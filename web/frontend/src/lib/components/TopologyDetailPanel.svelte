<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  TopologyDetailPanel (spec §6.9). Slide-in right side panel showing
  a single route's full detail + sparklines for the last 60 ticks.

  Closes on Escape, overlay click, or the parent's second-click of
  the same node.

  Inline SVG sparklines (spec §6.9 — "single thin SVG path"); no
  charting lib.
-->
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import type { RouteState } from '$lib/stores/topology.svelte';
	import { HISTORY_CAPACITY } from '$lib/stores/topology-constants';

	interface Props {
		route: RouteState;
		onClose: () => void;
	}

	let { route, onClose }: Props = $props();

	// Build a sparkline SVG path from the history. valueOf maps each
	// tick to its data point; the returned string is "M x,y L x,y ..."
	// scaled into the sparkline viewBox (200 × 32).
	function sparklinePath(valueOf: (t: { reqs: number; errs: number }) => number): string {
		if (route.history.length === 0) return '';
		const values = route.history.map(valueOf);
		const maxV = Math.max(1, ...values); // avoid div-by-zero
		const W = 200;
		const H = 32;
		const PAD = 2;
		const n = values.length;
		// Render the last HISTORY_CAPACITY points right-aligned, so a
		// fresh route (few ticks) appears on the right of the viewBox.
		const xStep = (W - 2 * PAD) / Math.max(1, HISTORY_CAPACITY - 1);
		const startIdx = HISTORY_CAPACITY - n;
		const cmds: string[] = [];
		for (let i = 0; i < n; i++) {
			const x = PAD + (startIdx + i) * xStep;
			const y = H - PAD - (values[i] / maxV) * (H - 2 * PAD);
			cmds.push(`${i === 0 ? 'M' : 'L'} ${x.toFixed(1)},${y.toFixed(1)}`);
		}
		return cmds.join(' ');
	}

	const reqPath = $derived(sparklinePath((t) => t.reqs));
	const errPath = $derived(sparklinePath((t) => t.errs));

	const errRatePct = $derived((route.errRate5xx * 100).toFixed(1));

	function onKeydown(e: KeyboardEvent): void {
		if (e.key === 'Escape') {
			e.preventDefault();
			onClose();
		}
	}

	onMount(() => {
		document.addEventListener('keydown', onKeydown);
	});

	onDestroy(() => {
		document.removeEventListener('keydown', onKeydown);
	});
</script>

<div
	class="overlay"
	role="presentation"
	onclick={onClose}
	onkeydown={onKeydown}
></div>

<div
	class="panel"
	role="dialog"
	aria-label={`Route detail: ${route.host}`}
	tabindex="-1"
>
	<header class="panel-header">
		<div>
			<h2 class="title">{route.host}</h2>
			<p class="subtitle">{route.upstream}</p>
		</div>
		<button
			type="button"
			class="close-btn"
			aria-label="Close panel"
			onclick={onClose}
		>×</button>
	</header>

	<div class="metrics-row">
		<div class="metric">
			<div class="metric-value">{route.reqPerSec}</div>
			<div class="metric-label">req/s</div>
		</div>
		<div class="metric">
			<div class="metric-value">{errRatePct}<span class="unit">%</span></div>
			<div class="metric-label">5xx</div>
		</div>
	</div>

	<section class="sparkline-section">
		<h3>Requests / sec — last {route.history.length}s</h3>
		<svg
			viewBox="0 0 200 32"
			class="sparkline"
			role="img"
			aria-label={`Sparkline of requests per second over the last ${route.history.length} seconds`}
		>
			<path d={reqPath} class="spark-line spark-reqs" />
		</svg>
	</section>

	<section class="sparkline-section">
		<h3>5xx errors — last {route.history.length}s</h3>
		<svg
			viewBox="0 0 200 32"
			class="sparkline"
			role="img"
			aria-label={`Sparkline of 5xx errors over the last ${route.history.length} seconds`}
		>
			<path d={errPath} class="spark-line spark-errs" />
		</svg>
	</section>

	<footer class="panel-footer">
		<a href="/observability/{route.id}" class="edit-link">Historical →</a>
		<a href="/routes" class="edit-link">Edit route ↗</a>
	</footer>
</div>

<style>
	.overlay {
		position: fixed;
		inset: 0;
		background: rgba(10, 14, 20, 0.4);
		z-index: 40;
		cursor: pointer;
	}
	.panel {
		position: fixed;
		top: 0;
		right: 0;
		bottom: 0;
		width: 360px;
		background: var(--bg-elevated);
		border-left: 1px solid var(--border-default);
		z-index: 50;
		display: flex;
		flex-direction: column;
		padding: 1.25rem;
		gap: 1rem;
		animation: slide-in 200ms ease-out;
	}
	@media (prefers-reduced-motion: reduce) {
		.panel {
			animation: none;
		}
	}
	@keyframes slide-in {
		from {
			transform: translateX(100%);
		}
		to {
			transform: translateX(0);
		}
	}

	.panel-header {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 0.5rem;
	}
	.title {
		font-family: 'Inter', system-ui, sans-serif;
		font-size: 1.125rem;
		font-weight: 600;
		color: var(--text-primary);
		margin: 0;
		word-break: break-all;
	}
	.subtitle {
		font-family: ui-monospace, monospace;
		font-size: 0.75rem;
		color: var(--text-secondary);
		margin: 0.25rem 0 0;
		word-break: break-all;
	}
	.close-btn {
		font-size: 1.5rem;
		line-height: 1;
		width: 2rem;
		height: 2rem;
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--text-secondary);
		border-radius: 4px;
		flex-shrink: 0;
	}
	.close-btn:hover {
		background-color: var(--bg-hover);
		color: var(--text-primary);
	}

	.metrics-row {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.75rem;
	}
	.metric {
		background: var(--bg-surface);
		border: 1px solid var(--border-default);
		border-radius: 6px;
		padding: 0.75rem;
		text-align: center;
	}
	.metric-value {
		font-family: ui-monospace, monospace;
		font-size: 1.5rem;
		font-weight: 600;
		color: var(--text-primary);
	}
	.metric-value .unit {
		font-size: 1rem;
		color: var(--text-secondary);
		margin-left: 2px;
	}
	.metric-label {
		font-size: 0.75rem;
		color: var(--text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.5px;
		margin-top: 0.25rem;
	}

	.sparkline-section h3 {
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.5px;
		color: var(--text-secondary);
		margin-bottom: 0.375rem;
	}
	.sparkline {
		width: 100%;
		height: 40px;
		display: block;
	}
	.spark-line {
		fill: none;
		stroke-width: 1.2;
		stroke-linejoin: round;
		stroke-linecap: round;
	}
	.spark-reqs {
		stroke: var(--accent-cyan);
	}
	.spark-errs {
		stroke: var(--status-down);
	}

	.panel-footer {
		margin-top: auto;
		padding-top: 0.5rem;
		border-top: 1px solid var(--border-subtle);
	}
	.edit-link {
		display: inline-block;
		font-size: 0.875rem;
		color: var(--accent-cyan);
	}
	.edit-link:hover {
		text-decoration: underline;
	}
</style>
