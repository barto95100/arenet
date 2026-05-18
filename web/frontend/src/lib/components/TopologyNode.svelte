<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  TopologyNode (spec §6.5). One SVG <g> containing the route's box,
  host label, and live req/s. Three discrete visual states driven
  by props from the parent (computed via isActive / isErrorSpike).

  Hover shows a tooltip ~200 ms after pointer enter (spec §6.10).
  Click toggles selection — parent (TopologySvg) opens the detail
  panel.
-->
<script lang="ts">
	interface Props {
		x: number;
		y: number;
		width: number;
		height: number;
		label: string;
		reqPerSec: number;
		errRate5xx: number;
		nodeState: 'active' | 'idle' | 'spike';
		selected: boolean;
		onClick: () => void;
		/** When true, no pulse animation on spike state (spec §6.6). */
		reducedMotion: boolean;
	}

	let {
		x,
		y,
		width,
		height,
		label,
		reqPerSec,
		errRate5xx,
		nodeState,
		selected,
		onClick,
		reducedMotion
	}: Props = $props();

	// Hover tooltip (spec §6.10). 200 ms delay before show.
	let hovering = $state(false);
	let hoverTimer: ReturnType<typeof setTimeout> | null = null;

	function onPointerEnter(): void {
		if (hoverTimer !== null) clearTimeout(hoverTimer);
		hoverTimer = setTimeout(() => {
			hovering = true;
			hoverTimer = null;
		}, 200);
	}
	function onPointerLeave(): void {
		if (hoverTimer !== null) {
			clearTimeout(hoverTimer);
			hoverTimer = null;
		}
		hovering = false;
	}

	const errRatePct = $derived((errRate5xx * 100).toFixed(1));
</script>

<g
	class="node"
	class:active={nodeState === 'active'}
	class:idle={nodeState === 'idle'}
	class:spike={nodeState === 'spike'}
	class:selected
	class:reduced-motion={reducedMotion}
	role="button"
	tabindex="0"
	aria-label={`Route ${label}, ${reqPerSec} requests per second, ${errRatePct}% 5xx errors`}
	onclick={onClick}
	onkeydown={(e) => {
		if (e.key === 'Enter' || e.key === ' ') {
			e.preventDefault();
			onClick();
		}
	}}
	onpointerenter={onPointerEnter}
	onpointerleave={onPointerLeave}
>
	<rect
		{x}
		{y}
		{width}
		{height}
		rx="6"
		class="box"
	/>
	<text
		x={x + width / 2}
		y={y + height / 2 - 4}
		text-anchor="middle"
		dominant-baseline="middle"
		class="label"
	>
		{label}
	</text>
	<text
		x={x + width / 2}
		y={y + height / 2 + 14}
		text-anchor="middle"
		dominant-baseline="middle"
		class="metrics"
	>
		{reqPerSec} req/s · {errRatePct}% 5xx
	</text>

	{#if hovering}
		<!-- Inline tooltip (spec §6.10). Positioned above the node. -->
		<g class="tooltip-group" transform={`translate(${x + width / 2}, ${y - 4})`}>
			<rect
				x="-90"
				y="-44"
				width="180"
				height="40"
				rx="4"
				class="tooltip-bg"
			/>
			<text x="0" y="-26" text-anchor="middle" class="tooltip-host">{label}</text>
			<text x="0" y="-12" text-anchor="middle" class="tooltip-stats">
				{reqPerSec} req/s · {errRatePct}% 5xx
			</text>
		</g>
	{/if}
</g>

<style>
	.node {
		cursor: pointer;
		transition: opacity 200ms ease-out;
	}
	.box {
		fill: var(--bg-elevated);
		stroke: var(--border-default);
		stroke-width: 1.5;
		transition: stroke 200ms, opacity 200ms;
	}
	.label {
		fill: var(--text-primary);
		font-family: 'Inter', system-ui, sans-serif;
		font-size: 13px;
		font-weight: 500;
		pointer-events: none;
	}
	.metrics {
		fill: var(--text-secondary);
		font-family: 'JetBrains Mono', ui-monospace, monospace;
		font-size: 11px;
		pointer-events: none;
	}

	/* Active — normal stroke, full opacity. */
	.node.active .box {
		stroke: var(--accent-cyan);
	}

	/* Idle — dimmed, dashed border. */
	.node.idle {
		opacity: 0.4;
	}
	.node.idle .box {
		stroke-dasharray: 4 4;
	}

	/* Spike — red border + pulse animation. Pulse disabled in reduced
	   motion. */
	.node.spike .box {
		stroke: var(--status-down);
	}
	.node.spike:not(.reduced-motion) .box {
		animation: pulse 1s ease-in-out infinite;
	}
	@keyframes pulse {
		0%,
		100% {
			filter: drop-shadow(0 0 0 var(--status-down));
		}
		50% {
			filter: drop-shadow(0 0 10px var(--status-down));
		}
	}

	/* Selected — cyan glow regardless of state. */
	.node.selected .box {
		stroke: var(--accent-cyan);
		filter: drop-shadow(0 0 8px var(--accent-cyan));
	}

	/* Focus indicator for keyboard navigation. */
	.node:focus-visible .box {
		stroke: var(--accent-cyan);
		stroke-width: 2.5;
	}

	/* Tooltip. */
	.tooltip-bg {
		fill: var(--bg-surface);
		stroke: var(--border-default);
		stroke-width: 1;
	}
	.tooltip-host {
		fill: var(--text-primary);
		font-family: 'Inter', system-ui, sans-serif;
		font-size: 12px;
		font-weight: 500;
	}
	.tooltip-stats {
		fill: var(--text-secondary);
		font-family: 'JetBrains Mono', ui-monospace, monospace;
		font-size: 10px;
	}
	.tooltip-group {
		pointer-events: none;
	}
</style>
