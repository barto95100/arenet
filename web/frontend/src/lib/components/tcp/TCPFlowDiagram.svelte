<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  v2.42.2 — what a layer-4 relay does, drawn.

  One row, three nodes, two segments of equal length. The first
  version also drew an HTTP route above for contrast; it earned its
  place in an explanation but not on screen — the page is about
  relays, and the second row only made the one that matters harder
  to read.

  The geometry is a grid rather than flex so the two segments are
  the same width whatever the labels say: with flex, the wider
  "Arenet" node ate into the segment on its right and pushed the
  stamp against the backend.

  The animation is decoration: the diagram reads correctly frozen,
  every label is text, and prefers-reduced-motion stops the motion.
-->
<script lang="ts">
	interface Props {
		/** Labels, resolved by the caller so this stays i18n-free. */
		labels: {
			client: string;
			service: string;
			backend: string;
			serviceNote: string;
			proxyNote: string;
		};
	}

	let { labels }: Props = $props();
</script>

<div class="diagram" role="img" aria-label="{labels.client} → Arenet ({labels.serviceNote}) → {labels.backend}. {labels.proxyNote}">
	<span class="node">{labels.client}</span>

	<span class="wire">
		<span class="dot d1"></span>
		<span class="dot d2"></span>
	</span>

	<span class="node arenet">
		Arenet
		<span class="note">{labels.serviceNote}</span>
	</span>

	<span class="wire">
		<span class="stamp">{labels.proxyNote}</span>
		<span class="dot d3"></span>
		<span class="dot d4"></span>
	</span>

	<span class="node">{labels.backend}</span>
</div>

<style>
	/* Equal segments by construction: the node columns size to their
	   content, the two wire columns share what is left. */
	.diagram {
		display: grid;
		grid-template-columns: auto 1fr auto 1fr auto;
		align-items: center;
		gap: 14px;
		width: 100%;
		max-width: 640px;
		margin: 26px auto 6px;
	}

	.node {
		padding: 7px 12px;
		border-radius: 8px;
		border: 1px solid var(--border-subtle);
		background: var(--bg-surface);
		font-size: 12px;
		color: var(--text-secondary);
		text-align: center;
		white-space: nowrap;
	}
	.node.arenet {
		border-color: color-mix(in oklch, var(--accent-cyan) 45%, transparent);
		color: var(--text-primary);
	}
	.note {
		display: block;
		margin-top: 2px;
		font-size: 10px;
		color: var(--accent-cyan);
	}

	.wire {
		position: relative;
		height: 2px;
		min-width: 70px;
		background: color-mix(in oklch, var(--accent-cyan) 40%, var(--border-default));
	}

	.dot {
		position: absolute;
		top: -3px;
		width: 8px;
		height: 8px;
		border-radius: 50%;
		background: var(--accent-cyan);
		animation: travel 2.4s linear infinite;
	}
	.d1 {
		animation-delay: 0s;
	}
	.d2 {
		animation-delay: 1.2s;
	}
	.d3 {
		animation-delay: 0.4s;
	}
	.d4 {
		animation-delay: 1.6s;
	}

	@keyframes travel {
		from {
			left: -4px;
			opacity: 0;
		}
		15% {
			opacity: 1;
		}
		85% {
			opacity: 1;
		}
		to {
			left: calc(100% - 4px);
			opacity: 0;
		}
	}

	/* The only thing the relay adds, sitting clear above its segment
	   rather than wedged between two boxes. */
	.stamp {
		position: absolute;
		bottom: 12px;
		left: 50%;
		transform: translateX(-50%);
		white-space: nowrap;
		font-size: 10px;
		color: var(--accent-cyan);
		border: 1px solid color-mix(in oklch, var(--accent-cyan) 45%, transparent);
		background: color-mix(in oklch, var(--accent-cyan) 12%, transparent);
		border-radius: 999px;
		padding: 1px 8px;
	}

	@media (max-width: 560px) {
		.diagram {
			gap: 8px;
			margin-top: 22px;
		}
		.node {
			padding: 5px 8px;
			font-size: 11px;
		}
		.wire {
			min-width: 28px;
		}
		.stamp {
			font-size: 9px;
			padding: 1px 5px;
		}
	}

	@media (prefers-reduced-motion: reduce) {
		.dot {
			animation: none;
			left: 45%;
		}
	}
</style>
