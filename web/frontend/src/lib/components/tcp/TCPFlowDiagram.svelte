<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  v2.42.1 — what a layer-4 relay does, drawn.

  The empty state explains it in a sentence, but the thing worth
  understanding is spatial: the bytes cross Arenet without being
  read, the TLS session spans the whole path rather than stopping in
  the middle, and the only thing Arenet adds is the client's address
  in front of the stream.

  Two rows on purpose: an HTTP route above, where Arenet terminates
  TLS and inspects, and a relay below, where it does not. The
  contrast is the explanation.

  The animation is decoration: the diagram reads correctly frozen,
  every label is text, and prefers-reduced-motion stops the motion
  entirely.
-->
<script lang="ts">
	interface Props {
		/** Labels, resolved by the caller so this stays i18n-free. */
		labels: {
			client: string;
			route: string;
			service: string;
			backend: string;
			routeNote: string;
			serviceNote: string;
			proxyNote: string;
		};
	}

	let { labels }: Props = $props();
</script>

<div class="diagram" role="img" aria-label="{labels.routeNote}. {labels.serviceNote}">
	<div class="row">
		<span class="tag">{labels.route}</span>
		<div class="track">
			<span class="node">{labels.client}</span>
			<span class="wire">
				<span class="dot d1"></span>
				<span class="dot d2"></span>
			</span>
			<span class="node arenet">Arenet<span class="opens">{labels.routeNote}</span></span>
			<span class="wire">
				<span class="dot d3"></span>
			</span>
			<span class="node">{labels.backend}</span>
		</div>
	</div>

	<div class="row">
		<span class="tag tag-l4">{labels.service}</span>
		<div class="track">
			<span class="node">{labels.client}</span>
			<span class="wire sealed">
				<span class="dot sealed-dot s1"></span>
				<span class="dot sealed-dot s2"></span>
			</span>
			<span class="node arenet pass">Arenet<span class="opens">{labels.serviceNote}</span></span>
			<span class="wire sealed">
				<span class="dot sealed-dot s3"></span>
				<span class="stamp">{labels.proxyNote}</span>
			</span>
			<span class="node">{labels.backend}</span>
		</div>
	</div>
</div>

<style>
	.diagram {
		display: flex;
		flex-direction: column;
		gap: 18px;
		width: 100%;
		max-width: 720px;
		margin: 6px auto 2px;
	}
	.row {
		display: flex;
		align-items: center;
		gap: 12px;
	}
	.tag {
		flex: none;
		width: 84px;
		text-align: right;
		font-size: 10.5px;
		font-weight: 600;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		color: var(--text-muted);
	}
	.tag-l4 {
		color: var(--accent-cyan);
	}
	.track {
		flex: 1;
		display: flex;
		align-items: center;
		min-width: 0;
	}
	.node {
		flex: none;
		position: relative;
		padding: 5px 10px;
		border-radius: 7px;
		border: 1px solid var(--border-subtle);
		background: var(--bg-surface);
		font-size: 11.5px;
		color: var(--text-secondary);
		white-space: nowrap;
	}
	.node.arenet {
		border-color: var(--border-default);
		color: var(--text-primary);
	}
	.node.pass {
		border-color: color-mix(in oklch, var(--accent-cyan) 45%, transparent);
	}
	.opens {
		display: block;
		font-size: 9.5px;
		color: var(--text-muted);
		text-transform: none;
		letter-spacing: 0;
	}
	.node.pass .opens {
		color: var(--accent-cyan);
	}

	.wire {
		position: relative;
		flex: 1;
		min-width: 24px;
		height: 2px;
		background: var(--border-default);
	}
	/* A sealed wire is one Arenet does not open: drawn solid and
	   tinted, against the plain grey of the inspected one. */
	.wire.sealed {
		background: color-mix(in oklch, var(--accent-cyan) 40%, var(--border-default));
	}

	.dot {
		position: absolute;
		top: -3px;
		width: 8px;
		height: 8px;
		border-radius: 50%;
		background: var(--text-muted);
		animation: travel 2.6s linear infinite;
	}
	.sealed-dot {
		background: var(--accent-cyan);
	}
	.d1 {
		animation-delay: 0s;
	}
	.d2 {
		animation-delay: 1.3s;
	}
	.d3 {
		animation-delay: 0.65s;
	}
	.s1 {
		animation-delay: 0.2s;
	}
	.s2 {
		animation-delay: 1.5s;
	}
	.s3 {
		animation-delay: 0.85s;
	}

	@keyframes travel {
		from {
			left: -4px;
			opacity: 0;
		}
		12% {
			opacity: 1;
		}
		88% {
			opacity: 1;
		}
		to {
			left: calc(100% - 4px);
			opacity: 0;
		}
	}

	/* The only thing the relay adds: the client's address, stamped in
	   front of the stream on the way out. */
	.stamp {
		position: absolute;
		top: -22px;
		left: 50%;
		transform: translateX(-50%);
		white-space: nowrap;
		font-size: 9.5px;
		color: var(--accent-cyan);
		border: 1px solid color-mix(in oklch, var(--accent-cyan) 45%, transparent);
		background: color-mix(in oklch, var(--accent-cyan) 12%, transparent);
		border-radius: 999px;
		padding: 1px 7px;
	}

	@media (max-width: 640px) {
		.row {
			gap: 8px;
		}
		.tag {
			width: 58px;
			font-size: 9.5px;
		}
		.node {
			padding: 4px 7px;
			font-size: 10.5px;
		}
		.stamp {
			display: none;
		}
	}

	@media (prefers-reduced-motion: reduce) {
		.dot {
			animation: none;
			left: 45%;
		}
	}
</style>
