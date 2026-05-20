<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import type { Snippet } from 'svelte';

	type Variant =
		| 'tls'
		| 'waf'
		| 'status-up'
		| 'status-warn'
		| 'status-down'
		| 'neutral'
		| 'current';

	interface Props {
		variant?: Variant;
		children?: Snippet;
	}

	let { variant = 'neutral', children }: Props = $props();
</script>

<span class="badge" data-variant={variant}>
	{@render children?.()}
</span>

<style>
	.badge {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		padding: 2px var(--space-2);
		font-size: var(--text-xs);
		font-weight: 500;
		border-radius: var(--radius-full);
		border: 1px solid;
		line-height: 1.5;
	}

	/* Variants use the --badge-*-{bg,border} token pairs from
	 * tokens.css (Step F Chunk 3 additions). bg is a 15% tint of
	 * the variant's accent/status color via color-mix(); border is
	 * the saturated source color. Text is also the saturated source.
	 * Pre-Chunk-3 these were 5 rgba() hardcoded blocks per variant. */
	.badge[data-variant='tls'] {
		background: var(--badge-info-bg);
		border-color: var(--badge-info-border);
		color: var(--accent-cyan);
	}
	.badge[data-variant='waf'] {
		background: var(--badge-violet-bg);
		border-color: var(--badge-violet-border);
		color: var(--status-info);
	}
	.badge[data-variant='status-up'] {
		background: var(--badge-success-bg);
		border-color: var(--badge-success-border);
		color: var(--status-up);
	}
	.badge[data-variant='status-warn'] {
		background: var(--badge-warning-bg);
		border-color: var(--badge-warning-border);
		color: var(--status-warn);
	}
	.badge[data-variant='status-down'] {
		background: var(--badge-danger-bg);
		border-color: var(--badge-danger-border);
		color: var(--status-down);
	}
	.badge[data-variant='neutral'] {
		background: var(--bg-elevated);
		border-color: var(--border-default);
		color: var(--text-secondary);
	}
	/* "current" reuses the cyan info palette but exists as its own
	 * variant name for caller-side semantics. Sessions table marks
	 * the active session with <Badge variant="current">; reading
	 * variant="current" makes the intent obvious, whereas
	 * variant="tls" (the Chunk 6.2 placeholder) suggested a TLS
	 * indicator. Chunk 7.5 smoke fix. */
	.badge[data-variant='current'] {
		background: var(--badge-info-bg);
		border-color: var(--badge-info-border);
		color: var(--accent-cyan);
	}
</style>
