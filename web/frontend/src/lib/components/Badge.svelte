<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import type { Snippet } from 'svelte';

	type Variant = 'tls' | 'waf' | 'status-up' | 'status-warn' | 'status-down' | 'neutral';

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
		gap: 0.25rem;
		padding: 0.125rem 0.5rem;
		font-size: 12px;
		font-weight: 500;
		border-radius: 9999px;
		border: 1px solid;
		line-height: 1.5;
	}

	/*
	 * Each variant uses three shades of the same hue:
	 * - background = 15% opacity tint
	 * - border = 40% opacity tint
	 * - text = full hue
	 * Implemented with explicit rgba()/hsl() values because Tailwind v3 cannot
	 * derive opacity variants from CSS custom properties without extra plumbing.
	 */
	.badge[data-variant='tls'] {
		background: rgba(0, 217, 255, 0.15);
		border-color: rgba(0, 217, 255, 0.4);
		color: var(--accent-cyan);
	}
	.badge[data-variant='waf'] {
		background: rgba(167, 139, 250, 0.15);
		border-color: rgba(167, 139, 250, 0.4);
		color: var(--status-info);
	}
	.badge[data-variant='status-up'] {
		background: rgba(0, 255, 136, 0.15);
		border-color: rgba(0, 255, 136, 0.4);
		color: var(--status-up);
	}
	.badge[data-variant='status-warn'] {
		background: rgba(255, 170, 0, 0.15);
		border-color: rgba(255, 170, 0, 0.4);
		color: var(--status-warn);
	}
	.badge[data-variant='status-down'] {
		background: rgba(255, 71, 87, 0.15);
		border-color: rgba(255, 71, 87, 0.4);
		color: var(--status-down);
	}
	.badge[data-variant='neutral'] {
		background: var(--bg-elevated);
		border-color: var(--border-default);
		color: var(--text-secondary);
	}
</style>
