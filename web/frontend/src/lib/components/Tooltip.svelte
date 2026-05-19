<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Tooltip (Step F §5.1 — new in Chunk 3.1).

  Renders a small floating label anchored to the trigger element
  the caller wraps. Show/hide is driven by hover + focus on the
  trigger; the tooltip itself is non-interactive (pointer-events:
  none) so it never blocks clicks.

  Positioning is CSS-only via absolute positioning around the
  wrapper, no floating-ui dependency. The wrapper is
  `display: inline-block` so trigger sizing isn't disturbed.
  Side: 'top' | 'bottom' | 'left' | 'right' — defaults to 'top'.

  Reduced-motion is respected by the global @media block in
  app.css (the transition:fade duration collapses to 0).

  Public API (add-only per §1.3):

    label   — string (required)
    side    — 'top' | 'bottom' | 'left' | 'right' (default 'top')
    children — Snippet (the trigger element)
-->
<script lang="ts">
	import { fade } from 'svelte/transition';
	import type { Snippet } from 'svelte';

	type Side = 'top' | 'bottom' | 'left' | 'right';

	interface Props {
		label: string;
		side?: Side;
		children?: Snippet;
	}

	let { label, side = 'top', children }: Props = $props();

	let open = $state(false);
	const id = `tt-${Math.random().toString(36).slice(2, 9)}`;
</script>

<!-- svelte-ignore a11y_no_static_element_interactions —
     the wrapper is purely a positioning container; the actual
     interactive surface is the child element passed via children.
     mouseenter/leave drive tooltip visibility, focusin/out for
     keyboard nav. Adding role="group" or "presentation" would
     mislead AT users; we mark and explain instead. -->
<span
	class="tt-wrapper"
	onmouseenter={() => (open = true)}
	onmouseleave={() => (open = false)}
	onfocusin={() => (open = true)}
	onfocusout={() => (open = false)}
	aria-describedby={open ? id : undefined}
>
	{@render children?.()}
	{#if open}
		<span class="tt-bubble tt-{side}" {id} role="tooltip" transition:fade={{ duration: 100 }}>
			{label}
		</span>
	{/if}
</span>

<style>
	.tt-wrapper {
		position: relative;
		display: inline-block;
	}
	.tt-bubble {
		position: absolute;
		z-index: 50;
		padding: var(--space-1) var(--space-2);
		background: var(--bg-surface);
		color: var(--text-primary);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		font-size: var(--text-xs);
		font-weight: 500;
		white-space: nowrap;
		box-shadow: var(--shadow-md);
		pointer-events: none;
		line-height: 1.3;
	}
	.tt-top {
		bottom: calc(100% + var(--space-1));
		left: 50%;
		transform: translateX(-50%);
	}
	.tt-bottom {
		top: calc(100% + var(--space-1));
		left: 50%;
		transform: translateX(-50%);
	}
	.tt-left {
		right: calc(100% + var(--space-1));
		top: 50%;
		transform: translateY(-50%);
	}
	.tt-right {
		left: calc(100% + var(--space-1));
		top: 50%;
		transform: translateY(-50%);
	}
</style>
