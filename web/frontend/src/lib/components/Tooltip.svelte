<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
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

	// v2.72 — the description reaches the trigger, and Escape dismisses.
	//
	// Two defects, both reported from outside and both confirmed here.
	// aria-describedby sat on the wrapper <span> below — a positioning
	// container with no tabindex, so never focusable — and
	// aria-describedby does not inherit to descendants. When the real
	// trigger took focus the accessible description was EMPTY: every
	// tooltip in the application was silent to a screen reader while
	// looking perfectly fine on screen. And nothing dismissed the
	// bubble without moving focus, which WCAG 2.1 SC 1.4.13 requires.
	let wrapper = $state<HTMLSpanElement | null>(null);

	// Which element gets the description: the first focusable thing
	// inside, which is the trigger the caller passed. If there is none —
	// a bare icon or plain text — the wrapper becomes focusable, because
	// a description nobody can reach is no description.
	const FOCUSABLE =
		'a[href], button, input, select, textarea, summary, [tabindex]:not([tabindex="-1"])';

	$effect(() => {
		const root = wrapper;
		if (!root) return;
		const target = root.querySelector<HTMLElement>(FOCUSABLE) ?? root;
		if (target === root) {
			root.setAttribute('tabindex', '0');
		}
		target.setAttribute('aria-describedby', mergeIds(target.getAttribute('aria-describedby')));
	});

	// mergeIds appends our id without dropping any the caller's element
	// already carries — a trigger can legitimately be described by its
	// own hint or error text as well.
	function mergeIds(existing: string | null): string {
		const ids = (existing ?? '').split(/\s+/).filter((v) => v !== '');
		if (!ids.includes(id)) ids.push(id);
		return ids.join(' ');
	}
</script>

<svelte:window
	onkeydown={(e) => {
		// WCAG 1.4.13: a tooltip obscuring the content under it has to
		// be dismissable without moving focus. Guarded on `open` so an
		// Escape another component is waiting for is never swallowed.
		if (open && e.key === 'Escape') open = false;
	}}
/>

<!-- svelte-ignore a11y_no_static_element_interactions —
     the wrapper is purely a positioning container; the actual
     interactive surface is the child element passed via children.
     mouseenter/leave drive tooltip visibility, focusin/out for
     keyboard nav. Adding role="group" or "presentation" would
     mislead AT users; we mark and explain instead. -->
<span
	class="tt-wrapper"
	bind:this={wrapper}
	onmouseenter={() => (open = true)}
	onmouseleave={() => (open = false)}
	onfocusin={() => (open = true)}
	onfocusout={() => (open = false)}
>
	{@render children?.()}
	<!-- Always in the DOM, hidden when closed, rather than mounted by an
	     {#if}. The description is computed when focus lands on the
	     trigger, and `open` is set by that same focus event, so a
	     conditionally-rendered target may not exist yet at the moment it
	     is read. A node that is always present has no such window — and
	     the accessible-name spec deliberately includes hidden nodes when
	     it follows an aria-describedby reference, so hiding it costs
	     nothing. The fade moves to CSS since there is no mount to
	     transition. -->
	<span
		class="tt-bubble tt-{side}"
		{id}
		role="tooltip"
		hidden={!open}
		data-testid="tooltip-bubble"
	>
		{label}
	</span>
</span>

<style>
	.tt-wrapper {
		position: relative;
		display: inline-block;
	}
	.tt-bubble[hidden] {
		/* The UA stylesheet gives [hidden] display:none, which would
		   win over opacity and kill the fade, so the display is set
		   back explicitly. visibility keeps it out of hit-testing and
		   out of the accessibility tree while it is closed — and the
		   accessible-description lookup follows aria-describedby into
		   hidden nodes by spec, so the text is still available to the
		   trigger either way. */
		display: inline;
		opacity: 0;
		visibility: hidden;
	}
	.tt-bubble {
		opacity: 1;
		transition:
			opacity 100ms ease-out,
			visibility 100ms;
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
