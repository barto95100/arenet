<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Tabs (Step CS.3 — extracted from /security/decisions).

  Underline-primary tab navigation. Used at the top of a page
  (or page-section) to switch between sibling views that share
  the same URL slot. NOT for in-card filter chips — /certs has
  a chip-style filter that intentionally diverges, see the
  inline comment near its tablist for the rationale.

  ARIA contract:
    - role="tablist" wrapper with operator-supplied aria-label
    - role="tab" buttons with aria-selected reflecting state
    - keyboard activation: Enter and Space both trigger select;
      arrows and Home/End move focus WITHOUT selecting (v2.72 —
      manual activation, because callers do real work in onChange)
      (matches the native <button> behavior used by the
      pre-extraction inline implementation in
      /security/decisions and /certs)

  Public API (Svelte 5 runes):

    value           — generic string discriminant (bindable)
    tabs            — readonly array of { id, label, testId? }
    ariaLabel       — wrapper aria-label (required for a11y)
    onChange?       — optional callback fired on user selection.
                      Receives the new id. If omitted, the
                      bindable `value` is the only signal; if
                      provided, the consumer can run effectful
                      logic (lazy loads, analytics) without
                      reacting to a $derived on `value`.

  testId vs label: label is the user-visible text; testId is
  the data-testid attribute used by tests. Both are owned by
  the consumer so existing test IDs (tab-snapshot, tab-live,
  tab-scenarios on /security/decisions) survive the extraction
  without rewrites.

  Generic T — Svelte 5 components can be made generic via the
  `generics` attribute. Constrained to string so the tab id
  fits as a Map key + a discriminated union in callers.
-->
<script lang="ts" generics="T extends string">
	interface TabDescriptor<TId extends string> {
		id: TId;
		label: string;
		testId?: string;
	}

	interface Props {
		value: T;
		tabs: readonly TabDescriptor<T>[];
		ariaLabel: string;
		onChange?: (next: T) => void;
		/**
		 * Vetoes a switch. Returning false leaves `value` alone and
		 * skips onChange, so the caller owns what happens next — it has
		 * the pending id and can apply the switch itself once the
		 * operator has answered. Omitted, every switch proceeds, which
		 * is what the other call sites rely on.
		 */
		canLeave?: (next: T) => boolean;
	}

	let { value = $bindable(), tabs, ariaLabel, onChange, canLeave }: Props = $props();

	function select(next: T): void {
		if (next === value) return;
		if (canLeave && !canLeave(next)) return;
		value = next;
		onChange?.(next);
	}

	// v2.72 — the declared role answers the keys it promises.
	//
	// This renders role="tablist" with role="tab" children and handled
	// clicks only. Everything stayed REACHABLE — native <button>s with
	// no negative tabindex, so Tab visited each one and Enter or Space
	// activated it — so nothing was unusable. What was wrong is that
	// the role was a lie: a tablist is a SINGLE tab stop whose tabs are
	// traversed with the arrow keys, and assistive tech that trusts the
	// declared role tells the user to press them. Nothing happened.
	//
	// MANUAL activation, deliberately: arrows move focus only, Enter or
	// Space selects. Callers do real work in onChange — the CrowdSec
	// panel restarts polling, the settings page rewrites the URL hash,
	// and since the unsaved-input guard it can veto the switch and open
	// a dialog. Selecting a tab merely because focus passed over it
	// would fire all of that on the way to somewhere else.
	let tablist = $state<HTMLDivElement | null>(null);

	function focusTab(index: number): void {
		const buttons = tablist?.querySelectorAll<HTMLButtonElement>('[role="tab"]');
		if (!buttons || buttons.length === 0) return;
		const wrapped = (index + buttons.length) % buttons.length;
		// A non-selected tab carries tabindex="-1", which keeps it out
		// of the Tab order while still allowing programmatic focus —
		// that is what makes the roving pattern work.
		buttons[wrapped].focus();
	}

	function onKeydown(e: KeyboardEvent): void {
		const buttons = tablist?.querySelectorAll<HTMLButtonElement>('[role="tab"]');
		if (!buttons || buttons.length === 0) return;
		// Relative to where focus IS, not to what is selected, so
		// repeated arrows walk along the strip.
		const current = Array.from(buttons).indexOf(
			document.activeElement as HTMLButtonElement
		);
		const from = current === -1 ? tabs.findIndex((t) => t.id === value) : current;
		switch (e.key) {
			case 'ArrowLeft':
			case 'ArrowUp':
				focusTab(from - 1);
				break;
			case 'ArrowRight':
			case 'ArrowDown':
				focusTab(from + 1);
				break;
			case 'Home':
				focusTab(0);
				break;
			case 'End':
				focusTab(buttons.length - 1);
				break;
			default:
				return;
		}
		e.preventDefault();
	}
</script>

<!-- svelte-ignore a11y_interactive_supports_focus —
     the tablist is not itself focusable; focus lives on a tab (roving
     tabindex below), which is the WAI-ARIA pattern. -->
<div class="tabs" role="tablist" aria-label={ariaLabel} bind:this={tablist} onkeydown={onKeydown}>
	{#each tabs as tab (tab.id)}
		<button
			type="button"
			role="tab"
			class="tab"
			class:active={value === tab.id}
			aria-selected={value === tab.id}
			tabindex={value === tab.id ? 0 : -1}
			data-testid={tab.testId}
			onclick={() => select(tab.id)}
		>
			{tab.label}
		</button>
	{/each}
</div>

<style>
	.tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 0.5rem;
		border-bottom: 1px solid var(--border-subtle, var(--bg-hover));
	}
	.tab {
		background: transparent;
		color: var(--text-secondary);
		border: none;
		padding: 0.5rem 1rem;
		font-size: var(--text-sm);
		cursor: pointer;
		border-bottom: 2px solid transparent;
		margin-bottom: -1px;
		font-family: inherit;
	}
	.tab:hover {
		color: var(--text-primary);
	}
	.tab.active {
		color: var(--accent-cyan);
		border-bottom-color: var(--accent-cyan);
	}
	.tab:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 2px;
		border-radius: 2px;
	}
</style>
