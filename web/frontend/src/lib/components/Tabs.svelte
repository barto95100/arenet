<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
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
    - keyboard activation: Enter and Space both trigger select
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
	}

	let { value = $bindable(), tabs, ariaLabel, onChange }: Props = $props();

	function select(next: T): void {
		if (next === value) return;
		value = next;
		onChange?.(next);
	}
</script>

<div class="tabs" role="tablist" aria-label={ariaLabel}>
	{#each tabs as tab (tab.id)}
		<button
			type="button"
			role="tab"
			class="tab"
			class:active={value === tab.id}
			aria-selected={value === tab.id}
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
