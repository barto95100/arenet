<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts" generics="T extends { id: string }">
	import type { Snippet } from 'svelte';

	interface Props {
		headers: string[];
		items: T[];
		row: Snippet<[T]>;
		/** Optional snippet rendered in an extra row beneath the active item. */
		expanded?: Snippet<[T]>;
		/**
		 * Whether rows are click-to-expand interactive. Defaults to `true`
		 * for backward compatibility with Routes / Audit which use the
		 * expanded snippet. Set to `false` for read-only tables (e.g.
		 * Sessions) so rows don't carry cursor-pointer, role=button,
		 * tabindex, hover-rail, or focus-ring — Step G G.3 fix for the
		 * "interactive parasite" cosmetic debt (smoke doc Step F §5 #1).
		 */
		interactive?: boolean;
		/**
		 * Names the disclosure button of each row, e.g. "Details for
		 * route.update, 2 minutes ago" (v2.72).
		 *
		 * Without it the button falls back to a generic label, which is
		 * useless in a list: a screen-reader user tabbing through gets
		 * "Details, button" fifty times with nothing to tell them apart.
		 */
		rowLabel?: (item: T) => string;
		/** Screen-reader text for the disclosure column's header cell. */
		rowLabelHeader?: string;
	}

	let {
		headers,
		items,
		row,
		expanded,
		interactive = true,
		rowLabel,
		rowLabelHeader = 'Details'
	}: Props = $props();

	let activeId = $state<string | null>(null);

	// v2.72 — the row stops being a button.
	//
	// It used to carry role="button" + tabindex="0". role="button"
	// overrides the implicit `row` role, which takes the <td> children
	// out of the table's accessibility tree: a screen reader announced
	// ONE control whose name was all five cells concatenated, with no
	// column headers to anchor them. And the audit row contains two
	// real filter buttons, so that was a button inside a button — the
	// nested controls stayed Tab-focusable but were flattened out of
	// the tree, so focus could land on something that announced
	// nothing.
	//
	// A disclosure button in its own leading cell is the standard shape
	// for an expandable row. The row keeps its mouse click, because
	// that affordance is years old and operators use it.
	const disclosureColumns = $derived(interactive && expanded ? 1 : 0);

	function toggle(id: string) {
		activeId = activeId === id ? null : id;
	}

	// detailsId ties the button to the row it opens, which is what
	// aria-controls has to point at.
	function detailsId(id: string): string {
		return `data-row-details-${id}`;
	}

	/**
	 * Row-level click. Ignores anything that started on a control
	 * inside the row — the audit row's own filter buttons, and the
	 * disclosure button itself, which handles its own click.
	 */
	function onRowClick(event: MouseEvent, id: string) {
		const target = event.target;
		if (target instanceof Element && target.closest('button, a, input, select, textarea')) {
			return;
		}
		toggle(id);
	}
</script>

<div class="overflow-hidden border border-border-subtle rounded-lg">
	<table class="w-full text-sm border-collapse table-fixed">
		<thead class="bg-sidebar sticky top-0">
			<tr>
				{#if disclosureColumns === 1}
					<th class="px-2 py-3 w-10">
						<span class="dt-sr">{rowLabelHeader}</span>
					</th>
				{/if}
				{#each headers as h (h)}
					<th
						class="px-4 py-3 text-left text-xs uppercase tracking-wide text-secondary font-medium"
					>
						{h}
					</th>
				{/each}
			</tr>
		</thead>
		<tbody>
			{#each items as item (item.id)}
				<tr
					class="data-row border-t border-border-subtle"
					class:interactive
					class:active={interactive && activeId === item.id}
					onclick={interactive ? (e) => onRowClick(e, item.id) : undefined}
				>
					{#if disclosureColumns === 1}
						<td class="px-2 py-3 align-top">
							<button
								type="button"
								class="dt-disclosure"
								aria-expanded={activeId === item.id}
								aria-controls={activeId === item.id ? detailsId(item.id) : undefined}
								aria-label={rowLabel ? rowLabel(item) : rowLabelHeader}
								data-testid={`data-row-toggle-${item.id}`}
								onclick={() => toggle(item.id)}
							>
								<span aria-hidden="true">{activeId === item.id ? '▾' : '▸'}</span>
							</button>
						</td>
					{/if}
					{@render row(item)}
				</tr>
				{#if expanded && activeId === item.id}
					<tr class="bg-surface" id={detailsId(item.id)}>
						<td colspan={headers.length + disclosureColumns} class="px-6 py-4">
							{@render expanded(item)}
						</td>
					</tr>
				{/if}
			{/each}
			{#if items.length === 0}
				<tr>
					<td
						colspan={headers.length + disclosureColumns}
						class="px-4 py-6 text-center text-secondary text-sm"
					>
						No items.
					</td>
				</tr>
			{/if}
		</tbody>
	</table>
</div>

<style>
	/* Visually hidden, still in the accessibility tree — the disclosure
	   column's header needs a name for the column association to mean
	   anything, and it has nothing to show. */
	.dt-sr {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip: rect(0 0 0 0);
		white-space: nowrap;
	}
	.dt-disclosure {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 1.5rem;
		height: 1.5rem;
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		background: transparent;
		border: none;
		cursor: pointer;
	}
	.dt-disclosure:hover {
		color: var(--text-primary);
		background: var(--bg-hover);
	}
	.dt-disclosure:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 1px;
	}

	/*
	 * The cyan left "rail" is rendered as an inset box-shadow on the row
	 * itself. This avoids the HTML pitfall of absolutely-positioning a <td>
	 * outside its parent <tr> flow, while still animating smoothly.
	 */
	.data-row {
		transition:
			background-color var(--motion-fast),
			box-shadow var(--motion-fast);
	}
	/* Step G G.3: hover-rail + focus-ring + active-rail only apply to
	 * interactive rows. Read-only tables (Sessions) keep the default
	 * cursor + no rail + no focus outline. */
	.data-row.interactive {
		cursor: pointer;
	}
	.data-row.interactive:hover {
		background-color: var(--bg-hover);
		box-shadow: inset 2px 0 0 var(--accent-cyan);
	}
	.data-row.active {
		background-color: var(--bg-hover);
		box-shadow: inset 2px 0 0 var(--accent-cyan);
	}
	.data-row.interactive:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: -2px;
	}
</style>
