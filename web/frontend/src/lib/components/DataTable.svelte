<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
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
	}

	let { headers, items, row, expanded }: Props = $props();

	let activeId = $state<string | null>(null);

	function toggle(id: string) {
		activeId = activeId === id ? null : id;
	}

	function onKey(event: KeyboardEvent, id: string) {
		if (event.key === 'Enter' || event.key === ' ') {
			event.preventDefault();
			toggle(id);
		}
	}
</script>

<div class="overflow-hidden border border-border-subtle rounded-lg">
	<table class="w-full text-sm border-collapse">
		<thead class="bg-sidebar sticky top-0">
			<tr>
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
					class="data-row border-t border-border-subtle cursor-pointer"
					class:active={activeId === item.id}
					onclick={() => toggle(item.id)}
					onkeydown={(e) => onKey(e, item.id)}
					tabindex="0"
					role="button"
					aria-expanded={expanded ? activeId === item.id : undefined}
				>
					{@render row(item)}
				</tr>
				{#if expanded && activeId === item.id}
					<tr class="bg-surface">
						<td colspan={headers.length} class="px-6 py-4">
							{@render expanded(item)}
						</td>
					</tr>
				{/if}
			{/each}
			{#if items.length === 0}
				<tr>
					<td
						colspan={headers.length}
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
	/*
	 * The cyan left "rail" is rendered as an inset box-shadow on the row
	 * itself. This avoids the HTML pitfall of absolutely-positioning a <td>
	 * outside its parent <tr> flow, while still animating smoothly.
	 */
	.data-row {
		transition: background-color 150ms ease-out, box-shadow 150ms ease-out;
	}
	.data-row:hover {
		background-color: var(--bg-hover);
		box-shadow: inset 2px 0 0 var(--accent-cyan);
	}
	.data-row.active {
		background-color: var(--bg-hover);
		box-shadow: inset 2px 0 0 var(--accent-cyan);
	}
	.data-row:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: -2px;
	}
</style>
