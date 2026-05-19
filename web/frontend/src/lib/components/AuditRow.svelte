<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  AuditRow (spec §9.4). Renders one collapsed-row of the audit table.
  The parent <tr> (in DataTable) handles the expand/collapse click;
  this component only renders the <td> cells.

  Two interactive elements stop click propagation so they don't toggle
  the row: the action badge (click → filter by action) and the actor
  filter icon (click → filter by actor user ID).
-->
<script lang="ts">
	import type { AuditEvent } from '$lib/api/audit';
	import {
		categoryOf,
		relativeTime,
		targetDisplayShort,
		actorDisplayShort
	} from '$lib/utils/audit-format';

	interface Props {
		event: AuditEvent;
		/** Called when the action badge is clicked. */
		onFilterAction: (action: string) => void;
		/** Called when the actor filter icon is clicked. */
		onFilterActor: (actorUserId: string) => void;
	}

	let { event, onFilterAction, onFilterActor }: Props = $props();

	const category = $derived(categoryOf(event.action));
	const actorInfo = $derived(
		actorDisplayShort({
			actorUserId: event.actorUserId,
			actorUsernameSnapshot: event.actorUsernameSnapshot
		})
	);
	const targetText = $derived(targetDisplayShort(event.targetType, event.targetId));
	const timeShort = $derived(relativeTime(event.timestamp));
	const ipDisplay = $derived(event.ip || '—');

	function handleBadgeClick(e: MouseEvent): void {
		e.stopPropagation();
		onFilterAction(event.action);
	}

	function handleActorFilterClick(e: MouseEvent): void {
		e.stopPropagation();
		onFilterActor(event.actorUserId);
	}
</script>

<td class="px-4 py-3 text-sm text-secondary" title={event.timestamp}>{timeShort}</td>
<td class="px-4 py-3">
	<button
		type="button"
		class="audit-badge"
		data-category={category}
		onclick={handleBadgeClick}
		aria-label={`Filter by action: ${event.action}`}
	>
		{event.action}
	</button>
</td>
<td class="px-4 py-3 text-sm">
	{#if actorInfo.anonymous}
		<span class="italic text-muted">{actorInfo.text}</span>
	{:else}
		<span class="inline-flex items-center gap-1.5 group">
			<span class="text-primary">{actorInfo.text}</span>
			<button
				type="button"
				class="text-muted opacity-0 group-hover:opacity-100 transition-opacity"
				onclick={handleActorFilterClick}
				aria-label={`Filter by actor: ${actorInfo.text}`}
				title="Filter by this actor"
			>
				<!-- Lucide: filter (small) -->
				<svg
					class="w-3.5 h-3.5"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
					stroke-linecap="round"
					stroke-linejoin="round"
					aria-hidden="true"
				>
					<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
				</svg>
			</button>
		</span>
	{/if}
</td>
<td class="px-4 py-3 text-sm text-secondary" title={event.targetId || undefined}>
	{targetText}
</td>
<td class="px-4 py-3 text-xs font-mono text-secondary">{ipDisplay}</td>

<style>
	.audit-badge {
		display: inline-flex;
		align-items: center;
		padding: 2px var(--space-2);
		font-size: var(--text-xs);
		font-weight: 500;
		border-radius: var(--radius-full);
		border: 1px solid;
		line-height: 1.5;
		cursor: pointer;
		transition: opacity var(--motion-fast);
	}
	.audit-badge:hover {
		opacity: 0.85;
	}
	.audit-badge:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 2px;
	}
	/*
	 * One rule per category (spec §9.4). Uses --badge-*-{bg,border}
	 * tokens from tokens.css (Chunk 3.1). Pre-Chunk-3 these were 5
	 * rgba()@30% blocks; switching to the shared 15% mix aligns the
	 * audit category badges with Badge.svelte's variant pairs across
	 * the app. White text (--text-on-color) on the tinted backgrounds
	 * stays legible because the border carries the saturated hue.
	 */
	.audit-badge[data-category='auth'] {
		background: var(--badge-info-bg);
		border-color: var(--badge-info-border);
		color: var(--text-on-color);
	}
	.audit-badge[data-category='mutation'] {
		background: var(--badge-warning-bg);
		border-color: var(--badge-warning-border);
		color: var(--text-on-color);
	}
	.audit-badge[data-category='security'] {
		background: var(--badge-danger-bg);
		border-color: var(--badge-danger-border);
		color: var(--text-on-color);
	}
	.audit-badge[data-category='hibp'] {
		background: var(--badge-violet-bg);
		border-color: var(--badge-violet-border);
		color: var(--text-on-color);
	}
	.audit-badge[data-category='meta'] {
		background: var(--badge-meta-bg);
		border-color: var(--badge-meta-border);
		color: var(--text-on-color);
	}
	.audit-badge[data-category='unknown'] {
		background: var(--bg-elevated);
		border-color: var(--border-default);
		color: var(--text-secondary);
	}
</style>
