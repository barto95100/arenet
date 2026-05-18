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
		padding: 0.125rem 0.5rem;
		font-size: 12px;
		font-weight: 500;
		border-radius: 9999px;
		border: 1px solid;
		line-height: 1.5;
		cursor: pointer;
		transition: opacity 150ms ease-out;
	}
	.audit-badge:hover {
		opacity: 0.85;
	}
	.audit-badge:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 2px;
	}
	/*
	 * One rule per category (spec §9.4). Background at 30% opacity, border
	 * at full opacity, white text — matches the Step C button glass effect.
	 */
	.audit-badge[data-category='auth'] {
		background: rgba(0, 217, 255, 0.3);
		border-color: var(--accent-cyan);
		color: #ffffff;
	}
	.audit-badge[data-category='mutation'] {
		background: rgba(255, 170, 0, 0.3);
		border-color: var(--status-warn);
		color: #ffffff;
	}
	.audit-badge[data-category='security'] {
		background: rgba(255, 71, 87, 0.3);
		border-color: var(--status-down);
		color: #ffffff;
	}
	.audit-badge[data-category='hibp'] {
		background: rgba(167, 139, 250, 0.3);
		border-color: var(--status-info);
		color: #ffffff;
	}
	.audit-badge[data-category='meta'] {
		background: rgba(148, 163, 184, 0.3);
		border-color: var(--status-meta);
		color: #ffffff;
	}
	.audit-badge[data-category='unknown'] {
		background: var(--bg-elevated);
		border-color: var(--border-default);
		color: var(--text-secondary);
	}
</style>
