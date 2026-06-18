<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

<!--
Step M.3 — Recent WAF events table.

Reused by /security (limit=20, no filter) AND
/security/[routeId] (limit=20, route-scoped, M.4).

Columns:
  - ts           (relative: "12s ago" / "3m ago" / absolute past 1h)
  - route        (link to /security/<routeId>; falls back to UUID
                  if the host isn't supplied in props)
  - category     (coloured badge, same palette as CategoryDistribution)
  - ruleId       (mono, narrow column)
  - srcIp        (mono)
  - payload      (truncated; full sample available on hover via title)

Empty state: italic "no events" message inside a card-sized
panel — same shape as the TimelineChart's empty state so the
dashboard feels coherent.

Compact mode (prop): drops the route column. Used by the
drill-down page where every row already belongs to the
selected route.
-->

<script lang="ts">
	import type { OwaspCategory, WafEvent } from '$lib/api/types';

	interface Props {
		events: WafEvent[];
		/**
		 * Optional map of routeId → host string so the route
		 * cell can show the friendly host instead of the bare
		 * UUID. When the routeId isn't in the map, falls back
		 * to a truncated UUID.
		 */
		hostByRouteId?: Record<string, string>;
		/**
		 * Compact mode = drop the route column. Drill-down
		 * page sets this true (every row is the same route).
		 */
		compact?: boolean;
	}
	let { events, hostByRouteId = {}, compact = false }: Props = $props();

	// Category badge colours mirror CategoryDistribution.
	// Phase Y — colour mapping moved to lib/utils/waf-category
	// (single source of truth across CategoryDistribution +
	// WafEventList + MixedEventList + /waf + /security/[routeId]).
	import { categoryMeta } from '$lib/utils/waf-category';

	// Relative time formatting: "Ns ago" up to a minute, "Nm
	// ago" up to an hour, then HH:MM. Pure function — no
	// re-renders on tick (caller controls refresh cadence).
	function relativeTs(iso: string): string {
		const then = new Date(iso).getTime();
		const now = Date.now();
		const secs = Math.max(0, Math.floor((now - then) / 1000));
		if (secs < 60) return `${secs}s ago`;
		const mins = Math.floor(secs / 60);
		if (mins < 60) return `${mins}m ago`;
		const d = new Date(iso);
		const hh = String(d.getHours()).padStart(2, '0');
		const mm = String(d.getMinutes()).padStart(2, '0');
		return `${hh}:${mm}`;
	}

	// Short host display: prefer the friendly host from the
	// caller, fall back to a UUID prefix. The cell always
	// links to /security/<routeId>.
	function hostFor(routeId: string): string {
		return hostByRouteId[routeId] ?? routeId.slice(0, 8) + '…';
	}

	// Truncate payload to 60 chars for the table cell; full
	// text in the title= tooltip.
	function payloadPreview(s: string): string {
		if (s.length <= 60) return s;
		return s.slice(0, 60) + '…';
	}
</script>

{#if events.length === 0}
	<div class="empty">no WAF events in window</div>
{:else}
	<table>
		<thead>
			<tr>
				<th>Time</th>
				{#if !compact}
					<th>Route</th>
				{/if}
				<th>Category</th>
				<th>Rule</th>
				<th>Source IP</th>
				<th>Payload</th>
			</tr>
		</thead>
		<tbody>
			{#each events as e (e.id)}
				<tr>
					<td class="ts" title={e.ts}>{relativeTs(e.ts)}</td>
					{#if !compact}
						<td class="route">
							<a href="/security/{e.routeId}">{hostFor(e.routeId)}</a>
						</td>
					{/if}
					<td>
						<span class="badge" style:background={categoryMeta(e.category).color}>
							{e.category}
						</span>
					</td>
					<td class="mono">{e.ruleId}</td>
					<td class="mono">{e.srcIp}</td>
					<td class="payload mono" title={e.payloadSample || '(empty)'}>
						{payloadPreview(e.payloadSample) || '—'}
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
{/if}

<style>
	table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm, 13px);
	}
	th,
	td {
		padding: 0.4rem 0.6rem;
		text-align: left;
		border-bottom: 1px solid var(--border-subtle, var(--bg-hover));
		vertical-align: top;
	}
	th {
		color: var(--text-secondary);
		font-weight: 500;
		font-size: var(--text-xs, 11px);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.ts {
		font-family: var(--font-mono, monospace);
		color: var(--text-secondary);
		white-space: nowrap;
	}
	.route a {
		color: var(--text-primary);
		text-decoration: none;
		border-bottom: 1px dashed var(--text-muted);
	}
	.route a:hover {
		color: var(--accent-cyan);
		border-bottom-color: var(--accent-cyan);
	}
	.mono {
		font-family: var(--font-mono, monospace);
	}
	.payload {
		color: var(--text-secondary);
		word-break: break-all;
	}
	.badge {
		display: inline-block;
		padding: 0.1rem 0.45rem;
		border-radius: 3px;
		color: var(--text-on-color, #ffffff);
		font-size: var(--text-xs, 11px);
		font-weight: 600;
		letter-spacing: 0.04em;
	}
	.empty {
		padding: 1rem;
		text-align: center;
		font-style: italic;
		color: var(--text-muted);
		font-size: var(--text-sm, 13px);
	}
</style>
