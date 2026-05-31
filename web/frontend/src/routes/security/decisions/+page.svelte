<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

<!--
Step N.4 — /security/decisions page.

List view of CrowdSec LAPI decisions, materializing the mock
UI promise of rows like "185.142.86.0/24 · http-probing ·
ban — expires in 23h 12m".

Layout:
  - PageHeader
  - Toggle: "active only" vs "include expired" (operator
    forensic view).
  - Table columns:
      * Captured (relative ts, full ts in title)
      * Scope (badge)
      * Value (IP / CIDR / country / AS)
      * Scenario (short form: "http-probing")
      * Type (ban / captcha / throttle — colored badge)
      * Expires (countdown, or "expired Nd ago" for past)

States:
  - AC #15 disabled (LAPI key not configured OR
    observability boot failed) → empty-state panel.
  - Empty list → italic "no decisions in window" line.

The mounting under /security/decisions is intentionally
separate from /security to keep the main dashboard's mixed-
event feed at 20 rows per source while letting the operator
drill into the full 100-row decision history when needed.
Per N spec §5.4 carve-out: per-route drill-down at
/security/[routeId] stays WAF-only (CrowdSec is per-IP, not
per-route).

Step F design tokens only.
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Card from '$lib/components/Card.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import { fetchDecisions } from '$lib/api/security';
	import type { Decision } from '$lib/api/types';
	import { ApiError, isArenetAutoScenario } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';

	let loading = $state(true);
	let loadError = $state<string | null>(null);
	let disabled = $state(false);
	let onlyActive = $state(false);
	let decisions = $state<Decision[]>([]);

	async function load(): Promise<void> {
		loading = true;
		loadError = null;
		try {
			const resp = await fetchDecisions({ limit: 100, onlyActive });
			disabled = resp.disabled === true;
			decisions = resp.events;
		} catch (err) {
			loadError =
				err instanceof ApiError ? err.message : 'failed to load decisions';
			pushToast(loadError, 'danger');
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		void load();
	});

	function toggleActive(next: boolean): void {
		onlyActive = next;
		void load();
	}

	// Scope badge color mapping. Range (community blocklist)
	// gets a slightly different shade from single-IP bans so
	// the operator can scan for "wide" decisions at a glance.
	const SCOPE_COLOR: Record<string, string> = {
		ip: 'var(--status-down)',
		range: 'var(--status-warn)',
		country: 'var(--status-info)',
		as: 'var(--accent-cyan)'
	};
	function scopeColor(scope: string): string {
		return SCOPE_COLOR[scope] ?? 'var(--text-muted)';
	}

	// Decision-type color: ban+captcha (functionally identical
	// in caddy-crowdsec-bouncer v0.12.1 per upstream issue #46)
	// share the down/red palette; throttle gets the amber 429
	// shade to distinguish soft-cap from deny.
	const TYPE_COLOR: Record<string, string> = {
		ban: 'var(--status-down)',
		captcha: 'var(--status-down)',
		throttle: 'var(--status-warn)'
	};
	function typeColor(t: string): string {
		return TYPE_COLOR[t] ?? 'var(--text-muted)';
	}

	function shortScenario(s: string): string {
		if (!s) return 'ban';
		const i = s.lastIndexOf('/');
		return i >= 0 ? s.slice(i + 1) : s;
	}

	// relativeTs: "12s ago" / "3m ago" / HH:MM past one hour.
	// Same shape as MixedEventList — duplicated rather than
	// shared because the two widgets evolve independently.
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

	// Countdown to expires_at. Negative durations format as
	// "expired Nd ago" so the operator forensic view (onlyActive
	// false) is honest about historical rows.
	function formatExpiry(iso: string): string {
		const target = new Date(iso).getTime();
		const now = Date.now();
		const diffSecs = Math.floor((target - now) / 1000);
		if (diffSecs <= 0) {
			const past = Math.abs(diffSecs);
			if (past < 60) return `expired ${past}s ago`;
			if (past < 3600) return `expired ${Math.floor(past / 60)}m ago`;
			if (past < 86400) return `expired ${Math.floor(past / 3600)}h ago`;
			return `expired ${Math.floor(past / 86400)}d ago`;
		}
		if (diffSecs < 60) return `in ${diffSecs}s`;
		if (diffSecs < 3600) {
			return `in ${Math.floor(diffSecs / 60)}m`;
		}
		if (diffSecs < 86400) {
			const h = Math.floor(diffSecs / 3600);
			const m = Math.floor((diffSecs % 3600) / 60);
			return m > 0 ? `in ${h}h ${m}m` : `in ${h}h`;
		}
		return `in ${Math.floor(diffSecs / 86400)}d`;
	}
</script>

<PageHeader title="Decisions CrowdSec" subtitle="LAPI-sourced IP / range / country / AS bans" />

{#if loading}
	<div class="loading-wrap">
		<Spinner />
	</div>
{:else if loadError}
	<Card>
		<div class="error-wrap">{loadError}</div>
	</Card>
{:else if disabled}
	<Card>
		<div class="empty-wrap">
			<h3>CrowdSec mirror non configuré</h3>
			<p>
				Le bouncer CrowdSec côté Caddy + le consommateur StreamBouncer
				côté Arenet partagent la même clé LAPI. Renseignez
				<code>ARENET_CROWDSEC_API_KEY</code> (obtenue via
				<code>cscli bouncers add arenet</code> sur votre instance
				CrowdSec) et redémarrez Arenet pour activer la passerelle de
				réputation.
			</p>
		</div>
	</Card>
{:else}
	<div class="filter-row">
		<div class="active-toggle">
			<button
				type="button"
				class:active={!onlyActive}
				onclick={() => toggleActive(false)}
			>
				Toutes
			</button>
			<button
				type="button"
				class:active={onlyActive}
				onclick={() => toggleActive(true)}
			>
				Actives uniquement
			</button>
		</div>
		<div class="meta">
			{decisions.length}{decisions.length === 100 ? '+' : ''} décision{decisions.length > 1
				? 's'
				: ''}
		</div>
	</div>

	<Card>
		<div class="block">
			{#if decisions.length === 0}
				<div class="empty-inline">
					{onlyActive
						? 'Aucune décision active. Le bouncer ne bloque aucune source actuellement.'
						: 'Aucune décision dans la fenêtre. Le bouncer n’a jamais reçu de décision de LAPI.'}
				</div>
			{:else}
				<table>
					<thead>
						<tr>
							<th>Captured</th>
							<th>Scope</th>
							<th>Value</th>
							<th>Scenario</th>
							<th>Type</th>
							<th>Expires</th>
						</tr>
					</thead>
					<tbody>
						{#each decisions as d (d.uuid)}
							<tr>
								<td class="ts" title={d.ts}>{relativeTs(d.ts)}</td>
								<td>
									<span class="badge" style:background={scopeColor(d.scope)}>
										{d.scope || '—'}
									</span>
								</td>
								<td class="mono">{d.value || '—'}</td>
								<td class="mono">
									{shortScenario(d.scenario)}
									{#if isArenetAutoScenario(d.scenario)}
										<!-- Step P.4: provenance badge for
										     auto-classified decisions
										     (scenario.startsWith("arenet/")). -->
										<span class="badge auto-badge" title="Auto-classified by Arenet (Step P)">
											auto
										</span>
									{/if}
								</td>
								<td>
									<span class="badge" style:background={typeColor(d.type)}>
										{d.type || 'ban'}
									</span>
								</td>
								<td class="ts" title={d.expiresAt}>{formatExpiry(d.expiresAt)}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
		</div>
	</Card>
{/if}

<style>
	.loading-wrap {
		display: flex;
		justify-content: center;
		padding: 2rem;
	}
	.error-wrap {
		padding: 1rem;
		color: var(--status-down);
	}
	.empty-wrap {
		padding: 1.5rem;
		text-align: center;
	}
	.empty-wrap h3 {
		font-size: var(--text-lg);
		margin: 0 0 0.5rem 0;
		color: var(--text-primary);
	}
	.empty-wrap p {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		max-width: 40rem;
		margin: 0 auto;
	}
	.empty-wrap code {
		font-family: var(--font-mono, monospace);
		background: var(--bg-surface);
		padding: 0 0.25rem;
		border-radius: 2px;
		color: var(--text-primary);
	}
	.filter-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		margin: 0 0 1rem 0;
	}
	.active-toggle {
		display: flex;
		gap: 0.25rem;
	}
	.active-toggle button {
		background: var(--bg-surface);
		color: var(--text-secondary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0.25rem 0.75rem;
		border-radius: 4px;
		font-size: var(--text-sm);
		cursor: pointer;
	}
	.active-toggle button.active {
		background: var(--accent-cyan);
		color: var(--text-inverse);
		border-color: var(--accent-cyan);
	}
	.meta {
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	.block {
		padding: 1rem;
	}
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
	.mono {
		font-family: var(--font-mono, monospace);
	}
	.badge {
		display: inline-block;
		padding: 0.1rem 0.45rem;
		border-radius: 3px;
		color: var(--text-on-color, #ffffff);
		font-size: var(--text-xs, 11px);
		font-weight: 600;
		letter-spacing: 0.04em;
		white-space: nowrap;
	}
	/* Step P.4: provenance badge — accent-cyan so an
	   operator scanning the decisions table can pick out
	   the Arenet-originated rows at a glance. */
	.auto-badge {
		background: var(--accent-cyan);
		margin-left: 0.4rem;
		font-size: var(--text-xs, 10px);
		text-transform: uppercase;
	}
	.empty-inline {
		padding: 1rem;
		text-align: center;
		font-style: italic;
		color: var(--text-muted);
		font-size: var(--text-sm, 13px);
	}
</style>
