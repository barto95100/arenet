<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R.4.2.c — Logs page. Replaces the R.2 stub.

  IMPORTANT honesty note: Arenet does NOT currently expose a live
  access-log stream. The mock at
  docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html:2352-2400
  shows a live tail of all traffic (info / ok / warn / err / block);
  the closest we can do today is unify the three event streams the
  backend DOES expose:
    - WAF events (Step M) — blocked requests with rule ID.
    - Throttle events (Step Q) — rate-limited auth attempts.
    - Auth-failure events (Step Q) — login_failure / oidc_*.
  Each row is mapped to a unified shape sorted ts-desc.

  Filters:
    - Search input (substring on path / IP / username).
    - Level segmented control (Tous / Block / Warn / Info).
    - Refresh interval (auto-poll every 10s; "Pause" toggles).

  Out of scope (matches spec §6 Logs audit):
    - True access-log stream (all 2xx / 3xx / 4xx / 5xx).
    - GeoIP country annotation per row (no MaxMind dep yet).
    - Export action.

  Reuses R.4.1 primitives: .card, .seg, .pill, .stack, .log-row,
  .mono. The page-level .log-table grid extends the dashboard's
  .log-row pattern with a 6-column header row.
-->
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import {
		fetchEvents,
		fetchThrottleEvents,
		fetchAuthFailures
	} from '$lib/api/security';
	import { ApiError } from '$lib/api/types';
	import type {
		WafEvent,
		ThrottleEvent,
		AuthFailureRecentEvent
	} from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';

	type LevelTag = 'block' | 'warn' | 'info';

	interface UnifiedRow {
		key: string;
		ts: string;
		level: LevelTag;
		code: string;
		source: string; // 'waf' / 'throttle' / 'auth'
		method: string;
		path: string;
		detail: string;
		srcIp: string;
	}

	const REFRESH_MS = 10_000;

	let loading = $state(true);
	let loadError = $state<string | null>(null);
	let rows = $state<UnifiedRow[]>([]);
	let search = $state('');
	let levelFilter = $state<'all' | LevelTag>('all');
	let paused = $state(false);
	let pollId: ReturnType<typeof setInterval> | null = null;

	const filteredRows = $derived(
		rows.filter((r) => {
			if (levelFilter !== 'all' && r.level !== levelFilter) return false;
			if (search.trim()) {
				const q = search.trim().toLowerCase();
				const hay = `${r.path} ${r.srcIp} ${r.detail}`.toLowerCase();
				if (!hay.includes(q)) return false;
			}
			return true;
		})
	);

	function mapWaf(e: WafEvent): UnifiedRow {
		return {
			key: `waf-${e.id}`,
			ts: e.ts,
			level: 'block',
			code: '403',
			source: 'waf',
			method: e.requestMethod,
			path: e.requestPath,
			detail: `WAF rule ${e.ruleId} · ${e.category}`,
			srcIp: e.srcIp
		};
	}
	function mapThrottle(e: ThrottleEvent): UnifiedRow {
		return {
			key: `throttle-${e.id}`,
			ts: e.ts,
			level: 'warn',
			code: '429',
			source: 'throttle',
			method: 'POST',
			path: '/auth/login',
			detail: `Rate-limit tier ${e.tier} · bloqué ${e.blockDurationSeconds}s · user "${e.attemptedUsername || '?'}"`,
			srcIp: e.srcIp
		};
	}
	function mapAuth(e: AuthFailureRecentEvent): UnifiedRow {
		const isOidc = e.action.startsWith('oidc_');
		return {
			key: `auth-${e.ts}-${e.srcIp}-${e.username}`,
			ts: e.ts,
			level: 'warn',
			code: '401',
			source: 'auth',
			method: isOidc ? 'OIDC' : 'POST',
			path: isOidc ? '/auth/oidc/callback' : '/auth/login',
			detail: `${e.action} · user "${e.username || '?'}"${e.message ? ' · ' + e.message : ''}`,
			srcIp: e.srcIp || '?'
		};
	}

	async function load(): Promise<void> {
		loadError = null;
		try {
			const [waf, throttle, auth] = await Promise.allSettled([
				fetchEvents({ limit: 100 }),
				fetchThrottleEvents({ limit: 100 }),
				fetchAuthFailures('24h')
			]);

			const merged: UnifiedRow[] = [];
			if (waf.status === 'fulfilled') {
				for (const e of waf.value.events ?? []) merged.push(mapWaf(e));
			}
			if (throttle.status === 'fulfilled') {
				for (const e of throttle.value.events ?? []) merged.push(mapThrottle(e));
			}
			if (auth.status === 'fulfilled') {
				for (const e of auth.value.recent ?? []) merged.push(mapAuth(e));
			}

			merged.sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0));
			rows = merged.slice(0, 200);
		} catch (err) {
			loadError = err instanceof ApiError ? err.message : 'failed to load events';
			pushToast(loadError, 'danger');
		} finally {
			loading = false;
		}
	}

	function startPolling(): void {
		if (pollId !== null) return;
		pollId = setInterval(() => {
			if (paused) return;
			if (typeof document !== 'undefined' && document.visibilityState !== 'visible') return;
			void load();
		}, REFRESH_MS);
	}
	function stopPolling(): void {
		if (pollId !== null) {
			clearInterval(pollId);
			pollId = null;
		}
	}

	function togglePause(): void {
		paused = !paused;
	}

	function fmtTime(iso: string): string {
		try {
			const d = new Date(iso);
			const hh = d.getHours().toString().padStart(2, '0');
			const mm = d.getMinutes().toString().padStart(2, '0');
			const ss = d.getSeconds().toString().padStart(2, '0');
			const ms = d.getMilliseconds().toString().padStart(3, '0');
			return `${hh}:${mm}:${ss}.${ms}`;
		} catch {
			return iso;
		}
	}

	onMount(() => {
		void load();
		startPolling();
	});
	onDestroy(() => {
		stopPolling();
	});
</script>

<svelte:head>
	<title>Logs · Arenet</title>
</svelte:head>

<PageHeader
	eyebrow="Trafic · Logs"
	title="Security events"
	subtitle="Real-time stream of WAF, throttling and authentication-failure events. Full access-log tail (2xx/3xx) is deferred to a future step — see backlog."
>
	{#snippet actions()}
		<button class="tb-btn" onclick={togglePause}>
			{paused ? '▶ Resume' : '⏸ Pause'}
		</button>
		<button class="tb-btn" disabled title="Coming soon">Export</button>
	{/snippet}
</PageHeader>

<div class="card filters">
	<div class="filters-row">
		<div class="search-inline">
			<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
				<circle cx="7" cy="7" r="5" />
				<path d="M11 11l3 3" />
			</svg>
			<input
				type="search"
				bind:value={search}
				placeholder="Filter by path, IP, detail…"
				aria-label="Filter events"
			/>
		</div>
		<div class="seg" role="group" aria-label="Filter by level">
			<button class:on={levelFilter === 'all'} onclick={() => (levelFilter = 'all')}>All</button>
			<button class:on={levelFilter === 'block'} onclick={() => (levelFilter = 'block')}>Block</button>
			<button class:on={levelFilter === 'warn'} onclick={() => (levelFilter = 'warn')}>Warn</button>
			<button class:on={levelFilter === 'info'} onclick={() => (levelFilter = 'info')}>Info</button>
		</div>
		<span class="status-pill" class:paused>
			<span class="dot"></span>
			{paused ? 'pause' : 'live'}
		</span>
	</div>
</div>

<div class="card log-card">
	<div class="log-header">
		<span>Timestamp</span>
		<span>Level</span>
		<span>Code</span>
		<span>Request</span>
		<span class="right">Source IP</span>
	</div>
	{#if loading && rows.length === 0}
		<div class="loading-wrap"><Spinner /></div>
	{:else if loadError && rows.length === 0}
		<div class="empty-row">{loadError}</div>
	{:else if filteredRows.length === 0}
		<div class="empty-row">
			{rows.length === 0
				? 'No events in the current window.'
				: 'No events match the filters.'}
		</div>
	{:else}
		<div class="logs">
			{#each filteredRows as r (r.key)}
				<div class="log-row level-{r.level}">
					<span class="log-time">{fmtTime(r.ts)}</span>
					<span class="log-lvl {r.level}">{r.level.toUpperCase()}</span>
					<span class="mono">{r.code}</span>
					<span class="log-msg">
						<span class="k">{r.method}</span>
						{r.path}
						<span class="k">·</span>
						{r.detail}
					</span>
					<span class="right mono dim">{r.srcIp}</span>
				</div>
			{/each}
		</div>
	{/if}
</div>

<style>
	.card {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
	}
	.card.filters {
		padding: 14px 16px;
		margin-bottom: 14px;
	}
	.filters-row {
		display: flex;
		gap: 10px;
		flex-wrap: wrap;
		align-items: center;
	}
	.search-inline {
		flex: 1;
		min-width: 240px;
		display: flex;
		align-items: center;
		gap: 8px;
		background: var(--bg);
		border: 1px solid var(--border);
		padding: 5px 10px;
		border-radius: var(--radius);
		color: var(--fg-muted);
		font-size: 12.5px;
	}
	.search-inline input {
		background: none;
		border: none;
		outline: none;
		flex: 1;
		color: var(--fg);
		font-size: 13px;
	}
	.seg {
		display: inline-flex;
		gap: 2px;
		padding: 2px;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: 999px;
		font-family: var(--font-mono);
		font-size: 10.5px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.seg button {
		padding: 4px 12px;
		border-radius: 999px;
		background: transparent;
		border: none;
		color: var(--fg-dim);
		cursor: pointer;
		font-weight: 500;
	}
	.seg button:hover { color: var(--fg); }
	.seg button.on {
		background: var(--surface-hi);
		color: var(--fg);
		box-shadow: inset 0 0 0 1px var(--border-hi);
	}
	.status-pill {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		font-family: var(--font-mono);
		font-size: 11px;
		color: var(--ok);
		padding: 4px 10px;
		border-radius: 999px;
		background: color-mix(in oklch, var(--ok) 14%, transparent);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.status-pill .dot {
		width: 6px;
		height: 6px;
		border-radius: 50%;
		background: currentColor;
		box-shadow: 0 0 6px currentColor;
	}
	.status-pill.paused {
		color: var(--fg-muted);
		background: var(--surface-2);
	}
	.status-pill.paused .dot { box-shadow: none; }

	.tb-btn {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 5px 10px;
		border-radius: var(--radius-sm);
		font-size: 12.5px;
		color: var(--fg-muted);
		border: 1px solid var(--border);
		background: var(--surface);
		cursor: pointer;
	}
	.tb-btn:hover:not(:disabled) {
		color: var(--fg);
		background: var(--surface-2);
	}
	.tb-btn:disabled {
		cursor: not-allowed;
		opacity: 0.5;
	}

	.log-card { padding: 0; overflow: hidden; }

	.log-header {
		display: grid;
		grid-template-columns: 120px 78px 60px 1fr 140px;
		gap: 10px;
		padding: 10px 16px;
		border-bottom: 1px solid var(--border);
		font-family: var(--font-mono);
		font-size: 10.5px;
		letter-spacing: 0.08em;
		text-transform: uppercase;
		color: var(--fg-dim);
		background: oklch(17% 0.006 250);
	}
	.log-header .right { text-align: right; }

	.logs {
		font-family: var(--font-mono);
		font-size: 11.5px;
		max-height: 540px;
		overflow-y: auto;
	}
	.log-row {
		display: grid;
		grid-template-columns: 120px 78px 60px 1fr 140px;
		gap: 10px;
		padding: 6px 16px;
		align-items: baseline;
		color: var(--fg);
		border-bottom: 1px solid var(--border);
	}
	.log-row:last-child { border-bottom: none; }
	.log-row.level-block { background: color-mix(in oklch, var(--bad) 8%, transparent); }
	.log-row.level-warn { background: color-mix(in oklch, var(--warn) 6%, transparent); }

	.log-time { color: var(--fg-dim); font-size: 11px; }
	.log-lvl {
		font-size: 10px;
		padding: 1px 6px;
		border-radius: 4px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		text-align: center;
		justify-self: start;
	}
	.log-lvl.block { background: color-mix(in oklch, var(--bad) 18%, transparent); color: var(--bad); }
	.log-lvl.warn { background: color-mix(in oklch, var(--warn) 18%, transparent); color: var(--warn); }
	.log-lvl.info { background: color-mix(in oklch, var(--info) 18%, transparent); color: var(--info); }
	.log-msg { color: var(--fg); min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.log-msg .k { color: var(--fg-dim); }
	.right { text-align: right; }
	.mono { font-family: var(--font-mono); }
	.dim { color: var(--fg-dim); }

	.loading-wrap { display: flex; justify-content: center; padding: 48px; }
	.empty-row { color: var(--fg-muted); font-size: 12.5px; padding: 32px; text-align: center; font-style: italic; }
</style>
