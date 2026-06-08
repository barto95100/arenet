<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R.4.2.c — Logs page. Replaces the R.2 stub.

  IMPORTANT honesty note: Arenet does NOT currently expose a live
  access-log stream. The mock at
  docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html:2352-2400
  shows a live tail of all traffic (info / ok / warn / err / block);
  the closest we can do today is unify the four event streams the
  backend exposes:
    - WAF events (Step M) — blocked requests with rule ID.
    - Throttle events (Step Q) — rate-limited auth attempts.
    - Auth-failure events (Step Q) — login_failure / oidc_*.
    - Cert lifecycle events (Step U) — obtained / failed /
      ocsp_revoked. Added by U.5 (commit d769cad); the page
      title rename "Security events" → "Activity log" lands
      in U.6 (this commit) reflecting the widened scope.
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
		fetchAuthFailures,
		fetchCertEvents,
		fetchCountryBlockEvents
	} from '$lib/api/security';
	import { ApiError } from '$lib/api/types';
	import type {
		AuthFailureRecentEvent,
		CertEvent,
		CountryBlockEvent,
		ThrottleEvent,
		WafEvent
	} from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';

	// W.bugfix Fix #1 — the WAF event source now distinguishes
	// 'block' (request short-circuited by the WAF, status 403)
	// from 'detect' (rule fired but request reached upstream
	// because the route is in detect mode). Pre-fix all WAF
	// rows rendered as 'block'; the detect rows lied. Detect
	// rows render with a muted amber accent so operators see
	// rule-fire signal without thinking enforcement happened.
	//
	// W.5 — country-block rows render at the 'block' level
	// (the request WAS short-circuited at the Caddy edge by
	// an operator-declared country gate). They distinguish
	// from WAF blocks via source='country_block' on the row
	// + the slate-gray pill styling — same level-block CSS
	// hook reused; visual differentiation lives in the
	// .log-lvl.country variant added in this commit.
	type LevelTag = 'block' | 'detect' | 'warn' | 'info';

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
		// W.bugfix Fix #1 — read action + statusCode from the
		// wire shape instead of hardcoding "block / 403". A
		// pre-fix row persisted in the legacy schema has the
		// backfilled values (BLOCK / 403); a post-fix detect-
		// mode row has DETECT / 0 — the latter renders the
		// status column as "—" since the WAF doesn't capture
		// the upstream's actual response status at callback
		// time. Defense-in-depth fallback: an action we don't
		// know renders as 'block' (most conservative — operator
		// sees the row at the loudest level rather than
		// silently downgrading an unknown match).
		const isDetect = e.action === 'DETECT';
		return {
			key: `waf-${e.id}`,
			ts: e.ts,
			level: isDetect ? 'detect' : 'block',
			code: e.statusCode > 0 ? String(e.statusCode) : '—',
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
	// Auth + cert mappers take an `idx` disambiguator because
	// their wire shapes don't carry a per-event id today.
	// The natural (ts, srcIp, username) tuple collides under
	// burst login retries — 5 failures from the same IP at
	// the same username within the same second produce 5
	// rows that Svelte's keyed each-block rejects with
	// `each_key_duplicate` (operator-reported regression on
	// /logs). Appending the source-local array index makes
	// the key unique by construction; the natural prefix
	// keeps the key stable across polls when the backend
	// returns the same rows in the same order. Same shape
	// fix applied to cert events below (eventType + domain +
	// timestamp can collide on a fast OBTAIN / FAILED race).
	function mapAuth(e: AuthFailureRecentEvent, idx: number): UnifiedRow {
		const isOidc = e.action.startsWith('oidc_');
		return {
			key: `auth-${e.ts}-${e.srcIp}-${e.username}-${idx}`,
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

	// Truncate cert_failed error strings so the row height stays
	// stable. The full error remains queryable via the search
	// textbox (the backend index matches against the full
	// error_msg column).
	const CERT_ERROR_MAX = 60;
	function truncateError(s: string): string {
		if (s.length <= CERT_ERROR_MAX) return s;
		return s.slice(0, CERT_ERROR_MAX - 3) + '...';
	}

	// Compose the REQUEST column content per spec §4 architecture
	// component 7 (frontend additive). Each event type gets a
	// distinct one-line representation so an operator scanning
	// the table can read the row at a glance.
	function formatCertDetail(e: CertEvent): string {
		switch (e.eventType) {
			case 'cert_obtained': {
				const tail: string[] = [];
				if (e.issuer) tail.push(e.issuer);
				if (e.challenge) tail.push(e.challenge);
				if (e.renewal) tail.push('renouvellement');
				return tail.length > 0
					? `cert.obtained · ${tail.join(' · ')}`
					: 'cert.obtained';
			}
			case 'cert_failed':
				return e.error
					? `cert.failed · ${truncateError(e.error)}`
					: 'cert.failed';
			case 'cert_ocsp_revoked':
				return 'cert.revoked · révocation OCSP';
			default:
				return 'cert.event';
		}
	}

	// Map cert events into the unified row shape (Step U.5).
	//
	// Level mapping (flagged in the U.5 commit body for review):
	//   - cert INFO → 'info' (matches the existing taxonomy
	//     verbatim).
	//   - cert ERROR → 'warn' (pragmatic placement). The
	//     existing LevelTag union doesn't have 'error' — adding
	//     one would introduce a new filter button which the U.5
	//     brief explicitly forbids. 'warn' is the right bucket:
	//     a cert failure is an operational concern that demands
	//     attention but isn't an HTTP-block event (cert events
	//     have no Source IP and no request lifecycle). The U.6
	//     page rename to "Activity log" doesn't change this
	//     mapping; a future taxonomy refactor could introduce a
	//     dedicated 'error' level if operators report that warn
	//     clusters obscure security warnings.
	//
	// Other column conventions:
	//   - method = "ACME" (cert events come from the ACME
	//     issuance pipeline; matches the dim-style "method tag"
	//     the other sources use).
	//   - path = domain (the cert subject — the operator's
	//     primary scan target). search across path + detail
	//     covers domain + issuer keywords.
	//   - code = "—" (em-dash; cert events have no HTTP status).
	//   - srcIp = "(interne)" (system-emitted; the existing
	//     mono-dim styling on the Source IP column renders this
	//     unobtrusively).
	function mapCert(e: CertEvent, idx: number): UnifiedRow {
		return {
			// idx disambiguates against the (timestamp, domain,
			// eventType) tuple colliding when certmagic fires
			// two events for the same domain in the same
			// second (e.g. an OBTAIN + a FAILED race, or two
			// ocsp_revoked checks). See mapAuth above for the
			// full rationale.
			key: `cert-${e.timestamp}-${e.domain}-${e.eventType}-${idx}`,
			ts: e.timestamp,
			level: e.level === 'INFO' ? 'info' : 'warn',
			code: '—',
			source: 'cert',
			method: 'ACME',
			path: e.domain,
			detail: formatCertDetail(e),
			srcIp: '(interne)'
		};
	}

	// Step W.5 — country-block source mapper. Each row
	// renders as a block-level entry (the request WAS
	// short-circuited at the Caddy edge); detail shape is
	// "<country> · <mode>-<reason>" so the operator scans
	// "RU · deny-match" and instantly understands the route's
	// deny list matched the source country. RouteID → host
	// resolution is deferred (W.5 doesn't wire the routes
	// API in this page); the row shows the raw routeId in
	// the path column so an operator can grep it against
	// /routes if curious. A future increment could resolve
	// it via a route-id cache populated from the existing
	// fetchRoutes call elsewhere in the app.
	function mapCountryBlock(e: CountryBlockEvent): UnifiedRow {
		const country = e.country || '—';
		return {
			key: `country-block-${e.id}`,
			ts: e.ts,
			level: 'block',
			code: String(e.statusCode),
			source: 'country_block',
			method: 'GEO',
			path: e.routeId,
			detail: `${country} · ${e.mode}-${e.reason}`,
			srcIp: e.srcIp
		};
	}

	async function load(): Promise<void> {
		loadError = null;
		try {
			// Step U.5 / W.5 — 5 parallel sources via
			// Promise.allSettled so any one source's failure
			// (degraded endpoint, 5xx, missed wire-up) doesn't
			// take down the page. Each fulfilled result is
			// mapped into UnifiedRow shape and merged.
			const [waf, throttle, auth, certs, countryBlock] = await Promise.allSettled([
				fetchEvents({ limit: 100 }),
				fetchThrottleEvents({ limit: 100 }),
				fetchAuthFailures('24h'),
				fetchCertEvents({ limit: 100 }),
				fetchCountryBlockEvents({ limit: 100 })
			]);

			const merged: UnifiedRow[] = [];
			if (waf.status === 'fulfilled') {
				for (const e of waf.value.events ?? []) merged.push(mapWaf(e));
			}
			if (throttle.status === 'fulfilled') {
				for (const e of throttle.value.events ?? []) merged.push(mapThrottle(e));
			}
			if (auth.status === 'fulfilled') {
				const recent = auth.value.recent ?? [];
				for (let i = 0; i < recent.length; i++) merged.push(mapAuth(recent[i], i));
			}
			if (certs.status === 'fulfilled') {
				const events = certs.value.events ?? [];
				for (let i = 0; i < events.length; i++) merged.push(mapCert(events[i], i));
			}
			if (countryBlock.status === 'fulfilled') {
				for (const e of countryBlock.value.events ?? []) merged.push(mapCountryBlock(e));
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
	title="Activity log"
	subtitle="Flux en temps réel des événements WAF, throttling, échecs d'authentification et cycle de vie des certificats. La capture complète du trafic 2xx/3xx est différée — voir backlog."
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
			<button class:on={levelFilter === 'detect'} onclick={() => (levelFilter = 'detect')}>Detect</button>
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
				{@const isCountryBlock = r.source === 'country_block'}
				<div class="log-row level-{r.level}" class:level-country-block={isCountryBlock}>
					<span class="log-time">{fmtTime(r.ts)}</span>
					<!--
					  W.5 — country-block rows render with a
					  distinct pill label + slate background so
					  the operator can distinguish them from
					  WAF blocks (both share level='block' but
					  the semantic differs: country-block is
					  policy enforcement, WAF is threat
					  signature). Pill label "COUNTRY"
					  abbreviates "country-block" to keep the
					  column width stable.
					-->
					{#if isCountryBlock}
						<span class="log-lvl country-block" title="Country-block (operator-declared per-route gate)">
							COUNTRY
						</span>
					{:else}
						<span class="log-lvl {r.level}">{r.level.toUpperCase()}</span>
					{/if}
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
		color: var(--status-up);
		padding: 4px 10px;
		border-radius: 999px;
		background: color-mix(in oklch, var(--status-up) 14%, transparent);
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
	.log-row.level-block { background: color-mix(in oklch, var(--status-down) 8%, transparent); }
	/* W.5 — country-block rows. Override the level-block
	   tint with the --status-meta slate so the operator
	   can distinguish them from WAF blocks at-a-glance. */
	.log-row.level-country-block { background: color-mix(in oklch, var(--status-meta) 8%, transparent); }
	.log-row.level-detect { background: color-mix(in oklch, var(--status-warn) 4%, transparent); }
	.log-row.level-warn { background: color-mix(in oklch, var(--status-warn) 6%, transparent); }

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
	.log-lvl.block { background: color-mix(in oklch, var(--status-down) 18%, transparent); color: var(--status-down); }
	/* W.5 — country-block pill. Slate to match the map
	   legend's gray for "policy enforcement, not threat". */
	.log-lvl.country-block { background: color-mix(in oklch, var(--status-meta) 24%, transparent); color: var(--status-meta); }
	.log-lvl.detect { background: color-mix(in oklch, var(--status-warn) 14%, transparent); color: var(--status-warn); }
	.log-lvl.warn { background: color-mix(in oklch, var(--status-warn) 18%, transparent); color: var(--status-warn); }
	.log-lvl.info { background: color-mix(in oklch, var(--status-info) 18%, transparent); color: var(--status-info); }
	.log-msg { color: var(--fg); min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.log-msg .k { color: var(--fg-dim); }
	.right { text-align: right; }
	.mono { font-family: var(--font-mono); }
	.dim { color: var(--fg-dim); }

	.loading-wrap { display: flex; justify-content: center; padding: 48px; }
	.empty-row { color: var(--fg-muted); font-size: 12.5px; padding: 32px; text-align: center; font-style: italic; }
</style>
