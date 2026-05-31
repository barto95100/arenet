<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

<!--
Step Q.4 — Mixed events feed for the /security dashboard.

Renders an interleaved table of WAF + THROTTLE + AUTH events
sorted ts-descending. Each row carries a `kind` badge
identifying the source bucket so an operator under
credential-stuffing can see Tier-1 / Tier-2 / login-failure
rows alongside the WAF blocks.

Per-row columns (uniform across the three kinds — the union
of fields fits cleanly into one table; per-kind cells render
"—" when the field isn't applicable):

  - ts      (relative: "12s ago" / "3m ago" / absolute past 1h)
  - kind    (coloured badge: WAF / THROTTLE / AUTH)
  - detail  (kind-specific second badge — OWASP category for
             WAF, Tier 1/2 for THROTTLE, audit action for
             AUTH)
  - target  (WAF: routeId → host; THROTTLE/AUTH: attempted
             username — both are the "who/what was the
             attacker after")
  - srcIp   (mono; consistent across all kinds)
  - payload (WAF only: payload sample; AUTH: message; THROTTLE:
             blocked-for duration)

Empty state mirror of WafEventList — italic "no events"
panel-sized line.

Color discipline (Step F design tokens):
  - WAF.SQLi/RCE     → status-down (red family)
  - WAF.XSS/LFI      → status-warn (amber family)
  - WAF.PROTOCOL     → status-info (blue family)
  - WAF.OTHER        → text-muted
  - THROTTLE         → status-warn (consistent with rate-limit
                       severity in the audit log)
  - AUTH             → status-info (lighter signal than a real
                       block — the rate-limiter will surface
                       blocks separately)
-->

<script lang="ts">
	import type {
		AuthFailureRecentEvent,
		Decision,
		OwaspCategory,
		ThrottleEvent,
		WafEvent
	} from '$lib/api/types';

	interface Props {
		wafEvents: WafEvent[];
		throttleEvents: ThrottleEvent[];
		authFailures: AuthFailureRecentEvent[];
		// Step N.4 — 4th source: CrowdSec LAPI decisions
		// (ban / captcha / throttle). Decisions don't carry a
		// routeId — the bouncer matches at the IP layer
		// before per-route dispatch. Optional + default []
		// so older callers that don't yet pass this prop
		// (i.e. the per-route drill-down which intentionally
		// stays WAF-only per N spec §5.4 + Q D5) still
		// compile.
		decisions?: Decision[];
		/**
		 * Optional map of routeId → host string so the WAF
		 * row's target cell can show the friendly host instead
		 * of a bare UUID prefix. Throttle / auth / crowdsec
		 * events don't carry a routeId.
		 */
		hostByRouteId?: Record<string, string>;
	}
	let {
		wafEvents,
		throttleEvents,
		authFailures,
		decisions = [],
		hostByRouteId = {}
	}: Props = $props();

	type Kind = 'WAF' | 'THROTTLE' | 'AUTH' | 'CROWDSEC';

	// Unified row shape for the table. Each event source is
	// projected into this shape once, then merged. `key` is
	// stable per row (used by Svelte's keyed each).
	interface Row {
		key: string;
		tsIso: string;
		tsEpochMs: number;
		kind: Kind;
		// Kind-specific secondary label — category for WAF,
		// tier-N for THROTTLE, action name for AUTH.
		detail: string;
		detailColor: string;
		target: string;
		srcIp: string;
		// Payload / message / duration depending on kind.
		// Renders "—" when empty.
		extra: string;
	}

	const KIND_COLOR: Record<Kind, string> = {
		WAF: 'var(--status-down)',
		THROTTLE: 'var(--status-warn)',
		AUTH: 'var(--status-info)',
		// Step N.4 — CROWDSEC reuses the WAF down/red palette
		// because the operator semantic is the same ("this IP
		// is currently blocked"). The scenario badge cell
		// disambiguates the type at a glance: "SQLi" comes
		// from CrowdSec's hub scenarios (e.g.
		// "crowdsecurity/http-probing"), not OWASP CRS.
		CROWDSEC: 'var(--status-down)'
	};

	const CATEGORY_COLOR: Record<OwaspCategory, string> = {
		SQLi: 'var(--status-down)',
		XSS: 'var(--status-warn)',
		RCE: 'var(--status-down)',
		LFI: 'var(--status-warn)',
		PROTOCOL: 'var(--status-info)',
		OTHER: 'var(--text-muted)'
	};

	function hostFor(routeId: string): string {
		return hostByRouteId[routeId] ?? routeId.slice(0, 8) + '…';
	}

	function payloadPreview(s: string): string {
		if (!s) return '';
		if (s.length <= 60) return s;
		return s.slice(0, 60) + '…';
	}

	function formatBlockDuration(seconds: number): string {
		if (seconds >= 3600) {
			const h = Math.round(seconds / 3600);
			return `blocked ${h}h`;
		}
		if (seconds >= 60) {
			const m = Math.round(seconds / 60);
			return `blocked ${m}m`;
		}
		return `blocked ${seconds}s`;
	}

	// Step N.4 — shorten a CrowdSec scenario name for the
	// detail badge cell. Hub scenarios are namespaced as
	// "crowdsecurity/http-probing"; the operator-facing
	// short form is the suffix after the slash. Custom
	// scenarios without the namespace render verbatim.
	function shortScenario(s: string): string {
		if (!s) return 'ban';
		const i = s.lastIndexOf('/');
		return i >= 0 ? s.slice(i + 1) : s;
	}

	// formatDecisionTarget builds the "scope · value" string
	// for the target cell. CrowdSec decisions don't have a
	// route or username — the natural target is the scope+
	// value pair: "ip · 1.2.3.4", "range · 185.142.86.0/24",
	// "country · RU", "as · AS12345". Empty scope falls
	// back to value alone.
	function formatDecisionTarget(scope: string, value: string): string {
		if (!value) return '—';
		if (!scope) return value;
		return `${scope} · ${value}`;
	}

	const rows = $derived.by<Row[]>(() => {
		const out: Row[] = [];
		for (const e of wafEvents) {
			out.push({
				key: `waf-${e.id}`,
				tsIso: e.ts,
				tsEpochMs: new Date(e.ts).getTime(),
				kind: 'WAF',
				detail: e.category,
				detailColor: CATEGORY_COLOR[e.category],
				target: hostFor(e.routeId),
				srcIp: e.srcIp,
				extra: payloadPreview(e.payloadSample)
			});
		}
		for (const e of throttleEvents) {
			out.push({
				key: `thr-${e.id}`,
				tsIso: e.ts,
				tsEpochMs: new Date(e.ts).getTime(),
				kind: 'THROTTLE',
				detail: `Tier ${e.tier}`,
				detailColor: 'var(--status-warn)',
				target: e.attemptedUsername || '—',
				srcIp: e.srcIp,
				extra: formatBlockDuration(e.blockDurationSeconds)
			});
		}
		for (const e of authFailures) {
			// Audit events don't carry a stable numeric id at
			// the JSON layer — synthesise one from the ts +
			// action + srcIp triple. Collisions are
			// practically impossible at sub-second cadence
			// (auth failures are bounded by the rate limiter).
			const key = `auth-${e.ts}-${e.action}-${e.srcIp}`;
			out.push({
				key,
				tsIso: e.ts,
				tsEpochMs: new Date(e.ts).getTime(),
				kind: 'AUTH',
				detail: e.action,
				detailColor: 'var(--status-info)',
				target: e.username || '—',
				srcIp: e.srcIp || '—',
				extra: e.message || ''
			});
		}
		// Step N.4 — 4th source: CrowdSec LAPI decisions. The
		// natural row identity is the LAPI UUID (stable across
		// our restarts and the bouncer's cache rebuilds). The
		// target cell shows scope+value (e.g. "range ·
		// 185.142.86.0/24") rather than a single field
		// because the scope is operator-semantic context the
		// dashboard owes the reader.
		for (const e of decisions) {
			// Step P.4: prefix the detail badge with "auto:"
			// when the scenario was emitted by Arenet's
			// auto-classify loop (D3.3.A: scenario.startsWith
			// "arenet/"). Matches the spec mock UI promise of
			// "auto:waf-sqli" / "auto:auth-burst" rows. Keeps
			// the existing color (status-down — decisions are
			// blocks at the proxy edge regardless of who
			// pushed them).
			const isAuto = e.scenario.startsWith('arenet/');
			const detail = isAuto
				? `auto:${shortScenario(e.scenario)}`
				: shortScenario(e.scenario);
			out.push({
				key: `cs-${e.uuid}`,
				tsIso: e.ts,
				tsEpochMs: new Date(e.ts).getTime(),
				kind: 'CROWDSEC',
				detail,
				detailColor: 'var(--status-down)',
				target: formatDecisionTarget(e.scope, e.value),
				srcIp: e.value || '—',
				extra: e.type || 'ban'
			});
		}
		// Merge sort by ts descending. The four sources are
		// each individually ordered by ts desc (server-side
		// guarantee on WAF/throttle/decisions; Q.2 guarantee
		// on audit), so a plain stable sort is correct and
		// bounded by O((W+T+A+D) log (...)) — trivially
		// small at the dashboard's 20-per-source cap.
		out.sort((a, b) => b.tsEpochMs - a.tsEpochMs);
		return out;
	});

	// Relative time formatting: "Ns ago" up to a minute, "Nm
	// ago" up to an hour, then HH:MM. Same shape as
	// WafEventList — duplicated rather than extracted to a
	// shared helper because the two widgets evolve
	// independently and the function is 10 lines.
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
</script>

{#if rows.length === 0}
	<div class="empty">no security events in window</div>
{:else}
	<table>
		<thead>
			<tr>
				<th>Time</th>
				<th>Kind</th>
				<th>Detail</th>
				<th>Target</th>
				<th>Source IP</th>
				<th>Info</th>
			</tr>
		</thead>
		<tbody>
			{#each rows as r (r.key)}
				<tr>
					<td class="ts" title={r.tsIso}>{relativeTs(r.tsIso)}</td>
					<td>
						<span class="badge" style:background={KIND_COLOR[r.kind]}>
							{r.kind}
						</span>
					</td>
					<td>
						<span class="badge" style:background={r.detailColor}>
							{r.detail}
						</span>
					</td>
					<td class="target">{r.target}</td>
					<td class="mono">{r.srcIp}</td>
					<td class="payload mono" title={r.extra || '(empty)'}>
						{r.extra || '—'}
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
	.target {
		color: var(--text-primary);
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
		white-space: nowrap;
	}
	.empty {
		padding: 1rem;
		text-align: center;
		font-style: italic;
		color: var(--text-muted);
		font-size: var(--text-sm, 13px);
	}
</style>
