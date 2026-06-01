<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R.4.1 — Dashboard. Replaces the R.2 stub with the mock's
  layout at docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html
  :749-948.

  Sources for each block (real backend, AC #1 anti-regression):
  - 4 KPI tiles: GET /api/v1/metrics/summary (Step L) — req/s,
    p95, 5xx rate, WAF blocks per hour.
  - Traffic chart: GET /api/v1/metrics/timeseries with switchable
    metric (req_per_sec / p95_latency_ms / five_xx_rate). The
    existing TimelineChart component handles the rendering; the
    new wrapper card mirrors the mock's segmented switcher.
  - WAF events recent: GET /api/v1/security/events (Step M).
  - Top routes: summary.topRoutes (Step L).
  - Upstreams flat list: GET /api/v1/routes flattened per upstream
    URL. The mock's "Services amont" card aggregates by service
    name with per-service health; we ship the per-upstream-URL
    variant in v1.4 because per-service-name aggregation +
    health-rollup is not a backend feature today (tracked as a
    R.5 backlog candidate).
  - Recent events tail card: derived from the same WAF events
    stream, monospace-styled per mock; "ouvrir Logs →" link to
    /logs (still a stub in v1.4 but routable).

  Empty + disabled states preserved from Step L:
  - disabled (summary.disabled=true): single panel, no charts.
  - noRoutes (0 routes): clean message + link to /routes.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { fetchSummary, fetchTimeseries } from '$lib/api/metrics';
	import { fetchEvents as fetchWafEvents } from '$lib/api/security';
	import { listRoutes } from '$lib/api/client';
	import { ApiError } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import Spinner from '$lib/components/Spinner.svelte';
	import TimelineChart from '$lib/components/TimelineChart.svelte';
	import type {
		SummaryResponse,
		TimeseriesPoint,
		WafEvent,
		Route,
		MetricName,
		MetricWindow
	} from '$lib/api/types';

	let loading = $state(true);
	let loadError = $state<string | null>(null);

	let summary = $state<SummaryResponse | null>(null);
	let recentEvents = $state<WafEvent[]>([]);
	let routes = $state<Route[]>([]);
	let chartMetric = $state<MetricName>('req_per_sec');
	let chartPoints = $state<TimeseriesPoint[]>([]);
	let chartLoading = $state(false);
	const window: MetricWindow = '24h';

	const disabled = $derived(summary?.disabled === true);
	const noRoutes = $derived(!disabled && routes.length === 0);

	// 4 KPI derivations from the summary response.
	const kpiReqPerSec = $derived(
		Math.round(((summary?.totalReqPerMin ?? 0) / 60) * 10) / 10
	);
	const kpiP95 = $derived(summary?.globalP95LatencyMs ?? null);
	const kpi5xxPct = $derived(
		(() => {
			const req = summary?.totalReqPerMin ?? 0;
			const fivexx = summary?.totalFiveXxPerMin ?? 0;
			if (req <= 0) return 0;
			return Math.round((fivexx / req) * 10000) / 100;
		})()
	);
	const kpiWafPerHour = $derived(
		Math.round((summary?.totalWafBlockedPerMin ?? 0) * 60)
	);

	// Distinct upstream URLs across all routes — the v1.4 stand-in
	// for the mock's per-service-name aggregation.
	const upstreams = $derived(
		(() => {
			const seen = new Set<string>();
			const result: Array<{ url: string; routes: string[] }> = [];
			for (const r of routes) {
				for (const u of r.upstreams ?? []) {
					if (seen.has(u.url)) {
						const existing = result.find((x) => x.url === u.url);
						existing?.routes.push(r.host);
					} else {
						seen.add(u.url);
						result.push({ url: u.url, routes: [r.host] });
					}
				}
			}
			return result.slice(0, 8);
		})()
	);

	async function load(): Promise<void> {
		loading = true;
		loadError = null;
		try {
			const [rs, sum, evs] = await Promise.all([
				listRoutes(),
				fetchSummary(),
				fetchWafEvents({ limit: 5 }).catch(() => ({ events: [] }))
			]);
			routes = rs;
			summary = sum;
			recentEvents = evs.events ?? [];
			if (!sum.disabled) {
				void loadChart();
			}
		} catch (err) {
			loadError = err instanceof ApiError ? err.message : 'failed to load dashboard';
			pushToast(loadError, 'danger');
		} finally {
			loading = false;
		}
	}

	async function loadChart(): Promise<void> {
		chartLoading = true;
		try {
			const resp = await fetchTimeseries('all', chartMetric, window);
			// Drop the in-progress last point (#L.2-2 trailing bucket).
			chartPoints = resp.points.length > 0 ? resp.points.slice(0, -1) : [];
		} catch (err) {
			pushToast(
				err instanceof ApiError ? err.message : 'failed to load timeseries',
				'danger'
			);
		} finally {
			chartLoading = false;
		}
	}

	function switchMetric(m: MetricName): void {
		if (m === chartMetric) return;
		chartMetric = m;
		void loadChart();
	}

	function fmtP95(v: number | null): string {
		return v === null ? '—' : `${Math.round(v)}`;
	}

	function fmtRelative(iso: string): string {
		const ts = new Date(iso).getTime();
		const diffSec = Math.floor((Date.now() - ts) / 1000);
		if (diffSec < 60) return `il y a ${diffSec}s`;
		if (diffSec < 3600) return `il y a ${Math.floor(diffSec / 60)} min`;
		if (diffSec < 86400) {
			const h = Math.floor(diffSec / 3600);
			const m = Math.floor((diffSec % 3600) / 60);
			return `il y a ${h}h ${m.toString().padStart(2, '0')}`;
		}
		return `il y a ${Math.floor(diffSec / 86400)}j`;
	}

	function chartColor(m: MetricName): string {
		switch (m) {
			case 'req_per_sec':
				return 'var(--accent)';
			case 'p95_latency_ms':
				return 'var(--info)';
			case 'five_xx_rate':
				return 'var(--bad)';
			default:
				return 'var(--accent)';
		}
	}

	onMount(() => {
		void load();
	});
</script>

<svelte:head>
	<title>Dashboard · Arenet</title>
</svelte:head>

{#if loading}
	<div class="loading-wrap"><Spinner /></div>
{:else if loadError}
	<div class="card error">{loadError}</div>
{:else if disabled}
	<div class="screen-head">
		<div>
			<div class="eyebrow">Aperçu</div>
			<h1>État de la passerelle</h1>
		</div>
	</div>
	<div class="card empty">
		<h3>Métriques indisponibles</h3>
		<p>
			Le sous-système d'observabilité n'a pas pu démarrer. Le proxy continue de
			fonctionner ; seule l'historique des métriques est manquant. Consultez les
			logs Arenet pour la cause exacte.
		</p>
	</div>
{:else if noRoutes}
	<div class="screen-head">
		<div>
			<div class="eyebrow">Aperçu</div>
			<h1>État de la passerelle</h1>
		</div>
	</div>
	<div class="card empty">
		<h3>Aucune route configurée</h3>
		<p>
			Créez une route depuis la page <a href="/routes">Routes</a> pour commencer
			à collecter des métriques.
		</p>
	</div>
{:else}
	<div class="screen-head">
		<div>
			<div class="eyebrow">Vue d'ensemble</div>
			<h1>État de la passerelle</h1>
			<div class="sub">
				Trafic temps réel à travers vos {routes.length} routes, événements WAF récents,
				et services en amont. Fenêtre {window}.
			</div>
		</div>
	</div>

	<!-- KPIs -->
	<div class="kpis">
		<div class="kpi">
			<div class="kpi-label">Requêtes / s</div>
			<div class="kpi-val">{kpiReqPerSec}<span class="unit">req/s</span></div>
			<div class="kpi-foot">
				{summary?.totalReqPerMin ?? 0} req/min · {summary?.activeRouteCount ?? 0} routes actives
			</div>
		</div>
		<div class="kpi">
			<div class="kpi-label">Latence p95</div>
			<div class="kpi-val">{fmtP95(kpiP95)}<span class="unit">ms</span></div>
			<div class="kpi-foot">
				{kpiP95 === null ? 'aucune donnée dans la fenêtre' : 'global, fenêtre 24h'}
			</div>
		</div>
		<div class="kpi">
			<div class="kpi-label">Taux d'erreur 5xx</div>
			<div class="kpi-val">{kpi5xxPct}<span class="unit">%</span></div>
			<div class="kpi-foot">
				{summary?.totalFiveXxPerMin ?? 0} 5xx/min · {summary?.totalFourXxPerMin ?? 0} 4xx/min
			</div>
		</div>
		<div class="kpi">
			<div class="kpi-label">Blocages WAF / h</div>
			<div class="kpi-val">{kpiWafPerHour}</div>
			<div class="kpi-foot">
				{summary?.attackerIpsUnique ?? 0} IP uniques · {summary?.totalThrottlePerMin ?? 0} throttle/min
			</div>
		</div>
	</div>

	<!-- Main row: traffic chart + WAF events recent -->
	<div class="two-col main-row">
		<div class="card">
			<div class="card-h">
				<h3>Trafic — fenêtre {window}</h3>
				<div class="seg">
					<button
						class:on={chartMetric === 'req_per_sec'}
						onclick={() => switchMetric('req_per_sec')}>Req/s</button
					>
					<button
						class:on={chartMetric === 'p95_latency_ms'}
						onclick={() => switchMetric('p95_latency_ms')}>Latence</button
					>
					<button
						class:on={chartMetric === 'five_xx_rate'}
						onclick={() => switchMetric('five_xx_rate')}>Erreurs</button
					>
				</div>
			</div>
			<div class="chart-wrap">
				{#if chartLoading}
					<div class="chart-loading"><Spinner size="sm" /></div>
				{:else}
					<TimelineChart
						points={chartPoints}
						color={chartColor(chartMetric)}
						label={`Series for ${chartMetric}`}
					/>
				{/if}
			</div>
		</div>

		<div class="card">
			<div class="card-h">
				<h3>Événements WAF récents</h3>
				<div class="meta">5 derniers</div>
			</div>
			<div class="stack">
				{#each recentEvents as ev (ev.id)}
					<div class="event">
						<span class="pill bad">block</span>
						<div class="what">
							<b>{ev.category} · {ev.ruleId}</b>
							<span>{ev.requestMethod} {ev.requestPath} — depuis {ev.srcIp}</span>
						</div>
						<div class="when">{fmtRelative(ev.ts)}</div>
					</div>
				{:else}
					<div class="empty-row">Aucun événement WAF récent dans la fenêtre.</div>
				{/each}
			</div>
		</div>
	</div>

	<!-- Bottom row: top routes + upstreams -->
	<div class="two-col bottom-row">
		<div class="card">
			<div class="card-h">
				<h3>Top routes</h3>
				<div class="meta">trié par RPS</div>
			</div>
			<table>
				<thead>
					<tr>
						<th>Route</th>
						<th class="right">Req/min</th>
						<th class="right">4xx/min</th>
						<th class="right">5xx/min</th>
						<th class="right">WAF blocks</th>
					</tr>
				</thead>
				<tbody>
					{#each summary?.topRoutes ?? [] as r (r.routeId)}
						<tr>
							<td class="mono">{r.host}</td>
							<td class="mono right">{r.reqsPerMin}</td>
							<td class="mono right warn-text">{r.fourxxPerMin}</td>
							<td class="mono right bad-text">{r.fivexxPerMin}</td>
							<td class="mono right">{r.wafBlockedPerMin}</td>
						</tr>
					{:else}
						<tr><td colspan="5" class="empty-row">Aucune donnée dans la fenêtre.</td></tr>
					{/each}
				</tbody>
			</table>
		</div>

		<div class="card">
			<div class="card-h">
				<h3>Services amont</h3>
				<div class="meta">{upstreams.length} distincts</div>
			</div>
			<div class="stack">
				{#each upstreams as u (u.url)}
					<div class="upstream-row">
						<span class="mono">{u.url}</span>
						<span class="mono dim">{u.routes.length} route{u.routes.length > 1 ? 's' : ''}</span>
					</div>
				{:else}
					<div class="empty-row">Aucun upstream configuré.</div>
				{/each}
			</div>
		</div>
	</div>

	<!-- Live tail preview -->
	<div class="card tail-card">
		<div class="card-h">
			<h3>Événements WAF — flux récent</h3>
			<div class="meta">
				<a href="/logs" class="meta-link">Ouvrir Logs →</a>
			</div>
		</div>
		<div class="logs">
			{#each recentEvents as ev (`tail-${ev.id}`)}
				<div class="log-row">
					<span class="log-time">{new Date(ev.ts).toISOString().substring(11, 19)}</span>
					<span class="log-lvl block">BLOCK</span>
					<span class="mono">403</span>
					<span class="log-msg">
						<span class="k">{ev.requestMethod}</span>
						{ev.requestPath}
						<span class="k">·</span>
						WAF {ev.ruleId}
						<span class="k">·</span>
						{ev.srcIp}
					</span>
				</div>
			{:else}
				<div class="empty-row">Aucun événement récent.</div>
			{/each}
		</div>
	</div>
{/if}

<style>
	.loading-wrap { display: flex; justify-content: center; padding: 48px; }
	.card.error { padding: 16px; color: var(--bad); border-radius: var(--radius); background: var(--surface); border: 1px solid var(--border); }

	.screen-head {
		display: flex; align-items: flex-start; justify-content: space-between;
		margin-bottom: 18px;
	}
	.eyebrow { color: var(--fg-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 6px; font-family: var(--font-mono); }
	h1 { color: var(--fg); font-size: 22px; font-weight: 600; margin: 0 0 6px; letter-spacing: -0.01em; }
	.sub { color: var(--fg-muted); font-size: 13px; max-width: 640px; line-height: 1.5; }

	.card {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 14px 16px;
	}
	.card.empty {
		padding: 32px;
		text-align: center;
	}
	.card.empty h3 { color: var(--fg); font-size: 16px; margin: 0 0 8px; font-weight: 500; }
	.card.empty p { color: var(--fg-muted); font-size: 13px; max-width: 480px; margin: 0 auto; line-height: 1.6; }
	.card.empty a { color: var(--accent); }
	.card-h {
		display: flex; align-items: center; gap: 12px;
		margin-bottom: 12px;
	}
	.card-h h3 { color: var(--fg); font-size: 13.5px; font-weight: 500; margin: 0; }
	.card-h .meta { margin-left: auto; color: var(--fg-dim); font-size: 11.5px; font-family: var(--font-mono); }
	.meta-link { color: var(--accent); text-decoration: none; }
	.meta-link:hover { text-decoration: underline; }

	.kpis {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 12px;
		margin-bottom: 18px;
	}
	.kpi {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 14px 16px;
	}
	.kpi-label { color: var(--fg-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; font-family: var(--font-mono); margin-bottom: 6px; }
	.kpi-val { color: var(--fg); font-size: 28px; font-weight: 500; letter-spacing: -0.02em; }
	.kpi-val .unit { color: var(--fg-dim); font-size: 13px; margin-left: 4px; font-weight: 400; }
	.kpi-foot { color: var(--fg-muted); font-size: 11.5px; margin-top: 8px; font-family: var(--font-mono); }

	.two-col {
		display: grid;
		gap: 14px;
		margin-bottom: 18px;
	}
	.main-row { grid-template-columns: 2fr 1fr; }
	.bottom-row { grid-template-columns: 1.4fr 1fr; }

	.seg {
		margin-left: auto;
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
		padding: 4px 10px;
		border-radius: 999px;
		background: transparent;
		border: none;
		color: var(--fg-dim);
		cursor: pointer;
		font-weight: 500;
		transition: background 0.12s, color 0.12s;
	}
	.seg button:hover { color: var(--fg); }
	.seg button.on { background: var(--surface-hi); color: var(--fg); box-shadow: inset 0 0 0 1px var(--border-hi); }

	.chart-wrap { min-height: 160px; }
	.chart-loading { display: flex; justify-content: center; padding: 48px; }

	.stack { display: flex; flex-direction: column; gap: 10px; }
	.event {
		display: flex; align-items: center; gap: 10px;
		padding: 8px 0;
		border-bottom: 1px solid var(--border);
	}
	.event:last-child { border-bottom: none; }
	.event .what { flex: 1; min-width: 0; font-size: 12.5px; line-height: 1.4; }
	.event .what b { display: block; color: var(--fg); font-weight: 500; }
	.event .what span { color: var(--fg-muted); font-family: var(--font-mono); font-size: 11.5px; }
	.event .when { color: var(--fg-dim); font-size: 11px; font-family: var(--font-mono); text-align: right; flex: none; }

	.pill {
		display: inline-flex; align-items: center; padding: 2px 8px;
		border-radius: 999px;
		font-family: var(--font-mono);
		font-size: 10px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		flex: none;
	}
	.pill.bad { background: color-mix(in oklch, var(--bad) 18%, transparent); color: var(--bad); }

	table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
	th, td { padding: 7px 8px; text-align: left; }
	th { color: var(--fg-muted); font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }
	td { color: var(--fg); border-bottom: 1px solid var(--border); }
	tbody tr:last-child td { border-bottom: none; }
	.mono { font-family: var(--font-mono); font-size: 12px; }
	.right { text-align: right; }
	.dim { color: var(--fg-dim); }
	.warn-text { color: var(--warn); }
	.bad-text { color: var(--bad); }
	.empty-row { color: var(--fg-muted); font-size: 12px; padding: 12px 0; text-align: center; font-style: italic; }

	.upstream-row {
		display: flex; align-items: center; justify-content: space-between;
		padding: 8px 0;
		border-bottom: 1px solid var(--border);
		font-size: 12.5px;
	}
	.upstream-row:last-child { border-bottom: none; }

	.tail-card { margin-bottom: 18px; }
	.logs { font-family: var(--font-mono); font-size: 11.5px; }
	.log-row {
		display: grid;
		grid-template-columns: 80px 50px 40px 1fr;
		gap: 10px;
		padding: 4px 0;
		color: var(--fg-muted);
		align-items: baseline;
	}
	.log-time { color: var(--fg-dim); font-size: 11px; }
	.log-lvl {
		font-size: 10px;
		padding: 1px 6px;
		border-radius: 4px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		text-align: center;
	}
	.log-lvl.block { background: color-mix(in oklch, var(--bad) 18%, transparent); color: var(--bad); }
	.log-msg { color: var(--fg); }
	.log-msg .k { color: var(--fg-dim); }
</style>
