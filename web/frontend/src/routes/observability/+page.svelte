<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

<!--
Step L L.3 — Observability dashboard.

Layout (top → bottom):
  - PageHeader
  - 5 stat cards (req/min, 4xx/min, 5xx/min, p95, # active routes)
  - 3 timeline charts: req, 4xx, 5xx (each independent — AC #3)
  - Top-5-by-traffic table

State handling beyond the happy path:
  - AC #13 disabled (store nil at boot): "métriques indisponibles"
    panel. No charts, no error toast.
  - AC #7 empty (zero routes / zero traffic): clean message, no
    buggy-looking blank chart.

Trailing in-progress bucket (backlog #L.2-2): the last point of
each timeseries lags up to one minute (the current minute isn't
flushed yet). We DROP that last point client-side so the chart
doesn't render a fake "traffic dropped to zero" cliff on every
refresh. The Step E live tick stays real-time for the topology
page; this dashboard is historical-only.

Design tokens: Step F HEX palette (cyan/warn/down/info), NOT the
OKLCH from the auth-page mock. The mock migration is its own
later step.
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import StatCard from '$lib/components/StatCard.svelte';
	import Card from '$lib/components/Card.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import TimelineChart from '$lib/components/TimelineChart.svelte';
	import { fetchSummary, fetchTimeseries } from '$lib/api/metrics';
	import type {
		MetricWindow,
		SummaryResponse,
		TimeseriesPoint,
		TimeseriesResponse
	} from '$lib/api/types';
	import { listRoutes } from '$lib/api/client';
	import { ApiError } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';

	// --- View state -----------------------------------------------------------

	let window = $state<MetricWindow>('24h');
	let loading = $state(true);
	let loadError = $state<string | null>(null);

	let summary = $state<SummaryResponse | null>(null);
	let totalRouteCount = $state(0);
	let reqSeries = $state<TimeseriesPoint[]>([]);
	let fourxxSeries = $state<TimeseriesPoint[]>([]);
	let fivexxSeries = $state<TimeseriesPoint[]>([]);

	// disabled = true iff the observability subsystem failed at
	// boot (AC #13). When set, every endpoint returns
	// disabled=true; we surface a single panel and skip the
	// charts entirely.
	const disabled = $derived(summary?.disabled === true);

	// "No routes configured" empty state (AC #7). The "no
	// traffic in window" case is delegated to the chart, which
	// renders an in-SVG "no data in this window" empty-state
	// label — the stat cards naturally show zeros, no panel
	// substitution needed.
	const noRoutes = $derived(!disabled && totalRouteCount === 0);

	// --- Data loading ---------------------------------------------------------

	async function load(): Promise<void> {
		loading = true;
		loadError = null;
		try {
			// Discover routes first so we can pick a representative
			// route for the historical timeseries (Step L.3 ships
			// the global aggregated view; per-route drill-down
			// comes in L.4). The summary endpoint surfaces top-5
			// for us — we use its leader for the charts.
			const [routes, sum] = await Promise.all([listRoutes(), fetchSummary()]);
			totalRouteCount = routes.length;
			summary = sum;

			if (sum.disabled === true) {
				reqSeries = [];
				fourxxSeries = [];
				fivexxSeries = [];
				return;
			}
			// Charts use the GLOBAL aggregated timeseries
			// (Spec-1 §10.1, route=all) — they're the visual
			// counterpart of the stat cards. Showing a
			// leader-only chart while the cards report global
			// numbers was the L.3 review issue: a system-wide
			// 5xx spike on a quiet route would be invisible,
			// and "is the proxy being scanned?" needs the
			// 4xx-rate-across-all-routes signal.
			//
			// Fetched in parallel, independent series — AC #3
			// anti-regression. 4xx is its own series, never
			// folded into req or 5xx.
			const [req, fourxx, fivexx] = await Promise.all([
				fetchTimeseries('all', 'req_per_sec', window),
				fetchTimeseries('all', 'four_xx_rate', window),
				fetchTimeseries('all', 'five_xx_rate', window)
			]);
			reqSeries = trimTrailing(req);
			fourxxSeries = trimTrailing(fourxx);
			fivexxSeries = trimTrailing(fivexx);
		} catch (err) {
			loadError = err instanceof ApiError ? err.message : 'failed to load metrics';
			pushToast(loadError, 'danger');
		} finally {
			loading = false;
		}
	}

	// trimTrailing drops the last point. The current bucket is
	// in-progress (lags up to one bucket size) and would render
	// as a phantom near-zero data point — see backlog
	// #L.2-2. If the response has no points (disabled / no
	// data), return as-is.
	function trimTrailing(resp: TimeseriesResponse): TimeseriesPoint[] {
		if (resp.points.length === 0) return [];
		return resp.points.slice(0, -1);
	}

	function switchWindow(w: MetricWindow): void {
		if (w === window) return;
		window = w;
		void load();
	}

	onMount(() => {
		void load();
	});

	// --- Formatters -----------------------------------------------------------

	const fmtCount = (v: number) => Math.round(v).toString();
	const fmtMs = (v: number) => `${Math.round(v)} ms`;

	function p95Label(v: number | null): string {
		return v === null ? '—' : `${Math.round(v)} ms`;
	}
</script>

<PageHeader title="Observability" subtitle="Per-route metrics history" />

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
			<h3>Métriques indisponibles</h3>
			<p>
				Le sous-système d'observabilité n'a pas pu démarrer. Le proxy continue
				de fonctionner ; seule l'historique des métriques est manquant.
				Consultez les logs Arenet pour la cause exacte.
			</p>
		</div>
	</Card>
{:else if noRoutes}
	<Card>
		<div class="empty-wrap">
			<h3>Aucune route configurée</h3>
			<p>
				Créez une route depuis la page <a href="/routes">Routes</a> pour
				commencer à collecter des métriques.
			</p>
		</div>
	</Card>
{:else}
	<!-- Window toggle -->
	<div class="window-toggle">
		<button
			type="button"
			class:active={window === '24h'}
			onclick={() => switchWindow('24h')}>24h</button
		>
		<button
			type="button"
			class:active={window === '30d'}
			onclick={() => switchWindow('30d')}>30j</button
		>
	</div>

	<!-- Stat cards -->
	<div class="stat-grid">
		<StatCard label="Req / min" value={summary?.totalReqPerMin ?? 0} />
		<StatCard label="4xx / min" value={summary?.totalFourXxPerMin ?? 0} />
		<StatCard label="5xx / min" value={summary?.totalFiveXxPerMin ?? 0} />
		<StatCard
			label="p95 global"
			value={p95Label(summary?.globalP95LatencyMs ?? null)}
		/>
		<StatCard label="Routes actives" value={summary?.activeRouteCount ?? 0} />
	</div>

	<!-- Three independent charts on the GLOBAL aggregated
	     timeseries (Spec-1 §10.1, route=all). Each one is a
	     SEPARATE visual block — never stacked or overlaid
	     (AC #3). Empty-state ("no data in this window") is
	     rendered by the chart itself when the series is
	     all-zero or all-null. -->
	<div class="chart-grid">
		<Card>
			<div class="chart-block">
				<h3>Requêtes / minute</h3>
				<TimelineChart
					points={reqSeries}
					color="var(--accent-cyan)"
					formatValue={fmtCount}
					label="System-wide requests per minute"
				/>
			</div>
		</Card>
		<Card>
			<div class="chart-block">
				<h3>4xx / minute</h3>
				<TimelineChart
					points={fourxxSeries}
					color="var(--status-warn)"
					formatValue={fmtCount}
					label="System-wide 4xx responses per minute"
				/>
			</div>
		</Card>
		<Card>
			<div class="chart-block">
				<h3>5xx / minute</h3>
				<TimelineChart
					points={fivexxSeries}
					color="var(--status-down)"
					formatValue={fmtCount}
					label="System-wide 5xx responses per minute"
				/>
			</div>
		</Card>
	</div>

	<!-- Top-5 by traffic -->
	<Card>
		<div class="top-block">
			<h3>Top 5 par trafic (dernière minute)</h3>
				<table>
					<thead>
						<tr>
							<th>Host</th>
							<th class="num">Req</th>
							<th class="num">4xx</th>
							<th class="num">5xx</th>
						</tr>
					</thead>
					<tbody>
						{#each summary?.topRoutes ?? [] as route (route.routeId)}
							<tr>
								<td>{route.host}</td>
								<td class="num">{route.reqsPerMin}</td>
								<td class="num warn">{route.fourxxPerMin}</td>
								<td class="num down">{route.fivexxPerMin}</td>
							</tr>
						{/each}
				</tbody>
			</table>
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
		max-width: 32rem;
		margin: 0 auto;
	}
	.window-toggle {
		display: flex;
		gap: 0.25rem;
		margin: 0 0 1rem 0;
	}
	.window-toggle button {
		background: var(--bg-surface);
		color: var(--text-secondary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0.25rem 0.75rem;
		border-radius: 4px;
		font-size: var(--text-sm);
		cursor: pointer;
	}
	.window-toggle button.active {
		background: var(--accent-cyan);
		color: var(--text-inverse);
		border-color: var(--accent-cyan);
	}
	.stat-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
		gap: 0.75rem;
		margin: 0 0 1rem 0;
	}
	.chart-grid {
		display: grid;
		grid-template-columns: 1fr;
		gap: 0.75rem;
		margin: 0 0 1rem 0;
	}
	@media (min-width: 1200px) {
		.chart-grid {
			grid-template-columns: repeat(3, 1fr);
		}
	}
	.chart-block {
		padding: 1rem;
	}
	.chart-block h3 {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
		margin: 0 0 0.75rem 0;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.top-block {
		padding: 1rem;
	}
	.top-block h3 {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
		margin: 0 0 0.75rem 0;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}
	th,
	td {
		padding: 0.5rem 0.75rem;
		text-align: left;
		border-bottom: 1px solid var(--border-subtle, var(--bg-hover));
	}
	th {
		color: var(--text-secondary);
		font-weight: 500;
		font-size: var(--text-xs);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	td {
		color: var(--text-primary);
	}
	.num {
		text-align: right;
		font-variant-numeric: tabular-nums;
	}
	.warn {
		color: var(--status-warn);
	}
	.down {
		color: var(--status-down);
	}
</style>
