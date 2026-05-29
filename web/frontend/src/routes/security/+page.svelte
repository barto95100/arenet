<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

<!--
Step M.3 — /security dashboard.

Layout (top → bottom):
  - PageHeader
  - 5 stat cards: WAF blocks/min, top-attacked-route
    blocks/min, % requests blocked, total 4xx/min for
    context, # active WAF-enabled routes
  - Category distribution strip (SQLi / XSS / RCE / LFI /
    PROTOCOL / OTHER)
  - 3 independent timeline charts on route=all (AC #3): WAF
    blocks (the headline), 4xx for context, req for context
  - Top-5 table filtered to WAF-enabled routes (D6=B)
  - Recent WAF events widget (limit=20, no filter)

States:
  - AC #13 disabled (boot-failed observability) → single
    panel, no charts, no error toast.
  - AC #7 zero routes → panel pointing to /routes.
  - AC #7 zero WAF-enabled routes → panel asking the
    operator to enable WAF on a route.
  - AC #7 zero traffic → cards at zero, charts show in-SVG
    "no data" label, category strip shows "no WAF events".

Step F design tokens only.
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import StatCard from '$lib/components/StatCard.svelte';
	import Card from '$lib/components/Card.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import TimelineChart from '$lib/components/TimelineChart.svelte';
	import CategoryDistribution from '$lib/components/CategoryDistribution.svelte';
	import WafEventList from '$lib/components/WafEventList.svelte';
	import { fetchSummary, fetchTimeseries } from '$lib/api/metrics';
	import { fetchEvents } from '$lib/api/security';
	import { listRoutes } from '$lib/api/client';
	import type {
		MetricWindow,
		Route,
		SummaryResponse,
		TimeseriesPoint,
		TimeseriesResponse,
		WafEvent
	} from '$lib/api/types';
	import { ApiError } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';

	let window = $state<MetricWindow>('24h');
	let loading = $state(true);
	let loadError = $state<string | null>(null);

	let summary = $state<SummaryResponse | null>(null);
	let allRoutes = $state<Route[]>([]);
	let recentEvents = $state<WafEvent[]>([]);

	let reqSeries = $state<TimeseriesPoint[]>([]);
	let fourxxSeries = $state<TimeseriesPoint[]>([]);
	let wafSeries = $state<TimeseriesPoint[]>([]);

	const disabled = $derived(summary?.disabled === true);
	const noRoutes = $derived(!disabled && allRoutes.length === 0);
	const wafEnabledRoutes = $derived(
		allRoutes.filter((r) => r.wafMode === 'block' || r.wafMode === 'detect')
	);
	const noWafEnabledRoutes = $derived(
		!disabled && !noRoutes && wafEnabledRoutes.length === 0
	);

	// Map route_id → host so the events list can show friendly
	// hostnames instead of UUIDs.
	const hostByRouteId = $derived.by(() => {
		const out: Record<string, string> = {};
		for (const r of allRoutes) out[r.id] = r.host;
		return out;
	});

	// Set of WAF-enabled route IDs for the D6=B top-5 filter.
	const wafEnabledIds = $derived.by(() => {
		const out = new Set<string>();
		for (const r of wafEnabledRoutes) out.add(r.id);
		return out;
	});

	// Top-5 filtered to WAF-enabled routes per spec D6=B. A
	// WAF-off route at the top of the table with 0 blocks
	// would be confusing on a SECURITY dashboard.
	const wafTopRoutes = $derived(
		(summary?.topRoutes ?? []).filter((r) => wafEnabledIds.has(r.routeId))
	);

	// Top-attacked-route headline stat. Reads from the
	// server-side TopAttackedRoute field (M.2 amendment),
	// computed across ALL routes — not constrained to the
	// traffic-ranked top-5. Critical for the spec §1.3 D8
	// promise: a targeted attack on a low-traffic admin/
	// auth surface stays visible in this card even when the
	// route is far below the traffic top-5.
	const topAttackedRouteBlocks = $derived(summary?.topAttackedRoute?.wafBlockedPerMin ?? 0);
	const topAttackedRouteHost = $derived(summary?.topAttackedRoute?.host ?? null);

	// Percentage of requests blocked over the just-closed
	// minute. Useful pulse — "is the proxy blocking a lot
	// right now?". Capped at 100 % to handle the rare
	// transient where the per-minute counters disagree
	// across the (Reqs, WAF) atomic-swap boundary.
	const pctBlocked = $derived.by(() => {
		const s = summary;
		if (!s || s.totalReqPerMin === 0) return 0;
		const raw = (s.totalWafBlockedPerMin / s.totalReqPerMin) * 100;
		return Math.min(100, raw);
	});

	async function load(): Promise<void> {
		loading = true;
		loadError = null;
		try {
			const [routes, sum] = await Promise.all([listRoutes(), fetchSummary()]);
			allRoutes = routes;
			summary = sum;

			if (sum.disabled === true) {
				reqSeries = [];
				fourxxSeries = [];
				wafSeries = [];
				recentEvents = [];
				return;
			}

			// 3 independent timeline series + the recent events
			// widget, all fetched in parallel. Charts use
			// route=all per Spec-1 §10.1 (global view; consistent
			// with /observability semantics).
			const [req, fourxx, waf, events] = await Promise.all([
				fetchTimeseries('all', 'req_per_sec', window),
				fetchTimeseries('all', 'four_xx_rate', window),
				fetchTimeseries('all', 'waf_block_rate', window),
				fetchEvents({ limit: 20 })
			]);
			reqSeries = trimTrailing(req);
			fourxxSeries = trimTrailing(fourxx);
			wafSeries = trimTrailing(waf);
			recentEvents = events.events;
		} catch (err) {
			loadError = err instanceof ApiError ? err.message : 'failed to load security data';
			pushToast(loadError, 'danger');
		} finally {
			loading = false;
		}
	}

	// trimTrailing drops the in-progress current minute (Step
	// L backlog #L.2-2) so the chart's right edge doesn't show
	// a fake zero cliff.
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

	const fmtCount = (v: number) => Math.round(v).toString();
	const fmtPct = (n: number) => `${n.toFixed(1)}%`;
</script>

<PageHeader title="Security" subtitle="WAF block events" />

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
			<h3>Métriques de sécurité indisponibles</h3>
			<p>
				Le sous-système d'observabilité n'a pas pu démarrer, donc
				l'historique des événements WAF est manquant. Le proxy continue
				de bloquer les requêtes malveillantes selon les règles
				configurées ; seul le tableau de bord est temporairement vide.
			</p>
		</div>
	</Card>
{:else if noRoutes}
	<Card>
		<div class="empty-wrap">
			<h3>Aucune route configurée</h3>
			<p>
				Créez une route depuis la page <a href="/routes">Routes</a> et
				activez le WAF (mode <code>detect</code> ou <code>block</code>)
				pour commencer à collecter des événements.
			</p>
		</div>
	</Card>
{:else if noWafEnabledRoutes}
	<Card>
		<div class="empty-wrap">
			<h3>Aucune route avec WAF activé</h3>
			<p>
				Vous avez des routes configurées, mais aucune n'a le WAF
				activé. Modifiez une route depuis la page <a href="/routes"
					>Routes</a
				>
				et passez <code>wafMode</code> à <code>detect</code> ou
				<code>block</code>.
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

	<!-- 5 stat cards -->
	<div class="stat-grid">
		<StatCard label="WAF blocks / min" value={summary?.totalWafBlockedPerMin ?? 0} />
		<StatCard
			label={topAttackedRouteHost ? `${topAttackedRouteHost} (top attaqué)` : 'Top route blocks / min'}
			value={topAttackedRouteBlocks}
		/>
		<StatCard label="% requests blocked" value={fmtPct(pctBlocked)} />
		<StatCard label="4xx / min (context)" value={summary?.totalFourXxPerMin ?? 0} />
		<StatCard label="Routes avec WAF" value={wafEnabledRoutes.length} />
	</div>

	<!-- Category distribution strip -->
	<Card>
		<div class="block">
			<h3>Catégories OWASP — dernière minute</h3>
			<CategoryDistribution counts={summary?.wafBlocksByCategory ?? {}} />
		</div>
	</Card>

	<!-- 3 independent timeline charts (route=all). AC #3:
	     each chart is a SEPARATE visual block — never
	     stacked or overlaid. -->
	<div class="chart-grid">
		<Card>
			<div class="chart-block">
				<h3>WAF blocks / minute</h3>
				<TimelineChart
					points={wafSeries}
					color="var(--status-down)"
					formatValue={fmtCount}
					label="System-wide WAF blocks per minute"
				/>
			</div>
		</Card>
		<Card>
			<div class="chart-block">
				<h3>4xx / minute (context)</h3>
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
				<h3>Requêtes / minute (context)</h3>
				<TimelineChart
					points={reqSeries}
					color="var(--accent-cyan)"
					formatValue={fmtCount}
					label="System-wide requests per minute"
				/>
			</div>
		</Card>
	</div>

	<!-- Top-5 by traffic, filtered to WAF-enabled routes (D6=B). -->
	<Card>
		<div class="block">
			<h3>Top 5 routes WAF-enabled par trafic (dernière minute)</h3>
			{#if wafTopRoutes.length === 0}
				<div class="empty-inline">
					Aucun trafic sur les routes WAF-enabled dans la dernière
					minute.
				</div>
			{:else}
				<table>
					<thead>
						<tr>
							<th>Host</th>
							<th class="num">Req</th>
							<th class="num warn">4xx</th>
							<th class="num down">WAF blocks</th>
						</tr>
					</thead>
					<tbody>
						{#each wafTopRoutes as route (route.routeId)}
							<tr>
								<td>
									<a
										href="/security/{route.routeId}"
										class="host-link">{route.host}</a
									>
								</td>
								<td class="num">{route.reqsPerMin}</td>
								<td class="num warn">{route.fourxxPerMin}</td>
								<td class="num down">{route.wafBlockedPerMin}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
		</div>
	</Card>

	<!-- Recent events feed -->
	<Card>
		<div class="block">
			<h3>Événements WAF récents</h3>
			<WafEventList events={recentEvents} {hostByRouteId} />
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
		max-width: 36rem;
		margin: 0 auto;
	}
	.empty-wrap code {
		font-family: var(--font-mono, monospace);
		background: var(--bg-surface);
		padding: 0 0.25rem;
		border-radius: 2px;
		color: var(--text-primary);
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
	.block {
		padding: 1rem;
	}
	.block h3 {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
		margin: 0 0 0.75rem 0;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.chart-grid {
		display: grid;
		grid-template-columns: 1fr;
		gap: 0.75rem;
		margin: 1rem 0 1rem 0;
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
	.host-link {
		color: var(--text-primary);
		text-decoration: none;
		border-bottom: 1px dashed var(--text-muted);
	}
	.host-link:hover {
		color: var(--accent-cyan);
		border-bottom-color: var(--accent-cyan);
	}
	.empty-inline {
		padding: 0.75rem;
		font-style: italic;
		color: var(--text-muted);
		font-size: var(--text-sm);
	}
</style>
