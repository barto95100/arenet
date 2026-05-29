<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

<!--
Step Q.4 — /security dashboard.

Extends the M.3 layout with the Step Q rate-limit and audit
auth-failure signals. The per-route drill-down at
/security/[routeId] STAYS M.4-WAF-only (per spec D5
carve-out: throttle + auth are per-IP, not per-route).

Layout (top → bottom):
  - PageHeader
  - 8 stat cards in two rows on wide screens:
    Row 1 (M):  WAF blocks/min, top-attacked route, %req
                blocked, 4xx/min, WAF-enabled routes
    Row 2 (Q):  THROTTLE/min, AUTH-FAIL/min, ATTACKER IPs
                unique
  - Category distribution strip (WAF only — throttle / auth
    don't have an OWASP taxonomy)
  - 5 timeline charts on route=all (3 M + 2 Q): WAF blocks,
    THROTTLE/min (Q), AUTH-FAIL/min (Q), 4xx for context,
    req for context
  - Top-5 table filtered to WAF-enabled routes (D6=B,
    unchanged from M)
  - Mixed events widget (WAF + THROTTLE + AUTH interleaved
    by ts desc) — replaces M's WAF-only WafEventList

States:
  - AC #13 disabled (boot-failed observability) → single
    panel, no charts, no error toast. AC #14 applies the
    same shape per-Q-endpoint.
  - AC #7 zero routes → panel pointing to /routes.
  - AC #7 zero WAF-enabled routes → still rendered as the
    M empty state (the dashboard is more useful with at
    least one WAF-enabled route, even though Q signals
    don't require one — auth failures and throttle blocks
    surface regardless).
  - Zero traffic → cards at zero, charts show in-SVG
    "no data" label.

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
	import MixedEventList from '$lib/components/MixedEventList.svelte';
	import { fetchSummary, fetchTimeseries } from '$lib/api/metrics';
	import {
		fetchAttackersSummary,
		fetchAuthFailures,
		fetchDecisions,
		fetchEvents,
		fetchThrottleEvents
	} from '$lib/api/security';
	import { listRoutes } from '$lib/api/client';
	import type {
		AttackersSummaryResponse,
		AuthFailureRecentEvent,
		Decision,
		MetricWindow,
		Route,
		SummaryResponse,
		ThrottleEvent,
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
	// Step Q.4 — three new event sources for the mixed feed
	// + the attackers-summary partial-state hint.
	let recentThrottle = $state<ThrottleEvent[]>([]);
	let recentAuthFailures = $state<AuthFailureRecentEvent[]>([]);
	let attackersSummary = $state<AttackersSummaryResponse | null>(null);
	// Step N.4 — 4th event source for the mixed feed
	// (CrowdSec LAPI decisions captured by the parallel
	// StreamBouncer consumer).
	let recentDecisions = $state<Decision[]>([]);

	let reqSeries = $state<TimeseriesPoint[]>([]);
	let fourxxSeries = $state<TimeseriesPoint[]>([]);
	let wafSeries = $state<TimeseriesPoint[]>([]);
	// Step Q.4 — two new chart series (throttle + auth-fail).
	// Both fetched on route=all (the signals are not
	// per-route per spec §3.5 / AC #10).
	let throttleSeries = $state<TimeseriesPoint[]>([]);
	let authFailSeries = $state<TimeseriesPoint[]>([]);
	// Step N.4 — CrowdSec decision rate chart series.
	// Same route=all convention as throttle: aggregated
	// SUM includes the "_crowdsec" sentinel row.
	let crowdsecSeries = $state<TimeseriesPoint[]>([]);

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
				throttleSeries = [];
				authFailSeries = [];
				crowdsecSeries = [];
				recentEvents = [];
				recentThrottle = [];
				recentAuthFailures = [];
				recentDecisions = [];
				attackersSummary = null;
				return;
			}

			// Step Q.4 + N.4 — 6 timeline series (3 M + 2 Q +
			// 1 N) + 4 event feeds + attackers summary, all
			// fetched in parallel. Per-endpoint AC degraded
			// shape is handled at the response level (events
			// arrays come back empty, timeseries gap-filled
			// with 0).
			//
			// All series use route=all: per AC #10, neither
			// throttle nor auth-failure nor CrowdSec is
			// per-route. The "all" sentinel's QueryAggregated
			// SUMs across every route including the sentinels
			// ("_throttle" + "_crowdsec", N spec §3.5), which
			// is exactly the system-wide view we want.
			const [
				req,
				fourxx,
				waf,
				throttle,
				authFail,
				crowdsec,
				events,
				throttleEvts,
				authFails,
				decisions,
				attackers
			] = await Promise.all([
				fetchTimeseries('all', 'req_per_sec', window),
				fetchTimeseries('all', 'four_xx_rate', window),
				fetchTimeseries('all', 'waf_block_rate', window),
				fetchTimeseries('all', 'throttle_block_rate', window),
				fetchTimeseries('all', 'auth_failure_rate', window),
				fetchTimeseries('all', 'crowdsec_decision_rate', window),
				fetchEvents({ limit: 20 }),
				fetchThrottleEvents({ limit: 20 }),
				fetchAuthFailures(window),
				fetchDecisions({ limit: 20 }),
				fetchAttackersSummary(window)
			]);
			reqSeries = trimTrailing(req);
			fourxxSeries = trimTrailing(fourxx);
			wafSeries = trimTrailing(waf);
			throttleSeries = trimTrailing(throttle);
			authFailSeries = trimTrailing(authFail);
			crowdsecSeries = trimTrailing(crowdsec);
			recentEvents = events.events;
			recentThrottle = throttleEvts.events;
			recentAuthFailures = authFails.recent;
			recentDecisions = decisions.events;
			attackersSummary = attackers;
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

	<!-- 10 stat cards: 5 M + 3 Q + 2 N. CSS auto-fit grid
	     wraps to multiple rows on narrow viewports. -->
	<div class="stat-grid">
		<StatCard label="WAF blocks / min" value={summary?.totalWafBlockedPerMin ?? 0} />
		<StatCard
			label={topAttackedRouteHost ? `${topAttackedRouteHost} (top attaqué)` : 'Top route blocks / min'}
			value={topAttackedRouteBlocks}
		/>
		<StatCard label="% requests blocked" value={fmtPct(pctBlocked)} />
		<StatCard label="4xx / min (context)" value={summary?.totalFourXxPerMin ?? 0} />
		<StatCard label="Routes avec WAF" value={wafEnabledRoutes.length} />
		<!-- Step Q.4 — 3 headline cards. THROTTLE / min +
		     AUTH-FAIL / min are per-minute counts (just-closed
		     minute). ATTACKER IPs unique is the server-side
		     union over the same window. -->
		<StatCard label="Throttle blocks / min" value={summary?.totalThrottlePerMin ?? 0} />
		<StatCard label="Auth fails / min" value={summary?.totalAuthFailuresPerMin ?? 0} />
		<StatCard label="Attacker IPs unique" value={summary?.attackerIpsUnique ?? 0} />
		<!-- Step N.4 — 2 headline cards: CrowdSec decisions/
		     min (NEW decisions arriving from LAPI, dedupe-
		     before-bump per N D4.A) + Active CrowdSec
		     attackers (distinct decision values in window —
		     includes non-IP scopes). -->
		<StatCard label="CrowdSec / min" value={summary?.totalCrowdSecDecisionsPerMin ?? 0} />
		<StatCard label="Active CrowdSec bans" value={summary?.activeCrowdSecIpsUnique ?? 0} />
	</div>

	{#if attackersSummary?.partial === true}
		<div class="partial-hint" role="status">
			Données partielles — au moins une source (WAF, throttle,
			audit ou CrowdSec) est indisponible. Les chiffres affichés
			reflètent les sources qui ont répondu.
		</div>
	{/if}

	<!-- Category distribution strip -->
	<Card>
		<div class="block">
			<h3>Catégories OWASP — dernière minute</h3>
			<CategoryDistribution counts={summary?.wafBlocksByCategory ?? {}} />
		</div>
	</Card>

	<!-- 5 independent timeline charts (route=all). AC #3 /
	     AC #10: each chart is a SEPARATE visual block —
	     never stacked or overlaid. -->
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
		<!-- Step Q.4 — throttle (rate-limit) blocks / min,
		     system-wide. Server sums across the sentinel
		     route_id when route=all (spec §3.5). -->
		<Card>
			<div class="chart-block">
				<h3>Throttle blocks / minute</h3>
				<TimelineChart
					points={throttleSeries}
					color="var(--status-warn)"
					formatValue={fmtCount}
					label="System-wide rate-limit blocks per minute"
				/>
			</div>
		</Card>
		<!-- Step Q.4 — auth-failure rate, audit-scan-backed
		     (spec D4.B). Same wire shape as the bucket
		     metrics; gap-filled to 0. -->
		<Card>
			<div class="chart-block">
				<h3>Auth fails / minute</h3>
				<TimelineChart
					points={authFailSeries}
					color="var(--status-info)"
					formatValue={fmtCount}
					label="System-wide authentication failures per minute"
				/>
			</div>
		</Card>
		<!-- Step N.4 — CrowdSec decision rate, sentinel-
		     keyed at "_crowdsec" + aggregated via the "all"
		     SUM path. Dedupe-before-bump per N D4.A means
		     each tick is a NEW decision arriving, not a
		     repeat of an active one. -->
		<Card>
			<div class="chart-block">
				<h3>CrowdSec decisions / minute</h3>
				<TimelineChart
					points={crowdsecSeries}
					color="var(--status-down)"
					formatValue={fmtCount}
					label="System-wide CrowdSec decisions per minute"
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

	<!-- Step Q.4 — mixed events feed (WAF + THROTTLE +
	     AUTH). Replaces the M.3 WAF-only WafEventList; the
	     drill-down at /security/[routeId] still uses
	     WafEventList because the per-route view is WAF-only
	     by spec D5 carve-out. -->
	<Card>
		<div class="block">
			<h3>Événements de sécurité récents</h3>
			<MixedEventList
				wafEvents={recentEvents}
				throttleEvents={recentThrottle}
				authFailures={recentAuthFailures}
				decisions={recentDecisions}
				{hostByRouteId}
			/>
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
	.partial-hint {
		background: var(--bg-surface);
		border-left: 3px solid var(--status-warn);
		padding: 0.5rem 0.75rem;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0 0 1rem 0;
		border-radius: 0 4px 4px 0;
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
