<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
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
	import { fetchEvents as fetchWafEvents, fetchCertEventsAggregate } from '$lib/api/security';
	import { certificatesApi } from '$lib/api/certificates';
	import { listRoutes } from '$lib/api/client';
	import { ApiError } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import Spinner from '$lib/components/Spinner.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import StatCard from '$lib/components/StatCard.svelte';
	import TimelineChart from '$lib/components/TimelineChart.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { relativeTime } from '$lib/utils/audit-format';
	import { auth } from '$lib/stores/auth.svelte';
	import MultiSeriesTimelineChart from '$lib/components/MultiSeriesTimelineChart.svelte';
	import type {
		Certificate,
		CertEventBucket,
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
	// Which metric the points on screen ACTUALLY are (v2.73).
	//
	// switchMetric used to assign chartMetric and only then await the
	// fetch, so the title and the colour changed at the click while
	// the old series was still drawn. Click "Latency" during an API
	// outage and the request-count series stayed on screen under the
	// latency title, in the latency colour — you read requests as
	// milliseconds. Two names: chartMetric is what the operator
	// asked for and drives the active button, chartMetricShown is
	// what the drawn points are and drives everything that describes
	// them.
	let chartMetricShown = $state<MetricName>('req_per_sec');
	// The bucket width the API reported for the drawn series, so the
	// chart can name its own unit instead of the page claiming "/s".
	let chartBucketSeconds = $state(0);
	// Monotonic token. Two quick metric switches can land in either
	// order; without this the loser overwrites the winner and the
	// chart ends up showing a series nobody selected.
	let chartRequestSeq = 0;
	const window: MetricWindow = '24h';

	// Phase 5 — cert lifecycle data. certificates feeds the
	// total + "expiring in 30d" KPI cards; certBuckets feeds
	// the chart; certFailed7d feeds the third KPI card. All
	// three are best-effort — degraded mode + fetch error
	// both collapse to zero counts / empty chart rather than
	// breaking the dashboard.
	let certificates = $state<Certificate[]>([]);
	let certBuckets = $state<CertEventBucket[]>([]);
	let certFailed7d = $state(0);

	const disabled = $derived(summary?.disabled === true);
	const noRoutes = $derived(!disabled && routes.length === 0);

	// 4 KPI derivations from the summary response.
	// #R-WAF-METRICS-WINDOW-1MIN-PROJECTION — pre-fix the
	// summary endpoint returned just-closed-minute counters
	// and the frontend multiplied by 60 (for "/h") or
	// 60×24 (for "/24h") to project rates. On bursty
	// homelab traffic the just-closed minute was often
	// empty, surfacing as zero everywhere. Post-fix the
	// summary returns 24h totals directly; the frontend
	// reads them raw (no projection).
	//
	// req/s is derived by dividing the 24h total by the
	// window length in seconds (windowSeconds = 86400).
	// The displayed average isn't instantaneous traffic
	// but a 24h-average rate, which is what an operator
	// reading the card actually wants to know about
	// sustained activity.
	const kpiReqPerSec = $derived.by(() => {
		const total = summary?.totalReq ?? 0;
		const win = summary?.windowSeconds ?? 86400;
		if (win <= 0) return 0;
		return Math.round((total / win) * 10) / 10;
	});
	const kpiP95 = $derived(summary?.globalP95LatencyMs ?? null);
	const kpi5xxPct = $derived(
		(() => {
			const req = summary?.totalReq ?? 0;
			const fivexx = summary?.totalFiveXx ?? 0;
			if (req <= 0) return 0;
			return Math.round((fivexx / req) * 10000) / 100;
		})()
	);
	// Two parallel WAF tiles. Values are 24h absolute
	// counts (no rate projection); the labels read
	// "/ 24h" to match the wire semantics.
	const kpiWafBlocked24h = $derived(summary?.totalWafBlocked ?? 0);
	const kpiWafDetected24h = $derived(summary?.totalWafDetected ?? 0);

	// Phase 5 — cert KPI derivations.
	const kpiCertTotal = $derived(certificates.length);
	const kpiCertExpiringSoon = $derived.by(() => {
		const horizon = Date.now() + 30 * 24 * 60 * 60 * 1000;
		return certificates.filter((c) => {
			const t = new Date(c.notAfter).getTime();
			return !isNaN(t) && t < horizon;
		}).length;
	});
	const kpiCertFailed7d = $derived(certFailed7d);

	// The chart's series definition lives at module scope
	// so the operator's theme-token references stay readable.
	// status-up / accent-cyan / status-down map respectively
	// to the green/blue/red triad the operator brief asked for.
	const certChartSeries = $derived(
		language.current
			? [
					{ key: 'issued' as const, label: t('dashboard.certChartIssued'), color: 'var(--status-up)' },
					{ key: 'renewed' as const, label: t('dashboard.certChartRenewed'), color: 'var(--accent-cyan)' },
					{ key: 'failed' as const, label: t('dashboard.certChartFailed'), color: 'var(--status-down)' }
				]
			: [
					{ key: 'issued' as const, label: 'Issued', color: 'var(--status-up)' },
					{ key: 'renewed' as const, label: 'Renewed', color: 'var(--accent-cyan)' },
					{ key: 'failed' as const, label: 'Failed', color: 'var(--status-down)' }
				]
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
			return result;
		})()
	);

	// The card shows at most this many. It used to slice silently, so
	// an operator with 11 distinct upstreams saw 8 and nothing said
	// the other 3 existed.
	const UPSTREAMS_SHOWN = 8;
	const upstreamsShown = $derived(upstreams.slice(0, UPSTREAMS_SHOWN));
	const upstreamsHidden = $derived(Math.max(0, upstreams.length - UPSTREAMS_SHOWN));

	async function load(): Promise<void> {
		loading = true;
		loadError = null;
		try {
			// Phase 5 — cert calls are best-effort: a failure
			// must NOT take down the dashboard, the existing
			// KPIs / chart / WAF panel stay valuable on a fresh
			// install with zero certificates. .catch returns
			// the empty-shape default so the destructure stays
			// safe.
			const [rs, sum, evs, certs, certAgg, failed7d] = await Promise.all([
				listRoutes(),
				fetchSummary(),
				fetchWafEvents({ limit: 5 }).catch(() => ({ events: [] })),
				certificatesApi.list().catch(() => [] as Certificate[]),
				fetchCertEventsAggregate({ windowDays: 30, intervalHours: 24 }).catch(() => ({
					buckets: [] as CertEventBucket[]
				})),
				fetchCertEventsAggregate({ windowDays: 7, intervalHours: 24 }).catch(() => ({
					buckets: [] as CertEventBucket[]
				}))
			]);
			routes = rs;
			summary = sum;
			recentEvents = evs.events ?? [];
			certificates = certs;
			certBuckets = certAgg.buckets ?? [];
			// Sum failed across the 7d window — one round-trip
			// to the same aggregate endpoint, no extra surface.
			certFailed7d = (failed7d.buckets ?? []).reduce((acc, b) => acc + (b.failed ?? 0), 0);
			if (!sum.disabled) {
				void loadChart();
			}
			// Only on the success path: a failed refresh must not
			// advance the freshness clock, or the page would claim to
			// be newer than its data.
			lastLoadedAt = new Date();
		} catch (err) {
			loadError = err instanceof ApiError ? err.message : 'failed to load dashboard';
			pushToast(loadError, 'danger');
		} finally {
			loading = false;
		}
	}

	async function loadChart(): Promise<void> {
		const seq = ++chartRequestSeq;
		const requested = chartMetric;
		chartLoading = true;
		try {
			const resp = await fetchTimeseries('all', requested, window);
			// A newer request has been issued since; this answer is
			// stale and applying it would show a series nobody asked
			// for.
			if (seq !== chartRequestSeq) return;
			// Drop the in-progress last point (#L.2-2 trailing bucket).
			chartPoints = resp.points.length > 0 ? resp.points.slice(0, -1) : [];
			// Only now do the title, the colour and the unit follow —
			// they describe these points, not the pending selection.
			chartMetricShown = requested;
			chartBucketSeconds = resp.bucketSizeSeconds;
		} catch (err) {
			if (seq !== chartRequestSeq) return;
			// chartMetricShown deliberately unchanged: the points still
			// on screen are the previous metric's, and relabelling them
			// is the defect this guards.
			pushToast(
				err instanceof ApiError ? err.message : 'failed to load timeseries',
				'danger'
			);
		} finally {
			if (seq === chartRequestSeq) chartLoading = false;
		}
	}

	function switchMetric(m: MetricName): void {
		if (m === chartMetric) return;
		chartMetric = m;
		void loadChart();
	}

	// What the series on screen is counted in (v2.73).
	//
	// The req_per_sec / four_xx_rate / five_xx_rate series carry
	// per-bucket COUNTS, not rates — metrics_handlers.go:968-976
	// returns float64(row.ReqCount) and friends straight out of the
	// bucket. The button said "Req/s", so on the 24h window (1-minute
	// buckets) every value read 60x too high, and on 30d (1-hour
	// buckets) 3600x. An operator reading "1 200 req/s" was looking
	// at 1 200 requests in a minute, i.e. 20 req/s.
	//
	// bucketSizeSeconds has always been on the wire
	// (metrics_handlers.go:115), so the honest unit was one field
	// away. Naming the bucket is also the better chart: a per-second
	// line over hour-wide buckets would be a smoothed row of tiny
	// numbers.
	const chartUnit = $derived.by(() => {
		if (chartMetricShown === 'p95_latency_ms') return t('dashboard.chartUnitMs');
		if (chartBucketSeconds === 60) return t('dashboard.chartUnitPerMinute');
		if (chartBucketSeconds === 3600) return t('dashboard.chartUnitPerHour');
		if (chartBucketSeconds > 0) {
			return t('dashboard.chartUnitPerSeconds', { seconds: chartBucketSeconds });
		}
		return '';
	});

	// The series name, translated. The chart's accessible label used
	// to be `Series for ${chartMetric}` — an English literal built
	// from the raw wire name, so a screen reader heard "Series for
	// five_xx_rate".
	const chartMetricLabel = $derived.by(() => {
		switch (chartMetricShown) {
			case 'p95_latency_ms':
				return t('dashboard.trafficBtnLatency');
			case 'five_xx_rate':
				return t('dashboard.trafficBtnErrors');
			default:
				return t('dashboard.trafficBtnReq');
		}
	});

	function fmtP95(v: number | null): string {
		return v === null ? '—' : `${Math.round(v)}`;
	}

	// v2.9.22 i18n — delegate to the shared relativeTime helper so
	// the dashboard footers ("2 hours ago" / "il y a 2 heures") respect
	// the active language preference instead of being locked to FR.
	function fmtRelative(iso: string): string {
		return relativeTime(iso);
	}

	// HH:MM:SS in the viewer's own timezone.
	//
	// The tail column used toISOString().substring(11, 19), which is
	// UTC, with nothing on the page saying so — a constant offset
	// against /logs, which has always shown local time, and no way to
	// tell which of the two was lying. Built from the parts rather
	// than toLocaleTimeString so the shape stays fixed across locales
	// (a 12-hour clock in a monospace column would also shift the
	// alignment).
	function localClock(iso: string): string {
		const d = new Date(iso);
		if (Number.isNaN(d.getTime())) return '—';
		const p = (n: number) => String(n).padStart(2, '0');
		return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
	}

	function chartColor(m: MetricName): string {
		switch (m) {
			case 'req_per_sec':
				return 'var(--accent)';
			case 'p95_latency_ms':
				return 'var(--status-info)';
			case 'five_xx_rate':
				return 'var(--status-down)';
			default:
				return 'var(--accent)';
		}
	}

	// "Real-time" is now true (v2.73).
	//
	// The subtitle has always read "Real-time traffic across your N
	// routes", and load() ran exactly once, from onMount. A dashboard
	// left open overnight showed yesterday's numbers under that
	// sentence. The honest options were to delete the claim or to make
	// it hold; a dashboard an operator keeps open is worth refreshing,
	// so it refreshes.
	//
	// 60 s rather than the topbar's 30 s because load() makes six
	// calls, two of them over the metrics store, and this project
	// targets 4 GB homelab hosts.
	const REFRESH_MS = 60_000;
	let lastLoadedAt = $state<Date | null>(null);

	// Read on a timer so the "updated Xs ago" line keeps climbing
	// between refreshes instead of freezing at the last fetch.
	let freshnessClock = $state(0);

	const lastUpdatedLabel = $derived.by(() => {
		void freshnessClock;
		if (lastLoadedAt === null) return '';
		const secs = Math.max(0, Math.round((Date.now() - lastLoadedAt.getTime()) / 1000));
		if (secs < 60) return t('dashboard.updatedSeconds', { seconds: secs });
		return t('dashboard.updatedMinutes', { minutes: Math.round(secs / 60) });
	});

	onMount(() => {
		void load();

		const freshness = setInterval(() => (freshnessClock += 1), 15_000);
		const poll = setInterval(() => {
			// Locked: the LockScreen overlay covers the page, so the
			// answer is unobservable. Hidden tab: same. client.ts
			// already refuses background traffic while locked, so this
			// only avoids the pointless request and its 403.
			if (auth.state === 'locked') return;
			if (typeof document !== 'undefined' && document.visibilityState !== 'visible') return;
			void load();
		}, REFRESH_MS);

		return () => {
			clearInterval(freshness);
			clearInterval(poll);
		};
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
	<PageHeader
		eyebrow={language.current && t('dashboard.eyebrow')}
		title={language.current && t('pageTitles.dashboard')}
	/>
	<div class="card empty">
		<h3>{language.current && t('dashboard.disabledTitle')}</h3>
		<p>{language.current && t('dashboard.disabledBody')}</p>
	</div>
{:else if noRoutes}
	<PageHeader
		eyebrow={language.current && t('dashboard.eyebrow')}
		title={language.current && t('pageTitles.dashboard')}
	/>
	<div class="card empty">
		<h3>{language.current && t('dashboard.noRoutesTitle')}</h3>
		<p>
			{language.current && t('dashboard.noRoutesBodyBefore')}
			<a href="/routes">{language.current && t('dashboard.noRoutesBodyLink')}</a>
			{language.current && t('dashboard.noRoutesBodyAfter')}
		</p>
	</div>
{:else}
	<PageHeader
		eyebrow={language.current && t('dashboard.eyebrow')}
		title={language.current && t('pageTitles.dashboard')}
		subtitle={language.current &&
			`${t('dashboard.subtitle', { count: routes.length, window })}${
				lastUpdatedLabel ? ` · ${lastUpdatedLabel}` : ''
			}`}
	/>

	<!-- KPIs -->
	<!-- v2.41 — the eight tiles were a scoped-CSS copy of StatCard,
	     which now carries this exact treatment plus the unit and the
	     foot line the copy had and it lacked. -->
	<div class="kpis">
		<StatCard
			label={language.current && t('dashboard.kpiReqPerSec')}
			value={kpiReqPerSec}
			unit="req/s"
			hint={language.current && t('dashboard.kpiReqPerSecFoot', { total: summary?.totalReq ?? 0, routes: summary?.activeRouteCount ?? 0 })}
		/>
		<StatCard
			label={language.current && t('dashboard.kpiP95')}
			value={fmtP95(kpiP95)}
			unit="ms"
			hint={language.current && (kpiP95 === null ? t('dashboard.kpiP95FootNoData') : t('dashboard.kpiP95FootData'))}
		/>
		<StatCard
			label={language.current && t('dashboard.kpi5xxRate')}
			value={kpi5xxPct}
			unit="%"
			hint={language.current && t('dashboard.kpi5xxRateFoot', { five: summary?.totalFiveXx ?? 0, four: summary?.totalFourXx ?? 0 })}
		/>
		<!--
			#R-DASHBOARD-WAF-COUNTERS-ZERO + #R-WAF-METRICS-
			WINDOW-1MIN-PROJECTION — two parallel tiles showing
			24h absolute counts. Blocked reads the canonical
			block counter; Detected reads the detect counter so
			detect-mode activity stays visible on homelab routes
			using the wafMode=detect default.
		-->
		<StatCard
			testid="kpi-waf-blocked"
			label={language.current && t('dashboard.kpiWafBlocked')}
			value={kpiWafBlocked24h}
			hint={language.current && t('dashboard.kpiWafBlockedFoot', { ips: summary?.attackerIpsUnique ?? 0, throttle: summary?.totalThrottle ?? 0, rl: summary?.totalRateLimitExceeded ?? 0 })}
		/>
		<StatCard
			testid="kpi-waf-detected"
			label={language.current && t('dashboard.kpiWafDetected')}
			value={kpiWafDetected24h}
			hint={language.current && t('dashboard.kpiWafDetectedFoot')}
		/>
		<!--
			Phase 5 — cert KPIs. The three tiles split the cert
			lifecycle into "what's deployed", "what's expiring",
			"what's failing" — the operator brief's triad.
		-->
		<StatCard
			testid="kpi-cert-total"
			label={language.current && t('dashboard.kpiCertTotal')}
			value={kpiCertTotal}
			hint={language.current && t('dashboard.kpiCertTotalFoot')}
		/>
		<StatCard
			testid="kpi-cert-expiring"
			label={language.current && t('dashboard.kpiCertExpiring')}
			value={kpiCertExpiringSoon}
			hint={language.current && (kpiCertExpiringSoon === 0 ? t('dashboard.kpiCertExpiringFootZero') : t('dashboard.kpiCertExpiringFootWatch'))}
		/>
		<StatCard
			testid="kpi-cert-failed-7d"
			label={language.current && t('dashboard.kpiCertFailed7d')}
			value={kpiCertFailed7d}
			hint={language.current && (kpiCertFailed7d === 0 ? t('dashboard.kpiCertFailedFootZero') : t('dashboard.kpiCertFailedFootInvestigate'))}
		/>
	</div>

	<!-- Main row: traffic chart + WAF events recent -->
	<div class="two-col main-row">
		<div class="card">
			<div class="card-h">
				<h3>
					{language.current && t('dashboard.trafficCardTitle', { window })}
					{#if chartUnit}<span class="unit">· {language.current && chartUnit}</span>{/if}
				</h3>
				<div class="seg">
					<button
						class:on={chartMetric === 'req_per_sec'}
						onclick={() => switchMetric('req_per_sec')}>{language.current && t('dashboard.trafficBtnReq')}</button
					>
					<button
						class:on={chartMetric === 'p95_latency_ms'}
						onclick={() => switchMetric('p95_latency_ms')}>{language.current && t('dashboard.trafficBtnLatency')}</button
					>
					<button
						class:on={chartMetric === 'five_xx_rate'}
						onclick={() => switchMetric('five_xx_rate')}>{language.current && t('dashboard.trafficBtnErrors')}</button
					>
				</div>
			</div>
			<!-- data-metric is what the drawn points ARE, so a test can
			     observe the metric the chart describes without going
			     through the unit label — otherwise a change to the
			     label makes the race tests fail too, and neither says
			     which mechanism broke. -->
			<div class="chart-wrap" data-metric={chartMetricShown}>
				{#if chartLoading}
					<div class="chart-loading"><Spinner size="sm" /></div>
				{:else}
					<TimelineChart
						points={chartPoints}
						color={chartColor(chartMetricShown)}
						label={language.current &&
							t('dashboard.chartAriaLabel', {
								metric: chartMetricLabel,
								unit: chartUnit
							})}
					/>
				{/if}
			</div>
		</div>

		<div class="card">
			<div class="card-h">
				<h3>{language.current && t('dashboard.recentWafCardTitle')}</h3>
				<div class="meta">{language.current && t('dashboard.recentWafCardMeta')}</div>
			</div>
			<div class="stack">
				{#each recentEvents as ev (ev.id)}
					<!--
						#R-WAF-EVENT-LABEL-INCONSISTENT — read
						ev.action instead of hardcoding "block".
						Pre-fix every event surfaced as a "block"
						pill regardless of whether the WAF actually
						rejected the request (BLOCK) or merely
						matched the rule and let it pass (DETECT).
						The Step W.bugfix migration backfilled
						legacy rows to "BLOCK" so old data still
						renders correctly.
					-->
					<div class="event" data-testid="recent-event-{ev.id}">
						<span class="pill {ev.action === 'DETECT' ? 'warn' : 'bad'}">
							{language.current && (ev.action === 'DETECT' ? t('dashboard.recentWafPillDetect') : t('dashboard.recentWafPillBlock'))}
						</span>
						<div class="what">
							<b>{ev.category} · {ev.ruleId}</b>
							<span>{language.current && t('dashboard.recentWafFromIp', { method: ev.requestMethod, path: ev.requestPath, ip: ev.srcIp })}</span>
						</div>
						<div class="when">{fmtRelative(ev.ts)}</div>
					</div>
				{:else}
					<div class="empty-row">{language.current && t('dashboard.recentWafEmpty')}</div>
				{/each}
			</div>
		</div>
	</div>

	<!--
		Phase 5 — cert lifecycle panel. Sits between the main
		traffic / WAF row and the bottom routes / upstreams row.
		Three series: issued (fresh certs), renewed (renewals),
		failed. Legend is click-to-toggle; tooltip on hover.
	-->
	<div class="card" data-testid="cert-lifecycle-panel">
		<div class="card-h">
			<h3>{language.current && t('dashboard.certLifecycleTitle')}</h3>
			<div class="meta">{language.current && t('dashboard.certLifecycleMeta')}</div>
		</div>
		<div class="chart-wrap">
			<MultiSeriesTimelineChart
				data={certBuckets}
				series={certChartSeries}
				label={language.current && t('dashboard.certLifecycleAria')}
				height={180}
			/>
		</div>
	</div>

	<!-- Bottom row: top routes + upstreams -->
	<div class="two-col bottom-row">
		<div class="card">
			<div class="card-h">
				<h3>{language.current && t('dashboard.topRoutesTitle')}</h3>
				<div class="meta">{language.current && t('dashboard.topRoutesMeta')}</div>
			</div>
			<table>
				<thead>
					<tr>
						<th>{language.current && t('dashboard.topRoutesColRoute')}</th>
						<th class="right">{language.current && t('dashboard.topRoutesColReq')}</th>
						<th class="right">{language.current && t('dashboard.topRoutesColFourXX')}</th>
						<th class="right">{language.current && t('dashboard.topRoutesColFiveXX')}</th>
						<th class="right">{language.current && t('dashboard.topRoutesColWAFBlock')}</th>
						<th class="right">{language.current && t('dashboard.topRoutesColWAFDetect')}</th>
					</tr>
				</thead>
				<tbody>
					{#each summary?.topRoutes ?? [] as r (r.routeId)}
						<tr>
							<td class="mono">
								<a href={`/observability/${r.routeId}`} class="host-link">{r.host}</a>
							</td>
							<td class="mono right">{r.reqs}</td>
							<td class="mono right warn-text">{r.fourxx}</td>
							<td class="mono right bad-text">{r.fivexx}</td>
							<td class="mono right bad-text">{r.wafBlocked}</td>
							<td class="mono right warn-text">{r.wafDetected}</td>
						</tr>
					{:else}
						<tr><td colspan="6" class="empty-row">{language.current && t('dashboard.topRoutesEmpty')}</td></tr>
					{/each}
				</tbody>
			</table>
		</div>

		<div class="card">
			<div class="card-h">
				<h3>{language.current && t('dashboard.upstreamsTitle')}</h3>
				<div class="meta">{language.current && t('dashboard.upstreamsMetaCount', { count: upstreams.length })}</div>
			</div>
			<div class="stack">
				{#each upstreamsShown as u (u.url)}
					<div class="upstream-row">
						<span class="mono">{u.url}</span>
						<span class="mono dim">{language.current && t('dashboard.upstreamsRouteSuffix', { count: u.routes.length, plural: u.routes.length > 1 ? 's' : '' })}</span>
					</div>
				{:else}
					<div class="empty-row">{language.current && t('dashboard.upstreamsEmpty')}</div>
				{/each}
				{#if upstreamsHidden > 0}
					<div class="upstream-row dim" data-testid="upstreams-truncated">
						{language.current &&
							t('dashboard.upstreamsTruncated', {
								hidden: upstreamsHidden,
								shown: UPSTREAMS_SHOWN,
								total: upstreams.length
							})}
					</div>
				{/if}
			</div>
		</div>
	</div>

	<!-- Live tail preview -->
	<div class="card tail-card">
		<div class="card-h">
			<h3>{language.current && t('dashboard.tailTitle')}</h3>
			<div class="meta">
				<a href="/logs" class="meta-link">{language.current && t('dashboard.tailOpenLogs')}</a>
			</div>
		</div>
		<div class="logs">
			{#each recentEvents as ev (`tail-${ev.id}`)}
				<!--
					#R-WAF-EVENT-LABEL-INCONSISTENT — second
					hardcoded site. Same fix as the Recent WAF
					events card above: read ev.action +
					ev.statusCode rather than fabricating
					"BLOCK 403" on every row. Status code on
					detect events is 0 (the upstream's response
					was unknown at WAF-decision time); render as
					"—" to make the operator-honest "no value"
					answer obvious.
				-->
				<div class="log-row" data-testid="tail-event-{ev.id}">
					<!-- Local time, not UTC. This was
					     toISOString().substring(11,19), so the column
					     read UTC with nothing saying so — a constant
					     offset against /logs, which has always shown
					     local time, and no way for the operator to
					     know which of the two was lying. -->
					<span class="log-time">{localClock(ev.ts)}</span>
					<span class="log-lvl {ev.action === 'DETECT' ? 'detect' : 'block'}">
						{ev.action}
					</span>
					<span class="mono">{ev.statusCode || '—'}</span>
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
				<div class="empty-row">{language.current && t('dashboard.tailEmpty')}</div>
			{/each}
		</div>
	</div>
{/if}

<style>
	.loading-wrap { display: flex; justify-content: center; padding: 48px; }
	.card.error { padding: 16px; color: var(--status-down); border-radius: var(--radius); background: var(--surface); border: 1px solid var(--border); }

	/* v2.41 — .screen-head / .eyebrow / h1 / .sub used to live here as
	   a copy of PageHeader (which was itself modelled on this very
	   block, see PageHeader.svelte). The page now uses the component. */

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
	/* The unit the series is counted in, beside the title rather than
	   under the axis: it is the part that was wrong, so it belongs
	   where the eye already is. */
	.card-h h3 .unit { color: var(--fg-dim); font-weight: 400; }
	.card-h .meta { margin-left: auto; color: var(--fg-dim); font-size: 11.5px; font-family: var(--font-mono); }
	.meta-link { color: var(--accent); text-decoration: none; }
	.meta-link:hover { text-decoration: underline; }

	.kpis {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 12px;
		margin-bottom: 18px;
	}
	/* v2.41 — the .kpi / .kpi-label / .kpi-val / .kpi-foot rules
	   moved into StatCard.svelte; only the grid stays here. */

	.two-col {
		display: grid;
		gap: 14px;
		margin-bottom: 18px;
	}
	.main-row { grid-template-columns: 1fr 1fr; }
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
	.pill.bad { background: color-mix(in oklch, var(--status-down) 18%, transparent); color: var(--status-down); }
	/* #R-WAF-EVENT-LABEL-INCONSISTENT — amber detect badge, parallel to the .bad red block badge. */
	.pill.warn { background: color-mix(in oklch, var(--status-warn) 18%, transparent); color: var(--status-warn); }

	table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
	th, td { padding: 7px 8px; text-align: left; }
	th { color: var(--fg-muted); font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }
	td { color: var(--fg); border-bottom: 1px solid var(--border); }
	tbody tr:last-child td { border-bottom: none; }
	.mono { font-family: var(--font-mono); font-size: 12px; }
	.right { text-align: right; }
	.dim { color: var(--fg-dim); }
	.host-link {
		color: var(--fg);
		text-decoration: none;
		border-bottom: 1px dashed var(--fg-dim);
	}
	.host-link:hover {
		color: var(--accent);
		border-bottom-color: var(--accent);
	}
	.warn-text { color: var(--status-warn); }
	.bad-text { color: var(--status-down); }
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
	.log-lvl.block { background: color-mix(in oklch, var(--status-down) 18%, transparent); color: var(--status-down); }
	/* #R-WAF-EVENT-LABEL-INCONSISTENT — amber detect log level, parallel to the .block red. */
	.log-lvl.detect { background: color-mix(in oklch, var(--status-warn) 18%, transparent); color: var(--status-warn); }
	.log-msg { color: var(--fg); }
	.log-msg .k { color: var(--fg-dim); }
</style>
