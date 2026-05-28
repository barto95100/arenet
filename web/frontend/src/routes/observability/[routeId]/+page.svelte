<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

<!--
Step L L.4 — Per-route historical drill-down.

Renders four independent timeline charts (req / 4xx / 5xx / p95)
for one route over the selected window. Linkable from:
  - /observability dashboard top-5 table → "host" cell
  - /topology detail panel footer "Historical →" link
  - direct URL: /observability/<routeId>

Reuses every L.3 primitive — TimelineChart with null-as-gap,
24h/30d window toggle, AC #13 disabled state, AC #7 empty
states, trailing in-progress bucket trim. The fourth chart
(p95) renders the latency series; AC #5 null-for-gap rule is
particularly important here.

Viewer-accessible — relies on the API gate (AC #17).
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Card from '$lib/components/Card.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import TimelineChart from '$lib/components/TimelineChart.svelte';
	import { fetchTimeseries } from '$lib/api/metrics';
	import { getRoute } from '$lib/api/client';
	import type {
		MetricWindow,
		TimeseriesPoint,
		TimeseriesResponse
	} from '$lib/api/types';
	import { ApiError } from '$lib/api/types';
	import type { Route } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';

	const routeId = $derived(page.params.routeId ?? '');

	let route = $state<Route | null>(null);
	let routeNotFound = $state(false);
	let window = $state<MetricWindow>('24h');
	let loading = $state(true);
	let loadError = $state<string | null>(null);
	let disabled = $state(false);

	let reqSeries = $state<TimeseriesPoint[]>([]);
	let fourxxSeries = $state<TimeseriesPoint[]>([]);
	let fivexxSeries = $state<TimeseriesPoint[]>([]);
	let p95Series = $state<TimeseriesPoint[]>([]);

	async function load(): Promise<void> {
		loading = true;
		loadError = null;
		routeNotFound = false;
		try {
			// Fetch the route metadata first; if it 404s, surface
			// a dedicated "route not found" empty state rather
			// than burning four timeseries requests.
			route = await getRoute(routeId);

			// Four independent series in parallel. AC #3: each is
			// its own request, response, and chart — they MUST
			// NOT be folded.
			const [req, fourxx, fivexx, p95] = await Promise.all([
				fetchTimeseries(routeId, 'req_per_sec', window),
				fetchTimeseries(routeId, 'four_xx_rate', window),
				fetchTimeseries(routeId, 'five_xx_rate', window),
				fetchTimeseries(routeId, 'p95_latency_ms', window)
			]);
			disabled = req.disabled === true;
			reqSeries = trimTrailing(req);
			fourxxSeries = trimTrailing(fourxx);
			fivexxSeries = trimTrailing(fivexx);
			p95Series = trimTrailing(p95);
		} catch (err) {
			if (err instanceof ApiError && err.status === 404) {
				routeNotFound = true;
			} else {
				loadError = err instanceof ApiError ? err.message : 'failed to load metrics';
				pushToast(loadError, 'danger');
			}
		} finally {
			loading = false;
		}
	}

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
	const fmtMs = (v: number) => `${Math.round(v)} ms`;
</script>

<PageHeader title="Observability" subtitle={route?.host ?? routeId} />

<div class="back-link">
	<a href="/observability">← Vue globale</a>
</div>

{#if loading}
	<div class="loading-wrap">
		<Spinner />
	</div>
{:else if loadError}
	<Card>
		<div class="error-wrap">{loadError}</div>
	</Card>
{:else if routeNotFound}
	<Card>
		<div class="empty-wrap">
			<h3>Route introuvable</h3>
			<p>
				La route <code>{routeId}</code> n'existe pas (ou plus). Retournez à
				la <a href="/observability">vue globale</a> ou à la liste des
				<a href="/routes">routes</a>.
			</p>
		</div>
	</Card>
{:else if disabled}
	<Card>
		<div class="empty-wrap">
			<h3>Métriques indisponibles</h3>
			<p>
				Le sous-système d'observabilité n'a pas pu démarrer. Le proxy
				continue de fonctionner ; seule l'historique des métriques est
				manquant.
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

	<!-- Four independent charts. AC #3: req / 4xx / 5xx / p95
	     are SEPARATE visual blocks, never stacked or overlaid.
	     The p95 chart deserves particular attention: null gaps
	     in the series MUST render as breaks in the line, never
	     as 0 ms (AC #5). The TimelineChart guarantees that. -->
	<div class="chart-grid">
		<Card>
			<div class="chart-block">
				<h3>Requêtes / minute</h3>
				<TimelineChart
					points={reqSeries}
					color="var(--accent-cyan)"
					formatValue={fmtCount}
					label="Requests per minute"
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
					label="4xx responses per minute"
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
					label="5xx responses per minute"
				/>
			</div>
		</Card>
		<Card>
			<div class="chart-block">
				<h3>Latence p95 (ms)</h3>
				<TimelineChart
					points={p95Series}
					color="var(--status-info)"
					formatValue={fmtMs}
					label="p95 latency in milliseconds"
				/>
			</div>
		</Card>
	</div>

	<!-- Route metadata strip — context for the operator who
	     landed directly via a bookmarked URL. -->
	{#if route}
		<Card>
			<div class="meta-block">
				<h3>Route</h3>
				<dl>
					<dt>Host</dt>
					<dd>{route.host}</dd>
					<dt>Upstreams</dt>
					<dd>
						{#each route.upstreams as up, i (i)}
							<code>{up.url}</code>{#if i < route.upstreams.length - 1}, {/if}
						{/each}
					</dd>
					<dt>ID</dt>
					<dd><code>{routeId}</code></dd>
				</dl>
			</div>
		</Card>
	{/if}
{/if}

<style>
	.back-link {
		margin: 0 0 0.75rem 0;
		font-size: var(--text-sm);
	}
	.back-link a {
		color: var(--accent-cyan);
		text-decoration: none;
	}
	.back-link a:hover {
		text-decoration: underline;
	}
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
	.chart-grid {
		display: grid;
		grid-template-columns: 1fr;
		gap: 0.75rem;
		margin: 0 0 1rem 0;
	}
	@media (min-width: 1200px) {
		.chart-grid {
			grid-template-columns: repeat(2, 1fr);
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
	.meta-block {
		padding: 1rem;
	}
	.meta-block h3 {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
		margin: 0 0 0.75rem 0;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.meta-block dl {
		display: grid;
		grid-template-columns: max-content 1fr;
		gap: 0.5rem 1rem;
		margin: 0;
		font-size: var(--text-sm);
	}
	.meta-block dt {
		color: var(--text-secondary);
	}
	.meta-block dd {
		color: var(--text-primary);
		margin: 0;
		word-break: break-all;
	}
	.meta-block code {
		font-family: var(--font-mono, monospace);
		background: var(--bg-surface);
		padding: 0 0.25rem;
		border-radius: 2px;
	}
</style>
