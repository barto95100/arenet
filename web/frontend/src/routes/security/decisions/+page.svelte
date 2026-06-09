<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step N.4 + CS.2 — /security/decisions CrowdSec drill-down.

  This is the operator's single drill-down for everything
  CrowdSec-related. Three tabs:

    1. Local snapshot (Step N.4, default tab)
       - DataTable of the metrics.db decision_event table
         (populated by the StreamBouncer sink).
       - Cumulative across restarts (~7d retention per
         spec D8.A).
       - Answers: "what has Arenet historically observed?"
       - "Active only" toggle scopes to expiresAt > now.

    2. Live LAPI (Step CS.2.A)
       - DataTable of LAPI's /v1/decisions response,
         live-polled every 30s.
       - Source of truth for "what is enforced this exact
         moment?" — distinct from the snapshot above which
         can lag by the bouncer's pull interval.
       - Filterable by scope + source (CAPI / crowdsec /
         cscli / lists:* / etc.).
       - Distinct empty states + error UX (Configure CTA
         when bouncer not configured, retry button on
         transient failure).

    3. Scenarios (Step CS.2.C — pending)
       - Placeholder. Will surface installed scenarios + 24h
         alert counts from LAPI's /v1/metrics endpoint.

  Layout decision (post-audit Lesson 1 triangulation): the
  Security page (Step R.4.3) is now a posture overview; the
  brief's "add panels next to WAF/throttle/auth" reflected
  pre-R.4.3 state. So all three CS.2 sub-panels land here as
  tabs rather than as separate sections on /security.
-->

<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Card from '$lib/components/Card.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import { fetchDecisions, fetchLAPIDecisions, fetchScenarios } from '$lib/api/security';
	import type {
		Decision,
		LAPIDecision,
		LAPIDecisionsMeta,
		ScenarioAggregate,
		ScenariosMeta
	} from '$lib/api/types';
	import { ApiError, isArenetAutoScenario } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';

	type Tab = 'snapshot' | 'live' | 'scenarios';
	let activeTab = $state<Tab>('snapshot');

	// --- Tab 1: Local snapshot (Step N.4, unchanged data path) ---

	let snapshotLoading = $state(true);
	let snapshotError = $state<string | null>(null);
	let snapshotDisabled = $state(false);
	let onlyActive = $state(false);
	let decisions = $state<Decision[]>([]);

	async function loadSnapshot(): Promise<void> {
		snapshotLoading = true;
		snapshotError = null;
		try {
			const resp = await fetchDecisions({ limit: 100, onlyActive });
			snapshotDisabled = resp.disabled === true;
			decisions = resp.events;
		} catch (err) {
			snapshotError = err instanceof ApiError ? err.message : 'failed to load decisions';
			pushToast(snapshotError, 'danger');
		} finally {
			snapshotLoading = false;
		}
	}

	function toggleActive(next: boolean): void {
		onlyActive = next;
		void loadSnapshot();
	}

	// --- Tab 2: Live LAPI (Step CS.2.A) ---

	type LiveErrorKind = 'not_configured' | 'unreachable' | 'other' | null;

	let liveLoading = $state(false);
	let liveErrorKind = $state<LiveErrorKind>(null);
	let liveErrorMsg = $state<string | null>(null);
	let liveDecisions = $state<LAPIDecision[]>([]);
	let liveMeta = $state<LAPIDecisionsMeta>({
		total: 0,
		totalByOrigin: {},
		limit: 100,
		offset: 0
	});
	let liveScope = $state<string>('');
	let liveSource = $state<string>('');
	let liveLastFetched = $state<number | null>(null);
	// 30s polling tick. Set up when the user opens the Live
	// tab; torn down when leaving (or on component destroy).
	// 30s matches CrowdSec's default bouncer pull interval —
	// the chosen cadence is the natural rhythm of the data,
	// not a guess.
	const LIVE_POLL_MS = 30_000;
	let livePollHandle: ReturnType<typeof setInterval> | null = null;

	async function loadLive(): Promise<void> {
		liveLoading = true;
		liveErrorMsg = null;
		try {
			const resp = await fetchLAPIDecisions({
				scope: liveScope || undefined,
				source: liveSource || undefined,
				limit: 100
			});
			liveDecisions = resp.decisions;
			liveMeta = resp.meta;
			liveErrorKind = null;
			liveLastFetched = Date.now();
		} catch (err) {
			if (err instanceof ApiError) {
				if (err.status === 404) {
					liveErrorKind = 'not_configured';
					liveErrorMsg = err.message;
				} else if (err.status === 502) {
					liveErrorKind = 'unreachable';
					liveErrorMsg = err.message;
				} else {
					liveErrorKind = 'other';
					liveErrorMsg = err.message;
				}
			} else {
				liveErrorKind = 'other';
				liveErrorMsg = err instanceof Error ? err.message : 'failed to load live decisions';
			}
			// Don't clear the existing decisions on a polling
			// failure — operators reading the table mid-poll
			// shouldn't see it blank out on a single hiccup.
			// The badge above the table flips to the error
			// state; data underneath stays as the last known
			// good response.
		} finally {
			liveLoading = false;
		}
	}

	function startLivePolling(): void {
		if (livePollHandle !== null) return;
		void loadLive();
		livePollHandle = setInterval(() => {
			// Skip the tick if the tab isn't visible (operator
			// navigated to a different tab in-app); the next
			// tab-open will refetch fresh.
			if (activeTab !== 'live') return;
			void loadLive();
		}, LIVE_POLL_MS);
	}

	function stopLivePolling(): void {
		if (livePollHandle !== null) {
			clearInterval(livePollHandle);
			livePollHandle = null;
		}
	}

	function onTabChange(next: Tab): void {
		activeTab = next;
		if (next === 'live') {
			startLivePolling();
		} else if (next === 'scenarios' && scenariosLastFetched === null) {
			void loadScenarios();
		}
		// Don't stop polling on a different tab change — the
		// timer skips ticks when activeTab !== 'live' (see
		// startLivePolling). This lets the operator hop between
		// snapshot ↔ live without paying the connect-startup
		// latency every flip.
	}

	// --- Tab 3: Scenarios (Step CS.2.C) ---

	type ScenariosErrorKind = 'not_configured' | 'unreachable' | 'other' | null;

	let scenariosLoading = $state(false);
	let scenariosErrorKind = $state<ScenariosErrorKind>(null);
	let scenariosErrorMsg = $state<string | null>(null);
	let scenarios = $state<ScenarioAggregate[]>([]);
	let scenariosMeta = $state<ScenariosMeta>({ totalAlerts: 0, windowHours: 24 });
	let scenariosLastFetched = $state<number | null>(null);
	let modalScenario = $state<ScenarioAggregate | null>(null);

	async function loadScenarios(): Promise<void> {
		scenariosLoading = true;
		scenariosErrorMsg = null;
		try {
			const resp = await fetchScenarios();
			scenarios = resp.scenarios;
			scenariosMeta = resp.meta;
			scenariosErrorKind = null;
			scenariosLastFetched = Date.now();
		} catch (err) {
			if (err instanceof ApiError) {
				if (err.status === 412) {
					scenariosErrorKind = 'not_configured';
					scenariosErrorMsg = err.message;
				} else if (err.status === 502) {
					scenariosErrorKind = 'unreachable';
					scenariosErrorMsg = err.message;
				} else {
					scenariosErrorKind = 'other';
					scenariosErrorMsg = err.message;
				}
			} else {
				scenariosErrorKind = 'other';
				scenariosErrorMsg =
					err instanceof Error ? err.message : 'failed to load scenarios';
			}
		} finally {
			scenariosLoading = false;
		}
	}

	function refreshScenarios(): void {
		void loadScenarios();
	}

	function openScenarioModal(s: ScenarioAggregate): void {
		modalScenario = s;
	}
	function closeScenarioModal(): void {
		modalScenario = null;
	}

	// Hub URL builder. CrowdSec scenarios are named
	// "<author>/<scenario>" (e.g. "crowdsecurity/http-cve");
	// the hub URL is https://hub.crowdsec.net/author/<author>/configurations/<scenario>.
	// For non-org-prefixed scenarios (e.g. "manual" from cscli,
	// or unknown) the function returns null and the UI hides
	// the hub link.
	function hubURL(scenario: string): string | null {
		const i = scenario.indexOf('/');
		if (i <= 0 || i === scenario.length - 1) return null;
		const author = scenario.slice(0, i);
		const name = scenario.slice(i + 1);
		return `https://hub.crowdsec.net/author/${encodeURIComponent(author)}/configurations/${encodeURIComponent(name)}`;
	}

	function cscliCommand(scenario: string): string {
		return `sudo cscli scenarios inspect ${scenario}`;
	}

	let copyToast = $state<string | null>(null);
	let copyToastTimer: ReturnType<typeof setTimeout> | null = null;
	async function copyToClipboard(text: string): Promise<void> {
		try {
			await navigator.clipboard.writeText(text);
			copyToast = 'Copié ✓';
		} catch {
			copyToast = 'Copie indisponible';
		}
		if (copyToastTimer !== null) clearTimeout(copyToastTimer);
		copyToastTimer = setTimeout(() => {
			copyToast = null;
		}, 1800);
	}

	function onLiveFilterChange(): void {
		// Filter change re-fetches immediately, then continues
		// the polling cadence.
		void loadLive();
	}

	function refreshLive(): void {
		void loadLive();
	}

	// --- Shared helpers (same as the pre-CS.2 page) ---

	const SCOPE_COLOR: Record<string, string> = {
		ip: 'var(--status-down)',
		range: 'var(--status-warn)',
		country: 'var(--status-info)',
		as: 'var(--accent-cyan)'
	};
	function scopeColor(scope: string): string {
		return SCOPE_COLOR[scope] ?? 'var(--text-muted)';
	}

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

	function formatExpiry(iso: string): string {
		if (!iso) return '—';
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
		if (diffSecs < 3600) return `in ${Math.floor(diffSecs / 60)}m`;
		if (diffSecs < 86400) {
			const h = Math.floor(diffSecs / 3600);
			const m = Math.floor((diffSecs % 3600) / 60);
			return m > 0 ? `in ${h}h ${m}m` : `in ${h}h`;
		}
		return `in ${Math.floor(diffSecs / 86400)}d`;
	}

	// Origin breakdown — sorted by count desc so the
	// dominant source shows first in the badge row.
	const liveBreakdown = $derived(
		Object.entries(liveMeta.totalByOrigin)
			.sort((a, b) => b[1] - a[1])
	);

	function lastFetchedLabel(ts: number | null): string {
		if (ts === null) return '';
		const ago = Math.floor((Date.now() - ts) / 1000);
		if (ago < 5) return 'just now';
		if (ago < 60) return `${ago}s ago`;
		const mins = Math.floor(ago / 60);
		return `${mins}m ago`;
	}

	onMount(() => {
		void loadSnapshot();
	});

	onDestroy(() => {
		stopLivePolling();
	});
</script>

<PageHeader
	title="Decisions CrowdSec"
	subtitle="Drill-down complet : snapshot historique, état live LAPI, scenarios installés"
/>

<div class="tabs" role="tablist" aria-label="CrowdSec decisions tabs">
	<button
		type="button"
		role="tab"
		class="tab"
		class:active={activeTab === 'snapshot'}
		aria-selected={activeTab === 'snapshot'}
		data-testid="tab-snapshot"
		onclick={() => onTabChange('snapshot')}
	>
		Local snapshot
	</button>
	<button
		type="button"
		role="tab"
		class="tab"
		class:active={activeTab === 'live'}
		aria-selected={activeTab === 'live'}
		data-testid="tab-live"
		onclick={() => onTabChange('live')}
	>
		Live LAPI
	</button>
	<button
		type="button"
		role="tab"
		class="tab"
		class:active={activeTab === 'scenarios'}
		aria-selected={activeTab === 'scenarios'}
		data-testid="tab-scenarios"
		onclick={() => onTabChange('scenarios')}
	>
		Scenarios
	</button>
</div>

{#if activeTab === 'snapshot'}
	<p class="tab-subtitle">
		Snapshot Arenet-side des decisions reçues du LAPI.
		Cumulatif sur ~7 jours. Pour voir ce qui est enforced
		<em>maintenant</em>, ouvre le tab <strong>Live LAPI</strong>.
	</p>

	{#if snapshotLoading}
		<div class="loading-wrap">
			<Spinner />
		</div>
	{:else if snapshotError}
		<Card>
			<div class="error-wrap">{snapshotError}</div>
		</Card>
	{:else if snapshotDisabled}
		<Card>
			<div class="empty-wrap">
				<h3>CrowdSec mirror non configuré</h3>
				<p>
					Le bouncer CrowdSec côté Caddy + le consommateur
					StreamBouncer côté Arenet partagent la même clé LAPI.
					Configure-le via Settings → CrowdSec bouncer
					(<code>cscli bouncers add arenet</code> sur ton instance
					CrowdSec).
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
							: "Aucune décision dans la fenêtre. Le bouncer n'a jamais reçu de décision de LAPI."}
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
{:else if activeTab === 'live'}
	<p class="tab-subtitle">
		Decisions actives <strong>maintenant</strong> selon LAPI
		(live pass-through, polling 30s). Source de vérité pour
		"qu'est-ce qui est enforced en ce moment ?". Diffère du
		snapshot car le bouncer peut prendre quelques secondes à
		propager une nouvelle décision.
	</p>

	{#if liveErrorKind === 'not_configured'}
		<Card>
			<div class="empty-wrap" data-testid="live-not-configured">
				<h3>CrowdSec non configuré</h3>
				<p>
					Le bouncer n'est pas configuré. Va dans
					<a href="/settings" class="link">Settings → CrowdSec bouncer</a>
					pour saisir l'URL LAPI + la clé bouncer
					(<code>cscli bouncers add arenet</code>).
				</p>
			</div>
		</Card>
	{:else}
		<div class="filter-row">
			<div class="live-filters">
				<label class="filter-label">
					Scope
					<select bind:value={liveScope} onchange={onLiveFilterChange} data-testid="live-scope-filter">
						<option value="">tous</option>
						<option value="ip">ip</option>
						<option value="range">range</option>
						<option value="country">country</option>
						<option value="as">as</option>
					</select>
				</label>
				<label class="filter-label">
					Source
					<select bind:value={liveSource} onchange={onLiveFilterChange} data-testid="live-source-filter">
						<option value="">toutes</option>
						{#each liveBreakdown as [origin, count] (origin)}
							<option value={origin}>{origin} ({count})</option>
						{/each}
					</select>
				</label>
			</div>
			<div class="meta">
				{#if liveLoading && liveDecisions.length === 0}
					<Spinner size="sm" /> chargement…
				{:else}
					{liveMeta.total} décision{liveMeta.total > 1 ? 's' : ''}
					{#if liveLastFetched !== null}
						<span class="muted">· fetched {lastFetchedLabel(liveLastFetched)}</span>
					{/if}
					<button type="button" class="refresh-btn" onclick={refreshLive} aria-label="Refresh">
						↻
					</button>
				{/if}
			</div>
		</div>

		{#if liveBreakdown.length > 0}
			<div class="breakdown" data-testid="live-breakdown">
				{#each liveBreakdown as [origin, count] (origin)}
					<button
						type="button"
						class="breakdown-chip"
						class:selected={liveSource === origin}
						onclick={() => {
							liveSource = liveSource === origin ? '' : origin;
							onLiveFilterChange();
						}}
					>
						<span class="chip-count">{count}</span>
						<span class="chip-label">{origin}</span>
					</button>
				{/each}
			</div>
		{/if}

		{#if liveErrorKind === 'unreachable'}
			<Card>
				<div class="error-banner" role="alert" data-testid="live-unreachable">
					<strong>LAPI inaccessible :</strong> {liveErrorMsg ?? 'unknown error'}
					{#if liveDecisions.length > 0}
						<p class="muted">
							Données affichées : dernier polling réussi (le tableau
							ne s'efface pas sur une erreur transitoire).
						</p>
					{/if}
					<button type="button" class="retry-btn" onclick={refreshLive}>
						Réessayer
					</button>
				</div>
			</Card>
		{:else if liveErrorKind === 'other' && liveErrorMsg}
			<Card>
				<div class="error-wrap" role="alert">{liveErrorMsg}</div>
			</Card>
		{/if}

		<Card>
			<div class="block">
				{#if liveDecisions.length === 0 && !liveLoading && !liveErrorKind}
					<div class="empty-inline" data-testid="live-empty">
						Aucune décision active selon LAPI. Le bouncer surveille
						mais aucune source n'est actuellement bloquée. (CAPI sync
						tourne toutes les ~2–15 min ; un bouncer fraîchement
						démarré peut prendre quelques minutes à recevoir la
						blocklist communauté.)
					</div>
				{:else if liveDecisions.length > 0}
					<table>
						<thead>
							<tr>
								<th>Type</th>
								<th>Scope</th>
								<th>Value</th>
								<th>Source</th>
								<th>Scenario</th>
								<th>Expires</th>
							</tr>
						</thead>
						<tbody>
							{#each liveDecisions as d (d.id)}
								<tr>
									<td>
										<span class="badge" style:background={typeColor(d.type)}>
											{d.type || 'ban'}
										</span>
									</td>
									<td>
										<span class="badge" style:background={scopeColor(d.scope)}>
											{d.scope || '—'}
										</span>
									</td>
									<td class="mono">{d.value || '—'}</td>
									<td class="mono">{d.origin || 'unknown'}</td>
									<td class="mono">
										{shortScenario(d.scenario)}
										{#if isArenetAutoScenario(d.scenario)}
											<span class="badge auto-badge" title="Auto-classified by Arenet (Step P)">
												auto
											</span>
										{/if}
									</td>
									<td class="ts" title={d.expiresAt ?? ''}>
										{d.expiresAt ? formatExpiry(d.expiresAt) : d.duration || '—'}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}
			</div>
		</Card>
	{/if}
{:else if activeTab === 'scenarios'}
	<p class="tab-subtitle">
		Scenarios CrowdSec ayant fired sur les dernières
		<strong>{scenariosMeta.windowHours}h</strong>. Lecture LAPI
		<code>/v1/alerts</code> via les credentials Security Automation
		(<a href="/settings#security-automation" class="link">Settings → Security Automation</a>).
		Read-only — utilise <code>cscli</code> sur le host pour
		install/inspect/disable.
	</p>

	{#if scenariosLoading && scenarios.length === 0}
		<div class="loading-wrap">
			<Spinner />
		</div>
	{:else if scenariosErrorKind === 'not_configured'}
		<Card>
			<div class="empty-wrap" data-testid="scenarios-not-configured">
				<h3>Security Automation non configurée</h3>
				<p>
					Le tab Scenarios utilise les credentials du watcher
					Security Automation (machine_id + password) pour
					s'authentifier auprès de LAPI <code>/v1/alerts</code>.
					Va dans
					<a href="/settings" class="link">Settings → Security Automation</a>
					et saisis ton watcher (<code>cscli machines add arenet-writer</code>
					sur le host CrowdSec).
				</p>
				<p class="muted">
					Les autres tabs (Local snapshot, Live LAPI) fonctionnent
					indépendamment — ce coupling concerne uniquement le tab
					Scenarios.
				</p>
			</div>
		</Card>
	{:else}
		<div class="filter-row">
			<div class="meta">
				{#if scenariosLoading}
					<Spinner size="sm" /> chargement…
				{:else}
					{scenariosMeta.totalAlerts} alert{scenariosMeta.totalAlerts > 1 ? 's' : ''}
					sur {scenarios.length} scenario{scenarios.length > 1 ? 's' : ''}
					{#if scenariosLastFetched !== null}
						<span class="muted">· fetched {lastFetchedLabel(scenariosLastFetched)}</span>
					{/if}
					<button type="button" class="refresh-btn" onclick={refreshScenarios} aria-label="Refresh">
						↻
					</button>
				{/if}
			</div>
		</div>

		{#if scenariosErrorKind === 'unreachable'}
			<Card>
				<div class="error-banner" role="alert" data-testid="scenarios-unreachable">
					<strong>LAPI inaccessible :</strong>
					{scenariosErrorMsg ?? 'unknown error'}
					<button type="button" class="retry-btn" onclick={refreshScenarios}>
						Réessayer
					</button>
				</div>
			</Card>
		{:else if scenariosErrorKind === 'other' && scenariosErrorMsg}
			<Card>
				<div class="error-wrap" role="alert">{scenariosErrorMsg}</div>
			</Card>
		{/if}

		<Card>
			<div class="block">
				{#if scenarios.length === 0 && !scenariosLoading && !scenariosErrorKind}
					<div class="empty-inline" data-testid="scenarios-empty">
						Aucune activité scenario sur {scenariosMeta.windowHours}h.
						Soit aucune attaque détectée, soit Arenet logs pas encore
						acquis par CrowdSec (voir
						<code>docs/setup/crowdsec.md</code> §acquisition).
					</div>
				{:else if scenarios.length > 0}
					<table>
						<thead>
							<tr>
								<th>Scenario</th>
								<th>Alerts 24h</th>
								<th>Last seen</th>
								<th>Sample source</th>
							</tr>
						</thead>
						<tbody>
							{#each scenarios as s (s.name)}
								<tr
									class="scenario-row"
									data-testid="scenario-row"
									tabindex="0"
									role="button"
									aria-label={`Inspect ${s.name}`}
									onclick={() => openScenarioModal(s)}
									onkeydown={(e) => {
										if (e.key === 'Enter' || e.key === ' ') {
											e.preventDefault();
											openScenarioModal(s);
										}
									}}
								>
									<td class="mono">
										{shortScenario(s.name)}
										{#if s.name.includes('/')}
											<span class="muted org">{s.name.split('/')[0]}</span>
										{/if}
									</td>
									<td><strong>{s.alerts24h}</strong></td>
									<td class="ts" title={s.lastSeen}>
										{s.lastSeen ? relativeTs(s.lastSeen) : '—'}
									</td>
									<td class="mono">
										{s.sampleValue || '—'}
										{#if s.sampleScope}
											<span class="muted">({s.sampleScope})</span>
										{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}
			</div>
		</Card>
	{/if}

	{#if modalScenario !== null}
		{@const ms = modalScenario}
		<div
			class="modal-backdrop"
			role="presentation"
			onclick={closeScenarioModal}
			onkeydown={(e) => {
				if (e.key === 'Escape') closeScenarioModal();
			}}
		></div>
		<div
			class="modal"
			role="dialog"
			aria-modal="true"
			aria-labelledby="scenario-modal-title"
			data-testid="scenario-modal"
		>
			<header class="modal-h">
				<h3 id="scenario-modal-title">{ms.name}</h3>
				<button type="button" class="modal-close" onclick={closeScenarioModal} aria-label="Close">
					×
				</button>
			</header>
			<dl class="modal-dl">
				<dt>Alerts {scenariosMeta.windowHours}h</dt>
				<dd><strong>{ms.alerts24h}</strong></dd>

				{#if ms.lastSeen}
					<dt>Last seen</dt>
					<dd class="ts" title={ms.lastSeen}>
						{relativeTs(ms.lastSeen)}
					</dd>
				{/if}

				{#if ms.sampleScope || ms.sampleValue}
					<dt>Sample alert source</dt>
					<dd class="mono">
						{ms.sampleValue}
						{#if ms.sampleScope}
							<span class="muted">({ms.sampleScope})</span>
						{/if}
					</dd>
				{/if}
			</dl>

			<div class="modal-section">
				<h4>Documentation</h4>
				{#if hubURL(ms.name)}
					<a
						href={hubURL(ms.name)!}
						target="_blank"
						rel="noopener noreferrer"
						class="link"
						data-testid="modal-hub-link"
					>
						Voir sur le CrowdSec hub ↗
					</a>
				{:else}
					<p class="muted">
						Scenario non-namespaced (manual ou local) — pas de page hub.
					</p>
				{/if}
			</div>

			<div class="modal-section">
				<h4>Inspect</h4>
				<div class="copy-row">
					<code class="copy-code">{cscliCommand(ms.name)}</code>
					<button
						type="button"
						class="copy-btn"
						onclick={() => copyToClipboard(cscliCommand(ms.name))}
					>
						Copier
					</button>
				</div>
				<p class="muted">
					Pour install / modify / disable ce scenario, utilise
					<code>cscli</code> sur le host CrowdSec — pas modifiable
					depuis l'UI Arenet.
				</p>
			</div>

			{#if copyToast !== null}
				<div class="copy-toast" role="status">{copyToast}</div>
			{/if}
		</div>
	{/if}
{/if}

<style>
	.tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 0.5rem;
		border-bottom: 1px solid var(--border-subtle, var(--bg-hover));
	}
	.tab {
		background: transparent;
		color: var(--text-secondary);
		border: none;
		padding: 0.5rem 1rem;
		font-size: var(--text-sm);
		cursor: pointer;
		border-bottom: 2px solid transparent;
		margin-bottom: -1px;
	}
	.tab:hover {
		color: var(--text-primary);
	}
	.tab.active {
		color: var(--accent-cyan);
		border-bottom-color: var(--accent-cyan);
	}
	.tab-subtitle {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0.5rem 0 1rem 0;
		max-width: 56rem;
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
	.error-banner {
		padding: 0.75rem 1rem;
		color: var(--status-down);
		background: rgba(255, 0, 0, 0.05);
		border-radius: 4px;
	}
	.error-banner .muted {
		color: var(--text-muted);
		font-size: var(--text-xs, 11px);
		margin: 0.4rem 0 0 0;
	}
	.retry-btn {
		display: inline-block;
		margin-top: 0.5rem;
		background: var(--bg-surface);
		color: var(--text-primary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0.25rem 0.75rem;
		border-radius: 4px;
		font-size: var(--text-sm);
		cursor: pointer;
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
	.link {
		color: var(--accent-cyan);
		text-decoration: underline;
	}
	.filter-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		margin: 0 0 1rem 0;
		flex-wrap: wrap;
	}
	.active-toggle,
	.live-filters {
		display: flex;
		gap: 0.5rem;
		align-items: center;
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
	.filter-label {
		display: inline-flex;
		gap: 0.4rem;
		align-items: center;
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	.filter-label select {
		background: var(--bg-surface);
		color: var(--text-primary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0.2rem 0.5rem;
		border-radius: 4px;
		font-size: var(--text-sm);
	}
	.meta {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		display: inline-flex;
		gap: 0.4rem;
		align-items: center;
	}
	.meta .muted {
		color: var(--text-muted);
		font-size: var(--text-xs, 11px);
	}
	.refresh-btn {
		background: transparent;
		color: var(--text-secondary);
		border: none;
		padding: 0 0.4rem;
		font-size: 1rem;
		cursor: pointer;
	}
	.refresh-btn:hover {
		color: var(--accent-cyan);
	}
	.breakdown {
		display: flex;
		flex-wrap: wrap;
		gap: 0.4rem;
		margin: 0 0 0.75rem 0;
	}
	.breakdown-chip {
		display: inline-flex;
		gap: 0.4rem;
		align-items: baseline;
		background: var(--bg-surface);
		color: var(--text-primary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0.2rem 0.6rem;
		border-radius: 999px;
		font-size: var(--text-xs, 11px);
		cursor: pointer;
	}
	.breakdown-chip.selected {
		background: var(--accent-cyan);
		color: var(--text-inverse);
		border-color: var(--accent-cyan);
	}
	.chip-count {
		font-weight: 600;
		font-variant-numeric: tabular-nums;
	}
	.chip-label {
		font-family: var(--font-mono, monospace);
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
	/* Step CS.2.C — Scenarios tab */
	.scenario-row {
		cursor: pointer;
	}
	.scenario-row:hover {
		background: var(--bg-hover);
	}
	.scenario-row:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: -2px;
	}
	.muted {
		color: var(--text-muted);
		font-size: var(--text-xs, 11px);
	}
	.org {
		margin-left: 0.4rem;
		font-family: var(--font-mono, monospace);
	}
	.modal-backdrop {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.5);
		z-index: 50;
	}
	.modal {
		position: fixed;
		top: 50%;
		left: 50%;
		transform: translate(-50%, -50%);
		background: var(--bg-surface);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		border-radius: 6px;
		padding: 1.25rem 1.5rem;
		min-width: 28rem;
		max-width: 36rem;
		z-index: 51;
		box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
	}
	.modal-h {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		margin: 0 0 0.75rem 0;
		padding-bottom: 0.5rem;
		border-bottom: 1px solid var(--border-subtle, var(--bg-hover));
	}
	.modal-h h3 {
		margin: 0;
		font-size: var(--text-lg, 16px);
		font-family: var(--font-mono, monospace);
		color: var(--text-primary);
		word-break: break-all;
	}
	.modal-close {
		background: transparent;
		border: none;
		color: var(--text-secondary);
		font-size: 1.5rem;
		line-height: 1;
		cursor: pointer;
		padding: 0 0.25rem;
	}
	.modal-close:hover {
		color: var(--text-primary);
	}
	.modal-dl {
		display: grid;
		grid-template-columns: 10rem 1fr;
		gap: 0.4rem 0.75rem;
		margin: 0 0 1rem 0;
		font-size: var(--text-sm);
	}
	.modal-dl dt {
		color: var(--text-secondary);
	}
	.modal-dl dd {
		margin: 0;
		color: var(--text-primary);
	}
	.modal-section {
		margin: 0.75rem 0;
		padding-top: 0.5rem;
		border-top: 1px solid var(--border-subtle, var(--bg-hover));
	}
	.modal-section h4 {
		font-size: var(--text-sm);
		margin: 0 0 0.5rem 0;
		color: var(--text-secondary);
		font-weight: 500;
	}
	.copy-row {
		display: flex;
		gap: 0.5rem;
		align-items: stretch;
	}
	.copy-code {
		flex: 1;
		font-family: var(--font-mono, monospace);
		font-size: var(--text-xs, 11px);
		background: var(--bg-default, #000);
		color: var(--text-primary);
		padding: 0.4rem 0.6rem;
		border-radius: 4px;
		overflow-x: auto;
		white-space: nowrap;
	}
	.copy-btn {
		background: var(--bg-surface);
		color: var(--text-primary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0 0.75rem;
		border-radius: 4px;
		font-size: var(--text-sm);
		cursor: pointer;
	}
	.copy-btn:hover {
		background: var(--bg-hover);
	}
	.copy-toast {
		position: absolute;
		bottom: 0.75rem;
		right: 1.5rem;
		background: var(--accent-cyan);
		color: var(--text-inverse);
		padding: 0.3rem 0.7rem;
		border-radius: 4px;
		font-size: var(--text-xs, 11px);
		font-weight: 600;
	}
</style>
