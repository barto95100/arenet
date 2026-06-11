<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R.4.3.a — /waf page. Replaces the R.2 stub.

  Per spec §6.1 WAF audit, this page renders ONLY the parts
  backed by real backend instrumentation today:

  - 4 KPI tiles: requests inspected, blocked, mode, paranoia.
    Mode + paranoia are STATIC reads of Coraza defaults (no
    backend API to mutate them today — read-only display).
  - OWASP CRS category event-count grid: read-only tiles per
    category, derived from summary.wafBlocksByCategory. The
    mock shows on/off switches per category; backend has NO
    such API (spec §6.1 GAP BACKEND). The grid surfaces the
    counts without claiming togglability — and ships an inline
    banner explicitly stating "granular control deferred".

  Omitted entirely (per spec §6.1):
  - Rate-limit named-rules card: backend has per-route limits
    only (Step Q); no named-rules engine. Operators configure
    rate limits in /routes detail.
  - IP allow/deny manual lists card: backend has NO manual
    list storage. The link "Voir toute la timeline →" points
    to /security?tab=crowdsec (per D8, post-CS.3) which is
    the CrowdSec drill-down — the closest real surface.
  - Geo-blocking section: zero backend (no MaxMind dep).
    Omitted; tracked in backlog #R-WAF-geo.

  All data from existing endpoints (anti-regression AC #1):
  - GET /api/v1/metrics/summary (Step L + M extensions).
  - GET /api/v1/security/events (Step M).
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import { fetchSummary } from '$lib/api/metrics';
	import { ApiError } from '$lib/api/types';
	import type { SummaryResponse, OwaspCategory } from '$lib/api/types';
	import { ALL_OWASP_CATEGORIES } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';

	let loading = $state(true);
	let loadError = $state<string | null>(null);
	let summary = $state<SummaryResponse | null>(null);

	const disabled = $derived(summary?.disabled === true);

	// #R-WAF-METRICS-WINDOW-1MIN-PROJECTION — pre-fix these
	// were per-minute values multiplied by 60×24 to project
	// "/ 24h". Post-fix the summary endpoint returns 24h
	// totals natively; the frontend reads them raw.
	const totalInspected24h = $derived(summary?.totalReq ?? 0);
	const totalBlocked24h = $derived(summary?.totalWafBlocked ?? 0);
	const totalDetected24h = $derived(summary?.totalWafDetected ?? 0);
	const blockRatioPct = $derived(
		(() => {
			if (totalInspected24h <= 0) return 0;
			return (
				Math.round((totalBlocked24h / totalInspected24h) * 10000) / 100
			);
		})()
	);

	// Per-category counts. Pre-#R-DASHBOARD-WAF-COUNTERS-
	// ZERO the rows read from a single wafBlocksByCategory
	// map that silently aggregated BLOCK and DETECT
	// populations; post-fix each row reports the two
	// separately so the operator sees real attack volume
	// on detect-mode routes.
	const categoryRows = $derived.by(() => {
		const blocks = summary?.wafBlocksByCategory ?? {};
		const detects = summary?.wafDetectsByCategory ?? {};
		return ALL_OWASP_CATEGORIES.map((cat) => ({
			cat,
			label: catLabel(cat),
			description: catDescription(cat),
			block24h: blocks[cat] ?? 0,
			detect24h: detects[cat] ?? 0
		}));
	});

	function catLabel(c: OwaspCategory): string {
		switch (c) {
			case 'SQLi':
				return 'SQL Injection';
			case 'XSS':
				return 'Cross-site scripting';
			case 'RCE':
				return 'Remote Code Execution';
			case 'LFI':
				return 'Local File Inclusion';
			case 'PROTOCOL':
				return 'HTTP protocol violations';
			case 'OTHER':
				return 'Other Coraza rules';
		}
	}
	function catDescription(c: OwaspCategory): string {
		switch (c) {
			case 'SQLi':
				return 'CRS 942xxx — UNION SELECT, blind SQLi, malicious comments.';
			case 'XSS':
				return 'CRS 941xxx — JS payloads, HTML vectors, encoding evasion.';
			case 'RCE':
				return 'CRS 932xxx — shell command injection, eval, deserialization.';
			case 'LFI':
				return 'CRS 930xxx — path traversal, /etc/passwd, config exfil.';
			case 'PROTOCOL':
				return 'CRS 920xxx — malformed requests, header smuggling.';
			case 'OTHER':
				return 'Uncategorised rules (catch-all for unknown CRS ranges).';
		}
	}

	async function load(): Promise<void> {
		loading = true;
		loadError = null;
		try {
			summary = await fetchSummary();
		} catch (err) {
			loadError = err instanceof ApiError ? err.message : 'failed to load summary';
			pushToast(loadError, 'danger');
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		void load();
	});
</script>

<svelte:head>
	<title>WAF · Arenet</title>
</svelte:head>

<PageHeader
	eyebrow="Sécurité · Web Application Firewall"
	title="WAF rules"
	subtitle="The Coraza engine applies the OWASP Core Rule Set. Event counts shown below reflect blocked requests over the last 24h, per category."
>
	{#snippet actions()}
		<a href="/security?tab=crowdsec" class="tb-btn">History →</a>
		<button class="tb-btn primary" disabled title="Coming soon — apply staged config">Apply changes</button>
	{/snippet}
</PageHeader>

{#if loading}
	<div class="loading-wrap"><Spinner /></div>
{:else if loadError}
	<div class="card error">{loadError}</div>
{:else if disabled}
	<div class="card empty">
		<h3>Observability subsystem disabled</h3>
		<p>WAF event counts are surfaced via the observability subsystem, which failed to start. Coraza is still inspecting traffic; only the dashboard projection is missing.</p>
	</div>
{:else}
	<!-- KPIs -->
	<div class="kpis">
		<div class="kpi">
			<div class="kpi-label">Requests inspected</div>
			<div class="kpi-val">{totalInspected24h.toLocaleString()}<span class="unit">/ 24h</span></div>
			<div class="kpi-foot">summed over rolling 24h window</div>
		</div>
		<!--
			#R-DASHBOARD-WAF-COUNTERS-ZERO — Blocked and
			Detected reported as parallel tiles. On a homelab
			with every route in wafMode=detect (the
			recommended I.4 default), the Blocked tile stays
			at zero while Detected carries the real attack
			volume.
		-->
		<div class="kpi" data-testid="kpi-blocked">
			<div class="kpi-label">Blocked</div>
			<div class="kpi-val">{totalBlocked24h.toLocaleString()}</div>
			<div class="kpi-foot">ratio {blockRatioPct}%</div>
		</div>
		<div class="kpi" data-testid="kpi-detected">
			<div class="kpi-label">Detected</div>
			<div class="kpi-val">{totalDetected24h.toLocaleString()}</div>
			<div class="kpi-foot">detect-mode (request passed through)</div>
		</div>
		<div class="kpi">
			<div class="kpi-label">Mode</div>
			<div class="kpi-val mode">Blocking</div>
			<div class="kpi-foot">detection + block enabled</div>
		</div>
		<div class="kpi">
			<div class="kpi-label">Paranoia level</div>
			<div class="kpi-val">2<span class="unit">/ 4</span></div>
			<div class="kpi-foot">Coraza default — read-only in v1.4</div>
		</div>
	</div>

	<!-- OWASP CRS categories — read-only event-count tiles -->
	<div class="card">
		<div class="card-h">
			<h3>OWASP Core Rule Set — categories</h3>
			<div class="meta">CRS via Coraza · {ALL_OWASP_CATEGORIES.length} categories</div>
		</div>
		<div class="ro-notice">
			<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
				<circle cx="8" cy="8" r="6.5" />
				<path d="M8 5v3.5M8 11v.5" />
			</svg>
			<span>Granular category control (enable/disable per category) is deferred to a future step. Counts shown below are read-only.</span>
		</div>
		<!--
			#R-DASHBOARD-WAF-COUNTERS-ZERO — each category
			row now reports BLOCK and DETECT counts
			separately, matching the split on the KPI tiles
			above. Pre-fix the single `blocks / 24h` cell
			silently aggregated both populations under a
			misleading "blocks" label; this resserement
			makes the operator-visible numbers honest about
			what the WAF actually did with the request.
		-->
		<div class="cat-grid">
			{#each categoryRows as row (row.cat)}
				<div class="cat-row" data-testid="cat-row-{row.cat}">
					<div class="cat-info">
						<div class="cat-name">{row.label}</div>
						<div class="cat-desc">{row.description}</div>
					</div>
					<div class="cat-meta">
						<div class="cat-meta-val cat-meta-block">{row.block24h.toLocaleString()}</div>
						<div class="cat-meta-foot">blocks / 24h</div>
					</div>
					<div class="cat-meta">
						<div class="cat-meta-val cat-meta-detect">{row.detect24h.toLocaleString()}</div>
						<div class="cat-meta-foot">detects / 24h</div>
					</div>
				</div>
			{/each}
		</div>
	</div>

	<!-- Per-route rate limits + IP lists redirect -->
	<div class="card">
		<div class="card-h">
			<h3>Rate limits &amp; IP enforcement</h3>
		</div>
		<div class="link-list">
			<a href="/routes" class="link-row">
				<div>
					<b>Per-route rate limits</b>
					<span>Configured on each route's detail panel. Step Q ships per-route tier-1 / tier-2 limits.</span>
				</div>
				<span class="arrow">→</span>
			</a>
			<a href="/security?tab=crowdsec" class="link-row">
				<div>
					<b>Active CrowdSec decisions</b>
					<span>The full timeline of blocked IPs (auto + manual). Manual list management is deferred (see backlog).</span>
				</div>
				<span class="arrow">→</span>
			</a>
		</div>
	</div>
{/if}

<style>
	.card {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 14px 16px;
		margin-bottom: 14px;
	}
	.card.error { color: var(--status-down); }
	.card.empty {
		padding: 32px;
		text-align: center;
	}
	.card.empty h3 { color: var(--fg); font-size: 16px; margin: 0 0 8px; font-weight: 500; }
	.card.empty p { color: var(--fg-muted); font-size: 13px; max-width: 480px; margin: 0 auto; line-height: 1.6; }

	.card-h {
		display: flex;
		align-items: center;
		gap: 12px;
		margin-bottom: 12px;
	}
	.card-h h3 { color: var(--fg); font-size: 13.5px; font-weight: 500; margin: 0; }
	.card-h .meta { margin-left: auto; color: var(--fg-dim); font-size: 11.5px; font-family: var(--font-mono); }

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
	.kpi-val { color: var(--fg); font-size: 24px; font-weight: 500; letter-spacing: -0.02em; }
	.kpi-val.mode { font-size: 20px; }
	.kpi-val .unit { color: var(--fg-dim); font-size: 12px; margin-left: 4px; font-weight: 400; }
	.kpi-foot { color: var(--fg-muted); font-size: 11.5px; margin-top: 8px; font-family: var(--font-mono); }

	.ro-notice {
		display: flex;
		align-items: flex-start;
		gap: 8px;
		padding: 10px 12px;
		margin-bottom: 14px;
		background: color-mix(in oklch, var(--status-warn) 8%, transparent);
		border: 1px solid color-mix(in oklch, var(--status-warn) 28%, transparent);
		border-radius: var(--radius-sm);
		color: var(--fg-muted);
		font-size: 12px;
		line-height: 1.5;
	}
	.ro-notice svg { flex: none; color: var(--status-warn); margin-top: 2px; }

	.cat-grid {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.cat-row {
		display: flex;
		align-items: flex-start;
		gap: 12px;
		padding: 10px 12px;
		background: var(--surface-2);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
	}
	.cat-info { flex: 1; min-width: 0; }
	.cat-name { color: var(--fg); font-size: 13px; font-weight: 500; margin-bottom: 2px; }
	.cat-desc { color: var(--fg-muted); font-size: 11.5px; line-height: 1.5; }
	.cat-meta { text-align: right; flex: none; font-family: var(--font-mono); margin-left: 18px; min-width: 80px; }
	.cat-meta-val { color: var(--fg); font-size: 16px; font-weight: 500; }
	/* #R-DASHBOARD-WAF-COUNTERS-ZERO — colour-code BLOCK red and DETECT amber so the split is recognisable at a glance. */
	.cat-meta-val.cat-meta-block { color: var(--status-down); }
	.cat-meta-val.cat-meta-detect { color: var(--status-warn); }
	.cat-meta-foot { color: var(--fg-dim); font-size: 10.5px; margin-top: 2px; text-transform: uppercase; letter-spacing: 0.04em; }

	.link-list {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.link-row {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 12px 14px;
		background: var(--surface-2);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		text-decoration: none;
		transition: background 0.12s, border-color 0.12s;
	}
	.link-row:hover {
		background: var(--surface-hi);
		border-color: var(--border-hi);
	}
	.link-row > div { flex: 1; min-width: 0; }
	.link-row b { display: block; color: var(--fg); font-weight: 500; font-size: 13px; margin-bottom: 2px; }
	.link-row span { color: var(--fg-muted); font-size: 12px; line-height: 1.5; }
	.arrow { color: var(--accent); font-size: 18px; flex: none; }

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
		text-decoration: none;
	}
	.tb-btn:hover:not(:disabled) {
		color: var(--fg);
		background: var(--surface-2);
	}
	.tb-btn.primary {
		background: var(--accent);
		color: #fff;
		border-color: transparent;
		font-weight: 500;
	}
	.tb-btn.primary:disabled {
		filter: saturate(0.6);
		cursor: not-allowed;
	}
	.tb-btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.loading-wrap { display: flex; justify-content: center; padding: 48px; }
</style>
