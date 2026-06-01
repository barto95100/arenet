<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R.4.3.b — /security page REPURPOSE per D4 reframing.

  Previously (Step M.3 + Q.4): WAF event surface — recent events
  table, per-OWASP-category aggregation, attackers union, "by-rule"
  drill-down, mixed events widget (WAF + throttle + auth-failures).
  That content is now distributed across:
    - Dashboard (/dashboard)         → "Recent WAF events" card.
    - /security/decisions            → CrowdSec decisions timeline
                                       (per D8 outcome — preserved,
                                       reachable by URL + /waf link).
    - /security/[routeId]            → per-route drill-down
                                       (per D8 outcome — preserved,
                                       reachable via /routes detail).
    - /waf                           → OWASP CRS category counts.

  This page now ships as the SECURITY POSTURE OVERVIEW — a read-
  only summary of which security policies are active across the
  stack. Per spec §6.1 /security audit, most policy editing is
  out-of-scope backend (TLS / headers / CSP). What we DO have
  exposed is auth providers config (Step K.2 OIDC etc.); the
  page summarises it and links to /settings for editing.

  Sections (in order, top-down):

  1. TLS — read-only Caddy defaults card. No mutation API; the
     mock's edit controls are deferred.
  2. Security headers — empty-state card with a coming-soon
     banner. Backend has zero header injection middleware today;
     spec §6.1 /security.GAP BACKEND.
  3. Auth providers — summary card showing the current OIDC
     state (enabled / kind / allowlist size) + a hint that
     forward-auth + basic-auth live per-route under /routes
     detail. Link to /settings for OIDC config.
  4. Decisions + per-route drill-down link cards (D8 entry
     points so operators landing on /security still reach the
     legacy surfaces).
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import { settingsApi } from '$lib/api/settings';
	import type { OIDCConfig } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import { ApiError } from '$lib/api/types';

	let loading = $state(true);
	let oidc = $state<OIDCConfig | null>(null);

	async function load(): Promise<void> {
		try {
			oidc = await settingsApi.getOIDCConfig();
		} catch (err) {
			if (err instanceof ApiError) {
				pushToast(err.message, 'danger');
			}
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		void load();
	});

	const oidcStatusLabel = $derived(
		oidc?.enabled ? 'Enabled' : oidc?.configured ? 'Configured · disabled' : 'Not configured'
	);
</script>

<svelte:head>
	<title>Security · Arenet</title>
</svelte:head>

<PageHeader
	eyebrow="Sécurité · Posture"
	title="Security posture"
	subtitle="Read-only summary of TLS, headers and authentication policies active on this gateway. Detailed editing surfaces are linked from each card."
/>

{#if loading}
	<div class="loading-wrap"><Spinner /></div>
{:else}
	<!-- TLS read-only card -->
	<div class="card">
		<div class="card-h">
			<h3>TLS</h3>
			<div class="meta">Caddy defaults · read-only in v1.4</div>
		</div>
		<div class="ro-banner">
			<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
				<circle cx="8" cy="8" r="6.5" />
				<path d="M8 5v3.5M8 11v.5" />
			</svg>
			<span>Granular TLS configuration (min version, curves, ciphers, HTTP/3, OCSP, session tickets) is deferred to a future step. Caddy's defaults are shown below.</span>
		</div>
		<div class="kv-grid">
			<div class="kv"><span class="k">Minimum version</span><span class="v">TLS 1.2</span></div>
			<div class="kv"><span class="k">HTTP/3 (QUIC)</span><span class="v">Enabled by default</span></div>
			<div class="kv"><span class="k">OCSP stapling</span><span class="v">Enabled</span></div>
			<div class="kv"><span class="k">Session tickets</span><span class="v">Auto-rotated</span></div>
			<div class="kv"><span class="k">Cipher selection</span><span class="v">Caddy auto</span></div>
			<div class="kv"><span class="k">Curves</span><span class="v">Caddy auto</span></div>
		</div>
	</div>

	<!-- Security headers placeholder -->
	<div class="card">
		<div class="card-h">
			<h3>Security headers</h3>
			<div class="meta">HSTS · X-Frame · CSP · Referrer-Policy</div>
		</div>
		<div class="empty">
			<p>Centralised security-header policy is not yet exposed by Arenet.</p>
			<p class="dim">
				Today, individual headers can be injected per-route via the route detail's <a href="/routes">custom headers</a>
				textarea. A global policy controller (HSTS / X-Frame-Options / CSP with nonce / Referrer-Policy /
				Permissions-Policy) is deferred to a future step. Tracked in <span class="mono">docs/backlog-step-r.md</span>.
			</p>
		</div>
	</div>

	<!-- Auth providers summary -->
	<div class="card">
		<div class="card-h">
			<h3>Authentication providers</h3>
			<a href="/settings" class="meta-link">Configure →</a>
		</div>
		<div class="kv-grid">
			<div class="kv">
				<span class="k">OIDC (SSO)</span>
				<span class="v">
					<span class="pill" class:on={oidc?.enabled} class:configured={oidc?.configured && !oidc?.enabled}>
						{oidcStatusLabel}
					</span>
				</span>
			</div>
			{#if oidc?.enabled}
				<div class="kv">
					<span class="k">Issuer</span>
					<span class="v mono">{oidc.issuerUrl || '—'}</span>
				</div>
				<div class="kv">
					<span class="k">Provider kind</span>
					<span class="v mono">{oidc.kind || 'generic'}</span>
				</div>
				<div class="kv">
					<span class="k">Allowlist</span>
					<span class="v mono">{oidc.allowedIdentities?.length ?? 0} entries</span>
				</div>
			{/if}
			<div class="kv">
				<span class="k">Forward-auth</span>
				<span class="v dim">Per-route — see <a href="/routes">/routes</a> detail</span>
			</div>
			<div class="kv">
				<span class="k">Basic auth</span>
				<span class="v dim">Per-route — see <a href="/routes">/routes</a> detail</span>
			</div>
		</div>
	</div>

	<!-- D8 sub-route entry points -->
	<div class="card">
		<div class="card-h">
			<h3>Security events &amp; decisions</h3>
		</div>
		<div class="link-list">
			<a href="/security/decisions" class="link-row">
				<div>
					<b>CrowdSec decisions timeline</b>
					<span>Full timeline of blocked IPs (auto + community list contributions). Step N read-side surface.</span>
				</div>
				<span class="arrow">→</span>
			</a>
			<a href="/dashboard" class="link-row">
				<div>
					<b>Dashboard event feed</b>
					<span>Recent WAF blocks across all routes. For per-route drill-down, open a route from /routes and click "Security".</span>
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
	.card-h {
		display: flex;
		align-items: center;
		gap: 12px;
		margin-bottom: 12px;
	}
	.card-h h3 { color: var(--fg); font-size: 13.5px; font-weight: 500; margin: 0; }
	.card-h .meta {
		margin-left: auto;
		color: var(--fg-dim);
		font-size: 11.5px;
		font-family: var(--font-mono);
	}
	.meta-link {
		margin-left: auto;
		color: var(--accent);
		font-size: 12.5px;
		text-decoration: none;
	}
	.meta-link:hover { text-decoration: underline; }

	.ro-banner {
		display: flex;
		align-items: flex-start;
		gap: 8px;
		padding: 10px 12px;
		margin-bottom: 14px;
		background: color-mix(in oklch, var(--warn) 8%, transparent);
		border: 1px solid color-mix(in oklch, var(--warn) 28%, transparent);
		border-radius: var(--radius-sm);
		color: var(--fg-muted);
		font-size: 12px;
		line-height: 1.5;
	}
	.ro-banner svg { flex: none; color: var(--warn); margin-top: 2px; }

	.kv-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 8px 16px;
	}
	.kv {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 6px 0;
		border-bottom: 1px solid var(--border);
		font-size: 12.5px;
	}
	.kv:last-child { border-bottom: none; }
	.kv .k { color: var(--fg-muted); flex: 0 0 140px; }
	.kv .v { color: var(--fg); flex: 1; min-width: 0; }
	.kv .v a { color: var(--accent); text-decoration: none; }
	.kv .v a:hover { text-decoration: underline; }

	.pill {
		display: inline-flex;
		align-items: center;
		padding: 2px 8px;
		border-radius: 999px;
		font-family: var(--font-mono);
		font-size: 10px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		background: color-mix(in oklch, var(--fg-muted) 18%, transparent);
		color: var(--fg-muted);
	}
	.pill.on {
		background: color-mix(in oklch, var(--ok) 18%, transparent);
		color: var(--ok);
	}
	.pill.configured {
		background: color-mix(in oklch, var(--warn) 18%, transparent);
		color: var(--warn);
	}

	.empty {
		padding: 8px 0;
	}
	.empty p { color: var(--fg); margin: 0 0 8px; font-size: 13px; }
	.empty p.dim { color: var(--fg-muted); font-size: 12.5px; line-height: 1.6; }
	.empty a { color: var(--accent); text-decoration: none; }
	.empty a:hover { text-decoration: underline; }

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

	.mono { font-family: var(--font-mono); font-size: 12px; }
	.dim { color: var(--fg-muted); }

	.loading-wrap { display: flex; justify-content: center; padding: 48px; }
</style>
