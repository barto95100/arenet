<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R.4.3.c — /certs page. Replaces the R.2 stub.

  /certs is promoted from /settings/certificates to a top-level
  route per D5 outcome. The legacy /settings/certificates URL is
  redirected to /certs in R.4.5.

  Per spec §6.1 /certs audit, the page is mostly IMPLÉMENTÉ:
  - Managed domains list (ACME wildcard apex config) — Step O.
  - TLS-enabled routes list — Step C/J.
  - ACME provider visible per managed domain (ovh today).

  Per-cert metadata (issuer, SAN list, expiry date, ACME method
  per cert) is NOT in the API surface today — certmagic stores
  them but doesn't expose a listing endpoint. The mock's per-cert
  table shows issuer + dates + SAN per cert; this page renders
  the *configured* certs (one row per route + one per managed
  domain) without the runtime metadata. Tracked in
  docs/backlog-step-r.md.

  No mutation buttons in v1.4 — domain CRUD stays under /settings
  for now; this page is read-only. The mock's "Force renewal"
  action is feature work outside R.4.3.c scope.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import { settingsApi } from '$lib/api/settings';
	import { listRoutes } from '$lib/api/client';
	import { ApiError } from '$lib/api/types';
	import type { ManagedDomain, Route } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';

	let loading = $state(true);
	let domains = $state<ManagedDomain[]>([]);
	let routes = $state<Route[]>([]);

	const tlsRoutes = $derived(routes.filter((r) => r.tlsEnabled));
	const tlsCount = $derived(tlsRoutes.length);
	const managedCount = $derived(domains.length);

	async function load(): Promise<void> {
		try {
			const [rs, ds] = await Promise.all([
				listRoutes(),
				settingsApi.listManagedDomains().catch(() => ({ domains: [] }))
			]);
			routes = rs;
			domains = ds.domains ?? [];
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
</script>

<svelte:head>
	<title>Certificates · Arenet</title>
</svelte:head>

<PageHeader
	eyebrow="Sécurité · Certificats"
	title="Certificates"
	subtitle="ACME-managed TLS certificates. Wildcard apex configuration ships under managed domains; per-route certs are auto-provisioned by certmagic when TLS is enabled."
/>

{#if loading}
	<div class="loading-wrap"><Spinner /></div>
{:else}
	<div class="kpis">
		<div class="kpi">
			<div class="kpi-label">Managed domains</div>
			<div class="kpi-val">{managedCount}</div>
			<div class="kpi-foot">DNS-01 wildcard apex</div>
		</div>
		<div class="kpi">
			<div class="kpi-label">TLS-enabled routes</div>
			<div class="kpi-val">{tlsCount}</div>
			<div class="kpi-foot">across {routes.length} total routes</div>
		</div>
		<div class="kpi">
			<div class="kpi-label">ACME method</div>
			<div class="kpi-val mode">Auto</div>
			<div class="kpi-foot">HTTP-01 + DNS-01 (wildcard)</div>
		</div>
		<div class="kpi">
			<div class="kpi-label">Issuer</div>
			<div class="kpi-val mode">Let's Encrypt</div>
			<div class="kpi-foot">certmagic default</div>
		</div>
	</div>

	<!-- Per-cert metadata gap notice -->
	<div class="ro-banner">
		<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
			<circle cx="8" cy="8" r="6.5" />
			<path d="M8 5v3.5M8 11v.5" />
		</svg>
		<span>Per-certificate runtime metadata (issuer, SAN list, expiry, last renewal) is not exposed via the Arenet API today. The lists below show the <em>configured</em> certificate scope — what certmagic provisions on behalf of each route or managed domain.</span>
	</div>

	<!-- Managed domains -->
	<div class="card">
		<div class="card-h">
			<h3>Managed domains</h3>
			<a href="/settings" class="meta-link">Configure →</a>
		</div>
		{#if domains.length === 0}
			<div class="empty-row">No managed domains configured. Add one from <a href="/settings">/settings</a> to enable DNS-01 wildcard ACME.</div>
		{:else}
			<table>
				<thead>
					<tr>
						<th>Apex</th>
						<th>Include apex</th>
						<th>Provider</th>
						<th>Mode</th>
					</tr>
				</thead>
				<tbody>
					{#each domains as d (d.apex)}
						<tr>
							<td class="mono">{d.apex}</td>
							<td class="mono">{d.includeApex ? 'yes' : 'wildcard only'}</td>
							<td class="mono">{d.provider}</td>
							<td>
								<span class="pill info">DNS-01</span>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</div>

	<!-- TLS-enabled routes -->
	<div class="card">
		<div class="card-h">
			<h3>TLS-enabled routes</h3>
			<a href="/routes" class="meta-link">Manage →</a>
		</div>
		{#if tlsRoutes.length === 0}
			<div class="empty-row">No TLS-enabled routes. Enable TLS on a route in <a href="/routes">/routes</a> to have certmagic provision a certificate.</div>
		{:else}
			<table>
				<thead>
					<tr>
						<th>Host</th>
						<th>Aliases</th>
						<th>HTTPS redirect</th>
						<th>ACME mode</th>
					</tr>
				</thead>
				<tbody>
					{#each tlsRoutes as r (r.id)}
						<tr>
							<td class="mono">{r.host}</td>
							<td class="mono dim">{(r.aliases ?? []).length > 0 ? (r.aliases ?? []).join(', ') : '—'}</td>
							<td>
								{#if r.redirectToHttps}
									<span class="pill ok">301 → https</span>
								{:else}
									<span class="dim">—</span>
								{/if}
							</td>
							<td>
								<span class="pill info">Auto (HTTP-01 or DNS-01)</span>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
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
	.meta-link {
		margin-left: auto;
		color: var(--accent);
		font-size: 12.5px;
		text-decoration: none;
	}
	.meta-link:hover { text-decoration: underline; }

	.kpis {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 12px;
		margin-bottom: 14px;
	}
	.kpi {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 14px 16px;
	}
	.kpi-label { color: var(--fg-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; font-family: var(--font-mono); margin-bottom: 6px; }
	.kpi-val { color: var(--fg); font-size: 24px; font-weight: 500; letter-spacing: -0.02em; }
	.kpi-val.mode { font-size: 18px; }
	.kpi-foot { color: var(--fg-muted); font-size: 11.5px; margin-top: 8px; font-family: var(--font-mono); }

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
	.ro-banner em { color: var(--fg); font-style: italic; }

	table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
	th, td { padding: 8px 10px; text-align: left; }
	th { color: var(--fg-muted); font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }
	td { color: var(--fg); border-bottom: 1px solid var(--border); }
	tbody tr:last-child td { border-bottom: none; }
	.mono { font-family: var(--font-mono); font-size: 12px; }
	.dim { color: var(--fg-dim); }

	.pill {
		display: inline-flex;
		align-items: center;
		padding: 2px 8px;
		border-radius: 999px;
		font-family: var(--font-mono);
		font-size: 10px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.pill.ok { background: color-mix(in oklch, var(--ok) 18%, transparent); color: var(--ok); }
	.pill.info { background: color-mix(in oklch, var(--info) 18%, transparent); color: var(--info); }

	.empty-row {
		color: var(--fg-muted);
		font-size: 12.5px;
		padding: 24px;
		text-align: center;
	}
	.empty-row a { color: var(--accent); text-decoration: none; }
	.empty-row a:hover { text-decoration: underline; }

	.loading-wrap { display: flex; justify-content: center; padding: 48px; }
</style>
