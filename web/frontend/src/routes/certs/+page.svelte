<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  /certs — top-level Sécurité IA entry for certificate visibility
  and managed-domain configuration.

  History:
  - R.2 (`4691eb2`): shipped as a minimal stub.
  - R.4.3.c: promoted to a read-only catalog summarising managed
    domains + TLS-enabled routes. The full CRUD stayed at
    `/settings` (the "softer split" — backlog §R-6 PARTIAL).
  - #R-6 Pack A (this commit): completes the §R-6 migration. The
    SSL/Certificates editor moves from `/settings` to `/certs`;
    `/settings` no longer has an SSL section. The page also gains
    an auto-renewal info card so the certmagic-driven automatic
    renewal behaviour is visible to operators (previously
    invisible — the UI never said anything about it).

  Pack B (per-certificate runtime metadata: issuer, SAN list,
  expiry, last-renewal timestamp) is a separate Step T concern —
  it requires a backend API surface that doesn't exist today.
  The ℹ banner about that gap stays in place until Pack B lands.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import Button from '$lib/components/Button.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import { settingsApi } from '$lib/api/settings';
	import { listRoutes } from '$lib/api/client';
	import { ApiError } from '$lib/api/types';
	import type {
		ManagedDomain,
		ManagedDomainProvider,
		ManagedDomainRevertTo,
		Route,
		DNSProviderOVH,
	} from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';

	let loading = $state(true);
	let domains = $state<ManagedDomain[]>([]);
	let routes = $state<Route[]>([]);

	// DNS provider state — used to render the "DNS provider
	// unconfigured" warning in the editor. The page reads it on
	// load and on every successful managed-domain mutation
	// (settings already mirrors the same dependency). nil-safe
	// when the GET fails (network blip / not-configured shape).
	let dnsProviderConfigured = $state(false);

	// Editor form state — mirrors the settings page's mdForm
	// shape pre-migration. `apex` placeholder works as the
	// example for the inferred wildcard hint string.
	let mdForm = $state<{
		apex: string;
		includeApex: boolean;
		provider: ManagedDomainProvider;
	}>({
		apex: '',
		includeApex: true,
		provider: 'ovh',
	});
	let mdSubmitting = $state(false);
	let mdFormError = $state<string | null>(null);

	// Delete-confirmation modal state. Mirrors the settings
	// page pre-migration verbatim — the revertTo dropdown is
	// the spec O.4 AC #21 affordance and must not change shape.
	let mdDeleteOpen = $state(false);
	let mdDeleteApex = $state('');
	let mdDeleteRevertTo = $state<ManagedDomainRevertTo>('');
	let mdDeleteError = $state<string | null>(null);

	const tlsRoutes = $derived(routes.filter((r) => r.tlsEnabled));
	const tlsCount = $derived(tlsRoutes.length);
	const managedCount = $derived(domains.length);

	// Warning shown above the editor when no DNS provider is
	// configured: ACME wildcard issuance via DNS-01 is disabled,
	// the editor stays enabled so the operator can stage a
	// managed domain ahead of configuring OVH credentials.
	const sslDNSUnconfigured = $derived(!dnsProviderConfigured);

	async function loadDNSProvider(): Promise<void> {
		try {
			const p: DNSProviderOVH = await settingsApi.getDNSProviderOVH();
			dnsProviderConfigured = p.configured;
		} catch {
			// Treat fetch failures as "not configured" so the
			// warning still surfaces. Logging is left to the
			// upstream request helper.
			dnsProviderConfigured = false;
		}
	}

	async function loadManagedDomains(): Promise<void> {
		try {
			const res = await settingsApi.listManagedDomains();
			domains = res.domains ?? [];
		} catch (err) {
			if (err instanceof ApiError) pushToast(err.message, 'danger');
		}
	}

	async function load(): Promise<void> {
		try {
			const [rs] = await Promise.all([
				listRoutes(),
				loadManagedDomains(),
				loadDNSProvider(),
			]);
			routes = rs;
		} catch (err) {
			if (err instanceof ApiError) pushToast(err.message, 'danger');
		} finally {
			loading = false;
		}
	}

	async function submitManagedDomain(): Promise<void> {
		mdSubmitting = true;
		mdFormError = null;
		try {
			await settingsApi.createManagedDomain({
				apex: mdForm.apex.trim(),
				includeApex: mdForm.includeApex,
				provider: mdForm.provider,
			});
			mdForm.apex = '';
			mdForm.includeApex = true;
			await loadManagedDomains();
		} catch (err) {
			mdFormError = err instanceof ApiError ? err.message : String(err);
		} finally {
			mdSubmitting = false;
		}
	}

	function openDeleteManagedDomain(apex: string): void {
		mdDeleteApex = apex;
		mdDeleteRevertTo = '';
		mdDeleteError = null;
		mdDeleteOpen = true;
	}

	async function confirmDeleteManagedDomain(): Promise<void> {
		mdDeleteError = null;
		try {
			await settingsApi.deleteManagedDomain(mdDeleteApex, mdDeleteRevertTo);
			mdDeleteOpen = false;
			await loadManagedDomains();
		} catch (err) {
			mdDeleteError = err instanceof ApiError ? err.message : String(err);
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

	<!-- Auto-renewal info card (Pack A).
	     Placed between the KPI row and the read-only metadata
	     banner so it's the first content the operator sees after
	     the at-a-glance numbers. Reassures that renewal is
	     automatic — addresses the operator's "is renewal
	     automated?" gap. -->
	<div class="renewal-card" data-testid="auto-renewal-card">
		<div class="renewal-icon" aria-hidden="true">
			<svg
				width="20"
				height="20"
				viewBox="0 0 24 24"
				fill="none"
				stroke="currentColor"
				stroke-width="1.8"
				stroke-linecap="round"
				stroke-linejoin="round"
			>
				<path d="M12 2 L20 6 V12 C20 17 16 21 12 22 C8 21 4 17 4 12 V6 Z" />
				<path d="m9 12 2 2 4-4" />
			</svg>
		</div>
		<div class="renewal-body">
			<div class="renewal-title">Renouvellement automatique</div>
			<p>
				Tous les certificats sont renouvelés automatiquement par
				certmagic (Caddy v2) ~30 jours avant expiration, avec retry
				exponentiel sur échec. Aucune action manuelle n'est requise.
				Les logs de renouvellement sont disponibles dans la page <a
					href="/logs">Logs</a
				>.
			</p>
		</div>
	</div>

	<!-- Per-cert metadata gap notice -->
	<div class="ro-banner">
		<svg
			width="14"
			height="14"
			viewBox="0 0 16 16"
			fill="none"
			stroke="currentColor"
			stroke-width="1.6"
			aria-hidden="true"
		>
			<circle cx="8" cy="8" r="6.5" />
			<path d="M8 5v3.5M8 11v.5" />
		</svg>
		<span
			>Per-certificate runtime metadata (issuer, SAN list, expiry, last
			renewal) is not exposed via the Arenet API today. The lists below
			show the <em>configured</em> certificate scope — what certmagic
			provisions on behalf of each route or managed domain.</span
		>
	</div>

	<!-- Managed domains — editor (migrated from /settings in
	     Pack A). The previous read-only summary table is folded
	     into the editor: the existing-domains list with inline
	     Delete buttons replaces the standalone table; the create
	     form sits below. Single source of managed-domain
	     visibility + CRUD per the #R-6 spec. -->
	<div class="card">
		<div class="card-h">
			<h3>Managed domains</h3>
			<span class="card-h-meta">
				{#if domains.length > 0}
					{domains.length} déclaré{domains.length === 1 ? '' : 's'}
				{:else}
					Aucun
				{/if}
			</span>
		</div>

		<p class="section-lead">
			Une managed domain émet UN certificat wildcard par apex via DNS-01
			(couvre toutes les routes en sous-domaine). Le DNS provider OVH se
			configure dans <a href="/settings">Settings</a>.
		</p>

		{#if sslDNSUnconfigured}
			<div class="warn-box" role="alert">
				<strong>DNS provider unconfigured.</strong>
				Wildcard issuance is disabled — covered routes will serve self-signed
				certs from Caddy's internal CA until you configure the DNS provider
				in <a href="/settings">/settings</a>.
			</div>
		{/if}

		{#if domains.length > 0}
			<ul class="md-list">
				{#each domains as md (md.apex)}
					<li class="md-row">
						<div class="md-meta">
							<div class="mono md-apex">
								*.{md.apex}{#if md.includeApex}<span class="dim"
										>, {md.apex}</span
									>{/if}
							</div>
							<div class="md-sub">
								Provider: <span class="mono">{md.provider}</span>
								{#if md.includeApex}· includes apex{/if}
							</div>
						</div>
						<Button
							variant="ghost"
							onclick={() => openDeleteManagedDomain(md.apex)}
							aria-label={`Delete managed domain ${md.apex}`}
						>
							Delete
						</Button>
					</li>
				{/each}
			</ul>
		{/if}

		<form
			class="md-form"
			onsubmit={(e) => {
				e.preventDefault();
				void submitManagedDomain();
			}}
		>
			<div class="md-form-row md-form-row-full">
				<label for="md-apex">Apex domain</label>
				<input
					id="md-apex"
					type="text"
					bind:value={mdForm.apex}
					placeholder="example.com"
					autocomplete="off"
					class="md-input mono"
				/>
				<p class="md-hint">
					Bare domain (no leading <code>*.</code>) — the wildcard is
					implied. Issues a cert for <code
						>*.{mdForm.apex || 'example.com'}</code
					>.
				</p>
			</div>

			<div class="md-form-row">
				<label for="md-provider">DNS provider</label>
				<select
					id="md-provider"
					bind:value={mdForm.provider}
					class="md-input"
				>
					<option value="ovh">OVH</option>
				</select>
			</div>

			<div class="md-form-row md-form-row-checkbox">
				<input
					id="md-include-apex"
					type="checkbox"
					bind:checked={mdForm.includeApex}
				/>
				<label for="md-include-apex">Include bare apex in cert SAN</label>
			</div>

			{#if mdFormError}
				<p class="md-form-error" role="alert">{mdFormError}</p>
			{/if}

			<div class="md-form-submit">
				<Button
					type="submit"
					disabled={mdSubmitting || mdForm.apex.trim() === ''}
				>
					{mdSubmitting ? 'Declaring…' : 'Declare managed domain'}
				</Button>
			</div>
		</form>

		<p class="section-lead md-foot">
			Declaring a managed domain marks every existing route under
			<code>*.&lt;apex&gt;</code> as covered by the wildcard. The route's
			per-route ACME selector is hidden in the route editor and the cert
			is provisioned once for all covered sub-domains.
		</p>
	</div>

	<!-- TLS-enabled routes (unchanged from R.4.3.c) -->
	<div class="card">
		<div class="card-h">
			<h3>TLS-enabled routes</h3>
			<a href="/routes" class="meta-link">Manage →</a>
		</div>
		{#if tlsRoutes.length === 0}
			<div class="empty-row">
				No TLS-enabled routes. Enable TLS on a route in <a
					href="/routes">/routes</a
				> to have certmagic provision a certificate.
			</div>
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
							<td class="mono dim"
								>{(r.aliases ?? []).length > 0
									? (r.aliases ?? []).join(', ')
									: '—'}</td
							>
							<td>
								{#if r.redirectToHttps}
									<span class="pill ok">301 → https</span>
								{:else}
									<span class="dim">—</span>
								{/if}
							</td>
							<td>
								<span class="pill info"
									>Auto (HTTP-01 or DNS-01)</span
								>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</div>
{/if}

<!-- Delete-managed-domain modal — verbatim port of the
     /settings dialog so the revertTo dropdown (spec O.4 AC #21)
     keeps its contract. The warning text on the "" / "http-01"
     branches stays unchanged. -->
{#if mdDeleteOpen}
	<Modal
		open={mdDeleteOpen}
		title={`Delete managed domain ${mdDeleteApex}?`}
		onClose={() => (mdDeleteOpen = false)}
	>
		{#snippet children()}
			<p class="modal-lead">
				Covered routes' ACMEChallenge will be reverted. Pick the
				post-revert challenge value below.
			</p>
			<div class="modal-field">
				<label for="md-delete-revert-to">Revert covered routes to</label>
				<select
					id="md-delete-revert-to"
					bind:value={mdDeleteRevertTo}
					class="md-input"
				>
					<option value="">Default (HTTP-01 on next reload)</option>
					<option value="http-01">Explicit HTTP-01</option>
					<option value="dns-01">Explicit DNS-01</option>
				</select>
			</div>
			{#if mdDeleteRevertTo === '' || mdDeleteRevertTo === 'http-01'}
				<p class="modal-warn" role="alert">
					<strong>Heads up.</strong> Each covered route will request its own HTTP-01
					cert on the next reload. Many routes on one apex may hit Let's
					Encrypt's per-domain rate limit (50 certs / week).
				</p>
			{/if}
			{#if mdDeleteError}
				<p class="modal-error" role="alert">{mdDeleteError}</p>
			{/if}
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (mdDeleteOpen = false)}
				>Cancel</Button
			>
			<Button
				variant="danger"
				onclick={() => void confirmDeleteManagedDomain()}>Delete</Button
			>
		{/snippet}
	</Modal>
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
	.card-h h3 {
		color: var(--fg);
		font-size: 13.5px;
		font-weight: 500;
		margin: 0;
	}
	.card-h-meta {
		margin-left: auto;
		color: var(--fg-muted);
		font-size: 11.5px;
		font-family: var(--font-mono);
	}
	.meta-link {
		margin-left: auto;
		color: var(--accent);
		font-size: 12.5px;
		text-decoration: none;
	}
	.meta-link:hover {
		text-decoration: underline;
	}

	.section-lead {
		color: var(--fg-muted);
		font-size: 12.5px;
		line-height: 1.55;
		margin: 0 0 12px 0;
	}
	.section-lead a {
		color: var(--accent);
		text-decoration: none;
	}
	.section-lead a:hover {
		text-decoration: underline;
	}
	.md-foot {
		margin-top: 14px;
		margin-bottom: 0;
	}

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
	.kpi-label {
		color: var(--fg-muted);
		font-size: 11px;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		font-family: var(--font-mono);
		margin-bottom: 6px;
	}
	.kpi-val {
		color: var(--fg);
		font-size: 24px;
		font-weight: 500;
		letter-spacing: -0.02em;
	}
	.kpi-val.mode {
		font-size: 18px;
	}
	.kpi-foot {
		color: var(--fg-muted);
		font-size: 11.5px;
		margin-top: 8px;
		font-family: var(--font-mono);
	}

	/* Auto-renewal info card. Uses the accent token for the
	   border + a soft accent tint for the background so the
	   panel reads as "informational + assuring", not a
	   warning. Distinct from the warn-tinted .ro-banner below. */
	.renewal-card {
		display: flex;
		gap: 14px;
		padding: 14px 16px;
		margin-bottom: 14px;
		background: color-mix(in oklch, var(--accent) 8%, transparent);
		border: 1px solid color-mix(in oklch, var(--accent) 30%, transparent);
		border-radius: var(--radius);
		color: var(--fg);
		font-size: 13px;
		line-height: 1.55;
	}
	.renewal-icon {
		flex: none;
		color: var(--accent);
		margin-top: 2px;
	}
	.renewal-title {
		font-weight: 500;
		font-size: 13.5px;
		margin-bottom: 4px;
		color: var(--fg);
	}
	.renewal-body p {
		margin: 0;
		color: var(--fg-muted);
		font-size: 12.5px;
	}
	.renewal-body a {
		color: var(--accent);
		text-decoration: none;
	}
	.renewal-body a:hover {
		text-decoration: underline;
	}

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
	.ro-banner svg {
		flex: none;
		color: var(--warn);
		margin-top: 2px;
	}
	.ro-banner em {
		color: var(--fg);
		font-style: italic;
	}

	.warn-box {
		margin-bottom: 12px;
		padding: 10px 12px;
		background: color-mix(in oklch, var(--warn) 10%, transparent);
		border: 1px solid color-mix(in oklch, var(--warn) 32%, transparent);
		border-radius: var(--radius-sm);
		color: var(--fg);
		font-size: 12.5px;
		line-height: 1.5;
	}
	.warn-box a {
		color: var(--accent);
	}

	/* Managed-domains editor */
	.md-list {
		list-style: none;
		margin: 0 0 16px 0;
		padding: 0;
		border-top: 1px solid var(--border);
	}
	.md-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 10px 0;
		border-bottom: 1px solid var(--border);
	}
	.md-meta {
		min-width: 0;
	}
	.md-apex {
		font-size: 13px;
	}
	.md-sub {
		font-size: 11.5px;
		color: var(--fg-muted);
		margin-top: 3px;
	}
	.md-form {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 14px;
	}
	.md-form-row label {
		display: block;
		color: var(--fg);
		font-size: 12.5px;
		font-weight: 500;
		margin-bottom: 4px;
	}
	.md-form-row-full {
		grid-column: 1 / -1;
	}
	.md-form-row-checkbox {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-top: 23px;
	}
	.md-form-row-checkbox label {
		margin-bottom: 0;
		font-weight: 400;
		color: var(--fg-muted);
	}
	.md-input {
		width: 100%;
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		padding: 8px 10px;
		color: var(--fg);
		font-size: 13px;
		font-family: inherit;
	}
	.md-input.mono {
		font-family: var(--font-mono);
		font-size: 12px;
	}
	.md-hint {
		font-size: 11.5px;
		color: var(--fg-muted);
		margin: 6px 0 0 0;
	}
	.md-hint code {
		font-family: var(--font-mono);
		font-size: 11px;
		color: var(--fg);
	}
	.md-form-error {
		grid-column: 1 / -1;
		color: var(--down);
		font-size: 12.5px;
		margin: 0;
	}
	.md-form-submit {
		grid-column: 1 / -1;
		display: flex;
		justify-content: flex-end;
	}

	/* Delete-managed-domain modal */
	.modal-lead {
		color: var(--fg-muted);
		font-size: 12.5px;
		margin: 0 0 12px 0;
	}
	.modal-field {
		margin-bottom: 12px;
	}
	.modal-field label {
		display: block;
		color: var(--fg);
		font-size: 12.5px;
		font-weight: 500;
		margin-bottom: 4px;
	}
	.modal-warn {
		padding: 8px 12px;
		background: color-mix(in oklch, var(--warn) 10%, transparent);
		border: 1px solid color-mix(in oklch, var(--warn) 30%, transparent);
		border-radius: var(--radius-sm);
		color: var(--fg);
		font-size: 12.5px;
		margin: 0;
	}
	.modal-error {
		color: var(--down);
		font-size: 12.5px;
		margin: 12px 0 0 0;
	}

	table {
		width: 100%;
		border-collapse: collapse;
		font-size: 12.5px;
	}
	th,
	td {
		padding: 8px 10px;
		text-align: left;
	}
	th {
		color: var(--fg-muted);
		font-weight: 500;
		font-size: 11px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		border-bottom: 1px solid var(--border);
	}
	td {
		color: var(--fg);
		border-bottom: 1px solid var(--border);
	}
	tbody tr:last-child td {
		border-bottom: none;
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 12px;
	}
	.dim {
		color: var(--fg-dim);
	}

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
	.pill.ok {
		background: color-mix(in oklch, var(--ok) 18%, transparent);
		color: var(--ok);
	}
	.pill.info {
		background: color-mix(in oklch, var(--info) 18%, transparent);
		color: var(--info);
	}

	.empty-row {
		color: var(--fg-muted);
		font-size: 12.5px;
		padding: 24px;
		text-align: center;
	}
	.empty-row a {
		color: var(--accent);
		text-decoration: none;
	}
	.empty-row a:hover {
		text-decoration: underline;
	}

	.loading-wrap {
		display: flex;
		justify-content: center;
		padding: 48px;
	}
</style>
