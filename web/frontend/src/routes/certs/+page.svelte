<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  /certs — top-level Sécurité IA entry for certificate visibility
  and managed-domain configuration.

  History:
  - R.2 (`4691eb2`): shipped as a minimal stub.
  - R.4.3.c: promoted to a read-only catalog summarising managed
    domains + TLS-enabled routes.
  - #R-6 Pack A (`06ba97a`): completed the §R-6 migration —
    Managed domains editor moved here from /settings, auto-renewal
    info card added.
  - Step T T.4 (this commit): consumes the T.1 GET /api/certificates
    runtime metadata. KPI cards now reflect the live cert pool;
    the previous "TLS-enabled routes" read-only table is replaced
    by the unified Domaines table with status badges and a
    Tous / Wildcard / Expirent bientôt tab filter. The stale
    "runtime metadata not exposed" banner is removed (T.1 ships
    the data). Force-renew button intentionally absent per the
    Step T amendment (docs/step-t-spec-amendment.md, commit
    `c62d657`) — Caddy v2.11.3's renewal seam is unexported.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Tooltip from '$lib/components/Tooltip.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import { settingsApi } from '$lib/api/settings';
	import { certificatesApi } from '$lib/api/certificates';
	import { listRoutes } from '$lib/api/client';
	import { ApiError } from '$lib/api/types';
	import type {
		Certificate,
		ManagedDomain,
		ManagedDomainProvider,
		ManagedDomainRevertTo,
		Route,
		DNSProviderOVH,
	} from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import { relativeTime } from '$lib/utils/audit-format';
	import {
		RENEWAL_WINDOW_DAYS,
		certificateSourceLabel,
		certificateStatusLabel,
		certificateStatusToBadgeVariant,
		daysUntilExpiry,
		dominantIssuer,
		inferChallengeLabel,
		isExpiringSoon,
	} from '$lib/utils/certificate-format';

	let loading = $state(true);
	let domains = $state<ManagedDomain[]>([]);
	let routes = $state<Route[]>([]);
	let certs = $state<Certificate[]>([]);
	// Tab filter for the Domaines table (AC #6 LOCKED). Local
	// component state, not URL-anchored — sharing the page link
	// implicitly means sharing the "Tous" default, which matches
	// the operator's "what's the state of all my certs?" entry
	// intent. URL-anchored tabs can be revisited if the dashboard
	// gains deep-link conventions elsewhere.
	type DomaineTab = 'all' | 'wildcard' | 'expiring';
	let activeTab = $state<DomaineTab>('all');
	// Distinct from the page-level `loading` (which gates the
	// editor markup): certsLoadError is the soft-fail state for
	// the Domaines table specifically. A 5xx on /api/certificates
	// must NOT take down the managed-domains editor (AC #13
	// degraded-mode policy mirrored on the frontend).
	let certsLoadError = $state(false);

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

	// Step T T.4 — runtime KPI derivations from the cert list.
	// All four cards must reflect the LIVE state (T.4 brief A);
	// the pre-T.4 cards were config viewers that didn't change
	// when a cert was issued or expired.
	const certsTotal = $derived(certs.length);
	const certsWildcard = $derived(certs.filter((c) => c.source === 'wildcard').length);
	const certsSpecific = $derived(
		certs.filter((c) => c.source === 'specific' || c.source === 'apex').length
	);
	const certsExpiringSoon = $derived(certs.filter((c) => isExpiringSoon(c)).length);
	const principalIssuer = $derived(dominantIssuer(certs));
	// ACME method KPI: DNS-01 wins as soon as at least one
	// managed-domain is declared (we're using DNS-01 for at least
	// some of the cert pool); else "Auto" (HTTP-01 default).
	const acmeMethodLabel = $derived(domains.length > 0 ? 'DNS-01' : 'Auto');
	const acmeMethodSub = $derived(
		domains.length > 0 ? `via ${domains[0].provider.toUpperCase()}` : 'HTTP-01'
	);

	// Filtered cert list per the active tab. Pure client-side —
	// no refetch — so tab switching is instant. Empty-state copy
	// branches on activeTab so the operator sees the right
	// "nothing in this category" message.
	const filteredCerts = $derived.by(() => {
		switch (activeTab) {
			case 'wildcard':
				return certs.filter((c) => c.source === 'wildcard');
			case 'expiring':
				return certs.filter((c) => isExpiringSoon(c));
			case 'all':
			default:
				return certs;
		}
	});

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

	// Step T T.4 — load the runtime cert list. Soft-failing on
	// purpose: a 5xx must NOT block the rest of the page (the
	// managed-domains editor and renewal info card stay
	// functional). The Domaines table renders the certsLoadError
	// branch instead.
	async function loadCertificates(): Promise<void> {
		try {
			certs = await certificatesApi.list();
			certsLoadError = false;
		} catch {
			certs = [];
			certsLoadError = true;
		}
	}

	async function load(): Promise<void> {
		try {
			const [rs] = await Promise.all([
				listRoutes(),
				loadManagedDomains(),
				loadDNSProvider(),
				loadCertificates(),
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
		<div class="kpi" data-testid="kpi-certs-actifs">
			<div class="kpi-label">Certificats actifs</div>
			<div class="kpi-val">{certsTotal}</div>
			<div class="kpi-foot">
				{certsWildcard} wildcard · {certsSpecific} spécifique{certsSpecific === 1 ? '' : 's'}
			</div>
		</div>
		<div class="kpi" data-testid="kpi-expirent-bientot">
			<div class="kpi-label">Expirent &lt; {RENEWAL_WINDOW_DAYS} jours</div>
			<div class="kpi-val">{certsExpiringSoon}</div>
			<div class="kpi-foot">
				{certsExpiringSoon > 0 ? 'renouvellement auto programmé' : '—'}
			</div>
		</div>
		<div class="kpi" data-testid="kpi-emetteur">
			<div class="kpi-label">Émetteur principal</div>
			<div class="kpi-val mode">{principalIssuer}</div>
			<div class="kpi-foot">&nbsp;</div>
		</div>
		<div class="kpi" data-testid="kpi-methode">
			<div class="kpi-label">Méthode ACME</div>
			<div class="kpi-val mode">{acmeMethodLabel}</div>
			<div class="kpi-foot">{acmeMethodSub}</div>
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

	<!-- Step T T.4 — unified Domaines table. Live runtime cert
	     metadata from GET /api/certificates (T.1, commit 1350777).
	     Replaces the pre-T.4 "TLS-enabled routes" read-only table
	     (which only knew the configured shape, never the actual
	     cert state). No row actions — force-renew button absent
	     per the Step T amendment (Caddy renewal seam unexported). -->
	<div class="card" data-testid="domaines-card">
		<div class="card-h">
			<h3>Domaines</h3>
			<div class="tabs" role="tablist" aria-label="Filter certificates">
				<button
					type="button"
					role="tab"
					class="tab"
					class:active={activeTab === 'all'}
					aria-selected={activeTab === 'all'}
					data-testid="tab-all"
					onclick={() => (activeTab = 'all')}
				>
					Tous
				</button>
				<button
					type="button"
					role="tab"
					class="tab"
					class:active={activeTab === 'wildcard'}
					aria-selected={activeTab === 'wildcard'}
					data-testid="tab-wildcard"
					onclick={() => (activeTab = 'wildcard')}
				>
					Wildcard
				</button>
				<button
					type="button"
					role="tab"
					class="tab"
					class:active={activeTab === 'expiring'}
					aria-selected={activeTab === 'expiring'}
					data-testid="tab-expiring"
					onclick={() => (activeTab = 'expiring')}
				>
					Expirent bientôt
				</button>
			</div>
		</div>

		{#if certsLoadError}
			<div class="empty-row" data-testid="certs-error">
				Impossible de récupérer les certificats (le service backend a
				répondu en erreur). Le reste de cette page reste utilisable.
			</div>
		{:else if certs.length === 0}
			<div class="empty-row" data-testid="certs-empty">
				Aucun certificat actif.
				<div class="empty-sub">
					Les certificats sont auto-provisionnés à la création d'une
					route TLS ou à la déclaration d'un apex géré.
				</div>
			</div>
		{:else if filteredCerts.length === 0}
			<div class="empty-row" data-testid="certs-tab-empty">
				Aucun certificat dans cette catégorie.
			</div>
		{:else}
			<table data-testid="certs-table">
				<thead>
					<tr>
						<th>Domaine</th>
						<th>Émetteur</th>
						<th>SAN</th>
						<th>Émis le</th>
						<th>Expire dans</th>
						<th>État</th>
					</tr>
				</thead>
				<tbody>
					{#each filteredCerts as cert (cert.domain)}
						{@const days = daysUntilExpiry(cert)}
						<tr data-testid="cert-row" data-domain={cert.domain}>
							<td>
								<div class="mono">{cert.domain}</div>
								<div class="dim cell-sub">
									{certificateSourceLabel(cert.source)} · {inferChallengeLabel(
										cert.source
									)}
								</div>
							</td>
							<td>{cert.issuer || '—'}</td>
							<td class="mono">
								{cert.sanList.length} SAN
							</td>
							<td class="dim">{relativeTime(cert.notBefore)}</td>
							<td>
								<span
									class="expiry"
									class:expiry-warn={days <= RENEWAL_WINDOW_DAYS && days > 0}
									class:expiry-down={days <= 0}
								>
									{#if days <= 0}
										expiré
									{:else}
										{days} jour{days === 1 ? '' : 's'}
									{/if}
								</span>
							</td>
							<td>
								{#if cert.status === 'OBTAIN_FAILED' && cert.lastError}
									<Tooltip
										label={`${cert.lastError}${
											cert.lastErrorAt
												? ` (${relativeTime(cert.lastErrorAt)})`
												: ''
										}`}
									>
										<Badge variant={certificateStatusToBadgeVariant(cert.status)}>
											{certificateStatusLabel(cert.status)}
										</Badge>
									</Tooltip>
								{:else}
									<Badge variant={certificateStatusToBadgeVariant(cert.status)}>
										{certificateStatusLabel(cert.status)}
									</Badge>
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
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
	   warning. */
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

	/* Step T T.4 — Domaines table tab filter (AC #6 LOCKED).
	   Renders top-right of the card header; small pills styled
	   like text-tabs (subtle separation, accent underline on
	   active). The button reset matches the other inline
	   tablists in the app (Topology Phase 2 protocol toggles). */
	.tabs {
		margin-left: auto;
		display: inline-flex;
		gap: 4px;
	}
	.tab {
		appearance: none;
		background: transparent;
		border: 1px solid transparent;
		color: var(--fg-muted);
		font-size: 11.5px;
		font-family: inherit;
		padding: 4px 10px;
		border-radius: var(--radius-sm);
		cursor: pointer;
		transition: color var(--motion-fast, 120ms), background var(--motion-fast, 120ms);
	}
	.tab:hover {
		color: var(--fg);
		background: var(--bg-elevated);
	}
	.tab.active {
		color: var(--fg);
		background: var(--bg-elevated);
		border-color: var(--border-default);
	}

	/* Sub-line under a primary cell (e.g. "<source> · <challenge>"
	   under DOMAINE). Smaller + dim so it doesn't compete with
	   the cell's main content. */
	.cell-sub {
		font-size: 11px;
		margin-top: 3px;
	}

	/* EXPIRE DANS column color states — amber inside the renewal
	   window, red once expired. Plain text color flip (not a
	   pill) per the mock's minimalist treatment. */
	.expiry {
		font-variant-numeric: tabular-nums;
	}
	.expiry-warn {
		color: var(--status-warn);
	}
	.expiry-down {
		color: var(--status-down);
	}

	.empty-row {
		color: var(--fg-muted);
		font-size: 12.5px;
		padding: 24px;
		text-align: center;
	}
	.empty-sub {
		margin-top: 6px;
		font-size: 11.5px;
		color: var(--fg-dim);
	}

	.loading-wrap {
		display: flex;
		justify-content: center;
		padding: 48px;
	}
</style>
