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
  - Step T T.4 (`e8e6311`): consumed the T.1 GET /api/certificates
    runtime metadata. KPI cards reflect the live cert pool;
    the previous "TLS-enabled routes" read-only table replaced
    by the unified Domaines table with status badges and a
    Tous / Wildcard / Expirent bientôt tab filter. The stale
    "runtime metadata not exposed" banner removed (T.1 ships
    the data). Force-renew button intentionally absent per the
    Step T amendment (docs/step-t-spec-amendment.md, commit
    `c62d657`) — Caddy v2.11.3's renewal seam is unexported.
  - Step T T.5 (this commit): reframes the bottom section from
    "Managed domains" to "Politiques wildcard par apex" (the
    semantically honest name — each row IS a per-apex wildcard
    policy). Inline declaration form is hoisted into a modal
    wizard launched by a header "+ Wildcard apex" button (matches
    the existing add-flow pattern used by ChangePasswordModal).
    Wire contract unchanged: same settingsApi.createManagedDomain
    POST, same payload shape, same delete-with-revertTo modal.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Tooltip from '$lib/components/Tooltip.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import WildcardApexWizard from '$lib/components/certs/WildcardApexWizard.svelte';
	import { settingsApi } from '$lib/api/settings';
	import { certificatesApi } from '$lib/api/certificates';
	import { listRoutes } from '$lib/api/client';
	import { ApiError } from '$lib/api/types';
	import type {
		Certificate,
		ManagedDomain,
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
		countByEffectiveSource,
		daysUntilExpiry,
		dominantIssuer,
		inferChallengeLabel,
		isExpiringSoon,
		isZeroTimestamp,
		resolveSource,
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

	// Step T T.5 — wizard-open state. Bindable; the wizard
	// component handles its own form state (apex / provider /
	// includeApex) so the page doesn't carry that anymore.
	let wizardOpen = $state(false);

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
	// Breakdown via resolveSource so OBTAIN_FAILED entries (which
	// carry source="" on the wire) still classify correctly —
	// pre-polish the breakdown didn't sum to the total.
	const certsBreakdown = $derived(countByEffectiveSource(certs));
	const certsWildcard = $derived(certsBreakdown.wildcard);
	const certsSpecific = $derived(certsBreakdown.specific);
	// isExpiringSoon now excludes OBTAIN_FAILED + zero-time
	// entries, so the count matches operator expectations
	// ("renewal scheduled" should not include certs that haven't
	// been obtained yet).
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
						{@const effectiveSource = resolveSource(cert)}
						{@const days = daysUntilExpiry(cert)}
						{@const notBeforeMissing = isZeroTimestamp(cert.notBefore)}
						<tr data-testid="cert-row" data-domain={cert.domain}>
							<td>
								<div class="mono">{cert.domain}</div>
								<div class="dim cell-sub">
									{certificateSourceLabel(effectiveSource)} · {inferChallengeLabel(
										effectiveSource,
										cert.status
									)}
								</div>
							</td>
							<td>{cert.issuer || '—'}</td>
							<td class="mono">
								{(cert.sanList ?? []).length} SAN
							</td>
							<td class="dim">
								{notBeforeMissing ? '—' : relativeTime(cert.notBefore)}
							</td>
							<td>
								<span
									class="expiry"
									class:expiry-warn={days !== null &&
										days <= RENEWAL_WINDOW_DAYS &&
										days > 0}
									class:expiry-down={days !== null && days <= 0}
								>
									{#if days === null}
										—
									{:else if days <= 0}
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

	<!-- Step T T.5 — Politiques wildcard par apex. Reframe of the
	     pre-T.5 "Managed domains" section: same wire contract,
	     semantically honest French copy, declaration form hoisted
	     into the WildcardApexWizard modal (header "+ Wildcard apex"
	     button). Delete flow (revertTo modal) is unchanged. -->
	<div class="card" data-testid="policies-card">
		<div class="card-h">
			<h3>Politiques wildcard par apex</h3>
			<span class="card-h-meta">
				{#if domains.length > 0}
					{domains.length} déclarée{domains.length === 1 ? '' : 's'}
				{:else}
					Aucune
				{/if}
			</span>
			<div class="card-h-actions">
				<Button
					variant="primary"
					size="sm"
					onclick={() => (wizardOpen = true)}
					data-testid="open-wildcard-wizard"
				>
					{#snippet children()}+ Wildcard apex{/snippet}
				</Button>
			</div>
		</div>

		<p class="section-lead">
			Un apex géré émet UN certificat wildcard via DNS-01 (couvre toutes
			les routes en sous-domaine). Le DNS provider se configure dans <a
				href="/settings">Settings</a
			>.
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

		<p class="section-lead md-foot">
			Déclarer un apex marque toutes les routes existantes sous
			<code>*.&lt;apex&gt;</code> comme couvertes par le wildcard. Le
			sélecteur ACME par route est masqué dans l'éditeur de routes, et le
			certificat est provisionné une seule fois pour tous les
			sous-domaines.
		</p>
	</div>

{/if}

<!-- Step T T.5 — wizard mount. Always mounted, gated by `open`
     prop so form state survives reopens within a session.
     loadManagedDomains is the onCreated callback so the new
     policy row appears in the list the moment the wizard closes.
     One-way prop + explicit onClose callback (same pattern as
     the delete-managed-domain Modal above) avoids the
     bidirectional-state surprises of $bindable. -->
<WildcardApexWizard
	open={wizardOpen}
	onClose={() => (wizardOpen = false)}
	onCreated={loadManagedDomains}
/>

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
	/* Delete-modal select reuses .md-input — kept after the T.5
	   wizard hoist; the wizard owns its own scoped copy so this
	   one survives only for the modal-field <select>. */
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

	/* Step T T.5 — right-side actions area inside the section
	   header. The container's flex gap separates it from the
	   adjacent .card-h-meta count chip; no extra margin needed. */
	.card-h-actions {
		display: inline-flex;
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
