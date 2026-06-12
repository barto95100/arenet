<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Users-page Phase 1 refactor — read-only OIDC config summary
  rendered in the right sidebar of /utilisateurs. Extracted
  from OIDCSettingsSection's display logic so the form-y
  inputs aren't dragged along; the page operator's intent is
  "show me the current SSO config" without prompting them to
  edit. Edits stay in /settings.

  Phase 2 polish — provider logo + title + CONNECTÉ outline
  badge header; mono field list with row separators; footer
  with "Tester la connexion" (POST /settings/oidc/test) +
  "Modifier la config" (anchor → /settings#oidc-config).
-->
<script lang="ts">
	import Card from './Card.svelte';
	import Badge from './Badge.svelte';
	import Button from './Button.svelte';
	import Spinner from './Spinner.svelte';
	import SSOProviderLogo from './SSOProviderLogo.svelte';
	import { settingsApi } from '$lib/api/settings';
	import { pushToast } from '$lib/stores/toast';
	import { oidcProviderLabel, hostnameOf } from '$lib/utils/oidc-labels';
	import type { OIDCConfig } from '$lib/api/types';
	import { onMount } from 'svelte';

	let config = $state<OIDCConfig | null>(null);
	let loading = $state(true);
	let loadError = $state('');
	let testing = $state(false);

	onMount(async () => {
		try {
			config = await settingsApi.getOIDCConfig();
		} catch (err) {
			loadError = err instanceof Error ? err.message : 'Failed to load OIDC config';
		} finally {
			loading = false;
		}
	});

	// Mirror OIDCSettingsSection's "Configured · disabled"
	// shape so the summary reads the same as the full panel
	// on /settings — operators see the same state vocabulary
	// in both places. Phase 2: when enabled, render the
	// outline "CONNECTÉ" pill that matches the mockup.
	const statusBadge = $derived.by(() => {
		if (!config) return { variant: 'neutral' as const, label: 'Non configuré' };
		if (config.enabled) return { variant: 'status-up-outline' as const, label: 'CONNECTÉ' };
		if (config.configured)
			return { variant: 'status-warn' as const, label: 'Configuré · désactivé' };
		return { variant: 'neutral' as const, label: 'Non configuré' };
	});

	const providerTitle = $derived(oidcProviderLabel(config?.kind));
	const providerSubtitle = $derived(
		config?.issuerUrl ? `OIDC · ${hostnameOf(config.issuerUrl)}` : 'OIDC'
	);

	async function handleTest() {
		if (!config || !config.configured) return;
		testing = true;
		try {
			const result = await settingsApi.testOIDCConnection();
			if (!result.reachable) {
				pushToast(`Échec : ${result.error || 'IdP injoignable'}`, 'danger');
				return;
			}
			if (!result.scopesMatch) {
				const missing = (result.missingScopes || []).join(', ');
				pushToast(
					`IdP atteint (${result.latencyMs} ms) mais scopes manquants : ${missing}`,
					'danger'
				);
				return;
			}
			pushToast(`IdP atteint en ${result.latencyMs} ms — scopes OK`, 'success');
		} catch (err) {
			const msg = err instanceof Error ? err.message : 'Erreur réseau';
			pushToast(`Échec du test : ${msg}`, 'danger');
		} finally {
			testing = false;
		}
	}
</script>

<Card padding="p-5">
	{#if loading}
		<div class="flex justify-center py-6"><Spinner size="sm" /></div>
	{:else if loadError}
		<p class="text-sm text-down" role="alert">Failed to load: {loadError}</p>
	{:else if !config || !config.configured}
		<header class="mb-3 flex items-start justify-between gap-3">
			<div>
				<h3 class="text-base font-semibold text-primary">SSO · OIDC</h3>
				<p class="mt-1 text-xs text-muted">Aucun fournisseur configuré</p>
			</div>
			<Badge variant={statusBadge.variant}>{statusBadge.label}</Badge>
		</header>
		<p class="text-sm text-muted">
			Aucun fournisseur d'identité configuré. La table /utilisateurs
			ne montre que les comptes locaux tant que SSO n'est pas activé
			dans Settings.
		</p>
		<div class="mt-4 flex justify-end">
			<Button variant="primary" size="sm" onclick={() => (window.location.href = '/settings#oidc-config')}>
				Configurer
			</Button>
		</div>
	{:else}
		<header class="mb-4 flex items-start gap-3">
			<SSOProviderLogo kind={config.kind} size={40} />
			<div class="flex-1 min-w-0">
				<h3 class="text-base font-semibold text-primary">{providerTitle}</h3>
				<p class="mt-0.5 text-xs text-muted truncate">{providerSubtitle}</p>
			</div>
			<Badge variant={statusBadge.variant}>{statusBadge.label}</Badge>
		</header>

		<dl class="text-sm divide-y divide-[var(--border-default)]">
			<div class="grid grid-cols-[7rem_1fr] gap-x-3 py-2">
				<dt class="text-secondary">Provider</dt>
				<dd class="font-mono">{config.kind || 'generic'}</dd>
			</div>
			<div class="grid grid-cols-[7rem_1fr] gap-x-3 py-2">
				<dt class="text-secondary">Issuer</dt>
				<dd class="font-mono break-all">{config.issuerUrl}</dd>
			</div>
			<div class="grid grid-cols-[7rem_1fr] gap-x-3 py-2">
				<dt class="text-secondary">Client ID</dt>
				<dd class="font-mono break-all">{config.clientId}</dd>
			</div>
			<div class="grid grid-cols-[7rem_1fr] gap-x-3 py-2">
				<dt class="text-secondary">Scopes</dt>
				<dd class="flex flex-wrap gap-1">
					{#each config.scopes as scope}
						<Badge variant="neutral">{scope}</Badge>
					{/each}
				</dd>
			</div>
			<div class="grid grid-cols-[7rem_1fr] gap-x-3 py-2">
				<dt class="text-secondary">Allowlist</dt>
				<dd>
					{config.allowedIdentities.length} entr{config.allowedIdentities.length === 1
						? 'ée'
						: 'ées'}
				</dd>
			</div>
			<div class="grid grid-cols-[7rem_1fr] gap-x-3 py-2">
				<dt class="text-secondary">Redirect</dt>
				<dd class="font-mono break-all">{config.redirectUrl}</dd>
			</div>
		</dl>

		<footer class="mt-4 flex items-center justify-between gap-2">
			<Button
				variant="secondary"
				size="sm"
				loading={testing}
				onclick={handleTest}
				data-testid="oidc-test-button"
			>
				Tester la connexion
			</Button>
			<Button
				variant="primary"
				size="sm"
				onclick={() => (window.location.href = '/settings#oidc-config')}
				data-testid="oidc-edit-button"
			>
				Modifier la config
			</Button>
		</footer>
	{/if}
</Card>
