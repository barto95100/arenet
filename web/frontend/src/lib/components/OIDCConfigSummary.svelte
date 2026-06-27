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
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

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
		void language.current;
		if (!config) return { variant: 'neutral' as const, label: t('users.oidc.statusUnconfigured') };
		if (config.enabled) return { variant: 'status-up-outline' as const, label: t('users.oidc.statusConnected') };
		if (config.configured)
			return { variant: 'status-warn' as const, label: t('users.oidc.statusConfiguredDisabled') };
		return { variant: 'neutral' as const, label: t('users.oidc.statusUnconfigured') };
	});

	const providerTitle = $derived(oidcProviderLabel(config?.kind));
	const providerSubtitle = $derived(
		language.current && (config?.issuerUrl
			? t('users.oidc.providerSubtitle', { host: hostnameOf(config.issuerUrl) })
			: t('users.oidc.providerSubtitleEmpty'))
	);

	async function handleTest() {
		if (!config || !config.configured) return;
		testing = true;
		try {
			const result = await settingsApi.testOIDCConnection();
			if (!result.reachable) {
				pushToast(t('users.oidc.testFail', { err: result.error || t('users.oidc.testIdpUnreachable') }), 'danger');
				return;
			}
			if (!result.scopesMatch) {
				const missing = (result.missingScopes || []).join(', ');
				pushToast(
					t('users.oidc.testScopesMissing', { ms: result.latencyMs, scopes: missing }),
					'danger'
				);
				return;
			}
			pushToast(t('users.oidc.testOk', { ms: result.latencyMs }), 'success');
		} catch (err) {
			const msg = err instanceof Error ? err.message : t('users.oidc.testNetworkErr');
			pushToast(t('users.oidc.testFailPrefix', { msg }), 'danger');
		} finally {
			testing = false;
		}
	}
</script>

<Card padding="p-5">
	{#if loading}
		<div class="flex justify-center py-6"><Spinner size="sm" /></div>
	{:else if loadError}
		<p class="text-sm text-down" role="alert">{language.current && t('users.oidc.loadFailed', { err: loadError })}</p>
	{:else if !config || !config.configured}
		<header class="mb-3 flex items-start justify-between gap-3">
			<div>
				<h3 class="text-base font-semibold text-primary">{language.current && t('users.oidc.ssoTitle')}</h3>
				<p class="mt-1 text-xs text-muted">{language.current && t('users.oidc.emptyTitle')}</p>
			</div>
			<Badge variant={statusBadge.variant}>{statusBadge.label}</Badge>
		</header>
		<p class="text-sm text-muted">
			{language.current && t('users.oidc.emptyBody')}
		</p>
		<div class="mt-4 flex justify-end">
			<Button
				variant="primary"
				size="sm"
				onclick={() => goto('/settings#oidc-config')}
				data-testid="oidc-configure-button"
			>
				{language.current && t('users.oidc.btnConfigure')}
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
				<dt class="text-secondary">{language.current && t('users.oidc.rowProvider')}</dt>
				<dd class="font-mono">{config.kind || 'generic'}</dd>
			</div>
			<div class="grid grid-cols-[7rem_1fr] gap-x-3 py-2">
				<dt class="text-secondary">{language.current && t('users.oidc.rowIssuer')}</dt>
				<dd class="font-mono break-all">{config.issuerUrl}</dd>
			</div>
			<div class="grid grid-cols-[7rem_1fr] gap-x-3 py-2">
				<dt class="text-secondary">{language.current && t('users.oidc.rowClientId')}</dt>
				<dd class="font-mono break-all">{config.clientId}</dd>
			</div>
			<div class="grid grid-cols-[7rem_1fr] gap-x-3 py-2">
				<dt class="text-secondary">{language.current && t('users.oidc.rowScopes')}</dt>
				<dd class="flex flex-wrap gap-1">
					{#each config.scopes as scope}
						<Badge variant="neutral">{scope}</Badge>
					{/each}
				</dd>
			</div>
			<div class="grid grid-cols-[7rem_1fr] gap-x-3 py-2">
				<dt class="text-secondary">{language.current && t('users.oidc.rowAllowlist')}</dt>
				<dd>
					{language.current && (config.allowedIdentities.length === 1
						? t('users.oidc.allowlistEntries', { count: config.allowedIdentities.length })
						: t('users.oidc.allowlistEntriesPlural', { count: config.allowedIdentities.length }))}
				</dd>
			</div>
			<div class="grid grid-cols-[7rem_1fr] gap-x-3 py-2">
				<dt class="text-secondary">{language.current && t('users.oidc.rowRedirect')}</dt>
				<dd class="font-mono break-all">{config.redirectUrl}</dd>
			</div>
			<div class="grid grid-cols-[7rem_1fr] gap-x-3 py-2">
				<dt class="text-secondary">{language.current && t('users.oidc.rowClientSecret')}</dt>
				<dd>
					{#if config.clientSecretSet}
						<Badge variant="status-up">{language.current && t('users.oidc.clientSecretSet')}</Badge>
					{:else}
						<Badge variant="status-warn">{language.current && t('users.oidc.clientSecretMissing')}</Badge>
					{/if}
				</dd>
			</div>
			<div class="grid grid-cols-[7rem_1fr] gap-x-3 py-2">
				<dt class="text-secondary">{language.current && t('users.oidc.rowEmailUnverified')}</dt>
				<dd>
					{#if config.acceptUnverifiedEmail}
						<Badge variant="status-warn">{language.current && t('users.oidc.emailUnverifiedAccepted')}</Badge>
					{:else}
						<Badge variant="neutral">{language.current && t('users.oidc.emailUnverifiedRejected')}</Badge>
					{/if}
				</dd>
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
				{language.current && t('users.oidc.btnTest')}
			</Button>
			<Button
				variant="primary"
				size="sm"
				onclick={() => goto('/settings#oidc-config')}
				data-testid="oidc-edit-button"
			>
				{language.current && t('users.oidc.btnEdit')}
			</Button>
		</footer>
	{/if}
</Card>
