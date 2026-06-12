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
-->
<script lang="ts">
	import Card from './Card.svelte';
	import Badge from './Badge.svelte';
	import Spinner from './Spinner.svelte';
	import { settingsApi } from '$lib/api/settings';
	import type { OIDCConfig } from '$lib/api/types';
	import { onMount } from 'svelte';

	let config = $state<OIDCConfig | null>(null);
	let loading = $state(true);
	let loadError = $state('');

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
	// in both places.
	const statusBadge = $derived.by(() => {
		if (!config) return { variant: 'neutral' as const, label: 'Not configured' };
		if (config.enabled) return { variant: 'status-up' as const, label: 'Active' };
		if (config.configured) return { variant: 'status-warn' as const, label: 'Configured · disabled' };
		return { variant: 'neutral' as const, label: 'Not configured' };
	});
</script>

<Card padding="p-5">
	<header class="flex items-start justify-between gap-3 mb-4">
		<div>
			<h3 class="text-base font-semibold text-primary">SSO · OIDC</h3>
			<p class="mt-1 text-xs text-muted">Live config — edits live in <a href="/settings" class="underline">Settings</a>.</p>
		</div>
		<Badge variant={statusBadge.variant}>{statusBadge.label}</Badge>
	</header>

	{#if loading}
		<div class="flex justify-center py-6"><Spinner size="sm" /></div>
	{:else if loadError}
		<p class="text-sm text-down" role="alert">Failed to load: {loadError}</p>
	{:else if !config || !config.configured}
		<p class="text-sm text-muted">
			No identity provider configured. The /utilisateurs table shows
			local accounts only until SSO is enabled in Settings.
		</p>
	{:else}
		<dl class="grid grid-cols-[7rem_1fr] gap-x-3 gap-y-2 text-sm">
			<dt class="text-secondary">Provider</dt>
			<dd class="font-mono">{config.kind || 'Generic OIDC'}</dd>

			<dt class="text-secondary">Issuer</dt>
			<dd class="font-mono break-all">{config.issuerUrl}</dd>

			<dt class="text-secondary">Client ID</dt>
			<dd class="font-mono break-all">{config.clientId}</dd>

			<dt class="text-secondary">Scopes</dt>
			<dd>
				<div class="flex flex-wrap gap-1">
					{#each config.scopes as scope}
						<Badge variant="neutral">{scope}</Badge>
					{/each}
				</div>
			</dd>

			<dt class="text-secondary">Allowlist</dt>
			<dd>
				{config.allowedIdentities.length} entr{config.allowedIdentities.length === 1
					? 'y'
					: 'ies'}
			</dd>

			<dt class="text-secondary">Redirect</dt>
			<dd class="font-mono break-all">{config.redirectUrl}</dd>
		</dl>
	{/if}
</Card>
