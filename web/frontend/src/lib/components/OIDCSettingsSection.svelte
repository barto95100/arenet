<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step K.2 — OIDC SSO settings section. Two sub-areas in one
  Card:

    1. Provider config (form, single row): issuer URL, client ID,
       client secret (preserve-on-edit), redirect URL, scopes,
       enabled toggle.

    2. Allowlist editor: add by email + display name; list with
       canonicalisation status badge ("pending" until first login
       canonicalises Sub, "linked" after); delete by email.

  The allowlist is preserved across config edits (server-side, in
  putOIDCConfig). Editing the form does NOT mutate the allowlist;
  use the add/delete actions on the list below.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { pushToast } from '$lib/stores/toast';
	import { settingsApi } from '$lib/api/settings';
	import {
		ApiError,
		type OIDCAllowedIdentity,
		type OIDCConfig
	} from '$lib/api/types';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';

	let config = $state<OIDCConfig | null>(null);
	let allowlist = $state<OIDCAllowedIdentity[]>([]);
	let loading = $state(true);
	let loadError = $state('');

	let form = $state({
		enabled: false,
		issuerUrl: '',
		clientId: '',
		clientSecret: '',
		redirectUrl: '',
		scopes: 'openid profile email' // space-separated for the textarea/input
	});
	let formError = $state('');
	let submitting = $state(false);

	let newEntry = $state({ email: '', displayName: '', sub: '' });
	let allowlistError = $state('');
	let allowlistSubmitting = $state(false);

	async function load(): Promise<void> {
		loading = true;
		loadError = '';
		try {
			const [cfg, list] = await Promise.all([
				settingsApi.getOIDCConfig(),
				settingsApi.listOIDCAllowlist()
			]);
			config = cfg;
			allowlist = list;
			form.enabled = cfg.enabled;
			form.issuerUrl = cfg.issuerUrl;
			form.clientId = cfg.clientId;
			form.redirectUrl = cfg.redirectUrl;
			form.scopes = (cfg.scopes ?? []).join(' ');
			// clientSecret stays "" — server redacts on GET; user only
			// types it on explicit rotation. The placeholder tells them
			// what the empty state means.
			form.clientSecret = '';
		} catch (err) {
			loadError = err instanceof Error ? err.message : 'Failed to load OIDC config';
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		void load();
	});

	async function submitConfig(): Promise<void> {
		if (submitting) return;
		formError = '';
		submitting = true;
		try {
			const scopes = form.scopes
				.split(/[\s,]+/)
				.map((s) => s.trim())
				.filter((s) => s.length > 0);
			const saved = await settingsApi.putOIDCConfig({
				enabled: form.enabled,
				issuerUrl: form.issuerUrl.trim(),
				clientId: form.clientId.trim(),
				clientSecret: form.clientSecret, // empty preserves
				redirectUrl: form.redirectUrl.trim(),
				scopes
			});
			config = saved;
			form.scopes = (saved.scopes ?? []).join(' ');
			form.clientSecret = ''; // reset the secret field after save
			pushToast('OIDC settings saved', 'success');
		} catch (err) {
			if (err instanceof ApiError) {
				formError = err.message;
			} else if (err instanceof Error) {
				formError = err.message;
			} else {
				formError = 'Failed to save OIDC settings';
			}
		} finally {
			submitting = false;
		}
	}

	async function addAllowlistEntry(): Promise<void> {
		if (allowlistSubmitting) return;
		allowlistError = '';
		const email = newEntry.email.trim();
		if (!email) {
			allowlistError = 'Email is required';
			return;
		}
		allowlistSubmitting = true;
		try {
			const sub = newEntry.sub.trim();
			await settingsApi.addOIDCAllowlist({
				email,
				displayName: newEntry.displayName.trim(),
				...(sub ? { sub } : {})
			});
			newEntry = { email: '', displayName: '', sub: '' };
			allowlist = await settingsApi.listOIDCAllowlist();
			pushToast(`Added ${email} to OIDC allowlist`, 'success');
		} catch (err) {
			allowlistError =
				err instanceof Error ? err.message : 'Failed to add allowlist entry';
		} finally {
			allowlistSubmitting = false;
		}
	}

	async function deleteAllowlistEntry(email: string): Promise<void> {
		try {
			await settingsApi.deleteOIDCAllowlist(email);
			allowlist = allowlist.filter((e) => e.email !== email);
			pushToast(`Removed ${email}`, 'success');
		} catch (err) {
			pushToast(
				err instanceof Error ? err.message : 'Failed to remove entry',
				'danger'
			);
		}
	}
</script>

<Card padding="p-6">
	<header class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4">
		<div>
			<h2 class="text-xl font-semibold">OIDC SSO</h2>
			<p class="text-xs text-muted mt-1">
				Delegate admin login to an external identity provider. Local
				login remains available regardless (break-glass).
			</p>
		</div>
		{#if loading}
			<Spinner size="sm" />
		{:else if config}
			{#if config.enabled && config.configured}
				<Badge variant="status-up">Enabled</Badge>
			{:else if config.configured}
				<Badge variant="status-warn">Configured · disabled</Badge>
			{:else}
				<Badge variant="status-warn">Not configured</Badge>
			{/if}
		{/if}
	</header>

	{#if loadError}
		<p class="text-sm text-down mb-3" role="alert">
			Failed to load OIDC config: {loadError}
		</p>
	{/if}

	<form
		class="grid grid-cols-1 md:grid-cols-2 gap-4"
		onsubmit={(e) => {
			e.preventDefault();
			void submitConfig();
		}}
	>
		<div class="md:col-span-2">
			<label class="text-sm font-medium text-secondary inline-flex items-center gap-2">
				<input
					type="checkbox"
					bind:checked={form.enabled}
					class="rounded border-border-default bg-surface text-cyan focus:ring-cyan"
				/>
				Enable OIDC SSO login
			</label>
		</div>

		<div class="md:col-span-2">
			<label for="oidc-issuer" class="text-sm font-medium text-secondary block mb-1">
				Issuer URL
			</label>
			<input
				id="oidc-issuer"
				type="url"
				bind:value={form.issuerUrl}
				placeholder="https://auth.example.com/application/o/arenet/"
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
			/>
			<p class="text-xs text-muted mt-1">
				URL d'émetteur OIDC (champ <code class="font-mono">issuer</code> du
				discovery document). NE PAS inclure le suffixe
				<code class="font-mono">/.well-known/openid-configuration</code> —
				Arenet l'ajoute automatiquement. Authentik :
				<code class="font-mono">/application/o/&lt;slug&gt;/</code> ; Keycloak :
				<code class="font-mono">/realms/&lt;realm&gt;</code> ; Authelia : la racine
				du déploiement.
			</p>
		</div>

		<div>
			<label for="oidc-client-id" class="text-sm font-medium text-secondary block mb-1">
				Client ID
			</label>
			<input
				id="oidc-client-id"
				type="text"
				bind:value={form.clientId}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
			/>
		</div>

		<div>
			<label for="oidc-client-secret" class="text-sm font-medium text-secondary block mb-1">
				Client secret
			</label>
			<input
				id="oidc-client-secret"
				type="password"
				autocomplete="off"
				bind:value={form.clientSecret}
				placeholder={config?.clientSecretSet ? '••• set (leave blank to keep)' : ''}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
			/>
		</div>

		<div class="md:col-span-2">
			<label for="oidc-redirect" class="text-sm font-medium text-secondary block mb-1">
				Redirect URL
			</label>
			<input
				id="oidc-redirect"
				type="url"
				bind:value={form.redirectUrl}
				placeholder="https://arenet.example.com/api/v1/auth/oidc/callback"
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
			/>
		</div>

		<div class="md:col-span-2">
			<label for="oidc-scopes" class="text-sm font-medium text-secondary block mb-1">
				Scopes
			</label>
			<input
				id="oidc-scopes"
				type="text"
				bind:value={form.scopes}
				placeholder="openid profile email"
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
			/>
			<p class="text-xs text-muted mt-1">
				Space- or comma-separated. <code class="font-mono">openid</code> is
				mandatory; <code class="font-mono">email</code> is required for the
				canonicalisation step.
			</p>
		</div>

		{#if formError}
			<p class="text-sm text-down md:col-span-2" role="alert">{formError}</p>
		{/if}

		<div class="md:col-span-2 flex justify-end">
			<Button type="submit" disabled={submitting}>
				{submitting ? 'Saving…' : 'Save'}
			</Button>
		</div>
	</form>

	<div class="mt-8 pt-6 border-t border-border-subtle">
		<h3 class="text-base font-semibold text-primary mb-2">Allowlist</h3>
		<p class="text-xs text-muted mb-4">
			Only emails on this list can log in via SSO. New entries are
			"pending" until the user's first login canonicalises them.
		</p>

		<form
			class="mb-4 space-y-2"
			onsubmit={(e) => {
				e.preventDefault();
				void addAllowlistEntry();
			}}
		>
			<div class="grid grid-cols-1 md:grid-cols-2 gap-3">
				<input
					type="email"
					bind:value={newEntry.email}
					placeholder="user@example.com"
					class="bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
				/>
				<input
					type="text"
					bind:value={newEntry.displayName}
					placeholder="Display name (optional)"
					class="bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
				/>
			</div>
			<div class="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-3">
				<input
					type="text"
					bind:value={newEntry.sub}
					placeholder="OIDC Subject ID (optional)"
					class="bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
				<Button type="submit" disabled={allowlistSubmitting}>
					{allowlistSubmitting ? 'Adding…' : 'Add'}
				</Button>
			</div>
			<p class="text-xs text-muted">
				To find the OIDC Subject ID, look it up in your IdP's admin
				console. Leaving this field empty uses email-bootstrap on
				first login (requires the IdP to emit
				<code class="font-mono">email_verified=true</code>).
			</p>
		</form>

		{#if allowlistError}
			<p class="text-sm text-down mb-3" role="alert">{allowlistError}</p>
		{/if}

		{#if allowlist.length === 0}
			<p class="text-sm text-muted">No entries yet.</p>
		{:else}
			<ul class="divide-y divide-border-subtle">
				{#each allowlist as entry (entry.email)}
					<li class="flex items-center justify-between py-2">
						<div class="min-w-0 flex-1">
							<div class="flex items-center gap-2">
								<span class="font-mono text-sm">{entry.email}</span>
								{#if entry.sub}
									<Badge variant="status-up">Linked</Badge>
								{:else}
									<Badge variant="status-warn">Pending</Badge>
								{/if}
							</div>
							{#if entry.displayName}
								<p class="text-xs text-muted">{entry.displayName}</p>
							{/if}
						</div>
						<Button
							variant="ghost"
							size="sm"
							onclick={() => void deleteAllowlistEntry(entry.email)}
						>
							Remove
						</Button>
					</li>
				{/each}
			</ul>
		{/if}
	</div>
</Card>
