<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  DNSProvidersSection (v2.12 Task 2c, 2026-07-12).

  Replaces the pre-v2.12 singleton OVH credentials form on
  /settings with a multi-config DNS provider collection: a table
  (Label | Type | Endpoint | Status | Used by | Actions) plus an
  add/edit Modal and a delete ConfirmDialog. Mirrors the
  forward-auth providers section's structure + the J.4 secret
  discipline (blank on edit = preserve-on-edit; secrets never
  displayed).

  The section root carries id="dns-providers" so the wildcard
  wizard's empty-state CTA can deep-link to /settings#dns-providers.

  Delete is guarded server-side: a provider still bound to one or
  more wildcard apexes yields a 409 `provider_in_use` whose
  `params.wildcards` names the offending apexes — surfaced verbatim
  in the danger toast so the operator knows exactly what to detach
  first.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { settingsApi } from '$lib/api/settings';
	import { ApiError, OVH_ENDPOINTS } from '$lib/api/types';
	import type { DNSProvider, DNSProviderRequest } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';

	// v1.0 supports OVH only. The Type field is a <select> (not a
	// hardcoded label) so a future Cloudflare / Route53 addition is
	// additive — just extend this list.
	const DNS_PROVIDER_TYPES: readonly string[] = ['ovh'] as const;

	let providers = $state<DNSProvider[]>([]);
	let loading = $state(true);
	let loadError = $state<string | null>(null);

	// Modal state. editingId === null → add mode (POST); non-null →
	// edit mode (PUT on /{id}). The three secret fields are
	// write-only: blank on edit preserves the stored value (the
	// backend merges against the previous row).
	let modalOpen = $state(false);
	let editingId = $state<string | null>(null);
	let editingConfigured = $state(false);
	let submitting = $state(false);
	let formError = $state<string | null>(null);
	let form = $state({
		label: '',
		type: 'ovh',
		endpoint: 'ovh-eu',
		applicationKey: '',
		applicationSecret: '',
		consumerKey: '',
	});

	// Delete state.
	let deleteOpen = $state(false);
	let deleteTarget = $state<DNSProvider | null>(null);

	async function loadProviders(): Promise<void> {
		loading = true;
		loadError = null;
		try {
			providers = await settingsApi.listDNSProviders();
		} catch (err) {
			loadError = err instanceof Error ? err.message : String(err);
		} finally {
			loading = false;
		}
	}

	function openAdd(): void {
		editingId = null;
		editingConfigured = false;
		form = {
			label: '',
			type: 'ovh',
			endpoint: 'ovh-eu',
			applicationKey: '',
			applicationSecret: '',
			consumerKey: '',
		};
		formError = null;
		modalOpen = true;
	}

	function openEdit(p: DNSProvider): void {
		editingId = p.id;
		editingConfigured = p.configured;
		form = {
			label: p.label,
			type: p.type || 'ovh',
			endpoint: p.endpoint || 'ovh-eu',
			// Secrets stay blank on edit — the wire never carries them
			// and a blank submit preserves the stored value.
			applicationKey: '',
			applicationSecret: '',
			consumerKey: '',
		};
		formError = null;
		modalOpen = true;
	}

	function closeModal(): void {
		if (submitting) return;
		modalOpen = false;
	}

	async function submitForm(): Promise<void> {
		if (submitting) return;
		const label = form.label.trim();
		if (label === '') {
			formError = t('settings.dnsProviders.validation.labelRequired');
			return;
		}
		if (form.endpoint.trim() === '') {
			formError = t('settings.dnsProviders.validation.endpointRequired');
			return;
		}
		submitting = true;
		formError = null;
		// Build the request body. Only send non-empty secret fields so a
		// blank secret on edit triggers the backend's preserve-on-edit
		// path (J.4 pattern). On add, blank secrets are sent as absent —
		// the backend 400s if they're required for the type.
		const body: DNSProviderRequest = {
			label,
			type: form.type,
			endpoint: form.endpoint,
		};
		if (form.applicationKey !== '') body.applicationKey = form.applicationKey;
		if (form.applicationSecret !== '') body.applicationSecret = form.applicationSecret;
		if (form.consumerKey !== '') body.consumerKey = form.consumerKey;
		try {
			if (editingId === null) {
				await settingsApi.createDNSProvider(body);
				pushToast(t('settings.dnsProviders.toast.created'), 'success');
			} else {
				await settingsApi.updateDNSProvider(editingId, body);
				pushToast(t('settings.dnsProviders.toast.updated'), 'success');
			}
			modalOpen = false;
			await loadProviders();
		} catch (err) {
			formError = err instanceof ApiError ? err.message : String(err);
		} finally {
			submitting = false;
		}
	}

	function openDelete(p: DNSProvider): void {
		deleteTarget = p;
		deleteOpen = true;
	}

	async function confirmDelete(): Promise<void> {
		const target = deleteTarget;
		if (!target) return;
		try {
			await settingsApi.deleteDNSProvider(target.id);
			pushToast(t('settings.dnsProviders.toast.deleted'), 'success');
			deleteOpen = false;
			deleteTarget = null;
			await loadProviders();
		} catch (err) {
			if (err instanceof ApiError && err.code === 'provider_in_use') {
				const wildcards = Array.isArray(err.params?.wildcards)
					? (err.params.wildcards as string[])
					: [];
				pushToast(
					t('settings.dnsProviders.delete.error409', {
						wildcards: wildcards.join(', '),
					}),
					'danger',
				);
			} else if (err instanceof ApiError && err.code === 'provider_in_use_by_routes') {
				const routes = Array.isArray(err.params?.routes)
					? (err.params.routes as string[])
					: [];
				pushToast(
					t('settings.dnsProviders.delete.error409Routes', {
						routes: routes.join(', '),
					}),
					'danger',
				);
			} else {
				const msg = err instanceof Error ? err.message : String(err);
				pushToast(
					t('settings.dnsProviders.delete.errorGeneric', { err: msg }),
					'danger',
				);
			}
			// Keep the dialog open so the operator can retry / cancel.
		}
	}

	onMount(() => {
		void loadProviders();
	});
</script>

<div id="dns-providers" class="mb-6">
	<Card padding="p-6">
		<header class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4">
			<div>
				<h2 class="text-xl font-semibold">
					{language.current && t('settings.dnsProviders.title')}
				</h2>
				<p class="text-xs text-muted mt-1">
					{language.current && t('settings.dnsProviders.subtitle')}
				</p>
			</div>
			{#if !loading && providers.length > 0}
				<Button onclick={openAdd} data-testid="dns-provider-add">
					{language.current && t('settings.dnsProviders.table.addButton')}
				</Button>
			{/if}
		</header>

		{#if loading}
			<div class="flex items-center gap-2 py-4 text-secondary text-sm">
				<Spinner size="sm" />
				{language.current && t('settings.dnsProviders.loading')}
			</div>
		{:else if loadError}
			<p class="text-sm text-down mb-3" role="alert">
				{language.current && t('settings.dnsProviders.loadError', { err: loadError })}
			</p>
		{:else if providers.length === 0}
			<div class="flex flex-col items-start gap-3 py-4">
				<Button onclick={openAdd} data-testid="dns-provider-empty-add">
					{language.current && t('settings.dnsProviders.table.emptyCta')}
				</Button>
			</div>
		{:else}
			<div class="overflow-x-auto">
				<table class="w-full text-sm">
					<thead>
						<tr class="text-left text-xs text-secondary uppercase">
							<th class="py-2 pr-3">{language.current && t('settings.dnsProviders.table.label')}</th>
							<th class="py-2 px-2">{language.current && t('settings.dnsProviders.table.type')}</th>
							<th class="py-2 px-2">{language.current && t('settings.dnsProviders.table.endpoint')}</th>
							<th class="py-2 px-2">{language.current && t('settings.dnsProviders.table.status')}</th>
							<th class="py-2 px-2">{language.current && t('settings.dnsProviders.table.usedBy')}</th>
							<th class="py-2 pl-2 text-right">{language.current && t('settings.dnsProviders.table.actions')}</th>
						</tr>
					</thead>
					<tbody>
						{#each providers as p (p.id)}
							<tr class="border-t border-border-subtle" data-testid={`dns-provider-row-${p.id}`}>
								<td class="py-2 pr-3 text-primary">{p.label}</td>
								<td class="py-2 px-2 font-mono text-secondary">{p.type}</td>
								<td class="py-2 px-2 font-mono text-secondary">{p.endpoint}</td>
								<td class="py-2 px-2">
									{#if p.configured}
										<Badge variant="status-up"
											>{language.current && t('settings.dnsProviders.badge.configured')}</Badge
										>
									{:else}
										<Badge variant="status-warn"
											>{language.current && t('settings.dnsProviders.badge.notConfigured')}</Badge
										>
									{/if}
								</td>
								<td class="py-2 px-2 text-secondary">
									{#if p.usedBy.length > 0}
										<span class="font-mono">{p.usedBy.join(', ')}</span>
									{:else}
										<span class="text-muted"
											>{language.current && t('settings.dnsProviders.table.usedByNone')}</span
										>
									{/if}
								</td>
								<td class="py-2 pl-2 text-right whitespace-nowrap">
									<Button
										variant="ghost"
										size="sm"
										onclick={() => openEdit(p)}
										data-testid={`dns-provider-edit-${p.id}`}
										aria-label={language.current &&
											t('settings.dnsProviders.modal.editTitle')}
									>
										✎
									</Button>
									<Button
										variant="ghost"
										size="sm"
										onclick={() => openDelete(p)}
										data-testid={`dns-provider-delete-${p.id}`}
										aria-label={language.current &&
											t('settings.dnsProviders.delete.confirmTitle')}
									>
										🗑
									</Button>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</Card>
</div>

<Modal
	open={modalOpen}
	title={language.current &&
		(editingId === null
			? t('settings.dnsProviders.modal.addTitle')
			: t('settings.dnsProviders.modal.editTitle'))}
	onClose={closeModal}
	width="lg"
>
	<form
		class="grid grid-cols-1 md:grid-cols-2 gap-4"
		data-testid="dns-provider-form"
		onsubmit={(e) => {
			e.preventDefault();
			void submitForm();
		}}
	>
		<div class="md:col-span-2">
			<label for="dnsp-label" class="text-sm font-medium text-secondary block mb-1">
				{language.current && t('settings.dnsProviders.modal.labelField')}
			</label>
			<input
				id="dnsp-label"
				type="text"
				bind:value={form.label}
				disabled={submitting}
				autocomplete="off"
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
			/>
		</div>

		<div>
			<label for="dnsp-type" class="text-sm font-medium text-secondary block mb-1">
				{language.current && t('settings.dnsProviders.modal.typeField')}
			</label>
			<select
				id="dnsp-type"
				bind:value={form.type}
				disabled={submitting}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
			>
				{#each DNS_PROVIDER_TYPES as ty (ty)}
					<option value={ty}>{ty}</option>
				{/each}
			</select>
		</div>

		<div>
			<label for="dnsp-endpoint" class="text-sm font-medium text-secondary block mb-1">
				{language.current && t('settings.dnsProviders.modal.endpointField')}
			</label>
			<select
				id="dnsp-endpoint"
				bind:value={form.endpoint}
				disabled={submitting}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
			>
				{#each OVH_ENDPOINTS as ep (ep)}
					<option value={ep}>{ep}</option>
				{/each}
			</select>
		</div>

		<div>
			<label for="dnsp-app-key" class="text-sm font-medium text-secondary block mb-1">
				{language.current && t('settings.dnsProviders.modal.appKey')}
			</label>
			<input
				id="dnsp-app-key"
				type="password"
				autocomplete="off"
				bind:value={form.applicationKey}
				disabled={submitting}
				placeholder={editingConfigured
					? (language.current && t('settings.dnsProviders.modal.secretsKeepHint')) || ''
					: ''}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
			/>
		</div>

		<div>
			<label for="dnsp-app-secret" class="text-sm font-medium text-secondary block mb-1">
				{language.current && t('settings.dnsProviders.modal.appSecret')}
			</label>
			<input
				id="dnsp-app-secret"
				type="password"
				autocomplete="off"
				bind:value={form.applicationSecret}
				disabled={submitting}
				placeholder={editingConfigured
					? (language.current && t('settings.dnsProviders.modal.secretsKeepHint')) || ''
					: ''}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
			/>
		</div>

		<div class="md:col-span-2">
			<label for="dnsp-consumer-key" class="text-sm font-medium text-secondary block mb-1">
				{language.current && t('settings.dnsProviders.modal.consumerKey')}
			</label>
			<input
				id="dnsp-consumer-key"
				type="password"
				autocomplete="off"
				bind:value={form.consumerKey}
				disabled={submitting}
				placeholder={editingConfigured
					? (language.current && t('settings.dnsProviders.modal.secretsKeepHint')) || ''
					: ''}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
			/>
		</div>

		{#if formError}
			<p class="text-sm text-down md:col-span-2" role="alert" data-testid="dns-provider-form-error">
				{formError}
			</p>
		{/if}

		<!-- Hidden submit so Enter inside a field fires the form. -->
		<button type="submit" class="sr-only" tabindex="-1" aria-hidden="true">Submit</button>
	</form>

	{#snippet footer()}
		<Button variant="ghost" onclick={closeModal} disabled={submitting}>
			{language.current && t('settings.dnsProviders.modal.cancel')}
		</Button>
		<Button variant="primary" onclick={() => void submitForm()} loading={submitting}>
			{language.current &&
				(submitting
					? t('settings.dnsProviders.modal.saving')
					: editingId === null
						? t('settings.dnsProviders.modal.add')
						: t('settings.dnsProviders.modal.save'))}
		</Button>
	{/snippet}
</Modal>

<ConfirmDialog
	bind:open={deleteOpen}
	title={language.current && t('settings.dnsProviders.delete.confirmTitle')}
	message={language.current && t('settings.dnsProviders.delete.confirmText')}
	confirmLabel={language.current && t('settings.dnsProviders.delete.confirm')}
	cancelLabel={language.current && t('settings.dnsProviders.delete.cancel')}
	confirmVariant="danger"
	onConfirm={confirmDelete}
/>
