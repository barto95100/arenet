<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  AL.4.b.2 — Channels tab. Table of alerting channels with
  Édit / Test / Supprimer per row + "Ajouter un canal"
  button opening ChannelModal. Mirrors the AL.4.b.1
  HistoryTab structure for empty/loading/error states.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { channelsStore } from '$lib/stores/alerting.svelte';
	import {
		severityBadgeVariant,
		severityLabelFR,
		type AlertChannel
	} from '$lib/api/alerting';
	import { ApiError } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import DataTable from '$lib/components/DataTable.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import ChannelModal from './ChannelModal.svelte';
	import { relativeTime } from '$lib/utils/audit-format';

	const channels = $derived(channelsStore.state.channels);
	const loading = $derived(channelsStore.state.loading);
	const loadError = $derived(channelsStore.state.loadError);

	let didInitialLoad = $state(false);

	let modalOpen = $state(false);
	let modalChannel = $state<AlertChannel | null>(null);

	let confirmOpen = $state(false);
	let confirmTarget = $state<AlertChannel | null>(null);

	// Per-row in-flight flags. Keyed by channel ID so the
	// table can disable per-row action buttons while a
	// test / delete is running without freezing the rest
	// of the table.
	let testingIds = $state<Record<string, boolean>>({});
	let deletingIds = $state<Record<string, boolean>>({});

	async function reload() {
		await channelsStore.load();
		didInitialLoad = true;
	}

	onMount(() => {
		void reload();
	});

	function openCreate() {
		modalChannel = null;
		modalOpen = true;
	}

	function openEdit(c: AlertChannel) {
		modalChannel = c;
		modalOpen = true;
	}

	function closeModal() {
		modalOpen = false;
		modalChannel = null;
	}

	async function onModalSaved() {
		modalOpen = false;
		modalChannel = null;
		// The store appended/replaced optimistically; a full
		// reload pulls fresh LastSentAt/LastError fields in
		// case a test was fired from inside the modal.
		await reload();
	}

	async function onTest(c: AlertChannel) {
		testingIds[c.id] = true;
		try {
			const res = await channelsStore.test(c.id);
			if (res.ok) {
				pushToast(`Canal "${c.name}" testé : envoi réussi.`, 'success');
			} else {
				pushToast(
					`Canal "${c.name}" : échec — ${res.error ?? 'erreur inconnue'}`,
					'danger'
				);
			}
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : 'Erreur réseau';
			pushToast(`Canal "${c.name}" : ${msg}`, 'danger');
		} finally {
			testingIds = { ...testingIds, [c.id]: false };
			// Refresh to pick up LastSentAt/LastError changes.
			void reload();
		}
	}

	function askDelete(c: AlertChannel) {
		confirmTarget = c;
		confirmOpen = true;
	}

	async function confirmDelete() {
		const target = confirmTarget;
		if (!target) return;
		deletingIds[target.id] = true;
		confirmOpen = false;
		try {
			await channelsStore.remove(target.id);
			pushToast(`Canal "${target.name}" supprimé.`, 'success');
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : 'Erreur réseau';
			pushToast(`Suppression échouée : ${msg}`, 'danger');
		} finally {
			deletingIds = { ...deletingIds, [target.id]: false };
			confirmTarget = null;
		}
	}

	function kindLabel(kind: string): string {
		switch (kind) {
			case 'webhook':
				return 'Webhook';
			case 'email':
				return 'Email';
			default:
				return kind;
		}
	}

	function kindIcon(kind: string): string {
		switch (kind) {
			case 'webhook':
				return '🔗';
			case 'email':
				return '✉️';
			default:
				return '•';
		}
	}

	function lastSentLabel(c: AlertChannel): string {
		if (!c.lastSentAt) return 'Jamais';
		return relativeTime(c.lastSentAt);
	}
</script>

<div class="space-y-4">
	<div class="flex justify-end">
		<Button variant="primary" onclick={openCreate}>
			{#snippet children()}Ajouter un canal{/snippet}
		</Button>
	</div>

	{#if loadError}
		<div
			class="p-4 rounded bg-down/10 border border-down text-down flex items-center justify-between"
			role="alert"
		>
			<span>⚠ Échec du chargement des canaux : {loadError}</span>
			<Button variant="secondary" size="sm" onclick={reload} disabled={loading}>
				{#snippet children()}Réessayer{/snippet}
			</Button>
		</div>
	{/if}

	{#if loading && channels.length === 0}
		<div class="flex justify-center mt-12">
			<Spinner size="lg" />
		</div>
	{:else if channels.length === 0 && didInitialLoad && !loadError}
		<div class="rounded-lg border border-border-subtle bg-elevated p-8 text-center">
			<div class="text-4xl text-muted mb-3">🔔</div>
			<p class="text-primary font-medium mb-1">Aucun canal configuré</p>
			<p class="text-secondary text-sm">
				Ajoutez un premier canal pour commencer à recevoir des notifications.
			</p>
		</div>
	{:else if channels.length > 0}
		<DataTable
			items={channels}
			headers={['Nom', 'Type', 'État', 'Sévérité min', 'Dernier envoi', 'Erreur', 'Actions']}
			row={channelRow}
			interactive={false}
		/>
	{/if}
</div>

{#snippet channelRow(c: AlertChannel)}
	<td class="px-4 py-3 text-sm text-primary truncate" title={c.name}>{c.name}</td>
	<td class="px-4 py-3 text-sm text-primary">
		<span aria-hidden="true" class="mr-1">{kindIcon(c.kind)}</span>
		{kindLabel(c.kind)}
	</td>
	<td class="px-4 py-3 text-sm">
		{#if c.enabled}
			<Badge variant="status-up">
				{#snippet children()}Actif{/snippet}
			</Badge>
		{:else}
			<Badge variant="neutral">
				{#snippet children()}Désactivé{/snippet}
			</Badge>
		{/if}
	</td>
	<td class="px-4 py-3 text-sm">
		<Badge variant={severityBadgeVariant(c.minSeverity)}>
			{#snippet children()}{severityLabelFR(c.minSeverity)}{/snippet}
		</Badge>
	</td>
	<td class="px-4 py-3 text-sm text-secondary" title={c.lastSentAt ?? 'Jamais'}>
		{lastSentLabel(c)}
	</td>
	<td class="px-4 py-3 text-sm">
		{#if c.lastError}
			<span title={`${c.lastError}\n(${c.lastErrorAt ?? ''})`}>
				<Badge variant="status-down">
					{#snippet children()}Erreur{/snippet}
				</Badge>
			</span>
		{:else}
			<span class="text-secondary">—</span>
		{/if}
	</td>
	<td class="px-4 py-3 text-sm">
		<div class="flex gap-2">
			<Button
				variant="ghost"
				size="sm"
				onclick={() => openEdit(c)}
				aria-label={`Éditer le canal ${c.name}`}
			>
				{#snippet children()}Édit{/snippet}
			</Button>
			<Button
				variant="ghost"
				size="sm"
				onclick={() => onTest(c)}
				disabled={testingIds[c.id]}
				loading={testingIds[c.id]}
				aria-label={`Tester le canal ${c.name}`}
			>
				{#snippet children()}Test{/snippet}
			</Button>
			<Button
				variant="ghost"
				size="sm"
				onclick={() => askDelete(c)}
				disabled={deletingIds[c.id]}
				aria-label={`Supprimer le canal ${c.name}`}
			>
				{#snippet children()}Suppr.{/snippet}
			</Button>
		</div>
	</td>
{/snippet}

<ChannelModal
	open={modalOpen}
	channel={modalChannel}
	onClose={closeModal}
	onSaved={onModalSaved}
/>

<ConfirmDialog
	bind:open={confirmOpen}
	title="Supprimer le canal"
	message={confirmTarget
		? `Supprimer le canal "${confirmTarget.name}" ? Cette action est irréversible.`
		: ''}
	confirmLabel="Supprimer"
	cancelLabel="Annuler"
	confirmVariant="danger"
	onConfirm={confirmDelete}
/>
