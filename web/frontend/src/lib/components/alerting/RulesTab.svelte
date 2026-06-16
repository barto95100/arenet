<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  AL.4.b.3 — Rules tab. Mirrors the AL.4.b.2 ChannelsTab
  structure (DataTable + per-row action buttons + Modal +
  ConfirmDialog). Adds channel-name resolution via the
  channelsStore so the "Canaux" column can show names
  instead of opaque IDs.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { rulesStore, channelsStore } from '$lib/stores/alerting.svelte';
	import {
		severityBadgeVariant,
		severityLabelFR,
		type AlertRule,
		type AlertRuleTestResponse
	} from '$lib/api/alerting';
	import { ApiError } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import DataTable from '$lib/components/DataTable.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import RuleModal from './RuleModal.svelte';
	import { relativeTime } from '$lib/utils/audit-format';

	const rules = $derived(rulesStore.state.rules);
	const loading = $derived(rulesStore.state.loading);
	const loadError = $derived(rulesStore.state.loadError);

	// Channel-name lookup so the Canaux column can render
	// human names from rule.channels (opaque UUIDs).
	const channelsById = $derived.by(() => {
		const m = new Map<string, { name: string; kind: string }>();
		for (const c of channelsStore.state.channels) {
			m.set(c.id, { name: c.name, kind: c.kind });
		}
		return m;
	});

	let didInitialLoad = $state(false);
	let modalOpen = $state(false);
	let modalRule = $state<AlertRule | null>(null);

	let confirmOpen = $state(false);
	let confirmTarget = $state<AlertRule | null>(null);

	let testingIds = $state<Record<string, boolean>>({});
	let deletingIds = $state<Record<string, boolean>>({});

	async function reload() {
		await rulesStore.load();
		didInitialLoad = true;
	}

	onMount(() => {
		void reload();
		// Channels needed for the name lookup. Load failure
		// is non-fatal — the table falls back to displaying
		// raw IDs.
		void channelsStore.load();
	});

	function openCreate() {
		modalRule = null;
		modalOpen = true;
	}

	function openEdit(r: AlertRule) {
		modalRule = r;
		modalOpen = true;
	}

	function closeModal() {
		modalOpen = false;
		modalRule = null;
	}

	async function onModalSaved() {
		modalOpen = false;
		modalRule = null;
		await reload();
	}

	function summariseTest(name: string, res: AlertRuleTestResponse): { msg: string; variant: 'success' | 'danger' | 'info' } {
		if (res.sent) {
			return {
				msg: `Règle "${name}" testée : envoi vers ${res.channelsFired.length} canal/aux.`,
				variant: 'success'
			};
		}
		const failedCount = res.errors ? Object.keys(res.errors).length : 0;
		const skippedCount = res.skipped ? Object.keys(res.skipped).length : 0;
		if (failedCount > 0) {
			return {
				msg: `Règle "${name}" : ${res.channelsFired.length} envoyé(s), ${failedCount} échec(s).`,
				variant: 'danger'
			};
		}
		if (skippedCount > 0) {
			return {
				msg: `Règle "${name}" : ${res.channelsFired.length} envoyé(s), ${skippedCount} ignoré(s) (canal désactivé ou sévérité min).`,
				variant: 'info'
			};
		}
		return { msg: `Règle "${name}" : aucun canal joignable.`, variant: 'danger' };
	}

	async function onTest(r: AlertRule) {
		testingIds[r.id] = true;
		try {
			const res = await rulesStore.test(r.id);
			const { msg, variant } = summariseTest(r.name, res);
			pushToast(msg, variant);
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : 'Erreur réseau';
			pushToast(`Règle "${r.name}" : ${msg}`, 'danger');
		} finally {
			testingIds = { ...testingIds, [r.id]: false };
			void reload();
		}
	}

	function askDelete(r: AlertRule) {
		confirmTarget = r;
		confirmOpen = true;
	}

	async function confirmDelete() {
		const target = confirmTarget;
		if (!target) return;
		deletingIds[target.id] = true;
		confirmOpen = false;
		try {
			await rulesStore.remove(target.id);
			pushToast(`Règle "${target.name}" supprimée.`, 'success');
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : 'Erreur réseau';
			pushToast(`Suppression échouée : ${msg}`, 'danger');
		} finally {
			deletingIds = { ...deletingIds, [target.id]: false };
			confirmTarget = null;
		}
	}

	function kindLabel(kind: string): string {
		return kind === 'threshold' ? 'Seuil' : kind === 'state' ? 'État' : kind;
	}

	function cooldownLabel(secs: number): string {
		if (secs % 3600 === 0) return `${secs / 3600} h`;
		if (secs % 60 === 0) return `${secs / 60} min`;
		return `${secs} s`;
	}

	function channelsTooltip(r: AlertRule): string {
		return r.channels
			.map((id) => {
				const c = channelsById.get(id);
				return c ? c.name : id;
			})
			.join(', ');
	}

	function lastEvalLabel(r: AlertRule): string {
		if (!r.lastEvalAt) return 'Jamais';
		return relativeTime(r.lastEvalAt);
	}

	function lastFireLabel(r: AlertRule): string {
		if (!r.lastFiredAt) return 'Jamais';
		return relativeTime(r.lastFiredAt);
	}
</script>

<div class="space-y-4">
	<div class="flex justify-end">
		<Button variant="primary" onclick={openCreate}>
			{#snippet children()}Ajouter une règle{/snippet}
		</Button>
	</div>

	{#if loadError}
		<div
			class="p-4 rounded bg-down/10 border border-down text-down flex items-center justify-between"
			role="alert"
		>
			<span>⚠ Échec du chargement des règles : {loadError}</span>
			<Button variant="secondary" size="sm" onclick={reload} disabled={loading}>
				{#snippet children()}Réessayer{/snippet}
			</Button>
		</div>
	{/if}

	{#if loading && rules.length === 0}
		<div class="flex justify-center mt-12">
			<Spinner size="lg" />
		</div>
	{:else if rules.length === 0 && didInitialLoad && !loadError}
		<div class="rounded-lg border border-border-subtle bg-elevated p-8 text-center">
			<div class="text-4xl text-muted mb-3">⚙️</div>
			<p class="text-primary font-medium mb-1">Aucune règle configurée</p>
			<p class="text-secondary text-sm">
				Ajoutez une première règle pour déclencher des notifications automatiques.
			</p>
		</div>
	{:else if rules.length > 0}
		<DataTable
			items={rules}
			headers={[
				'Nom',
				'État',
				'Type',
				'Source',
				'Sévérité',
				'Canaux',
				'Cooldown',
				'Dernière éval',
				'Dernière fire',
				'Actions'
			]}
			row={ruleRow}
			interactive={false}
		/>
	{/if}
</div>

{#snippet ruleRow(r: AlertRule)}
	<td class="px-4 py-3 text-sm text-primary truncate" title={r.name}>{r.name}</td>
	<td class="px-4 py-3 text-sm">
		{#if r.enabled}
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
		<Badge variant="neutral">
			{#snippet children()}{kindLabel(r.kind)}{/snippet}
		</Badge>
	</td>
	<td class="px-4 py-3 text-sm">
		<Badge variant="neutral">
			{#snippet children()}{r.source}{/snippet}
		</Badge>
	</td>
	<td class="px-4 py-3 text-sm">
		<Badge variant={severityBadgeVariant(r.severity)}>
			{#snippet children()}{severityLabelFR(r.severity)}{/snippet}
		</Badge>
	</td>
	<td class="px-4 py-3 text-sm text-primary" title={channelsTooltip(r)}>
		{r.channels.length}
	</td>
	<td class="px-4 py-3 text-sm text-secondary">{cooldownLabel(r.cooldownSecs)}</td>
	<td class="px-4 py-3 text-sm">
		<span title={r.lastEvalAt ?? 'Jamais'}>{lastEvalLabel(r)}</span>
		{#if r.lastError}
			<span title={`${r.lastError}\n(${r.lastErrorAt ?? ''})`} class="ml-2">
				<Badge variant="status-down">
					{#snippet children()}Erreur{/snippet}
				</Badge>
			</span>
		{/if}
	</td>
	<td class="px-4 py-3 text-sm text-secondary" title={r.lastFiredAt ?? 'Jamais'}>
		{lastFireLabel(r)}
	</td>
	<td class="px-4 py-3 text-sm">
		<div class="flex gap-2">
			<Button
				variant="ghost"
				size="sm"
				onclick={() => openEdit(r)}
				aria-label={`Éditer la règle ${r.name}`}
			>
				{#snippet children()}Édit{/snippet}
			</Button>
			<Button
				variant="ghost"
				size="sm"
				onclick={() => onTest(r)}
				disabled={testingIds[r.id]}
				loading={testingIds[r.id]}
				aria-label={`Tester la règle ${r.name}`}
			>
				{#snippet children()}Test{/snippet}
			</Button>
			<Button
				variant="ghost"
				size="sm"
				onclick={() => askDelete(r)}
				disabled={deletingIds[r.id]}
				aria-label={`Supprimer la règle ${r.name}`}
			>
				{#snippet children()}Suppr.{/snippet}
			</Button>
		</div>
	</td>
{/snippet}

<RuleModal open={modalOpen} rule={modalRule} onClose={closeModal} onSaved={onModalSaved} />

<ConfirmDialog
	bind:open={confirmOpen}
	title="Supprimer la règle"
	message={confirmTarget
		? `Supprimer la règle "${confirmTarget.name}" ? Cette action est irréversible.`
		: ''}
	confirmLabel="Supprimer"
	cancelLabel="Annuler"
	confirmVariant="danger"
	onConfirm={confirmDelete}
/>
