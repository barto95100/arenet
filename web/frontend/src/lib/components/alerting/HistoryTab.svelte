<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  AL.4.b.1 — Alerting History tab.

  Mirrors the audit page's filter+pagination shape: 300ms
  debounced auto-apply, cursor-based "Charger plus", screen
  reader status. Reads from /api/v1/observability/alert-events
  populated by the AL.4.a dispatcher sink.

  Filter dropdown for Rule is populated from the live rules
  list via rulesStore.load() at mount — the AL.3b rule
  CRUD already exists, no UI required upstream.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { alertEventsStore, rulesStore } from '$lib/stores/alerting.svelte';
	import {
		severityBadgeVariant,
		severityLabelFR,
		severityTooltip,
		SEVERITY_TOKENS,
		type AlertEvent
	} from '$lib/api/alerting';
	import { ApiError } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import DataTable from '$lib/components/DataTable.svelte';
	import Input from '$lib/components/Input.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import { relativeTime } from '$lib/utils/audit-format';

	const DEBOUNCE_MS = 300;
	const PAGE_SIZE = 50;

	let fromValue = $state('');
	let toValue = $state('');
	let severityFilter = $state(''); // '' = all; otherwise '0'..'3'
	let ruleFilter = $state(''); // rule id; '' = all
	let categoryFilter = $state('');

	let didInitialLoad = $state(false);
	let debounceTimer: ReturnType<typeof setTimeout> | null = null;
	let suppressEffectReload = true; // skip the mount fire of the $effect

	const events = $derived(alertEventsStore.state.events);
	const loading = $derived(alertEventsStore.state.loading);
	const loadMoreLoading = $derived(alertEventsStore.state.loadMoreLoading);
	const loadError = $derived(alertEventsStore.state.loadError);
	const nextCursor = $derived(alertEventsStore.state.nextCursor);
	const degraded = $derived(alertEventsStore.state.degraded);

	const rules = $derived(rulesStore.state.rules);

	function buildFilter() {
		const f: Parameters<typeof alertEventsStore.load>[0] = { limit: PAGE_SIZE };
		if (fromValue) f.since = fromValue;
		if (toValue) f.until = toValue;
		if (severityFilter !== '') f.severity = Number(severityFilter);
		if (ruleFilter) f.ruleId = ruleFilter;
		if (categoryFilter) f.category = categoryFilter;
		return f;
	}

	async function load(reset: boolean): Promise<void> {
		try {
			await alertEventsStore.load(buildFilter(), reset);
		} catch (err) {
			if (!reset) {
				// Load-more failure: keep existing rows visible,
				// surface as toast (mirrors /audit's pattern).
				const msg = err instanceof ApiError ? err.message : 'Échec du chargement';
				pushToast(msg, 'danger');
			}
		} finally {
			didInitialLoad = true;
		}
	}

	function scheduleReload(): void {
		if (debounceTimer !== null) clearTimeout(debounceTimer);
		debounceTimer = setTimeout(() => {
			void load(true);
		}, DEBOUNCE_MS);
	}

	$effect(() => {
		// Read every filter to subscribe to changes.
		void (fromValue + toValue + severityFilter + ruleFilter + categoryFilter);
		if (suppressEffectReload) {
			suppressEffectReload = false;
			return;
		}
		scheduleReload();
	});

	onMount(() => {
		void load(true);
		// Populate the rule filter dropdown. Failure is non-
		// fatal — the dropdown stays empty + the operator can
		// still filter by date/severity/category.
		void rulesStore.load();
	});

	function clearFilters(): void {
		fromValue = '';
		toValue = '';
		severityFilter = '';
		ruleFilter = '';
		categoryFilter = '';
	}

	const hasAnyFilter = $derived(
		Boolean(fromValue || toValue || severityFilter || ruleFilter || categoryFilter)
	);

	const emptyStateMessage = $derived(
		hasAnyFilter
			? 'Aucun événement ne correspond aux filtres actuels.'
			: 'Aucun événement enregistré pour le moment. Créez un canal puis une règle dans les onglets ci-dessus, puis cliquez sur Test pour générer un premier événement.'
	);

	const a11yStatus = $derived.by(() => {
		if (loading) return 'Chargement des événements…';
		if (loadError) return `Échec : ${loadError}`;
		if (events.length === 0 && didInitialLoad) return emptyStateMessage;
		return `${events.length} événement${events.length === 1 ? '' : 's'} chargé${
			events.length === 1 ? '' : 's'
		}`;
	});

	function failedCount(ev: AlertEvent): number {
		return ev.channelsFailed ? Object.keys(ev.channelsFailed).length : 0;
	}

	function failedTooltip(ev: AlertEvent): string {
		if (!ev.channelsFailed) return '';
		return Object.entries(ev.channelsFailed)
			.map(([id, err]) => `${id}: ${err}`)
			.join('\n');
	}
</script>

<div class="space-y-6">
	{#if degraded}
		<div class="rounded border border-down/40 bg-down/10 px-4 py-3 text-sm text-down" role="alert">
			Observabilité indisponible : l'historique des alertes n'est pas accessible. Vérifiez
			que <code>metrics.db</code> est ouvert.
		</div>
	{/if}

	<!-- Filters -->
	<div
		class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3 p-4 bg-elevated border border-border-default rounded-lg"
	>
		<Input bind:value={fromValue} label="Depuis (RFC 3339)" placeholder="2026-06-15T00:00:00Z" />
		<Input bind:value={toValue} label="Jusqu'à (RFC 3339)" placeholder="2026-06-16T00:00:00Z" />
		<div>
			<label
				for="alerting-severity-filter"
				class="text-sm font-medium text-secondary mb-1.5 block"
			>
				Sévérité
			</label>
			<select
				id="alerting-severity-filter"
				bind:value={severityFilter}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
			>
				<option value="">Toutes</option>
				{#each SEVERITY_TOKENS as token, i (token)}
					<option value={String(i)}>{severityLabelFR(i)}</option>
				{/each}
			</select>
		</div>
		<div>
			<label
				for="alerting-rule-filter"
				class="text-sm font-medium text-secondary mb-1.5 block"
			>
				Règle
			</label>
			<select
				id="alerting-rule-filter"
				bind:value={ruleFilter}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
			>
				<option value="">Toutes</option>
				{#each rules as r (r.id)}
					<option value={r.id}>{r.name}</option>
				{/each}
			</select>
		</div>
		<Input bind:value={categoryFilter} label="Catégorie" placeholder="waf / cert / ..." />
	</div>

	{#if hasAnyFilter}
		<div class="flex">
			<Button variant="ghost" size="sm" onclick={clearFilters}>
				{#snippet children()}Réinitialiser les filtres{/snippet}
			</Button>
		</div>
	{/if}

	{#if loadError}
		<div
			class="p-4 rounded bg-down/10 border border-down text-down flex items-center justify-between"
			role="alert"
		>
			<span>⚠ Échec du chargement : {loadError}</span>
			<Button variant="secondary" size="sm" onclick={() => load(true)} disabled={loading}>
				{#snippet children()}Réessayer{/snippet}
			</Button>
		</div>
	{/if}

	{#if loading && events.length === 0}
		<div class="flex justify-center mt-12">
			<Spinner size="lg" />
		</div>
	{:else if events.length === 0 && didInitialLoad && !loadError}
		<p class="text-secondary text-center mt-12">{emptyStateMessage}</p>
	{:else if events.length > 0}
		<DataTable
			items={events.map((e) => ({ ...e, id: e.eventId }))}
			headers={['Date', 'Règle', 'Sévérité', 'Catégorie', 'Sujet', 'Envoyés', 'Échecs']}
			row={historyRowSnippet}
			interactive={false}
		/>

		{#if nextCursor}
			<div class="flex justify-center">
				<Button
					variant="secondary"
					size="md"
					onclick={() => load(false)}
					disabled={loadMoreLoading}
					loading={loadMoreLoading}
				>
					{#snippet children()}
						<span>{loadMoreLoading ? 'Chargement…' : 'Charger plus'}</span>
					{/snippet}
				</Button>
			</div>
		{/if}
	{/if}
</div>

<div role="status" aria-live="polite" class="sr-only">{a11yStatus}</div>

{#snippet historyRowSnippet(ev: AlertEvent & { id: string })}
	<td class="px-4 py-3 text-sm text-primary" title={ev.timestamp}>
		{relativeTime(ev.timestamp)}
	</td>
	<td class="px-4 py-3 text-sm text-primary truncate">{ev.ruleName}</td>
	<td class="px-4 py-3 text-sm">
		<span title={severityTooltip(ev.severity)}>
			<Badge variant={severityBadgeVariant(ev.severity)}>
				{#snippet children()}{severityLabelFR(ev.severity)}{/snippet}
			</Badge>
		</span>
	</td>
	<td class="px-4 py-3 text-sm text-secondary">{ev.category}</td>
	<td class="px-4 py-3 text-sm text-primary truncate" title={ev.subject}>{ev.subject}</td>
	<td class="px-4 py-3 text-sm text-primary">
		<span title={ev.channelsFired.join(', ')}>{ev.channelsFired.length}</span>
	</td>
	<td class="px-4 py-3 text-sm">
		{#if failedCount(ev) > 0}
			<span title={failedTooltip(ev)}>
				<Badge variant="status-down">
					{#snippet children()}{failedCount(ev)}{/snippet}
				</Badge>
			</span>
		{:else}
			<span class="text-secondary">0</span>
		{/if}
	</td>
{/snippet}

<style>
	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		white-space: nowrap;
		border: 0;
	}
</style>
