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
		severityTooltip,
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
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

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
				msg: t('alerting.rules.summaryTestOk', { name, count: res.channelsFired.length }),
				variant: 'success'
			};
		}
		const failedCount = res.errors ? Object.keys(res.errors).length : 0;
		const skippedCount = res.skipped ? Object.keys(res.skipped).length : 0;
		if (failedCount > 0) {
			return {
				msg: t('alerting.rules.summaryTestErrors', { name, sent: res.channelsFired.length, failed: failedCount }),
				variant: 'danger'
			};
		}
		if (skippedCount > 0) {
			return {
				msg: t('alerting.rules.summaryTestSkipped', { name, sent: res.channelsFired.length, skipped: skippedCount }),
				variant: 'info'
			};
		}
		return { msg: t('alerting.rules.summaryTestNoChannels', { name }), variant: 'danger' };
	}

	async function onTest(r: AlertRule) {
		testingIds[r.id] = true;
		try {
			const res = await rulesStore.test(r.id);
			const { msg, variant } = summariseTest(r.name, res);
			pushToast(msg, variant);
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : t('alerting.networkError');
			pushToast(t('alerting.rules.toastTestNamedErr', { name: r.name, err: msg }), 'danger');
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
			pushToast(t('alerting.rules.toastDeleted', { name: target.name }), 'success');
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : t('alerting.networkError');
			pushToast(t('alerting.rules.toastDeleteFailed', { err: msg }), 'danger');
		} finally {
			deletingIds = { ...deletingIds, [target.id]: false };
			confirmTarget = null;
		}
	}

	function kindLabel(kind: string): string {
		void language.current;
		return kind === 'threshold' ? t('alerting.rules.kindThreshold') : kind === 'state' ? t('alerting.rules.kindState') : kind;
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
		void language.current;
		if (!r.lastEvalAt) return t('alerting.never');
		return relativeTime(r.lastEvalAt);
	}

	function lastEvalTooltip(r: AlertRule): string {
		void language.current;
		if (!r.lastEvalAt) {
			return r.enabled
				? t('alerting.rules.lastEvalTooltipPendingEnabled')
				: t('alerting.rules.lastEvalTooltipDisabled');
		}
		return r.lastEvalAt;
	}

	function lastFireLabel(r: AlertRule): string {
		void language.current;
		if (!r.lastFiredAt) return t('alerting.never');
		return relativeTime(r.lastFiredAt);
	}

	function lastFireTooltip(r: AlertRule): string {
		void language.current;
		if (!r.lastFiredAt) {
			return t('alerting.rules.lastFireTooltipNever');
		}
		return r.lastFiredAt;
	}
</script>

<div class="space-y-4">
	<div class="flex justify-end">
		<Button variant="primary" onclick={openCreate}>
			{#snippet children()}{language.current && t('alerting.rules.addBtn')}{/snippet}
		</Button>
	</div>

	{#if loadError}
		<div
			class="p-4 rounded bg-down/10 border border-down text-down flex items-center justify-between"
			role="alert"
		>
			<span>{language.current && t('alerting.rules.loadErr', { err: loadError })}</span>
			<Button variant="secondary" size="sm" onclick={reload} disabled={loading}>
				{#snippet children()}{language.current && t('alerting.actionRetry')}{/snippet}
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
			<p class="text-primary font-medium mb-1">{language.current && t('alerting.rules.emptyTitle')}</p>
			<p class="text-secondary text-sm max-w-md mx-auto">
				{language.current && t('alerting.rules.emptyBody')}
			</p>
		</div>
	{:else if rules.length > 0}
		<DataTable
			items={rules}
			headers={language.current ? [
				t('alerting.rules.colName'),
				t('alerting.rules.colState'),
				t('alerting.rules.colType'),
				t('alerting.rules.colSource'),
				t('alerting.rules.colSeverity'),
				t('alerting.rules.colChannels'),
				t('alerting.rules.colCooldown'),
				t('alerting.rules.colLastEval'),
				t('alerting.rules.colLastFire'),
				t('alerting.rules.colActions')
			] : []}
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
				{#snippet children()}{language.current && t('alerting.stateEnabled')}{/snippet}
			</Badge>
		{:else}
			<Badge variant="neutral">
				{#snippet children()}{language.current && t('alerting.stateDisabled')}{/snippet}
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
		<span title={severityTooltip(r.severity)}>
			<Badge variant={severityBadgeVariant(r.severity)}>
				{#snippet children()}{severityLabelFR(r.severity)}{/snippet}
			</Badge>
		</span>
	</td>
	<td class="px-4 py-3 text-sm text-primary" title={channelsTooltip(r)}>
		{r.channels.length}
	</td>
	<td class="px-4 py-3 text-sm text-secondary">{cooldownLabel(r.cooldownSecs)}</td>
	<td class="px-4 py-3 text-sm">
		<span title={lastEvalTooltip(r)}>{lastEvalLabel(r)}</span>
		{#if r.lastError}
			<span title={`${r.lastError}\n(${r.lastErrorAt ?? ''})`} class="ml-2">
				<Badge variant="status-down">
					{#snippet children()}{language.current && t('alerting.errorBadge')}{/snippet}
				</Badge>
			</span>
		{/if}
	</td>
	<td class="px-4 py-3 text-sm text-secondary" title={lastFireTooltip(r)}>
		{lastFireLabel(r)}
	</td>
	<td class="px-4 py-3 text-sm">
		<div class="flex gap-2">
			<Button
				variant="ghost"
				size="sm"
				onclick={() => openEdit(r)}
				aria-label={language.current && t('alerting.rules.ariaEdit', { name: r.name })}
			>
				{#snippet children()}{language.current && t('alerting.actionEdit')}{/snippet}
			</Button>
			<Button
				variant="ghost"
				size="sm"
				onclick={() => onTest(r)}
				disabled={testingIds[r.id]}
				loading={testingIds[r.id]}
				aria-label={language.current && t('alerting.rules.ariaTest', { name: r.name })}
			>
				{#snippet children()}{language.current && t('alerting.actionTest')}{/snippet}
			</Button>
			<Button
				variant="ghost"
				size="sm"
				onclick={() => askDelete(r)}
				disabled={deletingIds[r.id]}
				aria-label={language.current && t('alerting.rules.ariaDelete', { name: r.name })}
			>
				{#snippet children()}{language.current && t('alerting.actionDelete')}{/snippet}
			</Button>
		</div>
	</td>
{/snippet}

<RuleModal open={modalOpen} rule={modalRule} onClose={closeModal} onSaved={onModalSaved} />

<ConfirmDialog
	bind:open={confirmOpen}
	title={language.current && t('alerting.rules.confirmTitle')}
	message={confirmTarget && language.current
		? t('alerting.rules.confirmMessage', { name: confirmTarget.name })
		: ''}
	confirmLabel={language.current && t('alerting.rules.confirmDeleteLabel')}
	cancelLabel={language.current && t('alerting.rules.confirmCancelLabel')}
	confirmVariant="danger"
	onConfirm={confirmDelete}
/>
