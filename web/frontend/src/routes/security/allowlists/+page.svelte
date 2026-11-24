<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  #364 — AreNET Allowlist UI (Option A, AreNET-native). Trusted IPs/CIDRs
  exempt from AreNET Security Automation auto-bans, per scope category
  (block / throttle / audit). The enforcement is entirely AreNET-side
  (the trigger), independent of CrowdSec — hence the prominent limitation
  note: this covers origin=arenet bans only.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import SwitchRow from '$lib/components/form/SwitchRow.svelte';
	import { serverErrorMessage } from '$lib/api/server-errors';
	import { pushToast } from '$lib/stores/toast';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { auth } from '$lib/stores/auth.svelte';
	import {
		listAllowlists,
		createAllowlist,
		updateAllowlist,
		deleteAllowlist,
		parseEntriesText,
		entriesToText,
		type Allowlist,
		type AllowlistInput
	} from '$lib/api/allowlists';

	function tl(key: string, params?: Record<string, string | number>): string {
		void language.current;
		return t(key, params);
	}

	const isAdmin = $derived(auth.user?.role === 'admin');

	let allowlists = $state<Allowlist[]>([]);
	let loading = $state(true);
	let loadError = $state<string | null>(null);

	// Form state.
	let formOpen = $state(false);
	let editingSlug = $state<string | null>(null);
	let fName = $state('');
	let fDescription = $state('');
	let fEnabled = $state(true);
	let fBlock = $state(true);
	let fThrottle = $state(true);
	let fAudit = $state(true);
	let fEntriesText = $state('');
	let saving = $state(false);
	let formError = $state<string | null>(null);

	const parsed = $derived(parseEntriesText(fEntriesText));
	const invalidLines = $derived(parsed.invalidLines);

	// Delete confirmation.
	let confirmDeleteOpen = $state(false);
	let deleteTarget = $state<Allowlist | null>(null);

	async function load() {
		loading = true;
		loadError = null;
		try {
			allowlists = await listAllowlists();
		} catch (err) {
			loadError = serverErrorMessage(err) || tl('allowlists.loadError');
		} finally {
			loading = false;
		}
	}

	onMount(load);

	function openCreate() {
		editingSlug = null;
		fName = '';
		fDescription = '';
		fEnabled = true;
		fBlock = true;
		fThrottle = true;
		fAudit = true;
		fEntriesText = '';
		formError = null;
		formOpen = true;
	}

	function openEdit(a: Allowlist) {
		editingSlug = a.slug;
		fName = a.name;
		fDescription = a.description;
		fEnabled = a.enabled;
		fBlock = a.scopeBlock;
		fThrottle = a.scopeThrottle;
		fAudit = a.scopeAudit;
		fEntriesText = entriesToText(a.entries);
		formError = null;
		formOpen = true;
	}

	async function save() {
		formError = null;
		if (invalidLines.length > 0) {
			formError = tl('allowlists.invalidLines', { lines: invalidLines.join(', ') });
			return;
		}
		const input: AllowlistInput = {
			name: fName.trim(),
			description: fDescription.trim(),
			enabled: fEnabled,
			scopeBlock: fBlock,
			scopeThrottle: fThrottle,
			scopeAudit: fAudit,
			entries: parsed.entries
		};
		saving = true;
		try {
			if (editingSlug) {
				await updateAllowlist(editingSlug, input);
			} else {
				await createAllowlist(input);
			}
			formOpen = false;
			await load();
			pushToast(tl('common.saved'), 'success');
		} catch (err) {
			formError = serverErrorMessage(err) || tl('allowlists.saveError');
		} finally {
			saving = false;
		}
	}

	function askDelete(a: Allowlist) {
		deleteTarget = a;
		confirmDeleteOpen = true;
	}

	async function confirmDelete() {
		// Defensive (#377, part B): with no selection there is nothing to
		// delete — close the dialog instead of a silent early-return that
		// leaves an orphan modal on screen.
		if (!deleteTarget) {
			confirmDeleteOpen = false;
			return;
		}
		try {
			await deleteAllowlist(deleteTarget.slug);
			await load();
			pushToast(tl('common.deleted'), 'success');
		} catch (err) {
			pushToast(serverErrorMessage(err) || tl('allowlists.deleteError'), 'danger');
		} finally {
			// #377, part A: ConfirmDialog never closes itself (open is
			// bindable), so the caller must. Close BEFORE clearing the
			// target so the dialog unmounts in the same batch and never
			// flashes an empty name.
			confirmDeleteOpen = false;
			deleteTarget = null;
		}
	}

	function entryPreview(a: Allowlist): string {
		const entries = a.entries ?? [];
		if (entries.length === 0) return '—';
		const head = entries.slice(0, 2).map((e) => e.cidr);
		const extra = entries.length - head.length;
		return extra > 0 ? `${head.join(', ')} +${extra}` : head.join(', ');
	}

	function scopeBadges(a: Allowlist): { label: string }[] {
		const out: { label: string }[] = [];
		if (a.scopeBlock) out.push({ label: tl('allowlists.scopeBlock') });
		if (a.scopeThrottle) out.push({ label: tl('allowlists.scopeThrottle') });
		if (a.scopeAudit) out.push({ label: tl('allowlists.scopeAudit') });
		return out;
	}

	function fmtDate(iso: string): string {
		const d = new Date(iso);
		return isNaN(d.getTime()) ? '—' : d.toLocaleString();
	}
</script>

<svelte:head>
	<title>{tl('allowlists.title')} · AreNET</title>
</svelte:head>

<PageHeader
	eyebrow={tl('sidebar.sectionSecurity')}
	title={tl('allowlists.title')}
	subtitle={tl('allowlists.subtitle')}
>
	{#snippet actions()}
		{#if isAdmin}
			<Button onclick={openCreate}>{tl('allowlists.new')}</Button>
		{/if}
	{/snippet}
</PageHeader>

<div class="limitation" role="note" data-testid="allowlist-limitation">
	<span class="limitation-icon" aria-hidden="true">ℹ️</span>
	<p>{tl('allowlists.limitationNote')}</p>
</div>

{#if loading}
	<div class="flex justify-center mt-12"><Spinner size="lg" /></div>
{:else if loadError}
	<div
		class="rounded-md border border-border-subtle bg-elevated p-4 text-sm text-down mt-6"
		data-testid="allowlist-load-error"
	>
		{loadError}
	</div>
{:else if allowlists.length === 0}
	<div class="rounded-lg border border-border-subtle bg-elevated overflow-hidden mt-6">
		<EmptyState
			testid="allowlist-empty"
			title={tl('allowlists.emptyTitle')}
			body={tl('allowlists.emptyBody')}
			actionLabel={isAdmin ? tl('allowlists.new') : undefined}
			onAction={isAdmin ? openCreate : undefined}
		/>
	</div>
{:else}
	<div class="rounded-lg border border-border-subtle bg-elevated overflow-hidden mt-6">
		<table class="w-full text-sm">
			<thead>
				<tr class="text-left text-xs uppercase tracking-wide text-muted">
					<th class="px-4 py-3 font-medium">{tl('allowlists.colName')}</th>
					<th class="px-4 py-3 font-medium">{tl('allowlists.colEntries')}</th>
					<th class="px-4 py-3 font-medium">{tl('allowlists.colScope')}</th>
					<th class="px-4 py-3 font-medium">{tl('allowlists.colActive')}</th>
					<th class="px-4 py-3 font-medium">{tl('allowlists.colUpdated')}</th>
					{#if isAdmin}
						<th class="px-4 py-3 font-medium text-right">{tl('allowlists.colActions')}</th>
					{/if}
				</tr>
			</thead>
			<tbody>
				{#each allowlists as a (a.slug)}
					<tr class="border-t border-border-subtle" data-testid="allowlist-row">
						<td class="px-4 py-3">
							<div class="font-medium">{a.name}</div>
							{#if a.description}
								<div class="text-xs text-muted">{a.description}</div>
							{/if}
						</td>
						<td class="px-4 py-3">
							<span class="font-mono text-xs">{entryPreview(a)}</span>
							<div class="text-xs text-muted">
								{tl('allowlists.entryCount', { count: (a.entries ?? []).length })}
							</div>
						</td>
						<td class="px-4 py-3">
							<div class="flex gap-1 flex-wrap">
								{#each scopeBadges(a) as b}
									<Badge variant="neutral">{b.label}</Badge>
								{:else}
									<span class="text-xs text-muted">{tl('allowlists.scopeNone')}</span>
								{/each}
							</div>
						</td>
						<td class="px-4 py-3">
							{#if a.enabled}
								<Badge variant="status-up">{tl('allowlists.enabled')}</Badge>
							{:else}
								<Badge variant="status-warn">{tl('allowlists.disabled')}</Badge>
							{/if}
						</td>
						<td class="px-4 py-3 text-xs text-muted">{fmtDate(a.updatedAt)}</td>
						{#if isAdmin}
							<td class="px-4 py-3 text-right whitespace-nowrap">
								<Button variant="ghost" size="sm" onclick={() => openEdit(a)}
									>{tl('allowlists.edit')}</Button
								>
								<Button variant="ghost" size="sm" onclick={() => askDelete(a)}
									>{tl('common.delete')}</Button
								>
							</td>
						{/if}
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

<Modal
	open={formOpen}
	title={editingSlug ? tl('allowlists.editTitle') : tl('allowlists.createTitle')}
	onClose={() => (formOpen = false)}
	width="lg"
>
	<form
		onsubmit={(e) => {
			e.preventDefault();
			save();
		}}
		class="flex flex-col gap-4"
	>
		<label class="flex flex-col gap-1">
			<span class="text-sm font-medium">{tl('allowlists.fieldName')}</span>
			<input
				type="text"
				bind:value={fName}
				required
				class="rounded-md border border-border-subtle bg-base px-3 py-2 text-sm"
				data-testid="allowlist-name"
			/>
		</label>

		<label class="flex flex-col gap-1">
			<span class="text-sm font-medium">{tl('allowlists.fieldDescription')}</span>
			<input
				type="text"
				bind:value={fDescription}
				class="rounded-md border border-border-subtle bg-base px-3 py-2 text-sm"
			/>
		</label>

		<label class="flex flex-col gap-1">
			<span class="text-sm font-medium">{tl('allowlists.fieldEntries')}</span>
			<textarea
				bind:value={fEntriesText}
				rows="6"
				spellcheck="false"
				class="rounded-md border border-border-subtle bg-base px-3 py-2 text-sm font-mono"
				class:border-down={invalidLines.length > 0}
				data-testid="allowlist-entries"
			></textarea>
			<span class="text-xs text-muted">{tl('allowlists.fieldEntriesHint')}</span>
			{#if invalidLines.length > 0}
				<span class="text-xs text-down" data-testid="allowlist-invalid">
					{tl('allowlists.invalidLines', { lines: invalidLines.join(', ') })}
				</span>
			{/if}
		</label>

		<fieldset class="flex flex-col gap-2">
			<legend class="text-sm font-medium mb-1">{tl('allowlists.colScope')}</legend>
			<SwitchRow
				checked={fBlock}
				onchange={(v) => (fBlock = v)}
				label={tl('allowlists.scopeBlock')}
				helper={tl('allowlists.scopeBlockHint')}
				testid="allowlist-scope-block"
			/>
			<SwitchRow
				checked={fThrottle}
				onchange={(v) => (fThrottle = v)}
				label={tl('allowlists.scopeThrottle')}
				helper={tl('allowlists.scopeThrottleHint')}
				testid="allowlist-scope-throttle"
			/>
			<SwitchRow
				checked={fAudit}
				onchange={(v) => (fAudit = v)}
				label={tl('allowlists.scopeAudit')}
				helper={tl('allowlists.scopeAuditHint')}
				testid="allowlist-scope-audit"
			/>
		</fieldset>

		<SwitchRow
			checked={fEnabled}
			onchange={(v) => (fEnabled = v)}
			label={tl('allowlists.fieldActive')}
			testid="allowlist-active"
		/>

		{#if formError}
			<div class="text-sm text-down" data-testid="allowlist-form-error">{formError}</div>
		{/if}

		<div class="flex justify-end gap-2 pt-2">
			<Button variant="ghost" type="button" onclick={() => (formOpen = false)}
				>{tl('common.cancel')}</Button
			>
			<Button type="submit" loading={saving}>{tl('common.save')}</Button>
		</div>
	</form>
</Modal>

<ConfirmDialog
	bind:open={confirmDeleteOpen}
	title={tl('allowlists.deleteTitle')}
	message={tl('allowlists.deleteBody', { name: deleteTarget?.name ?? '' })}
	confirmLabel={tl('common.delete')}
	cancelLabel={tl('common.cancel')}
	confirmVariant="danger"
	confirmDisabled={!deleteTarget}
	onConfirm={confirmDelete}
/>

<style>
	.limitation {
		display: flex;
		gap: 0.6rem;
		align-items: flex-start;
		margin-top: 1rem;
		padding: 0.75rem 1rem;
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-md);
		background: var(--elevated);
		font-size: 0.85rem;
		color: var(--text-muted);
	}
	.limitation-icon {
		flex-shrink: 0;
	}
	.limitation p {
		margin: 0;
	}
</style>
