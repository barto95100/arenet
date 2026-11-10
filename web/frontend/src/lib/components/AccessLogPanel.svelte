<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  v2.80 — read-only access-log viewer (admin-only).

  The Logs page unifies internal event streams; it is NOT the raw
  access log. This panel adds a bounded view of the real access-log
  file on disk — but it fetches NOTHING on mount: content loads only
  when the operator clicks "Show latest" or runs a search. That keeps
  opening the Logs page from ever streaming a multi-gigabyte file.

  The mount is gated to admins by the parent page; the server also
  enforces admin on every request regardless.
-->
<script lang="ts">
	import Button from './Button.svelte';
	import Spinner from './Spinner.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { serverErrorMessage } from '$lib/api/server-errors';
	import {
		tailAccessLog,
		searchAccessLog,
		type AccessLogEntry,
		type AccessLogField,
		type AccessLogSearchResponse,
		type AccessLogTailResponse
	} from '$lib/api/accessLog';

	let open = $state(false);
	let loading = $state(false);
	let error = $state<string | null>(null);
	let field = $state<AccessLogField>('uuid');
	let query = $state('');

	// The last response and which action produced it, so the metadata
	// line (search only) and the empty-state copy can differ.
	let mode = $state<'tail' | 'search' | null>(null);
	let result = $state<AccessLogTailResponse | AccessLogSearchResponse | null>(null);

	const entries = $derived<AccessLogEntry[]>(result?.lines ?? []);
	const disabledOnServer = $derived(result !== null && result.enabled === false);
	const searchMeta = $derived(
		mode === 'search' && result ? (result as AccessLogSearchResponse) : null
	);

	function formatTime(ts: number): string {
		if (!ts || ts <= 0) return '';
		try {
			return new Date(ts * 1000).toLocaleTimeString();
		} catch {
			return '';
		}
	}

	async function showLatest(): Promise<void> {
		loading = true;
		error = null;
		try {
			const r = await tailAccessLog(200);
			result = r;
			mode = 'tail';
		} catch (e) {
			error = serverErrorMessage(e);
		} finally {
			loading = false;
		}
	}

	async function runSearch(): Promise<void> {
		const q = query.trim();
		if (!q) return;
		loading = true;
		error = null;
		try {
			const r = await searchAccessLog(field, q, 200);
			result = r;
			mode = 'search';
		} catch (e) {
			error = serverErrorMessage(e);
		} finally {
			loading = false;
		}
	}

	function onSearchSubmit(e: SubmitEvent): void {
		e.preventDefault();
		void runSearch();
	}
</script>

<section
	class="rounded-xl border border-border-default bg-surface"
	aria-label={language.current && t('logs.accessLog.title')}
>
	<button
		type="button"
		class="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
		aria-expanded={open}
		onclick={() => (open = !open)}
	>
		<span class="flex flex-col">
			<span class="text-sm font-semibold text-primary"
				>{language.current && t('logs.accessLog.title')}</span
			>
			<span class="text-xs text-secondary"
				>{language.current && t('logs.accessLog.subtitle')}</span
			>
		</span>
		<span class="text-secondary" aria-hidden="true">{open ? '▾' : '▸'}</span>
	</button>

	{#if open}
		<div class="flex flex-col gap-3 border-t border-border-default px-4 py-3">
			<div class="flex flex-wrap items-end gap-2">
				<form class="flex flex-wrap items-end gap-2" onsubmit={onSearchSubmit}>
					<label class="flex flex-col gap-1 text-xs text-secondary">
						{language.current && t('logs.accessLog.fieldLabel')}
						<select
							bind:value={field}
							class="rounded-md border border-border-default bg-elevated px-2 py-1.5 text-sm text-primary"
							aria-label={language.current && t('logs.accessLog.fieldLabel')}
						>
							<option value="uuid">{language.current && t('logs.accessLog.fieldUuid')}</option>
							<option value="ip">{language.current && t('logs.accessLog.fieldIp')}</option>
							<option value="path">{language.current && t('logs.accessLog.fieldPath')}</option>
						</select>
					</label>
					<label class="flex min-w-0 flex-1 flex-col gap-1 text-xs text-secondary">
						{language.current && t('logs.accessLog.queryLabel')}
						<input
							bind:value={query}
							type="text"
							class="w-full rounded-md border border-border-default bg-elevated px-2 py-1.5 font-mono text-sm text-primary"
							placeholder={language.current && t('logs.accessLog.queryPlaceholder')}
							aria-label={language.current && t('logs.accessLog.queryLabel')}
						/>
					</label>
					<Button type="submit" variant="primary" size="sm" disabled={loading || !query.trim()}>
						{language.current && t('logs.accessLog.btnSearch')}
					</Button>
				</form>
				<Button variant="secondary" size="sm" disabled={loading} onclick={showLatest}>
					{language.current && t('logs.accessLog.btnShowLatest')}
				</Button>
			</div>

			{#if loading}
				<div class="flex items-center gap-2 py-6 text-sm text-secondary">
					<Spinner />
					<span>{language.current && t('logs.accessLog.loading')}</span>
				</div>
			{:else if error}
				<p class="py-4 text-sm text-down" role="alert">{error}</p>
			{:else if disabledOnServer}
				<p class="py-4 text-sm text-secondary">
					{language.current && t('logs.accessLog.disabled')}
				</p>
			{:else if result && entries.length === 0}
				<p class="py-4 text-sm text-secondary">
					{language.current && t('logs.accessLog.noMatch')}
				</p>
			{:else if entries.length > 0}
				{#if searchMeta}
					<p class="text-xs text-secondary" role="status">
						{language.current &&
							t('logs.accessLog.meta', {
								files: searchMeta.filesScanned,
								ms: searchMeta.elapsedMs
							})}
						{#if searchMeta.searchedCompressed}
							· {language.current && t('logs.accessLog.alsoCompressed')}
						{/if}
						{#if searchMeta.truncated}
							· {language.current && t('logs.accessLog.truncated')}
						{/if}
					</p>
				{/if}
				<div class="overflow-x-auto">
					<table class="w-full min-w-[640px] border-collapse text-left font-mono text-xs">
						<thead>
							<tr class="text-secondary">
								<th class="px-2 py-1 font-medium">{language.current && t('logs.accessLog.colTime')}</th>
								<th class="px-2 py-1 font-medium">{language.current && t('logs.accessLog.colMethod')}</th>
								<th class="px-2 py-1 font-medium">{language.current && t('logs.accessLog.colStatus')}</th>
								<th class="px-2 py-1 font-medium">{language.current && t('logs.accessLog.colUri')}</th>
								<th class="px-2 py-1 font-medium">{language.current && t('logs.accessLog.colClientIp')}</th>
								<th class="px-2 py-1 font-medium">{language.current && t('logs.accessLog.colGate')}</th>
							</tr>
						</thead>
						<tbody>
							{#each entries as e, i (i)}
								<tr class="border-t border-border-default align-top">
									<td class="whitespace-nowrap px-2 py-1 text-secondary">{formatTime(e.ts)}</td>
									<td class="px-2 py-1">{e.method}</td>
									<td class="px-2 py-1">{e.status}</td>
									<td class="max-w-[28rem] break-all px-2 py-1">{e.uri}</td>
									<td class="whitespace-nowrap px-2 py-1">{e.clientIp}</td>
									<td class="px-2 py-1">
										{#if e.denied}
											<span
												class="rounded bg-elevated px-1.5 py-0.5 text-[0.7rem] text-down"
												title={language.current && t('logs.accessLog.gatePillTitle')}
												>{e.denied}</span
											>
										{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</div>
	{/if}
</section>
