<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  v2.80 — read-only access-log viewer (admin-only).

  The Logs page unifies internal event streams; it is NOT the raw
  access log. This panel adds a bounded view of the real access-log
  file on disk.

  v2.80.2 — the viewer is now one of two top-level views on the Logs
  page (an "Activity" / "Access log" selector, admin-only), instead of
  a collapsible section stacked under the activity table. The parent
  decides when it is shown; this component only renders its controls +
  results and fills the flex slot it is given, its result list
  scrolling internally so the page keeps its strict viewport fit.

  It still fetches NOTHING on its own: selecting the view shows only
  the controls, and content loads only when the operator clicks "Show
  latest" or runs a search. That keeps opening the Logs page (or this
  view) from ever streaming a multi-gigabyte file.

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

<section class="access-log-view" aria-label={language.current && t('logs.accessLog.title')}>
	<div class="alv-controls">
		<p class="alv-subtitle">{language.current && t('logs.accessLog.subtitle')}</p>
		<div class="alv-controls-row">
			<form class="alv-form" onsubmit={onSearchSubmit}>
				<label class="alv-field">
					{language.current && t('logs.accessLog.fieldLabel')}
					<select
						bind:value={field}
						aria-label={language.current && t('logs.accessLog.fieldLabel')}
					>
						<option value="uuid">{language.current && t('logs.accessLog.fieldUuid')}</option>
						<option value="ip">{language.current && t('logs.accessLog.fieldIp')}</option>
						<option value="path">{language.current && t('logs.accessLog.fieldPath')}</option>
					</select>
				</label>
				<label class="alv-field alv-query">
					{language.current && t('logs.accessLog.queryLabel')}
					<input
						bind:value={query}
						type="text"
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
	</div>

	<div class="alv-results card">
		{#if loading}
			<div class="alv-center">
				<Spinner />
				<span>{language.current && t('logs.accessLog.loading')}</span>
			</div>
		{:else if error}
			<p class="alv-center alv-error" role="alert">{error}</p>
		{:else if disabledOnServer}
			<p class="alv-center alv-muted">
				{language.current && t('logs.accessLog.disabled')}
			</p>
		{:else if result && entries.length === 0}
			<p class="alv-center alv-muted">
				{language.current && t('logs.accessLog.noMatch')}
			</p>
		{:else if entries.length > 0}
			{#if searchMeta}
				<p class="alv-meta" role="status">
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
			<div class="alv-table-wrap">
				<table class="alv-table">
					<thead>
						<tr>
							<th>{language.current && t('logs.accessLog.colTime')}</th>
							<th>{language.current && t('logs.accessLog.colMethod')}</th>
							<th>{language.current && t('logs.accessLog.colStatus')}</th>
							<th>{language.current && t('logs.accessLog.colUri')}</th>
							<th>{language.current && t('logs.accessLog.colClientIp')}</th>
							<th>{language.current && t('logs.accessLog.colGate')}</th>
						</tr>
					</thead>
					<tbody>
						{#each entries as e, i (i)}
							<tr>
								<td class="alv-nowrap alv-muted">{formatTime(e.ts)}</td>
								<td>{e.method}</td>
								<td>{e.status}</td>
								<td class="alv-uri">{e.uri}</td>
								<td class="alv-nowrap">{e.clientIp}</td>
								<td>
									{#if e.denied}
										<span
											class="alv-gate"
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
		{:else}
			<p class="alv-center alv-muted">
				{language.current && t('logs.accessLog.idleHint')}
			</p>
		{/if}
	</div>
</section>

<style>
	.access-log-view {
		display: flex;
		flex-direction: column;
		gap: 12px;
		flex: 1;
		min-height: 0;
		height: 100%;
	}

	.alv-controls {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.alv-subtitle {
		margin: 0;
		font-size: 12.5px;
		color: var(--fg-muted);
	}
	.alv-controls-row {
		display: flex;
		flex-wrap: wrap;
		align-items: end;
		gap: 10px;
	}
	.alv-form {
		display: flex;
		flex-wrap: wrap;
		align-items: end;
		gap: 10px;
		flex: 1;
		min-width: 0;
	}
	.alv-field {
		display: flex;
		flex-direction: column;
		gap: 4px;
		font-size: 11px;
		color: var(--fg-muted);
	}
	.alv-query {
		flex: 1;
		min-width: 200px;
	}
	.alv-field select,
	.alv-field input {
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm, 8px);
		color: var(--fg);
		font-size: 13px;
		padding: 6px 10px;
	}
	.alv-field input {
		font-family: var(--font-mono);
	}
	.alv-field select:focus-visible,
	.alv-field input:focus-visible {
		outline: none;
		border-color: var(--accent-cyan);
	}

	/* The results card fills the remaining viewport height and scrolls
	   internally, so the page keeps its strict viewport fit (no page
	   scroll) just like the activity view. */
	.alv-results {
		flex: 1;
		min-height: 0;
		overflow: auto;
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 0;
	}

	.alv-center {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 8px;
		min-height: 160px;
		padding: 32px 16px;
		font-size: 13px;
		color: var(--fg);
		text-align: center;
	}
	.alv-muted {
		color: var(--fg-muted);
	}
	.alv-error {
		color: var(--status-down);
	}

	.alv-meta {
		margin: 0;
		padding: 10px 16px;
		font-size: 11px;
		color: var(--fg-muted);
		border-bottom: 1px solid var(--border);
	}

	.alv-table-wrap {
		overflow-x: auto;
	}
	.alv-table {
		width: 100%;
		min-width: 640px;
		border-collapse: collapse;
		font-family: var(--font-mono);
		font-size: 11.5px;
		text-align: left;
	}
	.alv-table thead th {
		position: sticky;
		top: 0;
		background: var(--bg-elevated);
		color: var(--fg-dim);
		font-weight: 500;
		font-size: 10.5px;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		padding: 8px 10px;
		border-bottom: 1px solid var(--border);
		z-index: 1;
	}
	.alv-table tbody td {
		padding: 6px 10px;
		border-bottom: 1px solid var(--border);
		vertical-align: top;
		color: var(--fg);
	}
	.alv-table tbody tr:last-child td {
		border-bottom: none;
	}
	.alv-nowrap {
		white-space: nowrap;
	}
	.alv-uri {
		max-width: 28rem;
		word-break: break-all;
	}
	.alv-gate {
		display: inline-block;
		background: color-mix(in oklch, var(--status-down) 18%, transparent);
		color: var(--status-down);
		border-radius: 4px;
		padding: 1px 6px;
		font-size: 10.5px;
	}

	/* Narrow screens: the Logs page drops its strict viewport fit and
	   scrolls naturally (see the <900px rule on the page), so the
	   results stop claiming the viewport and grow with the page. */
	@media (max-width: 900px) {
		.access-log-view {
			flex: none;
		}
		.alv-results {
			overflow: visible;
			min-height: 420px;
		}
	}
</style>
