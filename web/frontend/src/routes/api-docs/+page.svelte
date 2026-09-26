<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  /api-docs (v2.39) — in-app viewer of Arenet's OpenAPI document
  (GET /api/v1/openapi.json): operations by tag with a search on the
  left, the selected operation on the right (OperationView), a link to
  download the JSON. Written in Svelte on purpose: the usual viewers
  (Swagger UI, Redoc, Scalar) bundle React or Vue.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import OperationView from '$lib/components/apidocs/OperationView.svelte';
	import { getOpenAPI } from '$lib/api/client';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { groupByTag, listOperations, matches, type OpenAPIDoc, type Operation } from '$lib/utils/openapi';

	let doc = $state<OpenAPIDoc | null>(null);
	let loadError = $state<string | null>(null);
	let query = $state('');
	let selectedKey = $state<string | null>(null);

	const ops = $derived<Operation[]>(doc ? listOperations(doc) : []);
	const groups = $derived(groupByTag(ops.filter((o) => matches(o, query))));
	const selected = $derived(ops.find((o) => o.key === selectedKey) ?? null);
	const intro = $derived<string>(doc?.info?.description ?? '');

	onMount(async () => {
		try {
			doc = await getOpenAPI();
		} catch (err) {
			loadError = err instanceof Error ? err.message : String(err);
		}
	});

	function download(): void {
		if (!doc) return;
		const blob = new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' });
		const a = document.createElement('a');
		a.href = URL.createObjectURL(blob);
		a.download = 'arenet-openapi.json';
		a.click();
		URL.revokeObjectURL(a.href);
	}
</script>

<PageHeader
	title={language.current && t('pageTitles.apiDocs')}
	subtitle={doc ? `OpenAPI ${doc.openapi} · ${doc.info?.version ?? ''} · ${ops.length} ${language.current && t('apiDocs.operations')}` : ''}
/>

{#if loadError}
	<p class="error" role="alert">{loadError}</p>
{:else if !doc}
	<div class="loading"><Spinner /></div>
{:else}
	<div class="layout">
		<nav class="nav" aria-label={language.current && t('apiDocs.navLabel')}>
			<input
				type="search"
				bind:value={query}
				placeholder={language.current && t('apiDocs.search')}
				aria-label={language.current && t('apiDocs.search')}
				data-testid="api-search"
				class="bg-surface border border-border-default rounded-md px-2 py-1 text-sm text-primary"
			/>
			<button type="button" class="link" onclick={download} data-testid="api-download">
				{language.current && t('apiDocs.download')}
			</button>
			{#each groups as g (g.tag)}
				<p class="tag">{g.tag}</p>
				<ul>
					{#each g.ops as o (o.key)}
						<li>
							<button
								type="button"
								class="op-link"
								class:active={o.key === selectedKey}
								onclick={() => (selectedKey = o.key)}
								data-testid="api-op-link"
							>
								<span class="m m-{o.method}">{o.method.toUpperCase()}</span>
								<span class="p">{o.path}</span>
							</button>
						</li>
					{/each}
				</ul>
			{:else}
				<p class="muted">{language.current && t('apiDocs.noMatch')}</p>
			{/each}
		</nav>
		<main class="detail">
			{#if selected}
				<OperationView {doc} op={selected} />
			{:else}
				<div class="intro" data-testid="api-intro">
					<h2>{doc.info?.title}</h2>
					<p>{intro}</p>
				</div>
			{/if}
		</main>
	</div>
{/if}

<style>
	.layout {
		display: grid;
		grid-template-columns: minmax(240px, 340px) 1fr;
		gap: 16px;
		align-items: start;
	}
	@media (max-width: 860px) {
		.layout {
			grid-template-columns: 1fr;
		}
	}
	.nav {
		position: sticky;
		top: 12px;
		max-height: calc(100vh - 140px);
		overflow: auto;
		display: flex;
		flex-direction: column;
		gap: 6px;
		padding: 10px;
		border: 1px solid var(--border-subtle);
		border-radius: 8px;
		background: var(--bg-surface);
	}
	.nav ul {
		list-style: none;
		margin: 0;
		padding: 0;
	}
	.tag {
		margin: 8px 0 2px 0;
		font-size: 11px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		color: var(--text-muted);
	}
	.op-link {
		display: flex;
		align-items: baseline;
		gap: 6px;
		width: 100%;
		padding: 3px 6px;
		border: none;
		border-radius: 4px;
		background: none;
		text-align: left;
		cursor: pointer;
		color: var(--text-secondary);
	}
	.op-link:hover,
	.op-link.active {
		background: var(--bg-hover);
		color: var(--text-primary);
	}
	.op-link:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: -2px;
	}
	.m {
		flex: none;
		width: 46px;
		font-family: var(--font-mono, monospace);
		font-size: 10px;
		font-weight: 700;
		color: var(--text-muted);
	}
	.m-get {
		color: var(--accent-cyan);
	}
	.m-post {
		color: var(--status-up);
	}
	.m-put,
	.m-patch {
		color: var(--status-warn);
	}
	.m-delete {
		color: var(--status-down);
	}
	.p {
		font-family: var(--font-mono, monospace);
		font-size: 12px;
		word-break: break-all;
	}
	.detail {
		min-width: 0;
		padding: 16px;
		border: 1px solid var(--border-subtle);
		border-radius: 8px;
		background: var(--bg-surface);
	}
	.intro h2 {
		margin: 0 0 8px 0;
		font-size: 18px;
		color: var(--text-primary);
	}
	.intro p {
		margin: 0;
		white-space: pre-line;
		font-size: 13px;
		color: var(--text-secondary);
		max-width: 80ch;
	}
	.link {
		align-self: flex-start;
		background: none;
		border: none;
		padding: 0;
		font-size: 12px;
		color: var(--accent-cyan);
		cursor: pointer;
	}
	.muted {
		color: var(--text-muted);
		font-size: 12px;
	}
	.error {
		color: var(--status-down);
	}
	.loading {
		display: flex;
		justify-content: center;
		padding: 40px;
	}
</style>
