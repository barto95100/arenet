<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  AL.4.b.1 — Alerting page shell. Three tabs:
    - Canaux     (AL.4.b.2 — stub for now)
    - Règles     (AL.4.b.3 — stub for now)
    - Historique (AL.4.b.1 — populated from AL.4.a backend)

  Deep-link via URL hash: /alerting, /alerting#channels,
  /alerting#rules, /alerting#history. The default tab is
  Canaux per the brief D1.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import ChannelsTab from '$lib/components/alerting/ChannelsTab.svelte';
	import RulesTab from '$lib/components/alerting/RulesTab.svelte';
	import HistoryTab from '$lib/components/alerting/HistoryTab.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	type TabKey = 'channels' | 'rules' | 'history';

	const TABS: { key: TabKey; label: string }[] = [
		{ key: 'channels', label: 'Canaux' },
		{ key: 'rules', label: 'Règles' },
		{ key: 'history', label: 'Historique' }
	];

	let active = $state<TabKey>('channels');

	function readHash(): TabKey {
		const raw = (typeof window !== 'undefined' ? window.location.hash : '').replace(/^#/, '');
		if (raw === 'channels' || raw === 'rules' || raw === 'history') return raw;
		return 'channels';
	}

	function selectTab(key: TabKey) {
		active = key;
		if (typeof window !== 'undefined') {
			// Replace the hash without scrolling the page or
			// pushing a history entry for every tab click — the
			// operator's back button should not be polluted by
			// in-page navigation.
			const url = new URL(window.location.href);
			url.hash = key;
			window.history.replaceState(null, '', url.toString());
		}
	}

	onMount(() => {
		active = readHash();
		const onHash = () => {
			active = readHash();
		};
		window.addEventListener('hashchange', onHash);
		return () => window.removeEventListener('hashchange', onHash);
	});
</script>

<PageHeader title={language.current && t('pageTitles.alerting')} subtitle={language.current && t('pageTitles.alertingSubtitle')} />

<div class="mt-4">
	<nav class="tab-bar" aria-label="Sections alerting">
		{#each TABS as tab (tab.key)}
			<button
				type="button"
				class="tab"
				class:active={active === tab.key}
				aria-current={active === tab.key ? 'page' : undefined}
				onclick={() => selectTab(tab.key)}
			>
				{tab.label}
			</button>
		{/each}
	</nav>

	<div class="tab-panel mt-6">
		{#if active === 'channels'}
			<ChannelsTab />
		{:else if active === 'rules'}
			<RulesTab />
		{:else if active === 'history'}
			<HistoryTab />
		{/if}
	</div>
</div>

<style>
	.tab-bar {
		display: flex;
		gap: var(--space-1);
		border-bottom: 1px solid var(--border-subtle);
	}
	.tab {
		appearance: none;
		background: transparent;
		border: 0;
		padding: var(--space-2) var(--space-4);
		margin-bottom: -1px;
		color: var(--text-secondary);
		font-weight: 500;
		font-size: var(--text-sm);
		border-bottom: 2px solid transparent;
		cursor: pointer;
		transition: color var(--motion-fast), border-color var(--motion-fast);
	}
	.tab:hover {
		color: var(--text-primary);
	}
	.tab.active {
		color: var(--accent-cyan);
		border-bottom-color: var(--accent-cyan);
	}
	.tab:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 2px;
	}
</style>
