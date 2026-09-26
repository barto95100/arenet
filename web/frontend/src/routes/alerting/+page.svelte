<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
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
	import Tabs from '$lib/components/Tabs.svelte';
	import ChannelsTab from '$lib/components/alerting/ChannelsTab.svelte';
	import RulesTab from '$lib/components/alerting/RulesTab.svelte';
	import HistoryTab from '$lib/components/alerting/HistoryTab.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	type TabKey = 'channels' | 'rules' | 'history';

	// v2.41 — the page used to carry its own tab bar, a near-verbatim
	// copy of Tabs.svelte that had drifted on accessibility
	// (aria-current="page" instead of role="tab"/aria-selected). It
	// now uses the shared component; the hash deep-links and the
	// hashchange listener are unchanged.
	const TABS: { key: TabKey; labelKey: string }[] = [
		{ key: 'channels', labelKey: 'alerting.tabChannels' },
		{ key: 'rules', labelKey: 'alerting.tabRules' },
		{ key: 'history', labelKey: 'alerting.tabHistory' }
	];

	let active = $state<TabKey>('channels');

	const tabDescriptors = $derived(
		TABS.map((tab) => ({
			id: tab.key,
			label: (language.current && t(tab.labelKey)) as string,
			testId: `alerting-tab-${tab.key}`
		}))
	);

	function readHash(): TabKey {
		const raw = (typeof window !== 'undefined' ? window.location.hash : '').replace(/^#/, '');
		if (raw === 'channels' || raw === 'rules' || raw === 'history') return raw;
		return 'channels';
	}

	function selectTab(key: TabKey) {
		// Tabs writes `active` through the bind; this only records
		// the choice in the URL.
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
	<Tabs
		bind:value={active}
		tabs={tabDescriptors}
		ariaLabel={language.current && t('alerting.tabsAria')}
		onChange={selectTab}
	/>

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
