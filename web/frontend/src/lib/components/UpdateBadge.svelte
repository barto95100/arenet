<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  v2.12.3 — discreet topbar "update available" indicator. Renders
  nothing unless the (opt-in) update checker reports a newer stable
  release. Click opens the GitHub release in a new tab.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { systemApi, type SystemVersion } from '$lib/api/system';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	let info = $state<SystemVersion | null>(null);

	async function load(): Promise<void> {
		try {
			info = await systemApi.getVersion();
		} catch {
			info = null;
		}
	}

	onMount(load);
</script>

{#if info?.updateAvailable}
	<a
		class="update-badge"
		href={info.url}
		target="_blank"
		rel="noopener noreferrer"
		data-testid="update-badge"
		title={language.current && t('topbar.updateAvailable', { version: info.latest })}
		aria-label={language.current && t('topbar.updateAvailable', { version: info.latest })}
	>
		<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
			<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" stroke-linecap="round" stroke-linejoin="round" />
			<path d="M13.73 21a2 2 0 0 1-3.46 0" stroke-linecap="round" stroke-linejoin="round" />
		</svg>
		<span class="dot" aria-hidden="true"></span>
	</a>
{/if}

<style>
	.update-badge {
		position: relative;
		display: inline-flex;
		align-items: center;
		color: var(--accent, #e0913a);
		text-decoration: none;
	}
	.update-badge .dot {
		position: absolute;
		top: -2px;
		right: -2px;
		width: 7px;
		height: 7px;
		border-radius: 50%;
		background: var(--accent, #e0913a);
	}
</style>
