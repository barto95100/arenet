<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  RouteCheckSection (v2.35) — toggles the post-apply route check: after
  each save Arenet probes the route through Caddy; a change that broke
  a working route is undone, other failures are reported.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { settingsApi } from '$lib/api/settings';
	import { pushToast } from '$lib/stores/toast';
	import { ApiError } from '$lib/api/types';
	import Card from '$lib/components/Card.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	let enabled = $state(true);
	let loaded = $state(false);
	let saving = $state(false);

	onMount(async () => {
		try {
			enabled = (await settingsApi.getRouteCheck()).enabled;
			loaded = true;
		} catch {
			loaded = false;
		}
	});

	async function toggle(next: boolean): Promise<void> {
		saving = true;
		try {
			enabled = (await settingsApi.putRouteCheck(next)).enabled;
			pushToast(t('routeCheck.toastSaved'), 'success');
		} catch (err) {
			pushToast(err instanceof ApiError ? err.message : t('routeCheck.errSave'), 'danger');
		} finally {
			saving = false;
		}
	}
</script>

{#if loaded}
	<Card padding="p-6" class="mb-6">
		<header class="border-b border-border-subtle pb-3 mb-4">
			<h2 class="text-xl font-semibold">{language.current && t('routeCheck.title')}</h2>
			<p class="text-xs text-muted mt-1">{language.current && t('routeCheck.subtitle')}</p>
		</header>
		<label class="inline-flex items-start gap-2 text-sm">
			<input
				type="checkbox"
				checked={enabled}
				disabled={saving}
				onchange={(e) => toggle((e.currentTarget as HTMLInputElement).checked)}
				class="mt-0.5 rounded border-border-default bg-surface text-cyan focus:ring-cyan"
				data-testid="route-check-enabled"
			/>
			<span>
				<span class="font-medium">{language.current && t('routeCheck.enabledLabel')}</span>
				<span class="text-xs text-muted block">{language.current && t('routeCheck.enabledHelper')}</span>
			</span>
		</label>
	</Card>
{/if}
