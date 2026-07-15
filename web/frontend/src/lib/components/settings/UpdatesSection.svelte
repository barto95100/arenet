<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  v2.12.3 — /settings Updates mini-card. Opt-in switch for the GitHub
  update check, a manual "Check now" button, current/latest version, and
  the last-check state (relative time + error line). No auto-update.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { systemApi, type SystemVersion } from '$lib/api/system';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { relativeTime } from '$lib/utils/audit-format';
	import { isZeroTimestamp } from '$lib/utils/certificate-format';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';

	let info = $state<SystemVersion | null>(null);
	let checking = $state(false);

	async function load(): Promise<void> {
		try {
			info = await systemApi.getVersion();
		} catch {
			info = null;
		}
	}

	async function toggleEnabled(next: boolean): Promise<void> {
		try {
			info = await systemApi.setVersionConfig({ enabled: next });
		} catch {
			/* keep prior state */
		}
	}

	async function checkNow(): Promise<void> {
		if (checking) return;
		checking = true;
		try {
			info = await systemApi.checkVersion();
		} catch {
			/* lastError surfaces via a reload */
			await load();
		} finally {
			checking = false;
		}
	}

	onMount(load);
</script>

<div id="updates" class="mb-6">
	<Card padding="p-6">
		<header class="border-b border-border-subtle pb-3 mb-4">
			<h2 class="text-xl font-semibold">{language.current && t('settings.updates.title')}</h2>
			<p class="text-xs text-muted mt-1">{language.current && t('settings.updates.subtitle')}</p>
		</header>

		<div class="flex flex-col gap-3 text-sm">
			<label class="flex items-center gap-2">
				<input
					type="checkbox"
					data-testid="updates-enable"
					checked={info?.enabled ?? false}
					onchange={(e) => toggleEnabled((e.currentTarget as HTMLInputElement).checked)}
				/>
				<span>{language.current && t('settings.updates.enableToggle')}</span>
			</label>

			<div class="flex gap-6">
				<div>
					<div class="text-xs text-muted">{language.current && t('settings.updates.current')}</div>
					<div class="mono" data-testid="updates-current">{info?.current ?? '—'}</div>
				</div>
				<div>
					<div class="text-xs text-muted">{language.current && t('settings.updates.latest')}</div>
					<div class="mono" data-testid="updates-latest">
						{#if info?.updateAvailable}
							{info.latest}
						{:else}
							{language.current && t('settings.updates.upToDate')}
						{/if}
					</div>
				</div>
			</div>

			{#if info?.updateAvailable && info.url}
				<a href={info.url} target="_blank" rel="noopener noreferrer" class="link" data-testid="updates-release-link">
					{language.current && t('settings.updates.viewRelease')}
				</a>
			{/if}

			<div class="text-xs text-muted" data-testid="updates-laststate">
				{language.current && t('settings.updates.lastChecked')}:
				{!isZeroTimestamp(info?.lastChecked)
					? relativeTime(info!.lastChecked)
					: (language.current && t('settings.updates.never'))}
				{#if info?.lastError}
					· <span class="text-down" data-testid="updates-lasterror">{language.current && t('settings.updates.lastErrorLabel')}</span>
				{/if}
			</div>

			<div>
				<Button onclick={checkNow} disabled={checking} data-testid="updates-check-now">
					{checking
						? (language.current && t('settings.updates.checking'))
						: (language.current && t('settings.updates.checkNow'))}
				</Button>
			</div>
		</div>
	</Card>
</div>
