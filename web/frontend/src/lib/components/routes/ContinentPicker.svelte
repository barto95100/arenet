<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  ContinentPicker (v2.27) — the "Continents" block of a route's geo
  filter: the 7 MaxMind continent codes as toggle pills (buttons with
  aria-pressed, v2.34 — was a checkbox grid) in a fieldset + legend.
  Two-way bound on `value` (the selected codes, kept in
  CONTINENT_CODES order).
-->
<script lang="ts">
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	/** MaxMind GeoLite2 continent codes, display order. */
	const CONTINENT_CODES = ['EU', 'AS', 'AF', 'NA', 'SA', 'OC', 'AN'] as const;

	interface Props {
		value: string[];
		disabled?: boolean;
	}

	let { value = $bindable(), disabled = false }: Props = $props();

	function toggle(code: string, checked: boolean): void {
		const next = new Set(value);
		if (checked) next.add(code);
		else next.delete(code);
		value = CONTINENT_CODES.filter((c) => next.has(c));
	}
</script>

<fieldset class="continent-picker" data-testid="geo-continents">
	<legend class="text-sm font-medium text-secondary mb-1">
		{language.current && t('routes.form.geoContinentsLabel')}
	</legend>
	<div class="continent-pills">
		{#each CONTINENT_CODES as code (code)}
			{@const on = value.includes(code)}
			<button
				type="button"
				class="continent-pill"
				class:on
				aria-pressed={on}
				{disabled}
				data-testid={`geo-continent-${code}`}
				onclick={() => toggle(code, !on)}
			>
				{#if on}<span aria-hidden="true">✓</span>{/if}
				{language.current && t(`routes.form.geoContinent.${code}`)}
			</button>
		{/each}
	</div>
</fieldset>

<style>
	.continent-picker {
		border: 0;
		margin: 0;
		padding: 0;
	}
	.continent-pills {
		display: flex;
		flex-wrap: wrap;
		gap: 6px;
	}
	.continent-pill {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		padding: 3px 10px;
		border-radius: 999px;
		border: 1px solid var(--border-default);
		background: var(--bg-surface);
		color: var(--text-secondary);
		font-size: 12.5px;
		cursor: pointer;
		transition: background var(--motion-base, 120ms), border-color var(--motion-base, 120ms);
	}
	.continent-pill:hover:not(:disabled) {
		border-color: var(--accent);
	}
	.continent-pill.on {
		background: color-mix(in oklch, var(--accent) 16%, transparent);
		border-color: var(--accent);
		color: var(--text-primary);
	}
	.continent-pill:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
</style>
