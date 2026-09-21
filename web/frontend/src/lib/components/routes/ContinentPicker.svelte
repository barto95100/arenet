<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  ContinentPicker (v2.27) — the "Continents" block of a route's geo
  filter: the 7 MaxMind continent codes as an accessible checkbox
  grid (fieldset + legend). Two-way bound on `value` (the selected
  codes, kept in CONTINENT_CODES order).
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
	<div class="continent-grid">
		{#each CONTINENT_CODES as code (code)}
			<label class="continent-option">
				<input
					type="checkbox"
					checked={value.includes(code)}
					{disabled}
					data-testid={`geo-continent-${code}`}
					onchange={(e) => toggle(code, (e.currentTarget as HTMLInputElement).checked)}
				/>
				<span>{language.current && t(`routes.form.geoContinent.${code}`)}</span>
			</label>
		{/each}
	</div>
</fieldset>

<style>
	.continent-picker {
		border: 0;
		margin: 0;
		padding: 0;
	}
	.continent-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
		gap: 6px 12px;
	}
	.continent-option {
		display: flex;
		align-items: center;
		gap: 8px;
		font-size: 13px;
		color: var(--text-secondary);
		cursor: pointer;
	}
</style>
