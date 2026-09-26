<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  GeoRuleSentence (v2.34) — one live sentence stating what a route's
  geo filter does, e.g. "Blocked if the visitor comes from Asia or
  Russia or AS14061 — except Japan". It makes the OR between the
  continent / country / ASN lists explicit (a request matches if ANY
  list matches; every list is optional) and shows the exceptions.
-->
<script lang="ts">
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	interface Props {
		mode: 'off' | 'allow' | 'deny';
		continents: string[];
		countries: string[];
		asns: number[];
		exceptionCountries: string[];
		exceptionAsns: number[];
		countryName: (code: string) => string;
	}

	let { mode, continents, countries, asns, exceptionCountries, exceptionAsns, countryName }: Props =
		$props();

	let items = $derived([
		...continents.map((c) => (language.current && t(`routes.form.geoContinent.${c}`)) || c),
		...countries.map((c) => countryName(c)),
		...asns.map((n) => `AS${n}`)
	]);
	let exceptions = $derived(
		mode === 'deny' ? [...exceptionCountries.map((c) => countryName(c)), ...exceptionAsns.map((n) => `AS${n}`)] : []
	);
</script>

{#if mode !== 'off'}
	<p class="geo-sentence geo-sentence--{mode}" data-testid="geo-rule-sentence" aria-live="polite">
		{#if items.length === 0}
			{language.current && t('routes.form.geoSentenceEmpty')}
		{:else}
			{language.current && t(mode === 'deny' ? 'routes.form.geoSentenceDeny' : 'routes.form.geoSentenceAllow')}
			{#each items as item, i (item + i)}{#if i > 0}{' '}<span class="geo-sentence__or"
						>{language.current && t('routes.form.geoSentenceOr')}</span
					>{/if}{' '}<strong>{item}</strong>{/each}
			{#if exceptions.length > 0}
				<span class="geo-sentence__except">— {language.current && t('routes.form.geoSentenceExcept')}</span>
				{#each exceptions as ex, i (ex + i)}<strong class="geo-sentence__exception">{ex}</strong
					>{#if i < exceptions.length - 1},{' '}{/if}{/each}
			{/if}
			{#if mode === 'allow'}
				<span class="geo-sentence__rest">— {language.current && t('routes.form.geoSentenceAllowRest')}</span>
			{/if}
		{/if}
	</p>
{/if}

<style>
	.geo-sentence {
		margin: 0;
		padding: 8px 10px;
		border-radius: 6px;
		font-size: 13px;
		line-height: 1.5;
		color: var(--text-secondary);
		border: 1px solid var(--border-subtle);
		background: var(--bg-surface);
	}
	.geo-sentence--deny {
		border-left: 3px solid var(--status-down, #d33);
	}
	.geo-sentence--allow {
		border-left: 3px solid var(--status-up, #2a2);
	}
	.geo-sentence strong {
		color: var(--text-primary);
		font-weight: 600;
	}
	.geo-sentence__or,
	.geo-sentence__except,
	.geo-sentence__rest {
		color: var(--text-muted);
	}
	.geo-sentence__exception {
		text-decoration: underline dotted;
	}
</style>
