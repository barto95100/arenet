<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  CountryExceptionsPicker (v2.27) — the "Exceptions" block of a
  deny-mode geo filter: countries that are ALWAYS allowed, even
  inside a blocked continent ("deny Asia except Japan"). Country
  autocomplete (name or ISO code) + flag chips. Codes already in
  the blocked-country list are excluded from suggestions (the API
  rejects a country that is both blocked and an exception).
-->
<script lang="ts">
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { countryName, matchCountries } from '$lib/data/countries';
	import Flag from '$lib/components/Flag.svelte';

	interface Props {
		value: string[];
		blocked?: readonly string[];
	}

	let { value = $bindable(), blocked = [] }: Props = $props();

	let query = $state('');
	let open = $state(false);
	let activeIndex = $state(0);

	const suggestions = $derived(open ? matchCountries(query, [...value, ...blocked]) : []);

	function add(code: string): void {
		if (!value.includes(code)) value = [...value, code];
		query = '';
		activeIndex = 0;
		open = false;
	}

	function remove(code: string): void {
		value = value.filter((c) => c !== code);
	}

	function onKeydown(e: KeyboardEvent): void {
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			open = true;
			activeIndex = Math.min(activeIndex + 1, Math.max(suggestions.length - 1, 0));
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			activeIndex = Math.max(activeIndex - 1, 0);
		} else if (e.key === 'Enter') {
			e.preventDefault();
			const pick = suggestions[activeIndex];
			if (pick) add(pick.code);
		} else if (e.key === 'Escape') {
			open = false;
		}
	}
</script>

<div data-testid="geo-exceptions">
	<label for="geo-exceptions-input" class="text-sm font-medium text-secondary block">
		{language.current && t('routes.form.geoExceptionsLabel')}
	</label>
	<p class="text-xs text-muted mb-1">
		{language.current && t('routes.form.geoExceptionsHint')}
	</p>
	<div class="flex flex-wrap gap-2 mb-2">
		{#each value as code (code)}
			<span class="exc-chip" data-testid="geo-exception-chip" title={countryName(code)}>
				<Flag {code} />
				<span>{countryName(code)}</span>
				<button
					type="button"
					class="exc-chip__remove"
					aria-label={language.current &&
						t('routes.form.geoExceptionRemoveAria', { country: countryName(code) })}
					onclick={() => remove(code)}
				>
					×
				</button>
			</span>
		{/each}
	</div>
	<div class="exc-input-wrap">
		<input
			id="geo-exceptions-input"
			type="text"
			autocomplete="off"
			placeholder={language.current && t('routes.form.countryBlockSearchPlaceholder')}
			data-testid="geo-exceptions-input"
			role="combobox"
			aria-expanded={suggestions.length > 0}
			aria-controls="geo-exceptions-listbox"
			bind:value={query}
			oninput={() => {
				open = true;
				activeIndex = 0;
			}}
			onfocus={() => (open = true)}
			onblur={() => setTimeout(() => (open = false), 120)}
			onkeydown={onKeydown}
			class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
		/>
		{#if suggestions.length > 0}
			<ul id="geo-exceptions-listbox" class="exc-dropdown" role="listbox">
				{#each suggestions as match, idx (match.code)}
					<li
						role="option"
						class="exc-dropdown__item"
						class:active={idx === activeIndex}
						aria-selected={idx === activeIndex}
						data-testid="geo-exception-suggestion"
						onmousedown={(e) => {
							e.preventDefault();
							add(match.code);
						}}
					>
						<Flag code={match.code} />
						<span>{match.name}</span>
						<span class="text-muted">{match.code}</span>
					</li>
				{/each}
			</ul>
		{/if}
	</div>
</div>

<style>
	.exc-chip {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 3px 4px 3px 8px;
		font-size: 11.5px;
		color: var(--text-secondary);
		background: color-mix(in oklch, var(--status-up) 12%, transparent);
		border: 1px solid color-mix(in oklch, var(--status-up) 40%, var(--border-subtle));
		border-radius: 999px;
	}
	.exc-chip__remove {
		appearance: none;
		background: none;
		border: 0;
		color: currentColor;
		opacity: 0.6;
		cursor: pointer;
		font-size: 14px;
		line-height: 1;
		padding: 0 4px;
		border-radius: 999px;
	}
	.exc-chip__remove:hover {
		opacity: 1;
	}
	.exc-input-wrap {
		position: relative;
	}
	.exc-dropdown {
		position: absolute;
		top: calc(100% + 4px);
		left: 0;
		right: 0;
		max-height: 240px;
		overflow-y: auto;
		background: var(--bg-surface);
		border: 1px solid var(--border-default);
		border-radius: 6px;
		z-index: 10;
		list-style: none;
		margin: 0;
		padding: 4px 0;
	}
	.exc-dropdown__item {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 6px 10px;
		cursor: pointer;
		font-size: 12.5px;
		color: var(--text-secondary);
	}
	.exc-dropdown__item.active,
	.exc-dropdown__item:hover {
		background: color-mix(in oklch, var(--accent) 12%, transparent);
		color: var(--text-primary);
	}
</style>
