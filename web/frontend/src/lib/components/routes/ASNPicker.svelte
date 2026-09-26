<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  ASNPicker (v2.28) — AS-number list of a route's geo filter (the
  "ASN" block, and the ASN part of deny-mode exceptions). Search by
  organisation name or number through GET /geo/asn (debounced);
  saved numbers are labelled via ?ids=. Without a GeoLite2-ASN
  database the picker still works by number and shows a hint to
  configure Settings → GeoIP.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { searchASN, namesASN } from '$lib/api/security';
	import type { ASNInfo } from '$lib/api/security';

	interface Props {
		value: number[];
		/** Numbers not to suggest (e.g. already blocked). */
		exclude?: readonly number[];
		label: string;
		/** Prefix for data-testid / element ids (two pickers per form). */
		testid: string;
	}

	let { value = $bindable(), exclude = [], label, testid }: Props = $props();

	const SEARCH_DEBOUNCE_MS = 250;
	const SEARCH_LIMIT = 20;

	let query = $state('');
	let open = $state(false);
	let activeIndex = $state(0);
	let results = $state<ASNInfo[]>([]);
	let loaded = $state(true);
	let names = $state<Record<number, string>>({});
	let timer: ReturnType<typeof setTimeout> | undefined;

	const suggestions = $derived(
		results.filter((r) => !value.includes(r.asn) && !exclude.includes(r.asn))
	);

	/** A bare number typed without a database hit can still be added. */
	const typedNumber = $derived.by(() => {
		const n = Number(query.trim().toUpperCase().replace(/^AS/, ''));
		return Number.isInteger(n) && n > 0 && n <= 4294967295 && !value.includes(n) ? n : null;
	});

	function label_(n: number): string {
		return names[n] ? `AS${n} ${names[n]}` : `AS${n}`;
	}

	async function resolveNames(asns: number[]): Promise<void> {
		const missing = asns.filter((n) => !(n in names));
		if (missing.length === 0) return;
		try {
			const res = await namesASN(missing);
			loaded = res.loaded;
			const next = { ...names };
			for (const r of res.results) next[r.asn] = r.name;
			names = next;
		} catch {
			// Labels are cosmetic: keep plain AS numbers.
		}
	}

	function onInput(): void {
		open = true;
		activeIndex = 0;
		clearTimeout(timer);
		const q = query.trim();
		if (q === '') {
			results = [];
			return;
		}
		timer = setTimeout(async () => {
			try {
				const res = await searchASN(q, SEARCH_LIMIT);
				loaded = res.loaded;
				results = res.results;
				const next = { ...names };
				for (const r of res.results) next[r.asn] = r.name;
				names = next;
			} catch {
				results = [];
			}
		}, SEARCH_DEBOUNCE_MS);
	}

	function add(n: number): void {
		if (!value.includes(n)) value = [...value, n];
		query = '';
		results = [];
		activeIndex = 0;
		open = false;
	}

	function remove(n: number): void {
		value = value.filter((v) => v !== n);
	}

	function onKeydown(e: KeyboardEvent): void {
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			activeIndex = Math.min(activeIndex + 1, Math.max(suggestions.length - 1, 0));
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			activeIndex = Math.max(activeIndex - 1, 0);
		} else if (e.key === 'Enter') {
			e.preventDefault();
			const pick = suggestions[activeIndex];
			if (pick) add(pick.asn);
			else if (typedNumber !== null) add(typedNumber);
		} else if (e.key === 'Escape') {
			open = false;
		}
	}

	onMount(() => {
		void resolveNames(value);
		return () => clearTimeout(timer);
	});
</script>

<div data-testid={testid}>
	<label for={`${testid}-input`} class="text-sm font-medium text-secondary block mb-1">{label}</label>
	<div class="flex flex-wrap gap-2 mb-2">
		{#each value as n (n)}
			<span class="asn-chip" data-testid={`${testid}-chip`} title={label_(n)}>
				<span>{label_(n)}</span>
				<button
					type="button"
					class="asn-chip__remove"
					aria-label={language.current && t('routes.form.geoASNRemoveAria', { asn: label_(n) })}
					onclick={() => remove(n)}
				>
					×
				</button>
			</span>
		{/each}
	</div>
	<div class="asn-input-wrap">
		<input
			id={`${testid}-input`}
			type="text"
			autocomplete="off"
			placeholder={language.current && t('routes.form.geoASNPlaceholder')}
			data-testid={`${testid}-input`}
			role="combobox"
			aria-expanded={open && suggestions.length > 0}
			aria-controls={`${testid}-listbox`}
			bind:value={query}
			oninput={onInput}
			onfocus={() => (open = true)}
			onblur={() => setTimeout(() => (open = false), 120)}
			onkeydown={onKeydown}
			class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
		/>
		{#if open && suggestions.length > 0}
			<ul id={`${testid}-listbox`} class="asn-dropdown" role="listbox">
				{#each suggestions as r, idx (r.asn)}
					<li
						role="option"
						class="asn-dropdown__item"
						class:active={idx === activeIndex}
						aria-selected={idx === activeIndex}
						data-testid={`${testid}-suggestion`}
						onmousedown={(e) => {
							e.preventDefault();
							add(r.asn);
						}}
					>
						<span class="font-mono">AS{r.asn}</span>
						<span>{r.name}</span>
					</li>
				{/each}
			</ul>
		{/if}
	</div>
	{#if !loaded}
		<p class="text-xs text-muted mt-1" data-testid={`${testid}-no-db`}>
			{language.current && t('routes.form.geoASNNoDatabase')}
			<a href="/settings" class="text-cyan hover:underline">
				{language.current && t('routes.form.geoASNSettingsLink')}
			</a>
		</p>
	{/if}
</div>

<style>
	.asn-chip {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 3px 4px 3px 8px;
		font-size: 11.5px;
		color: var(--text-secondary);
		background: color-mix(in oklch, var(--status-meta) 14%, transparent);
		border: 1px solid color-mix(in oklch, var(--status-meta) 40%, var(--border-subtle));
		border-radius: 999px;
		max-width: 100%;
	}
	.asn-chip__remove {
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
	.asn-chip__remove:hover {
		opacity: 1;
	}
	.asn-input-wrap {
		position: relative;
	}
	.asn-dropdown {
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
	.asn-dropdown__item {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 6px 10px;
		cursor: pointer;
		font-size: 12.5px;
		color: var(--text-secondary);
	}
	.asn-dropdown__item.active,
	.asn-dropdown__item:hover {
		background: color-mix(in oklch, var(--accent) 12%, transparent);
		color: var(--text-primary);
	}
</style>
