<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  IPFilterFields (path-based-rules Task 7). Reusable IP allow/deny
  gate control: a 3-way mode radio (Off / Allowlist / Denylist) plus
  a CIDR/IP list input, shown only when mode is allow or deny.

  Shared between the route-level IPFilter section and each PathRule's
  scoped IPFilter (Task 8's PathRulesSection composes one instance
  per path rule) — hence a standalone component rather than inline
  markup, unlike the CountryBlock section in routes/+page.svelte
  which this mirrors stylistically (mode pill toggle, chip list, same
  test-id naming discipline) but does NOT reuse directly (CountryBlock
  is inline in the giant form and not extracted).

  Two-way bound via Svelte 5 `$bindable` — the parent owns the
  IPFilter value (route-level formData.ipFilter, or a given
  pathRules[i].ipFilter) and this component mutates it in place,
  mirroring how CountryBlock's mode buttons write directly into
  formData.countryBlock.

  CIDR list editing model: a single textarea, one entry per line —
  simpler than CountryBlock's autocomplete-chip flow because there's
  no fixed vocabulary to suggest against (arbitrary IPs/CIDRs), so a
  free-text list editor is the honest affordance. Blank lines are
  filtered out on blur/change; the raw textarea text is kept in local
  $state while editing so the operator isn't fighting reformatting
  keystroke-by-keystroke, and committed into value.cidrs on change.

  Public API (add-only; do not rename/remove props):

    value — the bound IPFilter (mode + cidrs + statusCode).
-->
<script lang="ts">
	import type { IPFilter } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	interface Props {
		value: IPFilter;
	}

	let { value = $bindable() }: Props = $props();

	type Mode = '' | 'off' | 'allow' | 'deny';

	function pickMode(next: Mode): void {
		value.mode = next;
	}

	// Local textarea text, seeded from value.cidrs and kept in sync
	// via $effect on cidrs identity changes (e.g. parent resetting
	// the form). Editing this text does NOT write back to
	// value.cidrs on every keystroke — only on change/blur — so the
	// operator can type a partial line without the list "flickering"
	// mid-edit.
	let cidrsText = $state((value.cidrs ?? []).join('\n'));
	let lastCidrs = value.cidrs;
	$effect(() => {
		if (value.cidrs !== lastCidrs) {
			cidrsText = (value.cidrs ?? []).join('\n');
			lastCidrs = value.cidrs;
		}
	});

	function commitCidrsText(): void {
		const next = cidrsText
			.split('\n')
			.map((line) => line.trim())
			.filter((line) => line.length > 0);
		value.cidrs = next;
		lastCidrs = next;
	}

	const showList = $derived(value.mode === 'allow' || value.mode === 'deny');
</script>

<div class="ipf-fields">
	<div>
		<span class="text-sm font-medium text-secondary block mb-1">
			{language.current && t('routes.ipFilter.modeLabel')}
		</span>
		<div
			class="ipf-mode-toggle"
			role="group"
			aria-label={language.current && t('routes.ipFilter.modeLabel')}
			data-testid="ipfilter-mode-toggle"
		>
			<button
				type="button"
				class="ipf-mode-btn ipf-mode-btn--off"
				class:active={value.mode === 'off' || value.mode === ''}
				data-testid="ipfilter-mode-off"
				role="radio"
				aria-checked={value.mode === 'off' || value.mode === ''}
				onclick={() => pickMode('off')}
			>
				<span class="ipf-mode-btn__label">{language.current && t('routes.ipFilter.modeOff')}</span>
			</button>
			<button
				type="button"
				class="ipf-mode-btn ipf-mode-btn--allow"
				class:active={value.mode === 'allow'}
				data-testid="ipfilter-mode-allow"
				role="radio"
				aria-checked={value.mode === 'allow'}
				onclick={() => pickMode('allow')}
			>
				<span class="ipf-mode-btn__label">{language.current && t('routes.ipFilter.modeAllow')}</span>
			</button>
			<button
				type="button"
				class="ipf-mode-btn ipf-mode-btn--deny"
				class:active={value.mode === 'deny'}
				data-testid="ipfilter-mode-deny"
				role="radio"
				aria-checked={value.mode === 'deny'}
				onclick={() => pickMode('deny')}
			>
				<span class="ipf-mode-btn__label">{language.current && t('routes.ipFilter.modeDeny')}</span>
			</button>
		</div>
	</div>

	{#if showList}
		<div>
			<label for="ipfilter-cidrs-input" class="text-sm font-medium text-secondary block mb-1">
				{language.current && t('routes.ipFilter.cidrsLabel')}
			</label>
			<textarea
				id="ipfilter-cidrs-input"
				data-testid="ipfilter-cidrs"
				rows="4"
				placeholder={language.current && t('routes.ipFilter.cidrsPlaceholder')}
				bind:value={cidrsText}
				onchange={commitCidrsText}
				onblur={commitCidrsText}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
			></textarea>
			<p class="text-xs text-muted mt-1">
				{language.current && t('routes.ipFilter.cidrsHint')}
			</p>
		</div>
	{:else}
		<p class="text-xs text-muted" data-testid="ipfilter-off-hint">
			{language.current && t('routes.ipFilter.offHint')}
		</p>
	{/if}
</div>

<style>
	.ipf-fields {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
	.ipf-mode-toggle {
		display: inline-flex;
		border-radius: 6px;
		overflow: hidden;
		border: 1px solid var(--border-subtle, var(--bg-hover));
	}
	.ipf-mode-btn {
		background: var(--bg-surface);
		color: var(--text-secondary);
		border: none;
		padding: 0.35rem 0.75rem;
		font-size: var(--text-sm);
		font-family: inherit;
		cursor: pointer;
	}
	.ipf-mode-btn:not(:last-child) {
		border-right: 1px solid var(--border-subtle, var(--bg-hover));
	}
	.ipf-mode-btn.active.ipf-mode-btn--off {
		background: var(--bg-hover);
		color: var(--text-primary);
	}
	.ipf-mode-btn.active.ipf-mode-btn--allow {
		background: color-mix(in oklch, var(--status-up, #22c55e) 20%, transparent);
		color: var(--text-primary);
	}
	.ipf-mode-btn.active.ipf-mode-btn--deny {
		background: color-mix(in oklch, var(--status-down, #ef4444) 20%, transparent);
		color: var(--text-primary);
	}
	.ipf-mode-btn:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 1px;
	}
</style>
