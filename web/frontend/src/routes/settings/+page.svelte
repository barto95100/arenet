<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  TEMPORARY (Step F Chunk 1.6): minimal wiring of the theme Toggle for
  manual smoke validation of Chunk 1 (tokens + bootstrap + theme store
  + cookie wire-up + reconciliation). The full Settings page — sessions
  table, password change, account info, etc. — lands in Chunk 6 per
  spec §9. This file will be rewritten then; keeping the AGPL header
  preserved so the rewrite can `git mv`-equivalent the contents.
-->
<script lang="ts">
	import Toggle from '$lib/components/Toggle.svelte';
	import { theme, type Theme } from '$lib/stores/theme.svelte';

	const options: [
		{ value: Theme; label: string },
		{ value: Theme; label: string }
	] = [
		{ value: 'dark', label: 'Dark' },
		{ value: 'light', label: 'Light' }
	];

	async function onThemeChange(v: Theme): Promise<void> {
		try {
			await theme.set(v);
		} catch (_) {
			// Theme store already reverted and emitted a toast; nothing
			// to do here. Caught so the smoke session sees no unhandled
			// rejection in the console.
		}
	}
</script>

<div class="mx-auto max-w-2xl">
	<h1 class="text-4xl font-semibold">Settings</h1>
	<p class="mt-1 text-sm" style:color="var(--text-secondary)">
		Application preferences.
	</p>

	<section class="mt-10">
		<h2 class="text-xl font-semibold">Appearance</h2>
		<p class="mt-1 text-sm" style:color="var(--text-secondary)">
			Pick a theme. The change applies immediately and is saved to your account.
		</p>

		<div class="mt-4">
			<Toggle
				ariaLabel="Theme"
				{options}
				value={theme.current}
				disabled={theme.isApplying}
				onchange={onThemeChange}
			/>
		</div>

		<!-- Debug strip (smoke-only). Removed when this file is rewritten
		     for the real Settings page in Chunk 6. -->
		<dl class="mt-6 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs font-mono"
		    style:color="var(--text-muted)">
			<dt>theme.current</dt>
			<dd style:color="var(--text-primary)">{theme.current}</dd>
			<dt>theme.isApplying</dt>
			<dd style:color="var(--text-primary)">{theme.isApplying}</dd>
			<dt>data-theme attr</dt>
			<dd style:color="var(--text-primary)">
				{typeof document !== 'undefined'
					? (document.documentElement.dataset.theme ?? '(unset)')
					: '(ssr)'}
			</dd>
		</dl>
	</section>

	<p class="mt-12 text-xs" style:color="var(--text-muted)">
		Full Settings page lands in Chunk 6 (spec §9). This is a Chunk 1
		smoke-validation placeholder.
	</p>
</div>
