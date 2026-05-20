<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Settings (Step F §8.6 / §9). Three sections in a single page:

    1. Account  — display name + username (read-only), HIBP status
                  indicator (discreet — the compromised banner lives
                  in +layout.svelte, this is just an inline mirror),
                  Change password button.
    2. Appearance — theme Toggle (Chunk 1.6 wiring preserved),
                  Reduce motion read-only indicator.
    3. Sessions — DataTable (lands in Chunk 6.2).
    4. About — version / license / source (lands in Chunk 6.3).

  This file replaces the Chunk 1.6 placeholder (debug strip + footer
  note removed). The wrapper max-w-2xl is preserved — Settings is a
  configuration page, not a dashboard, so a column layout reads
  better than full-bleed.
-->
<script lang="ts">
	import { prefersReducedMotion } from 'svelte/motion';
	import { auth } from '$lib/stores/auth.svelte';
	import { theme, type Theme } from '$lib/stores/theme.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import Toggle from '$lib/components/Toggle.svelte';
	import ChangePasswordModal from '$lib/components/ChangePasswordModal.svelte';

	const options: [
		{ value: Theme; label: string },
		{ value: Theme; label: string }
	] = [
		{ value: 'dark', label: 'Dark' },
		{ value: 'light', label: 'Light' }
	];

	// Local ChangePasswordModal instance (Decision: Option B from the
	// Chunk 6 brief). The layout-shell instance handles the
	// compromised-password banner flow; this one is wired to the
	// explicit "Change password" button in the Account section.
	// Two instances of the same component, each with its own `open`
	// state — the component supports that by design.
	let changePasswordOpen = $state(false);

	async function onThemeChange(v: Theme): Promise<void> {
		try {
			await theme.set(v);
		} catch (_) {
			// theme store already reverted + toast emitted; just swallow
			// here so the smoke session sees no unhandled rejection.
		}
	}
</script>

<svelte:head>
	<title>Settings — Arenet</title>
</svelte:head>

<div class="mx-auto max-w-2xl">
	<PageHeader title="Settings" subtitle="Manage your account and preferences." />

	<!-- ACCOUNT SECTION -->
	<Card padding="p-6" class="mb-6">
		<header class="border-b border-border-subtle pb-3 mb-4">
			<h2 class="text-xl font-semibold">Account</h2>
		</header>

		<dl class="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-3 text-sm">
			<dt class="text-secondary">Display name</dt>
			<dd class="text-primary">{auth.user?.displayName ?? '—'}</dd>

			<dt class="text-secondary">Username</dt>
			<dd class="text-primary font-mono">{auth.user?.username ?? '—'}</dd>

			<dt class="text-secondary">Password security</dt>
			<dd>
				<!-- Discreet inline indicator — the compromised banner
				     in +layout.svelte handles the urgent attention
				     path; this is just a mirror so the user can read
				     their HIBP status without scrolling to the top. -->
				{#if auth.user?.passwordCompromised}
					<span class="text-down">Compromised — change required</span>
				{:else if auth.user?.hibpCheckStatus === 'clean'}
					<span class="text-up">Clean (HIBP verified)</span>
				{:else if auth.user?.hibpCheckStatus === 'pending'}
					<span class="text-muted">Pending check</span>
				{:else if auth.user?.hibpCheckStatus === 'skipped'}
					<span class="text-muted">Check skipped</span>
				{:else}
					<span class="text-muted">Unknown</span>
				{/if}
			</dd>
		</dl>

		<div class="mt-6">
			<Button variant="secondary" onclick={() => (changePasswordOpen = true)}>
				Change password
			</Button>
		</div>
	</Card>

	<!-- APPEARANCE SECTION -->
	<Card padding="p-6" class="mb-6">
		<header class="border-b border-border-subtle pb-3 mb-4">
			<h2 class="text-xl font-semibold">Appearance</h2>
		</header>

		<dl class="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-4 text-sm items-center">
			<dt class="text-secondary">Theme</dt>
			<dd>
				<Toggle
					ariaLabel="Theme"
					{options}
					value={theme.current}
					disabled={theme.isApplying}
					onchange={onThemeChange}
				/>
			</dd>

			<dt class="text-secondary">Reduce motion</dt>
			<dd class="text-primary">
				{prefersReducedMotion.current ? 'Enabled' : 'Disabled'}
				<span class="text-muted ml-2 text-xs">(system preference)</span>
			</dd>
		</dl>
	</Card>

	<!-- ChangePasswordModal mounted locally (Option B). The
	     layout-level instance handles the compromised-banner flow;
	     this one handles the explicit user click in Settings. They're
	     independent instances of the same component — both safe by
	     ChangePasswordModal's `bind:open` design. -->
	<ChangePasswordModal bind:open={changePasswordOpen} />
</div>
