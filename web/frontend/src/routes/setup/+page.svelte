<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Setup page (spec §6.10). First-boot admin creation flow. Same
  structure as /login, with the addition of the setup-token field
  and a banner explaining where to find it (server logs).

  The token is regenerated on every server restart while no admin
  exists; an admin already exists → the server returns 404 and the
  page surfaces "Setup is not available".
-->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { authApi } from '$lib/api/auth';
	import { auth } from '$lib/stores/auth.svelte';
	import { ApiError } from '$lib/api/types';
	import Input from '$lib/components/Input.svelte';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';

	let setupToken = $state('');
	let username = $state('');
	let displayName = $state('');
	let password = $state('');
	let errors = $state<Record<string, string>>({});
	let formError = $state('');
	let submitting = $state(false);

	async function handleSubmit(e: Event): Promise<void> {
		e.preventDefault();
		if (submitting) return;
		errors = {};
		formError = '';
		submitting = true;
		try {
			const user = await authApi.setup(setupToken, username, displayName, password);
			// /setup directly populates the auth store (the server sets
			// the cookie; the auth store now reflects the authenticated
			// admin without a follow-up /me round-trip).
			auth.user = user;
			auth.state = 'authenticated';
			void goto('/routes');
		} catch (err) {
			if (err instanceof ApiError) {
				if (err.status === 403) {
					errors = { setupToken: 'Invalid or expired setup token' };
				} else if (err.status === 404) {
					formError = 'Setup is not available: an admin account already exists.';
				} else if (err.status === 400) {
					// Heuristic field mapping based on the error message text
					// (spec §6.10). Phase 2 will replace this with structured
					// field-level errors from the wire format.
					const msg = err.message.toLowerCase();
					if (msg.includes('username')) errors = { username: err.message };
					else if (msg.includes('password')) errors = { password: err.message };
					else if (msg.includes('displayname')) errors = { displayName: err.message };
					else formError = err.message;
				} else {
					formError = err.message;
				}
			} else {
				formError = 'Unexpected error';
			}
		} finally {
			submitting = false;
		}
	}
</script>

<div class="flex items-center justify-center min-h-screen bg-base p-4">
	<Card class="w-[28rem] max-w-full" padding="p-8">
		<h1 class="text-3xl font-semibold text-primary mb-2">Initial setup</h1>
		<p class="text-secondary mb-2 text-sm">Create the first admin account.</p>
		<div class="mb-6 p-3 rounded bg-cyan/10 border border-cyan/30 text-sm">
			<p class="text-primary">
				<strong>Setup token required.</strong>
			</p>
			<p class="text-secondary mt-1">
				Look in your Arenet server logs for a line beginning with
				<code class="font-mono text-cyan">Setup token:</code>. The token is regenerated on
				every restart until an admin exists.
			</p>
		</div>
		{#if formError}
			<div
				class="mb-4 p-3 rounded bg-down/10 border border-down text-down text-sm"
				role="alert"
			>
				{formError}
			</div>
		{/if}
		<form onsubmit={handleSubmit}>
			<Input
				bind:value={setupToken}
				label="Setup token"
				placeholder="Paste from server logs"
				error={errors.setupToken ?? ''}
				disabled={submitting}
			/>
			<div class="mt-4">
				<Input
					bind:value={username}
					label="Username"
					placeholder="e.g. admin"
					autocomplete="username"
					error={errors.username ?? ''}
					disabled={submitting}
				/>
			</div>
			<div class="mt-4">
				<Input
					bind:value={displayName}
					label="Display name (optional)"
					placeholder="e.g. Site Admin"
					error={errors.displayName ?? ''}
					disabled={submitting}
				/>
			</div>
			<div class="mt-4">
				<Input
					bind:value={password}
					type="password"
					label="Password (minimum 15 characters)"
					autocomplete="new-password"
					error={errors.password ?? ''}
					disabled={submitting}
				/>
			</div>
			<div class="mt-6 w-full">
				<Button
					type="submit"
					variant="primary"
					size="md"
					loading={submitting}
					disabled={submitting}
				>
					{#snippet children()}
						<span class="w-full text-center">Create admin account</span>
					{/snippet}
				</Button>
			</div>
		</form>
	</Card>
</div>
