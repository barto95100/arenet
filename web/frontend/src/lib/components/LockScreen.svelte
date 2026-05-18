<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  LockScreen (spec §6.8). Full-screen overlay rendered above the
  existing UI when the session is in the `locked` state. Backdrop-blur
  preserves the underlying UI in the DOM (open modals, scroll position,
  form drafts) so the user resumes exactly where they were after
  unlocking.

  Mounted conditionally by +layout.svelte (Chunk 7 Étape 2) via
  {#if auth.state === 'locked'}. No escape handler: the user must
  authenticate or close the tab.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { auth } from '$lib/stores/auth.svelte';
	import { ApiError } from '$lib/api/types';
	import Input from './Input.svelte';
	import Button from './Button.svelte';

	let password = $state('');
	let error = $state('');
	let submitting = $state(false);
	let passwordInput: HTMLInputElement | undefined = $state();

	onMount(() => {
		passwordInput?.focus();
	});

	async function handleSubmit(e: Event): Promise<void> {
		e.preventDefault();
		if (submitting) return;
		if (!password) {
			error = 'Password is required';
			return;
		}
		submitting = true;
		error = '';
		try {
			await auth.unlock(password);
			// On success the auth store transitions to 'authenticated'
			// and this component unmounts via the parent's {#if} guard.
		} catch (err) {
			if (err instanceof ApiError) {
				error = err.status === 401 ? 'Incorrect password' : err.message;
			} else {
				error = 'Unexpected error';
			}
			password = '';
			passwordInput?.focus();
		} finally {
			submitting = false;
		}
	}
</script>

<div
	class="fixed inset-0 z-[1000] flex items-center justify-center"
	style:background-color="rgba(10, 14, 20, 0.8)"
	style:backdrop-filter="blur(8px)"
	role="dialog"
	aria-modal="true"
	aria-labelledby="lockscreen-title"
>
	<div
		class="bg-elevated border border-border-default rounded-lg shadow-glow-cyan p-8 w-96 max-w-full mx-4"
	>
		<h2 id="lockscreen-title" class="text-2xl font-semibold text-primary mb-2">
			Session locked
		</h2>
		<p class="text-secondary text-sm mb-6">
			Signed in as
			<span class="font-mono text-primary">{auth.user?.username ?? ''}</span>.
			Enter your password to continue.
		</p>
		<form onsubmit={handleSubmit}>
			<Input
				bind:value={password}
				bind:element={passwordInput}
				type="password"
				label="Password"
				autocomplete="current-password"
				error={error}
				disabled={submitting}
			/>
			<div class="mt-4 w-full">
				<Button
					type="submit"
					variant="primary"
					size="md"
					loading={submitting}
					disabled={submitting}
				>
					{#snippet children()}
						<span class="w-full text-center">Unlock</span>
					{/snippet}
				</Button>
			</div>
		</form>
	</div>
</div>
