<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Login page (spec §6.9). Standard username/password form with
  "Remember me" checkbox. Linked from the /login flow and from the
  "First time?" link at the bottom that points to /setup.

  Full-screen layout (no sidebar/main chrome) via the +layout.svelte
  reset in this same directory.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { auth } from '$lib/stores/auth.svelte';
	import { ApiError } from '$lib/api/types';
	import { authApi } from '$lib/api/auth';
	import Input from '$lib/components/Input.svelte';
	import Checkbox from '$lib/components/Checkbox.svelte';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';

	// Step K.2 — map the `?error=<code>` query the OIDC callback
	// posts to the login page on a rejected SSO flow. Spec §5.2
	// callback emits these five codes; any other value falls
	// through to a generic message.
	const OIDC_ERROR_MESSAGES: Record<string, string> = {
		not_authorized:
			'This account is not allowed to sign in. Ask an administrator to add your email or OIDC subject to the allowlist.',
		invalid_state:
			'The SSO request was rejected (state mismatch, expired session, or replay attempt). Please try again.',
		idp_error:
			'The identity provider rejected the sign-in request. Check with your IdP administrator.',
		idp_unreachable:
			'The identity provider could not be reached. Try again later, or sign in with your local account below.',
		internal:
			'An unexpected error occurred during the SSO sign-in. Please try again, or sign in with your local account.'
	};

	let username = $state('');
	let password = $state('');
	let rememberMe = $state(false);
	let usernameError = $state('');
	let passwordError = $state('');
	let formError = $state('');
	let submitting = $state(false);
	// Step K.2 — probe the anonymous status endpoint to decide
	// whether to render the SSO button. A read failure is treated
	// as "OIDC not available" (fail-closed for the UI hint; local
	// login is never affected).
	let oidcEnabled = $state(false);

	onMount(() => {
		void authApi
			.oidcStatus()
			.then((s) => {
				oidcEnabled = s.enabled;
			})
			.catch(() => {
				oidcEnabled = false;
			});

		// Step K.2 — surface ?error=<code> from the OIDC callback.
		// The callback handler can land the operator back on this
		// page with a query param identifying the rejection reason;
		// silently dropping it is a UX black hole.
		const errCode = page.url.searchParams.get('error');
		if (errCode) {
			formError =
				OIDC_ERROR_MESSAGES[errCode] ??
				`Sign-in failed (code: ${errCode}). Please try again or sign in with your local account.`;
		}
	});

	function handleSsoLogin(): void {
		// Full navigation (NOT a fetch) — the backend 302s to the
		// IdP, which 302s back to /api/v1/auth/oidc/callback, which
		// sets the session cookie and 302s to /routes.
		window.location.href = '/api/v1/auth/oidc/login';
	}

	async function handleSubmit(e: Event): Promise<void> {
		e.preventDefault();
		if (submitting) return;
		usernameError = '';
		passwordError = '';
		formError = '';
		if (!username) {
			usernameError = 'Username is required';
			return;
		}
		if (!password) {
			passwordError = 'Password is required';
			return;
		}
		submitting = true;
		try {
			await auth.login(username, password, rememberMe);
			void goto('/routes');
		} catch (err) {
			if (err instanceof ApiError) {
				if (err.status === 401) {
					// Spec §4.3: same message for "user not found" and "bad password"
					// (prevents enumeration). The frontend mirrors that messaging.
					formError = 'Invalid username or password';
				} else if (err.status === 400) {
					formError = err.message;
				} else if (err.status === 429) {
					// The 429 interceptor already pushed a toast; we surface
					// the same message inline so the rate-limit feedback is
					// not solely tied to the (auto-dismissing) toast.
					formError = err.message;
				} else {
					formError = 'Unable to sign in. Try again later.';
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
	<Card class="w-96 max-w-full" padding="p-8">
		<h1 class="text-3xl font-semibold text-primary mb-2">
			<span class="text-cyan font-mono">A</span><span class="font-mono">RENET</span>
		</h1>
		<p class="text-secondary mb-6 text-sm">Sign in to the admin panel.</p>
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
				bind:value={username}
				label="Username"
				autocomplete="username"
				error={usernameError}
				disabled={submitting}
			/>
			<div class="mt-4">
				<Input
					bind:value={password}
					type="password"
					label="Password"
					autocomplete="current-password"
					error={passwordError}
					disabled={submitting}
				/>
			</div>
			<div class="mt-4">
				<Checkbox
					bind:checked={rememberMe}
					label="Remember me for 30 days"
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
						<span class="w-full text-center">Sign in</span>
					{/snippet}
				</Button>
			</div>
		</form>
		{#if oidcEnabled}
			<div class="mt-4">
				<div
					class="relative my-4 text-center text-xs text-secondary"
					aria-hidden="true"
				>
					<span class="bg-surface px-2 relative z-10">or</span>
					<div class="absolute inset-x-0 top-1/2 h-px bg-border -translate-y-1/2"></div>
				</div>
				<Button
					type="button"
					variant="secondary"
					size="md"
					onclick={handleSsoLogin}
					disabled={submitting}
				>
					{#snippet children()}
						<span class="w-full text-center">Continue with SSO</span>
					{/snippet}
				</Button>
			</div>
		{/if}
		<p class="text-secondary text-xs mt-6 text-center">
			First time? <a href="/setup" class="text-cyan hover:underline">Set up admin account</a>
		</p>
	</Card>
</div>
