<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Login page — re-skinned from docs/mocks/auth/signin.html.
  All auth logic is preserved verbatim from the previous
  iteration:

    - onMount: probe /api/v1/auth/oidc/status to decide whether
      to render the SSO button; surface ?error=<code> from the
      callback into a readable banner.
    - handleSubmit: validate locally, call auth.login(), map
      401/400/429/other into formError, goto('/routes') on
      success.
    - handleSsoLogin: full navigation to /api/v1/auth/oidc/login
      so the backend can 302 to the IdP.

  Differences from the mock (deliberate, per the port brief):

    - MFA view dropped (out of scope).
    - "Forgot password?" and "Request invitation" links dropped
      — no backend behind them.
    - Topbar (brand wordmark + lang toggle) and footbar
      (build/region/links) dropped — kept only the centered
      card and the constellation background.
    - "Sync il y a 2 min · 9 comptes provisionnés" stub dropped;
      kept only the green dot when oidc/status returns enabled.
    - SSO label is the generic "Continuer avec SSO" (B3 decision
      — visual-only port, no backend extension for a per-provider
      display name).
    - Eye toggle on the password field kept as a bonus from the
      mock (no backend dependency).
    - Username field labelled "Identifiant" (Arenet stores
      usernames, not emails).
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { auth } from '$lib/stores/auth.svelte';
	import { ApiError } from '$lib/api/types';
	import { authApi } from '$lib/api/auth';
	import LoginBackground from '$lib/components/LoginBackground.svelte';
	import SSOProviderLogo from '$lib/components/SSOProviderLogo.svelte';
	import type { OIDCProviderKind } from '$lib/api/types';
	import logoUrl from '$lib/assets/arenet-logo.png';

	// Step K.2 — map the `?error=<code>` query the OIDC callback
	// posts to the login page on a rejected SSO flow. Spec §5.2
	// callback emits these five codes; any other value falls
	// through to a generic message.
	const OIDC_ERROR_MESSAGES: Record<string, string> = {
		not_authorized:
			"Ce compte n'est pas autorisé à se connecter. Demande à un administrateur d'ajouter ton e-mail ou ton identifiant OIDC à la liste des accès.",
		invalid_state:
			'La requête SSO a été rejetée (jeton d\'état invalide, expiré ou rejoué). Réessaie.',
		idp_error:
			"Le fournisseur d'identité a rejeté la demande de connexion. Contacte l'administrateur de l'IdP.",
		idp_unreachable:
			"Le fournisseur d'identité est injoignable. Réessaie plus tard, ou connecte-toi avec un compte local ci-dessous.",
		internal:
			'Une erreur inattendue est survenue pendant la connexion SSO. Réessaie, ou utilise un compte local.'
	};

	let username = $state('');
	let password = $state('');
	let rememberMe = $state(false);
	let showPassword = $state(false);
	let usernameError = $state('');
	let passwordError = $state('');
	let formError = $state('');
	let submitting = $state(false);
	// Step K.2 — probe the anonymous status endpoint to decide
	// whether to render the SSO button. A read failure is treated
	// as "OIDC not available" (fail-closed for the UI hint; local
	// login is never affected).
	let oidcEnabled = $state(false);
	let oidcKind = $state<OIDCProviderKind | ''>('');
	// Setup availability probe. The "Première connexion ?" link
	// only makes sense before the first admin is created; once
	// any admin exists the /setup endpoint 404s and the link
	// becomes a dead-end. We hide it in that case.
	let setupAvailable = $state(false);

	onMount(() => {
		void authApi
			.oidcStatus()
			.then((s) => {
				oidcEnabled = s.enabled;
				oidcKind = (s.kind ?? '') as OIDCProviderKind | '';
			})
			.catch(() => {
				oidcEnabled = false;
				oidcKind = '';
			});

		void authApi
			.setupStatus()
			.then((s) => {
				setupAvailable = s.available;
			})
			.catch(() => {
				setupAvailable = false;
			});

		// Step K.2 — surface ?error=<code> from the OIDC callback.
		const errCode = page.url.searchParams.get('error');
		if (errCode) {
			formError =
				OIDC_ERROR_MESSAGES[errCode] ??
				`La connexion a échoué (code : ${errCode}). Réessaie, ou utilise un compte local.`;
		}
	});

	function handleSsoLogin(): void {
		// Full navigation (NOT a fetch) — the backend 302s to the
		// IdP, which 302s back to /api/v1/auth/oidc/callback, which
		// sets the session cookie and 302s to /routes.
		window.location.href = '/api/v1/auth/oidc/login';
	}

	function togglePassword(): void {
		showPassword = !showPassword;
	}

	async function handleSubmit(e: Event): Promise<void> {
		e.preventDefault();
		if (submitting) return;
		usernameError = '';
		passwordError = '';
		formError = '';
		if (!username) {
			usernameError = "L'identifiant est requis.";
			return;
		}
		if (!password) {
			passwordError = 'Le mot de passe est requis.';
			return;
		}
		submitting = true;
		try {
			await auth.login(username, password, rememberMe);
			void goto('/routes');
		} catch (err) {
			if (err instanceof ApiError) {
				if (err.status === 401) {
					// Spec §4.3: same message for "user not found"
					// and "bad password" (anti-enumeration).
					formError = 'Identifiant ou mot de passe invalide.';
				} else if (err.status === 400) {
					formError = err.message;
				} else if (err.status === 429) {
					formError = err.message;
				} else {
					formError = 'Connexion impossible. Réessaie plus tard.';
				}
			} else {
				formError = 'Erreur inattendue.';
			}
		} finally {
			submitting = false;
		}
	}
</script>

<LoginBackground />

<div class="login-page">
	<!-- Brand wordmark in the top-left. The right side of the
	     topbar is intentionally empty (the mock's env badge and
	     lang toggle are dropped — no infra behind them). -->
	<div class="login-topbar">
		<div class="login-brand">
			<img class="login-brand-logo" src={logoUrl} alt="" aria-hidden="true" width="34" height="34" />
			<div class="login-brand-name">Arenet</div>
		</div>
	</div>

	<div class="login-card">
		<h1 class="login-title">Bienvenue.</h1>
		<p class="login-sub">Connecte-toi pour accéder à la console Arenet.</p>

		{#if formError}
			<div class="login-banner" role="alert">
				<svg
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
					stroke-linecap="round"
					stroke-linejoin="round"
					aria-hidden="true"
				>
					<circle cx="12" cy="12" r="10" />
					<line x1="12" y1="8" x2="12" y2="12" />
					<line x1="12" y1="16" x2="12.01" y2="16" />
				</svg>
				<div>{formError}</div>
			</div>
		{/if}

		{#if oidcEnabled}
			<button
				class="login-sso"
				type="button"
				onclick={handleSsoLogin}
				disabled={submitting}
				aria-label="Continuer avec SSO"
			>
				<SSOProviderLogo kind={oidcKind} size={22} />
				<span class="login-sso-label">Continuer avec <b>SSO</b></span>
				<svg
					class="login-sso-arrow"
					viewBox="0 0 24 24"
					width="16"
					height="16"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
					stroke-linecap="round"
					stroke-linejoin="round"
					aria-hidden="true"
				>
					<path d="M5 12h14M12 5l7 7-7 7" />
				</svg>
			</button>
			<div class="login-sso-hint">
				<span class="login-pdot" aria-hidden="true"></span>
				IdP joignable
			</div>

			<div class="login-divider">ou avec un compte local</div>
		{/if}

		<form onsubmit={handleSubmit} autocomplete="on" novalidate>
			<div class="login-field">
				<label for="login-username">Identifiant</label>
				<div class="login-input-wrap">
					<input
						id="login-username"
						class="login-input"
						type="text"
						autocomplete="username"
						bind:value={username}
						disabled={submitting}
						aria-invalid={usernameError ? 'true' : undefined}
						aria-describedby={usernameError ? 'login-username-error' : undefined}
					/>
				</div>
				{#if usernameError}
					<small id="login-username-error" class="login-field-error">{usernameError}</small>
				{/if}
			</div>

			<div class="login-field">
				<label for="login-password">Mot de passe</label>
				<div class="login-input-wrap">
					<input
						id="login-password"
						class="login-input login-input-with-toggle"
						type={showPassword ? 'text' : 'password'}
						autocomplete="current-password"
						bind:value={password}
						disabled={submitting}
						aria-invalid={passwordError ? 'true' : undefined}
						aria-describedby={passwordError ? 'login-password-error' : undefined}
					/>
					<button
						type="button"
						class="login-pw-toggle"
						onclick={togglePassword}
						tabindex={-1}
						aria-label={showPassword ? 'Masquer le mot de passe' : 'Afficher le mot de passe'}
					>
						{#if showPassword}
							<svg
								viewBox="0 0 24 24"
								fill="none"
								stroke="currentColor"
								stroke-width="2"
								stroke-linecap="round"
								stroke-linejoin="round"
								aria-hidden="true"
							>
								<path
									d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"
								/>
								<line x1="1" y1="1" x2="23" y2="23" />
							</svg>
						{:else}
							<svg
								viewBox="0 0 24 24"
								fill="none"
								stroke="currentColor"
								stroke-width="2"
								stroke-linecap="round"
								stroke-linejoin="round"
								aria-hidden="true"
							>
								<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
								<circle cx="12" cy="12" r="3" />
							</svg>
						{/if}
					</button>
				</div>
				{#if passwordError}
					<small id="login-password-error" class="login-field-error">{passwordError}</small>
				{/if}
			</div>

			<div class="login-row">
				<label class="login-check">
					<input type="checkbox" bind:checked={rememberMe} disabled={submitting} />
					<span>
						Faire confiance à cet appareil
						<small>session de 30 jours</small>
					</span>
				</label>
			</div>

			<button
				type="submit"
				class="login-submit"
				class:loading={submitting}
				disabled={submitting}
			>
				<span class="login-spin" aria-hidden="true"></span>
				<span class="login-submit-label">Se connecter</span>
			</button>
		</form>

		{#if setupAvailable}
			<div class="login-foot">
				Première connexion ? <a href="/setup">Créer le compte administrateur</a>
			</div>
		{/if}
	</div>
</div>

<style>
	/* Tokens scoped to the login page only. tokens.css unchanged. */
	.login-page {
		--bg: oklch(15% 0.005 250);
		--bg-deep: oklch(11% 0.005 250);
		--surface: oklch(19% 0.006 250);
		--surface-2: oklch(22% 0.007 250);
		--border: oklch(28% 0.009 250);
		--border-hi: oklch(34% 0.011 250);
		--fg: oklch(96% 0.005 250);
		--fg-muted: oklch(68% 0.012 250);
		--fg-dim: oklch(54% 0.011 250);
		--accent: oklch(68% 0.21 255);
		--accent-soft: oklch(68% 0.21 255 / 0.14);
		--accent-line: oklch(68% 0.21 255 / 0.45);
		--radius: 8px;
		--radius-sm: 6px;
		--radius-lg: 14px;
		--font-display: 'Inter', system-ui, -apple-system, sans-serif;
		--font-body: 'Inter', system-ui, -apple-system, sans-serif;
		--font-mono: 'Geist Mono', ui-monospace, monospace;

		position: relative;
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 28px 22px;
		color: var(--fg);
		font-family: var(--font-body);
		font-size: 14px;
		line-height: 1.5;
		-webkit-font-smoothing: antialiased;
		font-variant-numeric: tabular-nums;
		z-index: 10;
	}

	/* Topbar: brand wordmark left, nothing on the right (mock's
	 * env badge + lang toggle dropped per the port brief).
	 * Positioned absolute so the parent flex remains a pure
	 * viewport-centered container — that keeps the card aligned
	 * with the breathing halo (which is fixed at 50%/50% of the
	 * viewport). The mock balanced the flex with a footbar; we
	 * dropped the footbar, so removing the topbar from the flow
	 * is the equivalent solution. */
	.login-topbar {
		position: absolute;
		top: 28px;
		left: 22px;
		right: 22px;
		max-width: 1180px;
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.login-brand {
		display: flex;
		align-items: center;
		gap: 11px;
	}
	.login-brand-logo {
		width: 34px;
		height: 34px;
		object-fit: contain;
		flex-shrink: 0;
		/* Soft halo around the logo to preserve the depth of the
		   pre-logo gradient mark — keeps the brand block visually
		   anchored against the translucent login card. */
		filter: drop-shadow(0 12px 36px oklch(60% 0.22 260 / 0.5));
	}
	.login-brand-name {
		font-family: var(--font-display);
		font-size: 16px;
		font-weight: 600;
		letter-spacing: -0.02em;
	}

	.login-card {
		width: 100%;
		max-width: 440px;
		padding: 34px;
		background: oklch(19% 0.006 250 / 0.85);
		backdrop-filter: blur(18px) saturate(140%);
		-webkit-backdrop-filter: blur(18px) saturate(140%);
		border: 1px solid var(--border-hi);
		border-radius: var(--radius-lg);
		box-shadow:
			0 1px 0 0 oklch(60% 0.012 250 / 0.06) inset,
			0 32px 80px -32px oklch(0% 0 0 / 0.65),
			0 2px 6px oklch(0% 0 0 / 0.3);
	}

	.login-title {
		font-family: var(--font-display);
		font-size: 24px;
		font-weight: 600;
		letter-spacing: -0.025em;
		margin: 0 0 6px;
	}

	.login-sub {
		color: var(--fg-muted);
		font-size: 13.5px;
		margin: 0 0 22px;
	}

	/* Error banner — port of .banner (red variant). */
	.login-banner {
		display: flex;
		align-items: flex-start;
		gap: 10px;
		padding: 10px 12px;
		border-radius: var(--radius);
		background: oklch(66% 0.20 25 / 0.10);
		border: 1px solid oklch(66% 0.20 25 / 0.4);
		color: oklch(86% 0.12 25);
		font-size: 12.5px;
		line-height: 1.45;
		margin-bottom: 16px;
	}
	.login-banner :global(svg) {
		width: 16px;
		height: 16px;
		flex: none;
		margin-top: 1px;
	}

	/* SSO button — port of .sso-btn. Logo is a generic icon
	 * (Lucide log-in glyph), not a per-provider mark. */
	.login-sso {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 10px;
		width: 100%;
		padding: 12px 14px;
		border-radius: var(--radius);
		background: linear-gradient(180deg, oklch(28% 0.018 60) 0%, oklch(22% 0.014 60) 100%);
		border: 1px solid oklch(64% 0.18 35 / 0.45);
		color: var(--fg);
		font: inherit;
		font-size: 14px;
		font-weight: 500;
		cursor: pointer;
		transition: background 0.15s, border-color 0.15s, transform 0.04s;
	}
	.login-sso:hover {
		background: linear-gradient(180deg, oklch(32% 0.02 60) 0%, oklch(25% 0.016 60) 100%);
		border-color: oklch(64% 0.18 35 / 0.7);
	}
	.login-sso:active {
		transform: translateY(1px);
	}
	.login-sso:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
	.login-sso-label b {
		font-weight: 600;
	}
	.login-sso-arrow {
		margin-left: auto;
		color: var(--fg-dim);
	}
	.login-sso:hover .login-sso-arrow {
		color: var(--fg-muted);
	}

	.login-sso-hint {
		display: flex;
		align-items: center;
		gap: 6px;
		margin-top: 8px;
		font-family: var(--font-mono);
		font-size: 10.5px;
		color: var(--fg-dim);
		letter-spacing: 0.03em;
	}
	.login-pdot {
		width: 5px;
		height: 5px;
		border-radius: 50%;
		background: var(--status-up);
	}

	.login-divider {
		display: flex;
		align-items: center;
		gap: 12px;
		margin: 22px 0;
		color: var(--fg-dim);
		font-size: 11px;
		font-family: var(--font-mono);
		letter-spacing: 0.1em;
		text-transform: uppercase;
	}
	.login-divider::before,
	.login-divider::after {
		content: '';
		flex: 1;
		height: 1px;
		background: var(--border);
	}

	.login-field {
		display: flex;
		flex-direction: column;
		gap: 6px;
		margin-bottom: 14px;
	}
	.login-field label {
		font-size: 12.5px;
		color: var(--fg-muted);
	}
	.login-field-error {
		color: oklch(75% 0.16 25);
		font-size: 11.5px;
	}

	.login-input-wrap {
		position: relative;
	}
	.login-input {
		width: 100%;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 10px 12px;
		color: var(--fg);
		font: inherit;
		font-size: 14px;
		outline: none;
		transition: border-color 0.12s, box-shadow 0.12s, background 0.12s;
	}
	.login-input:hover:not(:disabled) {
		border-color: var(--border-hi);
	}
	.login-input:focus {
		border-color: var(--accent);
		box-shadow: 0 0 0 3px var(--accent-soft);
		background: var(--bg-elevated);
	}
	.login-input:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
	.login-input-with-toggle {
		padding-right: 42px;
	}

	.login-pw-toggle {
		position: absolute;
		right: 8px;
		top: 50%;
		transform: translateY(-50%);
		width: 28px;
		height: 28px;
		border-radius: 6px;
		display: grid;
		place-items: center;
		color: var(--fg-dim);
		background: none;
		border: none;
		cursor: pointer;
	}
	.login-pw-toggle:hover {
		color: var(--fg-muted);
		background: var(--surface-2);
	}
	.login-pw-toggle :global(svg) {
		width: 16px;
		height: 16px;
	}

	.login-row {
		display: flex;
		align-items: center;
		gap: 10px;
		margin: 2px 0 18px;
	}
	.login-check {
		display: flex;
		align-items: center;
		gap: 8px;
		font-size: 12.5px;
		color: var(--fg-muted);
		cursor: pointer;
		user-select: none;
	}
	.login-check input {
		appearance: none;
		width: 16px;
		height: 16px;
		border-radius: 4px;
		border: 1px solid var(--border-hi);
		background: var(--bg);
		display: grid;
		place-items: center;
		cursor: pointer;
		transition: border-color 0.12s, background 0.12s;
	}
	.login-check input:checked {
		background: var(--accent);
		border-color: var(--accent);
	}
	.login-check input:checked::after {
		content: '';
		width: 8px;
		height: 5px;
		border-left: 1.6px solid #fff;
		border-bottom: 1.6px solid #fff;
		transform: rotate(-45deg) translate(1px, -1px);
	}
	.login-check:hover input:not(:disabled) {
		border-color: var(--accent-line);
	}
	.login-check small {
		display: block;
		color: var(--fg-dim);
		font-size: 11px;
		margin-top: 1px;
	}

	.login-submit {
		width: 100%;
		padding: 11px 14px;
		background: var(--accent);
		color: #fff;
		font: inherit;
		font-weight: 500;
		font-size: 14px;
		border-radius: var(--radius);
		border: 1px solid transparent;
		cursor: pointer;
		transition: background 0.12s, transform 0.04s;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 8px;
	}
	.login-submit:hover:not(:disabled) {
		background: oklch(62% 0.22 255);
	}
	.login-submit:active:not(:disabled) {
		transform: translateY(1px);
	}
	.login-submit:disabled {
		opacity: 0.7;
		cursor: not-allowed;
	}
	.login-spin {
		display: none;
		width: 14px;
		height: 14px;
		border-radius: 50%;
		border: 2px solid oklch(98% 0.005 250 / 0.4);
		border-top-color: #fff;
		animation: loginSpin 0.8s linear infinite;
	}
	.login-submit.loading .login-spin {
		display: inline-block;
	}
	.login-submit.loading .login-submit-label {
		opacity: 0.85;
	}
	@keyframes loginSpin {
		to {
			transform: rotate(360deg);
		}
	}

	.login-foot {
		margin-top: 18px;
		text-align: center;
		color: var(--fg-muted);
		font-size: 12.5px;
	}
	.login-foot a {
		color: var(--accent);
		font-weight: 500;
		text-decoration: none;
	}
	.login-foot a:hover {
		text-decoration: underline;
		text-decoration-color: var(--accent-line);
		text-underline-offset: 3px;
	}

	@media (max-width: 640px) {
		.login-page {
			padding: 80px 14px 18px; /* top padding keeps the absolute topbar from overlapping the card on short viewports */
		}
		.login-topbar {
			top: 18px;
			left: 14px;
			right: 14px;
		}
		.login-card {
			padding: 26px;
		}
	}
	@media (max-width: 480px) {
		.login-card {
			padding: 22px;
		}
	}
</style>
