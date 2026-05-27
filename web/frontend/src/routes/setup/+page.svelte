<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Setup page (spec §6.10). First-boot admin creation flow. Re-
  skinned in symmetry with /login (same constellation background,
  same OKLCH tokens scoped to .setup-page, same glass card
  treatment) so the bootstrap flow doesn't look orphaned vs the
  signed-in chrome.

  The token is regenerated on every server restart while no admin
  exists; an admin already exists → the server returns 404 and the
  page surfaces "Setup indisponible : un compte admin existe déjà."

  Logic is preserved verbatim from the pre-reskin iteration: same
  authApi.setup call, same 403 → token error, 404 → admin exists,
  400 → heuristic field mapping (username / password / displayName).
  Visual rewrite only.
-->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { authApi } from '$lib/api/auth';
	import { auth } from '$lib/stores/auth.svelte';
	import { ApiError } from '$lib/api/types';
	import LoginBackground from '$lib/components/LoginBackground.svelte';

	let setupToken = $state('');
	let username = $state('');
	let displayName = $state('');
	let password = $state('');
	let showPassword = $state(false);
	let errors = $state<Record<string, string>>({});
	let formError = $state('');
	let submitting = $state(false);

	function togglePassword(): void {
		showPassword = !showPassword;
	}

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
					errors = { setupToken: 'Jeton de setup invalide ou expiré.' };
				} else if (err.status === 404) {
					formError = 'Setup indisponible : un compte administrateur existe déjà.';
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
				formError = 'Erreur inattendue.';
			}
		} finally {
			submitting = false;
		}
	}
</script>

<LoginBackground />

<div class="setup-page">
	<div class="setup-topbar">
		<div class="setup-brand">
			<div class="setup-brand-mark" aria-hidden="true">A</div>
			<div class="setup-brand-name">Arenet</div>
		</div>
	</div>

	<div class="setup-card">
		<h1 class="setup-title">Première installation</h1>
		<p class="setup-sub">Crée le compte administrateur initial.</p>

		<div class="setup-info-banner">
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
				<line x1="12" y1="16" x2="12" y2="12" />
				<line x1="12" y1="8" x2="12.01" y2="8" />
			</svg>
			<div>
				<b>Jeton de setup requis.</b> Cherche dans les logs serveur Arenet une ligne commençant par
				<code>Setup token:</code>. Le jeton est régénéré à chaque démarrage tant qu'aucun
				administrateur n'existe.
			</div>
		</div>

		{#if formError}
			<div class="setup-banner" role="alert">
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

		<form onsubmit={handleSubmit} autocomplete="on" novalidate>
			<div class="setup-field">
				<label for="setup-token">Jeton de setup</label>
				<div class="setup-input-wrap">
					<input
						id="setup-token"
						class="setup-input setup-input-mono"
						type="text"
						placeholder="Coller depuis les logs serveur"
						bind:value={setupToken}
						disabled={submitting}
						aria-invalid={errors.setupToken ? 'true' : undefined}
						aria-describedby={errors.setupToken ? 'setup-token-error' : undefined}
					/>
				</div>
				{#if errors.setupToken}
					<small id="setup-token-error" class="setup-field-error">{errors.setupToken}</small>
				{/if}
			</div>

			<div class="setup-field">
				<label for="setup-username">Identifiant</label>
				<div class="setup-input-wrap">
					<input
						id="setup-username"
						class="setup-input"
						type="text"
						placeholder="ex. admin"
						autocomplete="username"
						bind:value={username}
						disabled={submitting}
						aria-invalid={errors.username ? 'true' : undefined}
						aria-describedby={errors.username ? 'setup-username-error' : undefined}
					/>
				</div>
				{#if errors.username}
					<small id="setup-username-error" class="setup-field-error">{errors.username}</small>
				{/if}
			</div>

			<div class="setup-field">
				<label for="setup-displayname">Nom d'affichage <small>(optionnel)</small></label>
				<div class="setup-input-wrap">
					<input
						id="setup-displayname"
						class="setup-input"
						type="text"
						placeholder="ex. Site Admin"
						bind:value={displayName}
						disabled={submitting}
						aria-invalid={errors.displayName ? 'true' : undefined}
						aria-describedby={errors.displayName ? 'setup-displayname-error' : undefined}
					/>
				</div>
				{#if errors.displayName}
					<small id="setup-displayname-error" class="setup-field-error">
						{errors.displayName}
					</small>
				{/if}
			</div>

			<div class="setup-field">
				<label for="setup-password">Mot de passe <small>(minimum 15 caractères)</small></label>
				<div class="setup-input-wrap">
					<input
						id="setup-password"
						class="setup-input setup-input-with-toggle"
						type={showPassword ? 'text' : 'password'}
						autocomplete="new-password"
						bind:value={password}
						disabled={submitting}
						aria-invalid={errors.password ? 'true' : undefined}
						aria-describedby={errors.password ? 'setup-password-error' : undefined}
					/>
					<button
						type="button"
						class="setup-pw-toggle"
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
				{#if errors.password}
					<small id="setup-password-error" class="setup-field-error">{errors.password}</small>
				{/if}
			</div>

			<button
				type="submit"
				class="setup-submit"
				class:loading={submitting}
				disabled={submitting}
			>
				<span class="setup-spin" aria-hidden="true"></span>
				<span class="setup-submit-label">Créer le compte administrateur</span>
			</button>
		</form>
	</div>
</div>

<style>
	/* Tokens scoped to the setup page only. Same OKLCH palette as
	 * the login page (lib/components/LoginBackground.svelte) for
	 * visual continuity through the bootstrap flow. tokens.css
	 * unchanged. */
	.setup-page {
		--bg: oklch(15% 0.005 250);
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
		--ok: oklch(72% 0.16 150);
		--radius: 8px;
		--radius-sm: 6px;
		--radius-lg: 14px;
		--font-display: 'Inter', system-ui, -apple-system, sans-serif;
		--font-body: 'Inter', system-ui, -apple-system, sans-serif;
		--font-mono: 'Geist Mono', ui-monospace, 'JetBrains Mono', monospace;

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

	/* Topbar — absolute so the card stays viewport-centered
	 * (and thus aligned with the breathing halo behind it). Same
	 * approach as /login. */
	.setup-topbar {
		position: absolute;
		top: 28px;
		left: 22px;
		right: 22px;
		max-width: 1180px;
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.setup-brand {
		display: flex;
		align-items: center;
		gap: 11px;
	}
	.setup-brand-mark {
		width: 34px;
		height: 34px;
		border-radius: 9px;
		background: linear-gradient(140deg, var(--accent) 0%, oklch(52% 0.22 265) 100%);
		display: grid;
		place-items: center;
		color: #fff;
		font-family: var(--font-display);
		font-weight: 600;
		font-size: 16px;
		letter-spacing: -0.02em;
		box-shadow:
			inset 0 1px 0 oklch(82% 0.18 250 / 0.5),
			0 1px 0 oklch(0% 0 0 / 0.4),
			0 12px 36px -10px oklch(60% 0.22 260 / 0.5);
	}
	.setup-brand-name {
		font-family: var(--font-display);
		font-size: 16px;
		font-weight: 600;
		letter-spacing: -0.02em;
	}

	.setup-card {
		width: 100%;
		max-width: 480px; /* slightly wider than /login because the form has 4 fields + an info banner */
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

	.setup-title {
		font-family: var(--font-display);
		font-size: 24px;
		font-weight: 600;
		letter-spacing: -0.025em;
		margin: 0 0 6px;
	}
	.setup-sub {
		color: var(--fg-muted);
		font-size: 13.5px;
		margin: 0 0 18px;
	}

	/* Info banner (token-from-logs note) — cyan accent variant. */
	.setup-info-banner {
		display: flex;
		align-items: flex-start;
		gap: 10px;
		padding: 12px 14px;
		border-radius: var(--radius);
		background: var(--accent-soft);
		border: 1px solid oklch(68% 0.21 255 / 0.3);
		color: var(--fg-muted);
		font-size: 12.5px;
		line-height: 1.5;
		margin-bottom: 20px;
	}
	.setup-info-banner :global(svg) {
		width: 16px;
		height: 16px;
		flex: none;
		margin-top: 1px;
		color: var(--accent);
	}
	.setup-info-banner b {
		color: var(--fg);
		font-weight: 600;
	}
	.setup-info-banner code {
		font-family: var(--font-mono);
		font-size: 12px;
		color: var(--accent);
		padding: 1px 5px;
		background: oklch(13% 0.006 250);
		border-radius: 4px;
		border: 1px solid var(--border);
	}

	/* Error banner — red variant (port of the /login banner). */
	.setup-banner {
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
	.setup-banner :global(svg) {
		width: 16px;
		height: 16px;
		flex: none;
		margin-top: 1px;
	}

	.setup-field {
		display: flex;
		flex-direction: column;
		gap: 6px;
		margin-bottom: 14px;
	}
	.setup-field label {
		font-size: 12.5px;
		color: var(--fg-muted);
	}
	.setup-field label small {
		color: var(--fg-dim);
		font-size: 11.5px;
		font-weight: normal;
	}
	.setup-field-error {
		color: oklch(75% 0.16 25);
		font-size: 11.5px;
	}

	.setup-input-wrap {
		position: relative;
	}
	.setup-input {
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
	.setup-input:hover:not(:disabled) {
		border-color: var(--border-hi);
	}
	.setup-input:focus {
		border-color: var(--accent);
		box-shadow: 0 0 0 3px var(--accent-soft);
		background: oklch(17% 0.006 250);
	}
	.setup-input:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
	.setup-input-mono {
		font-family: var(--font-mono);
		font-size: 12.5px;
		letter-spacing: 0.01em;
	}
	.setup-input-with-toggle {
		padding-right: 42px;
	}

	.setup-pw-toggle {
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
	.setup-pw-toggle:hover {
		color: var(--fg-muted);
		background: var(--surface-2);
	}
	.setup-pw-toggle :global(svg) {
		width: 16px;
		height: 16px;
	}

	.setup-submit {
		width: 100%;
		margin-top: 6px;
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
	.setup-submit:hover:not(:disabled) {
		background: oklch(62% 0.22 255);
	}
	.setup-submit:active:not(:disabled) {
		transform: translateY(1px);
	}
	.setup-submit:disabled {
		opacity: 0.7;
		cursor: not-allowed;
	}
	.setup-spin {
		display: none;
		width: 14px;
		height: 14px;
		border-radius: 50%;
		border: 2px solid oklch(98% 0.005 250 / 0.4);
		border-top-color: #fff;
		animation: setupSpin 0.8s linear infinite;
	}
	.setup-submit.loading .setup-spin {
		display: inline-block;
	}
	.setup-submit.loading .setup-submit-label {
		opacity: 0.85;
	}
	@keyframes setupSpin {
		to {
			transform: rotate(360deg);
		}
	}

	@media (max-width: 640px) {
		.setup-page {
			padding: 80px 14px 18px;
		}
		.setup-topbar {
			top: 18px;
			left: 14px;
			right: 14px;
		}
		.setup-card {
			padding: 26px;
		}
	}
	@media (max-width: 480px) {
		.setup-card {
			padding: 22px;
		}
	}
</style>
