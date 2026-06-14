<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Phase 4 — "Créer un service account" modal. Two-stage flow:
    1. Form (name, role, expiry preset) → POST /admin/users
       /service-accounts → success
    2. Reveal stage — render the plain token in a monospace
       box, REQUIRE the operator to press "Copier" before
       enabling "Fermer". The token is shown ONCE; navigating
       away without copying is a meaningful loss (the operator
       would have to rotate to get a new one).

  The token is held in component-local state, never persisted
  beyond the modal lifecycle. Closing the modal nukes the
  reference even if the operator copy/pasted into a password
  manager — the component itself doesn't keep a copy.
-->
<script lang="ts">
	import Modal from './Modal.svelte';
	import Button from './Button.svelte';
	import { settingsApi } from '$lib/api/settings';
	import { pushToast } from '$lib/stores/toast';
	import type { CreateServiceAccountResponse, UserRole } from '$lib/api/types';

	interface Props {
		open: boolean;
		onClose: () => void;
		/**
		 * Called after a successful create so the parent page
		 * can refresh its users list — the new service account
		 * needs to appear in the table without a manual reload.
		 */
		onCreated?: () => void;
	}

	let { open, onClose, onCreated }: Props = $props();

	type ExpiryPreset = '30d' | '90d' | '1y' | 'never';

	let name = $state('');
	let role = $state<UserRole>('viewer');
	let expiry = $state<ExpiryPreset>('never');
	let submitting = $state(false);

	let revealed = $state<CreateServiceAccountResponse | null>(null);
	let copied = $state(false);

	function reset() {
		name = '';
		role = 'viewer';
		expiry = 'never';
		submitting = false;
		revealed = null;
		copied = false;
	}

	function handleClose() {
		// Operator-initiated close OR backdrop click. Reveal stage
		// only allows close once the token has been copied (guarded
		// at the button-disabled level — Modal still honours Esc /
		// backdrop because we can't realistically prevent the user
		// from leaving, only nudge them strongly).
		reset();
		onClose();
	}

	function expiryToISO(preset: ExpiryPreset): string | null {
		if (preset === 'never') return null;
		const d = new Date();
		switch (preset) {
			case '30d':
				d.setDate(d.getDate() + 30);
				break;
			case '90d':
				d.setDate(d.getDate() + 90);
				break;
			case '1y':
				d.setFullYear(d.getFullYear() + 1);
				break;
		}
		return d.toISOString();
	}

	async function submit() {
		const trimmed = name.trim();
		if (!trimmed) {
			pushToast('Nom requis', 'danger');
			return;
		}
		submitting = true;
		try {
			const expiresAt = expiryToISO(expiry);
			const result = await settingsApi.createServiceAccount({
				name: trimmed,
				role,
				expiresAt: expiresAt ?? undefined
			});
			revealed = result;
			onCreated?.();
		} catch (err) {
			const msg = err instanceof Error ? err.message : 'Erreur réseau';
			pushToast(`Échec : ${msg}`, 'danger');
		} finally {
			submitting = false;
		}
	}

	async function copyToken() {
		if (!revealed) return;
		try {
			await navigator.clipboard.writeText(revealed.token);
			copied = true;
			pushToast('Token copié dans le presse-papier', 'success');
		} catch {
			pushToast('Copie échouée — sélectionne le texte manuellement', 'danger');
		}
	}
</script>

<Modal {open} title={revealed ? 'Token API généré' : 'Créer un service account'} onClose={handleClose}>
	{#if !revealed}
		<form
			class="flex flex-col gap-4"
			onsubmit={(e) => {
				e.preventDefault();
				submit();
			}}
		>
			<label class="flex flex-col gap-1 text-sm">
				<span class="text-secondary">Nom</span>
				<input
					type="text"
					bind:value={name}
					placeholder="n8n-prod"
					required
					autocomplete="off"
					pattern="[a-z0-9_-]+"
					title="Lettres minuscules, chiffres, tiret, underscore"
					class="px-2 py-1 rounded-md bg-surface border border-border-default text-primary placeholder-muted outline-none focus:border-accent-cyan"
					data-testid="svc-name-input"
				/>
				<span class="text-xs text-muted">a-z 0-9 _ - · 3-32 caractères</span>
			</label>

			<label class="flex flex-col gap-1 text-sm">
				<span class="text-secondary">Rôle</span>
				<select
					bind:value={role}
					class="px-2 py-1 rounded-md bg-surface border border-border-default text-primary outline-none focus:border-accent-cyan"
					data-testid="svc-role-select"
				>
					<option value="viewer">viewer (lecture seule)</option>
					<option value="admin">admin (CRUD complet)</option>
				</select>
			</label>

			<label class="flex flex-col gap-1 text-sm">
				<span class="text-secondary">Expiration</span>
				<select
					bind:value={expiry}
					class="px-2 py-1 rounded-md bg-surface border border-border-default text-primary outline-none focus:border-accent-cyan"
					data-testid="svc-expiry-select"
				>
					<option value="never">Jamais (set-and-forget)</option>
					<option value="30d">30 jours</option>
					<option value="90d">90 jours</option>
					<option value="1y">1 an</option>
				</select>
			</label>
		</form>
	{:else}
		<div class="flex flex-col gap-3">
			<p class="text-sm">
				Le token est affiché <strong class="text-down">une seule fois</strong>.
				Copie-le maintenant — il ne sera plus jamais récupérable. La rotation
				régénère un nouveau token.
			</p>
			<pre
				class="px-3 py-2 rounded-md bg-surface border border-border-default font-mono text-xs break-all whitespace-pre-wrap select-all"
				data-testid="svc-revealed-token">{revealed.token}</pre>
			<p class="text-xs text-muted">
				Identifiant du token : <code class="font-mono">{revealed.tokenId}</code>
				{#if revealed.expiresAt}
					 · Expire le {new Date(revealed.expiresAt).toLocaleString()}
				{/if}
			</p>
		</div>
	{/if}

	{#snippet footer()}
		{#if !revealed}
			<Button variant="ghost" size="sm" onclick={handleClose}>Annuler</Button>
			<Button
				variant="primary"
				size="sm"
				loading={submitting}
				onclick={submit}
				data-testid="svc-submit-button"
			>
				Créer
			</Button>
		{:else}
			<Button
				variant="secondary"
				size="sm"
				onclick={copyToken}
				data-testid="svc-copy-button"
			>
				{copied ? '✓ Copié' : 'Copier'}
			</Button>
			<Button
				variant="primary"
				size="sm"
				disabled={!copied}
				onclick={handleClose}
				data-testid="svc-close-button"
			>
				Fermer
			</Button>
		{/if}
	{/snippet}
</Modal>
