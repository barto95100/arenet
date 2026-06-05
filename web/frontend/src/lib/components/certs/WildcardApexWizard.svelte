<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  WildcardApexWizard (Step T T.5, 2026-06-05).

  Modal wizard that packages the pre-T.5 inline "Declare managed
  domain" form into a Modal dialog. Same wire contract (POST
  /api/v1/settings/managed-domains via settingsApi.create-
  ManagedDomain) — no backend changes. The rename to "Politique
  wildcard par apex" lives in the section header and modal title;
  the API surface keeps its frozen v1 vocabulary.

  Satisfies AC #9 ("+ Wildcard apex" wizard) — Step T spec
  v1.2.0-step-t-spec, implemented by 6b03f1c (T.5).

  Stays mounted across show/hide cycles so the parent can keep
  form state via the bindable `open` prop (matches the
  ChangePasswordModal pattern shipped in Chunk 7).

  Behaviour:
    - Click "+ Wildcard apex" (parent) → open=true → modal mounts.
    - Submit "Déclarer" → calls settingsApi.createManagedDomain,
      invokes onCreated() (parent refreshes the list), resets the
      form, closes the modal.
    - Submission error → error message displayed inline inside
      the modal, modal stays open, fields untouched.
    - Cancel / overlay click / Escape → modal closes via the
      Modal primitive's existing focus-trap + onClose contract;
      form state is preserved until the next successful submit
      (operator can re-open and continue where they left off).
-->
<script lang="ts">
	import Modal from '$lib/components/Modal.svelte';
	import Button from '$lib/components/Button.svelte';
	import { settingsApi } from '$lib/api/settings';
	import { ApiError } from '$lib/api/types';
	import type { ManagedDomainProvider } from '$lib/api/types';

	interface Props {
		open: boolean;
		onClose: () => void;
		onCreated?: () => void | Promise<void>;
	}

	let { open, onClose, onCreated }: Props = $props();

	let apex = $state('');
	let provider = $state<ManagedDomainProvider>('ovh');
	let includeApex = $state(true);
	let submitting = $state(false);
	let formError = $state<string | null>(null);

	function close(): void {
		onClose();
	}

	function resetForm(): void {
		apex = '';
		provider = 'ovh';
		includeApex = true;
		formError = null;
	}

	async function handleSubmit(): Promise<void> {
		if (submitting) return;
		const trimmed = apex.trim();
		if (trimmed === '') {
			formError = 'Apex domain is required.';
			return;
		}
		submitting = true;
		formError = null;
		try {
			await settingsApi.createManagedDomain({
				apex: trimmed,
				includeApex,
				provider,
			});
			// onCreated lets the parent refresh the declared-policies
			// list BEFORE we reset/close so the new row is visible
			// the moment the wizard goes away.
			await onCreated?.();
			resetForm();
			close();
		} catch (err) {
			formError = err instanceof ApiError ? err.message : String(err);
		} finally {
			submitting = false;
		}
	}
</script>

<Modal {open} title="Nouvelle politique wildcard" onClose={close}>
	<form
		class="wizard-form"
		data-testid="wildcard-wizard-form"
		onsubmit={(e) => {
			e.preventDefault();
			void handleSubmit();
		}}
	>
		<div class="field field-full">
			<label for="wz-apex">Apex domain</label>
			<input
				id="wz-apex"
				type="text"
				bind:value={apex}
				placeholder="example.com"
				autocomplete="off"
				class="md-input mono"
				disabled={submitting}
				data-testid="wizard-apex-input"
			/>
			<p class="hint">
				Bare domain (no leading <code>*.</code>) — the wildcard is implied.
				Issues a cert for <code>*.{apex || 'example.com'}</code>.
			</p>
		</div>

		<div class="field">
			<label for="wz-provider">DNS provider</label>
			<select
				id="wz-provider"
				bind:value={provider}
				class="md-input"
				disabled={submitting}
			>
				<option value="ovh">OVH</option>
			</select>
		</div>

		<div class="field field-checkbox">
			<input
				id="wz-include-apex"
				type="checkbox"
				bind:checked={includeApex}
				disabled={submitting}
			/>
			<label for="wz-include-apex">Include bare apex in cert SAN</label>
		</div>

		{#if formError}
			<p class="form-error" role="alert" data-testid="wizard-error">
				{formError}
			</p>
		{/if}

		<!-- Hidden submit so Enter inside the apex input still
		     triggers submission. The visible Declare button in the
		     Modal footer also wires to handleSubmit via onclick. -->
		<button type="submit" class="hidden-submit" tabindex="-1" aria-hidden="true"
			>Submit</button
		>
	</form>

	{#snippet footer()}
		<Button variant="ghost" size="md" onclick={close} disabled={submitting}>
			{#snippet children()}Cancel{/snippet}
		</Button>
		<Button
			variant="primary"
			size="md"
			onclick={() => void handleSubmit()}
			loading={submitting}
			disabled={submitting || apex.trim() === ''}
		>
			{#snippet children()}{submitting ? 'Déclaration…' : 'Déclarer'}{/snippet}
		</Button>
	{/snippet}
</Modal>

<style>
	.wizard-form {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 14px;
	}
	.field label {
		display: block;
		color: var(--fg);
		font-size: 12.5px;
		font-weight: 500;
		margin-bottom: 4px;
	}
	.field-full {
		grid-column: 1 / -1;
	}
	.field-checkbox {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-top: 23px;
	}
	.field-checkbox label {
		margin-bottom: 0;
		font-weight: 400;
		color: var(--fg-muted);
	}
	.md-input {
		width: 100%;
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		padding: 8px 10px;
		color: var(--fg);
		font-size: 13px;
		font-family: inherit;
	}
	.md-input.mono {
		font-family: var(--font-mono);
		font-size: 12px;
	}
	.hint {
		font-size: 11.5px;
		color: var(--fg-muted);
		margin: 6px 0 0 0;
	}
	.hint code {
		font-family: var(--font-mono);
		font-size: 11px;
		color: var(--fg);
	}
	.form-error {
		grid-column: 1 / -1;
		color: var(--down);
		font-size: 12.5px;
		margin: 0;
	}
	/* Hidden but functional submit button so pressing Enter inside
	   the apex input fires the form submission. The visible
	   Déclarer button lives in the Modal footer outside the form. */
	.hidden-submit {
		position: absolute;
		left: -9999px;
		width: 1px;
		height: 1px;
		opacity: 0;
		pointer-events: none;
	}
</style>
