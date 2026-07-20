<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  ExternalCertsPanel (v2.19.0 external-certs SOCLE, Task 7).

  Bring-your-own-certificate surface for /certs. Self-contained: owns
  its own data load, upload form, list table, and delete/blocked
  dialogs, so the parent /certs page mounts it as a single card without
  threading state through.

  Sections:
    - Upload form: name (+ optional description) + 3 textareas
      (cert / chain / key PEM) + Upload button. On success the returned
      non-blocking `warnings` render as an inline notice.
    - List: one row per uploaded cert (name, subject/issuer, DNS names,
      expiry) with an expiry BADGE — amber when < 30 days to notAfter,
      red when < 7 days (or already expired). The backend returns the
      list already sorted soonest-first (notAfter ascending); the panel
      preserves that order verbatim — no client re-sort.
    - Delete: a confirm dialog whose copy is explicit that removal is
      Arenet-local and does NOT revoke the cert with the issuing CA.
      A 409 opens a blocked dialog listing the offending routes.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import Modal from '$lib/components/Modal.svelte';
	import Button from '$lib/components/Button.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import { externalCertsApi } from '$lib/api/external-certs';
	import type { ExternalCertificate, CertWarning } from '$lib/api/external-certs';
	import { ApiError } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { pushToast } from '$lib/stores/toast';

	// Expiry-badge thresholds (days-to-notAfter). Amber inside the
	// warning window, red inside the danger window OR already expired.
	const EXPIRY_WARN_DAYS = 30;
	const EXPIRY_DANGER_DAYS = 7;

	let loading = $state(true);
	let loadError = $state(false);
	let certs = $state<ExternalCertificate[]>([]);

	// Upload form state.
	let name = $state('');
	let description = $state('');
	let certPEM = $state('');
	let chainPEM = $state('');
	let keyPEM = $state('');
	let uploading = $state(false);
	let uploadError = $state<string | null>(null);
	// Set only for the chain_specified_twice case, so the same friendly
	// message can ALSO render inline next to the Chain field (Fix B) in
	// addition to the bottom form-error (Fix A). Cleared alongside
	// uploadError.
	let uploadErrorCode = $state<string | null>(null);
	// Non-blocking advisories from the most recent successful upload.
	// Cleared on the next upload attempt / form reset.
	let lastWarnings = $state<CertWarning[]>([]);

	// Backend validation-400 codes (external_cert_parse.go) mapped to
	// friendly, translated messages. The wire format is
	// "code: human detail" (English, technical) — split on the first
	// ": " and look up the leading token here. Unmapped codes fall back
	// to the raw backend message so unknown errors are never hidden.
	const UPLOAD_ERROR_CODE_KEYS: Record<string, string> = {
		chain_specified_twice: 'certificates.external.upload.errors.chainSpecifiedTwice',
		key_does_not_match_cert: 'certificates.external.upload.errors.keyDoesNotMatchCert',
		invalid_cert_pem: 'certificates.external.upload.errors.invalidCertPem',
		invalid_chain_pem: 'certificates.external.upload.errors.invalidChainPem',
		cert_required: 'certificates.external.upload.errors.certRequired',
		key_required: 'certificates.external.upload.errors.keyRequired'
	};

	/**
	 * Extracts the leading "code" token from a backend error message
	 * ("code: human detail") and resolves it to a friendly translated
	 * string via UPLOAD_ERROR_CODE_KEYS. Returns the raw message
	 * unchanged (and a null code) when the message doesn't match a
	 * known code, so unrecognized errors are still shown, not hidden.
	 */
	function resolveUploadError(rawMessage: string): { message: string; code: string | null } {
		const sep = rawMessage.indexOf(': ');
		const code = sep === -1 ? rawMessage : rawMessage.slice(0, sep);
		const key = UPLOAD_ERROR_CODE_KEYS[code];
		if (key) {
			return { message: t(key), code };
		}
		return { message: rawMessage, code: null };
	}

	// Delete-dialog state. deleteTarget holds the cert awaiting
	// confirmation; blockedDialog holds the 409 outcome (the routes
	// still referencing the cert) so the operator knows what to clear.
	let deleteTarget = $state<ExternalCertificate | null>(null);
	let blockedDialog = $state<{ name: string; routes: string[] } | null>(null);

	const canSubmit = $derived(
		name.trim() !== '' && certPEM.trim() !== '' && keyPEM.trim() !== '' && !uploading
	);

	/**
	 * Whole days until notAfter (negative once expired). Returns null
	 * for an unparseable / missing timestamp so the badge can render a
	 * neutral placeholder instead of NaN.
	 */
	function daysUntil(notAfter: string): number | null {
		const ts = Date.parse(notAfter);
		if (Number.isNaN(ts)) return null;
		return Math.floor((ts - Date.now()) / 86_400_000);
	}

	/** Badge variant per the expiry thresholds. */
	function expiryVariant(
		days: number | null
	): 'status-up' | 'status-warn' | 'status-down' | 'neutral' {
		if (days === null) return 'neutral';
		if (days <= EXPIRY_DANGER_DAYS) return 'status-down';
		if (days <= EXPIRY_WARN_DAYS) return 'status-warn';
		return 'status-up';
	}

	async function loadCerts(): Promise<void> {
		try {
			// The backend returns the list already sorted by notAfter
			// ascending (soonest-first). Assign verbatim — NO re-sort.
			certs = await externalCertsApi.list();
			loadError = false;
		} catch {
			certs = [];
			loadError = true;
		} finally {
			loading = false;
		}
	}

	function resetForm(): void {
		name = '';
		description = '';
		certPEM = '';
		chainPEM = '';
		keyPEM = '';
		uploadError = null;
		uploadErrorCode = null;
	}

	async function handleUpload(): Promise<void> {
		if (uploading) return;
		if (name.trim() === '' || certPEM.trim() === '' || keyPEM.trim() === '') {
			uploadError = t('certificates.external.upload.requiredError');
			uploadErrorCode = null;
			return;
		}
		uploading = true;
		uploadError = null;
		uploadErrorCode = null;
		lastWarnings = [];
		try {
			const created = await externalCertsApi.upload({
				name: name.trim(),
				description: description.trim() || undefined,
				certPEM: certPEM.trim(),
				keyPEM: keyPEM.trim(),
				chainPEM: chainPEM.trim() || undefined
			});
			lastWarnings = created.warnings ?? [];
			pushToast(t('certificates.external.upload.success', { name: created.name }), 'success');
			resetForm();
			await loadCerts();
		} catch (err) {
			const rawMessage = err instanceof ApiError ? err.message : String(err);
			const resolved = resolveUploadError(rawMessage);
			uploadError = resolved.message;
			uploadErrorCode = resolved.code;
		} finally {
			uploading = false;
		}
	}

	async function confirmDelete(): Promise<void> {
		const target = deleteTarget;
		if (!target) return;
		try {
			await externalCertsApi.remove(target.id);
			pushToast(
				t('certificates.external.delete.success', { name: target.name }),
				'success'
			);
			deleteTarget = null;
			await loadCerts();
		} catch (err) {
			deleteTarget = null;
			const e = err as { status?: number; blockingRoutes?: string[]; message?: string };
			if (e?.status === 409) {
				blockedDialog = { name: target.name, routes: e.blockingRoutes ?? [] };
			} else {
				pushToast(e?.message ?? t('certificates.external.delete.action'), 'danger');
			}
		}
	}

	onMount(() => {
		void loadCerts();
	});
</script>

<div class="card" data-testid="external-certs-card">
	<div class="card-h">
		<h3>{language.current && t('certificates.external.title')}</h3>
	</div>

	<p class="section-lead">
		{language.current && t('certificates.external.lead')}
	</p>

	<!-- Upload form -->
	<form
		class="upload-form"
		data-testid="external-cert-upload-form"
		onsubmit={(e) => {
			e.preventDefault();
			void handleUpload();
		}}
	>
		<div class="field">
			<label for="ext-name">{language.current && t('certificates.external.upload.nameLabel')}</label>
			<input
				id="ext-name"
				type="text"
				bind:value={name}
				autocomplete="off"
				class="ext-input"
				disabled={uploading}
				data-testid="external-cert-name"
			/>
		</div>
		<div class="field">
			<label for="ext-desc"
				>{language.current && t('certificates.external.upload.descriptionLabel')}</label
			>
			<input
				id="ext-desc"
				type="text"
				bind:value={description}
				autocomplete="off"
				class="ext-input"
				disabled={uploading}
				data-testid="external-cert-description"
			/>
		</div>

		<div class="field field-full">
			<label for="ext-cert">{language.current && t('certificates.external.upload.certLabel')}</label>
			<textarea
				id="ext-cert"
				bind:value={certPEM}
				rows="5"
				class="ext-input mono"
				placeholder="-----BEGIN CERTIFICATE-----"
				spellcheck="false"
				disabled={uploading}
				data-testid="external-cert-cert-pem"
			></textarea>
			<p class="field-help">{language.current && t('certificates.external.upload.certHelp')}</p>
		</div>

		<div class="field field-full">
			<label for="ext-chain"
				>{language.current && t('certificates.external.upload.chainLabel')}</label
			>
			<textarea
				id="ext-chain"
				bind:value={chainPEM}
				rows="4"
				class="ext-input mono"
				placeholder="-----BEGIN CERTIFICATE-----"
				spellcheck="false"
				disabled={uploading}
				data-testid="external-cert-chain-pem"
			></textarea>
			<p class="field-help">{language.current && t('certificates.external.upload.chainHelp')}</p>
			{#if uploadErrorCode === 'chain_specified_twice'}
				<p
					class="form-error field-error-inline"
					role="alert"
					data-testid="external-cert-chain-error-inline"
				>
					{uploadError}
				</p>
			{/if}
		</div>

		<div class="field field-full">
			<label for="ext-key">{language.current && t('certificates.external.upload.keyLabel')}</label>
			<textarea
				id="ext-key"
				bind:value={keyPEM}
				rows="5"
				class="ext-input mono"
				placeholder="-----BEGIN PRIVATE KEY-----"
				spellcheck="false"
				disabled={uploading}
				data-testid="external-cert-key-pem"
			></textarea>
			<p class="field-help">{language.current && t('certificates.external.upload.keyHelp')}</p>
		</div>

		{#if uploadError}
			<p class="form-error" role="alert" data-testid="external-cert-upload-error">
				{uploadError}
			</p>
		{/if}

		<div class="form-actions">
			<Button
				variant="primary"
				size="sm"
				type="submit"
				loading={uploading}
				disabled={!canSubmit}
				data-testid="external-cert-upload-btn"
			>
				{#snippet children()}{language.current &&
					(uploading
						? t('certificates.external.upload.submitting')
						: t('certificates.external.upload.submit'))}{/snippet}
			</Button>
		</div>
	</form>

	<!-- Post-upload warnings notice (non-blocking advisories) -->
	{#if lastWarnings.length > 0}
		<div class="warn-box" role="status" data-testid="external-cert-warnings">
			<strong>{language.current && t('certificates.external.upload.warningsTitle')}</strong>
			<ul>
				{#each lastWarnings as w (w.code)}
					<li data-testid="external-cert-warning">{w.message}</li>
				{/each}
			</ul>
		</div>
	{/if}

	<!-- List -->
	{#if loading}
		<div class="loading-wrap"><Spinner /></div>
	{:else if loadError}
		<div class="empty-row" data-testid="external-certs-error">
			{language.current && t('certificates.external.loadError')}
		</div>
	{:else if certs.length === 0}
		<div class="empty-row" data-testid="external-certs-empty">
			{language.current && t('certificates.external.empty')}
		</div>
	{:else}
		<table data-testid="external-certs-table">
			<thead>
				<tr>
					<th>{language.current && t('certificates.external.colName')}</th>
					<th>{language.current && t('certificates.external.colSubject')}</th>
					<th>{language.current && t('certificates.external.colDNS')}</th>
					<th>{language.current && t('certificates.external.colExpiry')}</th>
					<th class="col-actions"
						><span class="visually-hidden"
							>{language.current && t('certificates.external.delete.action')}</span
						></th
					>
				</tr>
			</thead>
			<tbody>
				{#each certs as cert (cert.id)}
					{@const days = daysUntil(cert.notAfter)}
					<tr data-testid="external-cert-row" data-id={cert.id}>
						<td>
							<div class="name-cell">{cert.name}</div>
							{#if cert.description}
								<div class="dim cell-sub">{cert.description}</div>
							{/if}
						</td>
						<td>
							<div class="mono">{cert.subject || '—'}</div>
							<div class="dim cell-sub">{cert.issuer || '—'}</div>
						</td>
						<td class="mono">
							{(cert.dnsNames ?? []).length > 0 ? (cert.dnsNames ?? []).join(', ') : '—'}
						</td>
						<td>
							<Badge variant={expiryVariant(days)}>
								{#if days === null}
									—
								{:else if days <= 0}
									{language.current && t('certificates.external.expiryExpired')}
								{:else}
									{language.current &&
										t('certificates.external.expiryDays', {
											days,
											plural: days === 1 ? '' : 's'
										})}
								{/if}
							</Badge>
						</td>
						<td class="col-actions">
							<button
								type="button"
								class="row-delete-btn"
								data-testid={`external-cert-delete-${cert.id}`}
								aria-label={language.current && t('certificates.external.delete.action')}
								onclick={() => (deleteTarget = cert)}
							>
								{language.current && t('certificates.external.delete.action')}
							</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
</div>

<!-- Delete confirm dialog. Copy is explicit that removal is Arenet-
     local and does NOT revoke the cert with the issuing CA. -->
{#if deleteTarget}
	<Modal
		open={deleteTarget !== null}
		title={language.current && t('certificates.external.delete.confirm.title')}
		onClose={() => (deleteTarget = null)}
	>
		{#snippet children()}
			<p class="modal-lead">
				{language.current &&
					t('certificates.external.delete.confirm.text', { name: deleteTarget?.name ?? '' })}
			</p>
			<p class="modal-warn" role="alert" data-testid="external-cert-revoke-notice">
				{language.current && t('certificates.external.delete.confirm.revokeNotice')}
			</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (deleteTarget = null)}>
				{#snippet children()}{language.current && t('common.cancel')}{/snippet}
			</Button>
			<Button
				variant="danger"
				data-testid="external-cert-delete-confirm"
				onclick={() => void confirmDelete()}
			>
				{#snippet children()}{language.current &&
					t('certificates.external.delete.confirm.action')}{/snippet}
			</Button>
		{/snippet}
	</Modal>
{/if}

<!-- Blocked-delete dialog. Surfaces the 409 outcome: the cert is still
     referenced by one or more routes, listed verbatim so the operator
     knows what to clear first. -->
{#if blockedDialog}
	<Modal
		open={blockedDialog !== null}
		title={language.current && t('certificates.external.delete.blocked.title')}
		onClose={() => (blockedDialog = null)}
	>
		{#snippet children()}
			<p class="modal-lead" role="alert" data-testid="external-cert-blocked-text">
				{language.current &&
					t('certificates.external.delete.blocked.text', {
						name: blockedDialog?.name ?? '',
						routes: (blockedDialog?.routes ?? []).join(', ')
					})}
			</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (blockedDialog = null)}>
				{#snippet children()}{language.current && t('common.confirm')}{/snippet}
			</Button>
		{/snippet}
	</Modal>
{/if}

<style>
	.card {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 14px 16px;
		margin-bottom: 14px;
	}
	.card-h {
		display: flex;
		align-items: center;
		gap: 12px;
		margin-bottom: 12px;
	}
	.card-h h3 {
		color: var(--fg);
		font-size: 13.5px;
		font-weight: 500;
		margin: 0;
	}
	.section-lead {
		color: var(--fg-muted);
		font-size: 12.5px;
		line-height: 1.55;
		margin: 0 0 12px 0;
	}

	.upload-form {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 12px;
		margin-bottom: 12px;
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
	.field-help {
		margin: 4px 0 0;
		color: var(--fg-muted);
		font-size: 11.5px;
		line-height: 1.45;
	}
	.ext-input {
		width: 100%;
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		padding: 8px 10px;
		color: var(--fg);
		font-size: 13px;
		font-family: inherit;
	}
	.ext-input.mono {
		font-family: var(--font-mono);
		font-size: 11.5px;
		resize: vertical;
		line-height: 1.4;
	}
	.form-error {
		grid-column: 1 / -1;
		color: var(--status-down);
		font-size: 12.5px;
		margin: 0;
	}
	.field-error-inline {
		margin-top: 6px;
	}
	.form-actions {
		grid-column: 1 / -1;
		display: flex;
		justify-content: flex-end;
	}

	.warn-box {
		margin-bottom: 12px;
		padding: 10px 12px;
		background: color-mix(in oklch, var(--status-warn) 10%, transparent);
		border: 1px solid color-mix(in oklch, var(--status-warn) 32%, transparent);
		border-radius: var(--radius-sm);
		color: var(--fg);
		font-size: 12.5px;
		line-height: 1.5;
	}
	.warn-box ul {
		margin: 6px 0 0 0;
		padding-left: 18px;
	}
	.warn-box li {
		margin-top: 2px;
	}

	table {
		width: 100%;
		border-collapse: collapse;
		font-size: 12.5px;
	}
	th,
	td {
		padding: 8px 10px;
		text-align: left;
		vertical-align: top;
	}
	th {
		color: var(--fg-muted);
		font-weight: 500;
		font-size: 11px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		border-bottom: 1px solid var(--border);
	}
	td {
		color: var(--fg);
		border-bottom: 1px solid var(--border);
	}
	tbody tr:last-child td {
		border-bottom: none;
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 12px;
		word-break: break-all;
	}
	.dim {
		color: var(--fg-dim);
	}
	.name-cell {
		font-weight: 500;
	}
	.cell-sub {
		font-size: 11px;
		margin-top: 3px;
	}

	.empty-row {
		color: var(--fg-muted);
		font-size: 12.5px;
		padding: 24px;
		text-align: center;
	}
	.loading-wrap {
		display: flex;
		justify-content: center;
		padding: 32px;
	}

	.modal-lead {
		color: var(--fg-muted);
		font-size: 12.5px;
		margin: 0 0 12px 0;
	}
	.modal-warn {
		padding: 8px 12px;
		background: color-mix(in oklch, var(--status-warn) 10%, transparent);
		border: 1px solid color-mix(in oklch, var(--status-warn) 30%, transparent);
		border-radius: var(--radius-sm);
		color: var(--fg);
		font-size: 12.5px;
		margin: 0;
	}

	.col-actions {
		width: 1%;
		white-space: nowrap;
		text-align: right;
	}
	.row-delete-btn {
		appearance: none;
		background: transparent;
		border: 1px solid var(--border);
		color: var(--fg-muted);
		font-size: 11px;
		font-family: inherit;
		padding: 4px 10px;
		border-radius: var(--radius-sm);
		cursor: pointer;
		transition:
			color var(--motion-fast, 120ms),
			background var(--motion-fast, 120ms),
			border-color var(--motion-fast, 120ms);
	}
	.row-delete-btn:hover {
		color: var(--status-down);
		border-color: var(--status-down);
		background: color-mix(in oklch, var(--status-down) 8%, transparent);
	}
	.row-delete-btn:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}
	.visually-hidden {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		white-space: nowrap;
		border: 0;
	}
</style>
