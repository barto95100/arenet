<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step K.3 — Backup & Restore section.

  Three operations:

    1. Export (default redacted)  — single click → JSON download.
    2. Export with secrets        — confirm-twice modal, warning
                                   wording about file permissions.
    3. Restore                    — file picker + opt-in checkboxes
                                   for the two bypass flags. The
                                   backend rejects loud on every
                                   failure path; we surface the
                                   reject body verbatim (it carries
                                   the "Two paths forward" wording).
-->
<script lang="ts">
	import { pushToast } from '$lib/stores/toast';
	import { settingsApi, type RestoreReport } from '$lib/api/settings';
	import { ApiError } from '$lib/api/types';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	let confirmIncludeSecretsOpen = $state(false);
	let restoreFile = $state<File | null>(null);
	let allowIncompleteRestore = $state(false);
	let allowEmptyUsers = $state(false);
	let restoreError = $state('');
	let restoreReport = $state<RestoreReport | null>(null);
	let restoreSubmitting = $state(false);

	function exportDefault(): void {
		window.location.href = settingsApi.exportBackupURL(false);
	}

	function exportIncludeSecrets(): void {
		confirmIncludeSecretsOpen = true;
	}

	function confirmIncludeSecretsDownload(): void {
		window.location.href = settingsApi.exportBackupURL(true);
	}

	function onFileChange(e: Event): void {
		const input = e.target as HTMLInputElement;
		restoreFile = input.files && input.files.length > 0 ? input.files[0] : null;
		restoreError = '';
		restoreReport = null;
	}

	async function submitRestore(): Promise<void> {
		if (!restoreFile || restoreSubmitting) return;
		restoreSubmitting = true;
		restoreError = '';
		restoreReport = null;
		try {
			const text = await restoreFile.text();
			const parsed = JSON.parse(text);
			const report = await settingsApi.postRestore(parsed, {
				allowIncompleteRestore,
				allowEmptyUsers
			});
			restoreReport = report;
			pushToast(
				t('backupSection.toastRestoreComplete', { routes: report.routesImported, users: report.usersImported }),
				'success'
			);
		} catch (err) {
			// The backend reject body carries the "Two paths
			// forward" wording verbatim. Surface it as-is.
			if (err instanceof ApiError) {
				restoreError = err.message;
			} else if (err instanceof SyntaxError) {
				restoreError = t('backupSection.errInvalidJson');
			} else if (err instanceof Error) {
				restoreError = err.message;
			} else {
				restoreError = t('backupSection.errUnexpected');
			}
		} finally {
			restoreSubmitting = false;
		}
	}
</script>

<Card padding="p-6">
	<header class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4">
		<div>
			<h2 class="text-xl font-semibold">{language.current && t('backupSection.title')}</h2>
			<p class="text-xs text-muted mt-1">
				{language.current && t('backupSection.subtitle')}
			</p>
		</div>
	</header>

	<div class="space-y-6">
		<section>
			<h3 class="text-base font-semibold text-primary mb-2">{language.current && t('backupSection.exportTitle')}</h3>
			<p class="text-xs text-muted mb-3">
				{language.current && t('backupSection.exportHelper')}
			</p>
			<div class="flex gap-2">
				<Button variant="primary" size="md" onclick={exportDefault}>
					{language.current && t('backupSection.btnExportRedacted')}
				</Button>
				<Button variant="secondary" size="md" onclick={exportIncludeSecrets}>
					{language.current && t('backupSection.btnExportWithSecrets')}
				</Button>
			</div>
		</section>

		<section class="pt-4 border-t border-border-subtle">
			<h3 class="text-base font-semibold text-primary mb-2">{language.current && t('backupSection.restoreTitle')}</h3>
			<p class="text-xs text-muted mb-3">
				{language.current && t('backupSection.restoreHelper')}
			</p>

			<input
				type="file"
				accept="application/json,.json"
				onchange={onFileChange}
				class="block w-full text-sm text-secondary file:mr-3 file:py-2 file:px-3 file:rounded-md file:border-0 file:text-sm file:font-medium file:bg-surface file:text-primary hover:file:bg-hover"
			/>

			<div class="mt-3 space-y-2 text-sm">
				<label class="inline-flex items-center gap-2">
					<input
						type="checkbox"
						bind:checked={allowIncompleteRestore}
						class="rounded border-border-default bg-surface text-cyan focus:ring-cyan"
					/>
					<span>
						<span class="font-medium">{language.current && t('backupSection.allowIncompleteLabel')}</span>
						<span class="text-xs text-muted block">
							{language.current && t('backupSection.allowIncompleteHelper')}
						</span>
					</span>
				</label>
				<label class="inline-flex items-center gap-2">
					<input
						type="checkbox"
						bind:checked={allowEmptyUsers}
						class="rounded border-border-default bg-surface text-cyan focus:ring-cyan"
					/>
					<span>
						<span class="font-medium">{language.current && t('backupSection.allowEmptyUsersLabel')}</span>
						<span class="text-xs text-muted block">
							{language.current && t('backupSection.allowEmptyUsersHelper')}
						</span>
					</span>
				</label>
			</div>

			<div class="mt-4">
				<Button
					variant="danger"
					size="md"
					disabled={!restoreFile || restoreSubmitting}
					onclick={submitRestore}
				>
					{language.current && (restoreSubmitting ? t('backupSection.btnRestoring') : t('backupSection.btnRestore'))}
				</Button>
			</div>

			{#if restoreError}
				<pre
					class="mt-4 p-3 rounded bg-down/10 border border-down text-down text-xs whitespace-pre-wrap font-mono"
					role="alert"
				>{restoreError}</pre>
			{/if}

			{#if restoreReport}
				<dl class="mt-4 grid grid-cols-[14rem_1fr] gap-x-4 gap-y-1 text-xs">
					<dt class="text-secondary">{language.current && t('backupSection.reportRoutesImported')}</dt>
					<dd class="font-mono">{restoreReport.routesImported}</dd>
					<dt class="text-secondary">{language.current && t('backupSection.reportUsersImported')}</dt>
					<dd class="font-mono">{restoreReport.usersImported}</dd>
					<dt class="text-secondary">{language.current && t('backupSection.reportDnsImported')}</dt>
					<dd class="font-mono">{restoreReport.dnsProvidersImported}</dd>
					<dt class="text-secondary">{language.current && t('backupSection.reportForwardAuthImported')}</dt>
					<dd class="font-mono">{restoreReport.forwardAuthProvidersImported}</dd>
					<dt class="text-secondary">{language.current && t('backupSection.reportOidcImported')}</dt>
					<dd class="font-mono">{language.current && (restoreReport.oidcConfigImported ? t('backupSection.yes') : t('backupSection.no'))}</dd>
					<dt class="text-secondary">{language.current && t('backupSection.reportSentinelsInherited')}</dt>
					<dd class="font-mono">{restoreReport.sentinelsInheritedTotal}</dd>
					<dt class="text-secondary">{language.current && t('backupSection.reportSentinelsUnresolved')}</dt>
					<dd class="font-mono">{restoreReport.sentinelsUnresolvedTotal}</dd>
				</dl>
			{/if}
		</section>
	</div>
</Card>

<ConfirmDialog
	bind:open={confirmIncludeSecretsOpen}
	title={language.current && t('backupSection.confirmDialogTitle')}
	message={language.current && t('backupSection.confirmDialogMessage')}
	confirmLabel={language.current && t('backupSection.confirmDialogConfirm')}
	confirmVariant="danger"
	onConfirm={confirmIncludeSecretsDownload}
/>
