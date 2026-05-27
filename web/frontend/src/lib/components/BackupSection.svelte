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
				`Restore complete: ${report.routesImported} routes, ${report.usersImported} users imported`,
				'success'
			);
		} catch (err) {
			// The backend reject body carries the "Two paths
			// forward" wording verbatim. Surface it as-is.
			if (err instanceof ApiError) {
				restoreError = err.message;
			} else if (err instanceof SyntaxError) {
				restoreError = 'Invalid JSON in selected file.';
			} else if (err instanceof Error) {
				restoreError = err.message;
			} else {
				restoreError = 'Unexpected error during restore.';
			}
		} finally {
			restoreSubmitting = false;
		}
	}
</script>

<Card padding="p-6">
	<header class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4">
		<div>
			<h2 class="text-xl font-semibold">Backup &amp; restore</h2>
			<p class="text-xs text-muted mt-1">
				Export the entire Arenet configuration as JSON, or restore
				from a previously-exported file.
			</p>
		</div>
	</header>

	<div class="space-y-6">
		<section>
			<h3 class="text-base font-semibold text-primary mb-2">Export</h3>
			<p class="text-xs text-muted mb-3">
				Default export redacts secrets (admin password hashes, OVH
				keys, OIDC client secret, forward-auth client secrets,
				per-route Basic Auth hashes). Use "Include secrets" only
				for disaster-recovery archives that you can store
				securely.
			</p>
			<div class="flex gap-2">
				<Button variant="primary" size="md" onclick={exportDefault}>
					Export (redacted)
				</Button>
				<Button variant="secondary" size="md" onclick={exportIncludeSecrets}>
					Export with secrets…
				</Button>
			</div>
		</section>

		<section class="pt-4 border-t border-border-subtle">
			<h3 class="text-base font-semibold text-primary mb-2">Restore</h3>
			<p class="text-xs text-muted mb-3">
				Choose a previously-exported file. The restore is
				all-or-nothing: any validation failure aborts before any
				change is written to storage.
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
						<span class="font-medium">Allow incomplete restore</span>
						<span class="text-xs text-muted block">
							Sentinels that can't inherit from this instance will
							be cleared. Affected secrets need to be re-saved.
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
						<span class="font-medium">Allow empty users</span>
						<span class="text-xs text-muted block">
							Accept a backup with zero users; the next boot will
							re-trigger the setup-token flow.
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
					{restoreSubmitting ? 'Restoring…' : 'Restore'}
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
					<dt class="text-secondary">Routes imported</dt>
					<dd class="font-mono">{restoreReport.routesImported}</dd>
					<dt class="text-secondary">Users imported</dt>
					<dd class="font-mono">{restoreReport.usersImported}</dd>
					<dt class="text-secondary">DNS providers imported</dt>
					<dd class="font-mono">{restoreReport.dnsProvidersImported}</dd>
					<dt class="text-secondary">Forward-auth providers imported</dt>
					<dd class="font-mono">{restoreReport.forwardAuthProvidersImported}</dd>
					<dt class="text-secondary">OIDC config imported</dt>
					<dd class="font-mono">{restoreReport.oidcConfigImported ? 'yes' : 'no'}</dd>
					<dt class="text-secondary">Sentinels inherited</dt>
					<dd class="font-mono">{restoreReport.sentinelsInheritedTotal}</dd>
					<dt class="text-secondary">Sentinels unresolved (cleared)</dt>
					<dd class="font-mono">{restoreReport.sentinelsUnresolvedTotal}</dd>
				</dl>
			{/if}
		</section>
	</div>
</Card>

<ConfirmDialog
	bind:open={confirmIncludeSecretsOpen}
	title="Export with cleartext secrets?"
	message="The exported file will contain plaintext admin password hashes, OVH API keys, OIDC client secret, forward-auth client secrets, and per-route Basic Auth hashes. The browser will save the file with its default permissions — store it to a restricted location and consider encrypting at rest (age / GPG / vault)."
	confirmLabel="Download with secrets"
	confirmVariant="danger"
	onConfirm={confirmIncludeSecretsDownload}
/>
