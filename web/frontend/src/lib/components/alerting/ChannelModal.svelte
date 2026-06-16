<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  AL.4.b.2 — Create / edit modal for alerting channels.
  Two kinds: webhook (URL + method + headers + timeout +
  optional templates) and email (SMTP host/port/user/pass +
  From + To/Cc/Bcc + TLS/STARTTLS + optional templates).

  Password preserve-on-omit (J.4 pattern, mirrors backend
  AL.1.b mergeAlertChannelSecrets):
    - Create: password input always editable, required.
    - Edit  : the stored password is rendered as the
      placeholder "[défini]" with a "Modifier le mot de
      passe" checkbox. Unchecked → submit sends "" so the
      backend preserves the stored value. Checked → an
      editable input appears for the operator to type the
      new password.

  Send-test button: fires POST /channels/{id}/test on the
  CURRENTLY-STORED channel (edit mode only — a not-yet-
  persisted draft has no ID). On create the button is
  hidden; the operator can test after first save.
-->
<script lang="ts">
	import {
		alertingApi,
		SEVERITY_TOKENS,
		severityLabelFR,
		type AlertChannel,
		type AlertChannelRequest,
		type ChannelKind,
		type EmailConfig,
		type WebhookConfig
	} from '$lib/api/alerting';
	import { channelsStore } from '$lib/stores/alerting.svelte';
	import { ApiError } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import Modal from '$lib/components/Modal.svelte';
	import Button from '$lib/components/Button.svelte';
	import Input from '$lib/components/Input.svelte';
	import Checkbox from '$lib/components/Checkbox.svelte';

	interface Props {
		open: boolean;
		channel: AlertChannel | null;
		onClose: () => void;
		onSaved: () => void;
	}

	let { open, channel, onClose, onSaved }: Props = $props();

	const isEdit = $derived(channel !== null);

	// --- form state -----------------------------------------

	let name = $state('');
	let enabled = $state(true);
	let kind = $state<ChannelKind>('webhook');
	let minSeverity = $state(0);

	// Webhook fields.
	let webhookUrl = $state('');
	let webhookMethod = $state<'POST'>('POST'); // V1 = POST only
	let webhookTimeout = $state(10);
	let webhookHeaders = $state<{ key: string; value: string }[]>([]);
	let webhookBodyTemplate = $state('');

	// Email fields.
	let smtpHost = $state('');
	let smtpPort = $state(587);
	let smtpUsername = $state('');
	let smtpPassword = $state('');
	let smtpPasswordDirty = $state(false); // true = operator wants to rotate
	let from = $state('');
	let toList = $state<string[]>(['']);
	let ccList = $state<string[]>([]);
	let bccList = $state<string[]>([]);
	let tlsMode = $state<'none' | 'tls' | 'starttls'>('starttls');
	let emailSubjectTemplate = $state('');
	let emailBodyTemplate = $state('');

	let submitting = $state(false);
	let testing = $state(false);
	let validationError = $state('');

	// Reset the form when the modal opens or the target
	// channel changes. The reactive guard means edit-mode
	// pre-populates from the supplied channel; create-mode
	// resets to clean defaults.
	$effect(() => {
		if (!open) return;
		validationError = '';
		if (channel) {
			name = channel.name;
			enabled = channel.enabled;
			kind = channel.kind;
			minSeverity = channel.minSeverity;
			if (channel.kind === 'webhook') {
				const cfg = channel.config as WebhookConfig;
				webhookUrl = cfg.url ?? '';
				webhookMethod = 'POST';
				webhookTimeout = cfg.timeoutSeconds ?? 10;
				webhookHeaders = cfg.headers
					? Object.entries(cfg.headers).map(([key, value]) => ({ key, value }))
					: [];
				webhookBodyTemplate = cfg.bodyTemplate ?? '';
			} else {
				const cfg = channel.config as EmailConfig;
				smtpHost = cfg.smtpHost ?? '';
				smtpPort = cfg.smtpPort ?? 587;
				smtpUsername = cfg.smtpUsername ?? '';
				smtpPassword = '';
				smtpPasswordDirty = false;
				from = cfg.from ?? '';
				toList = cfg.to && cfg.to.length > 0 ? [...cfg.to] : [''];
				ccList = cfg.cc ? [...cfg.cc] : [];
				bccList = cfg.bcc ? [...cfg.bcc] : [];
				if (cfg.useTLS) tlsMode = 'tls';
				else if (cfg.useStartTLS) tlsMode = 'starttls';
				else tlsMode = 'none';
				emailSubjectTemplate = cfg.subjectTemplate ?? '';
				emailBodyTemplate = cfg.bodyTemplate ?? '';
			}
		} else {
			// Create defaults.
			name = '';
			enabled = true;
			kind = 'webhook';
			minSeverity = 0;
			webhookUrl = '';
			webhookMethod = 'POST';
			webhookTimeout = 10;
			webhookHeaders = [];
			webhookBodyTemplate = '';
			smtpHost = '';
			smtpPort = 587;
			smtpUsername = '';
			smtpPassword = '';
			smtpPasswordDirty = true; // required on create
			from = '';
			toList = [''];
			ccList = [];
			bccList = [];
			tlsMode = 'starttls';
			emailSubjectTemplate = '';
			emailBodyTemplate = '';
		}
	});

	// --- dynamic list helpers ----------------------------------

	function addHeader() {
		webhookHeaders = [...webhookHeaders, { key: '', value: '' }];
	}
	function removeHeader(i: number) {
		webhookHeaders = webhookHeaders.filter((_, idx) => idx !== i);
	}

	function addRecipient(list: string[], setter: (next: string[]) => void) {
		setter([...list, '']);
	}
	function removeRecipient(list: string[], i: number, setter: (next: string[]) => void) {
		setter(list.filter((_, idx) => idx !== i));
	}

	// --- validation --------------------------------------------

	function buildRequest(): AlertChannelRequest | null {
		if (!name.trim()) {
			validationError = 'Le nom est requis.';
			return null;
		}
		if (kind === 'webhook') {
			if (!webhookUrl.trim()) {
				validationError = 'L’URL du webhook est requise.';
				return null;
			}
			if (!/^https?:\/\//.test(webhookUrl)) {
				validationError = 'L’URL doit commencer par http:// ou https://.';
				return null;
			}
			if (webhookTimeout < 1 || webhookTimeout > 60) {
				validationError = 'Le timeout doit être compris entre 1 et 60 secondes.';
				return null;
			}
			const headers: Record<string, string> = {};
			for (const h of webhookHeaders) {
				if (h.key.trim() === '') continue;
				headers[h.key.trim()] = h.value;
			}
			const cfg: WebhookConfig = {
				url: webhookUrl.trim(),
				method: 'POST',
				timeoutSeconds: webhookTimeout,
				headers: Object.keys(headers).length > 0 ? headers : undefined,
				bodyTemplate: webhookBodyTemplate.trim() || undefined
			};
			return {
				name: name.trim(),
				kind: 'webhook',
				enabled,
				minSeverity,
				config: cfg
			};
		}
		// email
		if (!smtpHost.trim()) {
			validationError = 'L’hôte SMTP est requis.';
			return null;
		}
		if (smtpPort < 1 || smtpPort > 65535) {
			validationError = 'Le port SMTP doit être compris entre 1 et 65535.';
			return null;
		}
		if (!from.trim() || !from.includes('@')) {
			validationError = 'L’adresse "From" doit être un email valide.';
			return null;
		}
		const tos = toList.map((t) => t.trim()).filter((t) => t !== '');
		if (tos.length === 0) {
			validationError = 'Au moins un destinataire "To" est requis.';
			return null;
		}
		for (const t of tos) {
			if (!t.includes('@')) {
				validationError = `Adresse "${t}" invalide.`;
				return null;
			}
		}
		const cc = ccList.map((t) => t.trim()).filter((t) => t !== '');
		const bcc = bccList.map((t) => t.trim()).filter((t) => t !== '');
		// Password: edit + unchecked → send "" so backend
		// preserves stored value. Otherwise send the typed
		// value (may be empty on create, in which case backend
		// may reject if it's a real SMTP relay).
		const password = !isEdit || smtpPasswordDirty ? smtpPassword : '';
		const cfg: EmailConfig = {
			smtpHost: smtpHost.trim(),
			smtpPort,
			smtpUsername: smtpUsername.trim(),
			smtpPassword: password,
			from: from.trim(),
			to: tos,
			cc: cc.length > 0 ? cc : undefined,
			bcc: bcc.length > 0 ? bcc : undefined,
			useTLS: tlsMode === 'tls',
			useStartTLS: tlsMode === 'starttls',
			subjectTemplate: emailSubjectTemplate.trim() || undefined,
			bodyTemplate: emailBodyTemplate.trim() || undefined
		};
		return {
			name: name.trim(),
			kind: 'email',
			enabled,
			minSeverity,
			config: cfg
		};
	}

	async function onSubmit(e: SubmitEvent) {
		e.preventDefault();
		validationError = '';
		const req = buildRequest();
		if (!req) return;
		submitting = true;
		try {
			if (channel) {
				await channelsStore.update(channel.id, req);
				pushToast(`Canal "${req.name}" enregistré.`, 'success');
			} else {
				await channelsStore.create(req);
				pushToast(`Canal "${req.name}" créé.`, 'success');
			}
			onSaved();
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : 'Erreur réseau';
			validationError = msg;
		} finally {
			submitting = false;
		}
	}

	async function onTest() {
		if (!channel) return;
		testing = true;
		try {
			const res = await alertingApi.testChannel(channel.id);
			if (res.ok) {
				pushToast(`Canal "${channel.name}" testé : envoi réussi.`, 'success');
			} else {
				pushToast(
					`Canal "${channel.name}" : échec — ${res.error ?? 'erreur inconnue'}`,
					'danger'
				);
			}
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : 'Erreur réseau';
			pushToast(`Canal "${channel.name}" : ${msg}`, 'danger');
		} finally {
			testing = false;
		}
	}
</script>

<Modal {open} title={isEdit ? 'Modifier le canal' : 'Ajouter un canal'} {onClose} width="lg">
	<form onsubmit={onSubmit} class="space-y-4">
		<!-- Common fields -->
		<Input bind:value={name} label="Nom" placeholder="ops-webhook" required />

		<div class="flex items-center gap-4">
			<Checkbox bind:checked={enabled} label="Actif" />
		</div>

		<div class="grid grid-cols-2 gap-4">
			<div>
				<label for="channel-kind" class="text-sm font-medium text-secondary mb-1.5 block">
					Type
				</label>
				<select
					id="channel-kind"
					bind:value={kind}
					disabled={isEdit}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary disabled:opacity-50"
				>
					<option value="webhook">Webhook</option>
					<option value="email">Email</option>
				</select>
				{#if isEdit}
					<p class="text-xs text-secondary mt-1">
						Le type ne peut pas être modifié après création.
					</p>
				{/if}
			</div>
			<div>
				<label
					for="channel-severity"
					class="text-sm font-medium text-secondary mb-1.5 block"
				>
					Sévérité min
				</label>
				<select
					id="channel-severity"
					bind:value={minSeverity}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
				>
					{#each SEVERITY_TOKENS as _token, i (i)}
						<option value={i}>{severityLabelFR(i)}</option>
					{/each}
				</select>
			</div>
		</div>

		<hr class="border-border-subtle" />

		<!-- Webhook fields -->
		{#if kind === 'webhook'}
			<Input
				bind:value={webhookUrl}
				label="URL"
				placeholder="https://example.com/hook"
				required
			/>

			<div class="grid grid-cols-2 gap-4">
				<div>
					<label
						for="webhook-method"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						Méthode
					</label>
					<select
						id="webhook-method"
						bind:value={webhookMethod}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					>
						<option value="POST">POST</option>
					</select>
					<p class="text-xs text-secondary mt-1">V1 : POST uniquement.</p>
				</div>
				<div>
					<label
						for="webhook-timeout"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						Timeout (s)
					</label>
					<input
						id="webhook-timeout"
						type="number"
						bind:value={webhookTimeout}
						min="1"
						max="60"
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					/>
				</div>
			</div>

			<div>
				<div class="flex items-center justify-between mb-2">
					<span class="text-sm font-medium text-secondary">En-têtes HTTP</span>
					<Button variant="ghost" size="sm" onclick={addHeader}>
						{#snippet children()}+ Ajouter{/snippet}
					</Button>
				</div>
				{#if webhookHeaders.length === 0}
					<p class="text-xs text-secondary">Aucun en-tête personnalisé.</p>
				{:else}
					<div class="space-y-2">
						{#each webhookHeaders as h, i (i)}
							<div class="flex gap-2 items-start">
								<Input bind:value={h.key} placeholder="X-Auth" />
								<Input
									bind:value={h.value}
									placeholder={isEdit && h.value === '[redacted]'
										? '[redacted] — laissez vide pour conserver'
										: 'valeur'}
								/>
								<Button
									variant="ghost"
									size="sm"
									onclick={() => removeHeader(i)}
									aria-label="Supprimer l’en-tête"
								>
									{#snippet children()}×{/snippet}
								</Button>
							</div>
						{/each}
					</div>
				{/if}
				{#if isEdit}
					<p class="text-xs text-secondary mt-2">
						Les valeurs d’en-tête sont redactées sur l’API. Laissez la valeur affichée
						"[redacted]" telle quelle pour conserver le secret existant.
					</p>
				{/if}
			</div>

			<div>
				<label
					for="webhook-body-template"
					class="text-sm font-medium text-secondary mb-1.5 block"
				>
					Template du corps (optionnel)
				</label>
				<textarea
					id="webhook-body-template"
					bind:value={webhookBodyTemplate}
					rows="3"
					placeholder={`{"text":"[{{.Severity}}] {{.Subject}}"}`}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				></textarea>
				<p class="text-xs text-secondary mt-1">
					Laissez vide pour envoyer l’événement complet en JSON. Placeholders :
					<code>{`{{.RuleName}}`}</code>, <code>{`{{.Severity}}`}</code>,
					<code>{`{{.Subject}}`}</code>.
				</p>
			</div>
		{/if}

		<!-- Email fields -->
		{#if kind === 'email'}
			<div class="grid grid-cols-3 gap-4">
				<div class="col-span-2">
					<Input
						bind:value={smtpHost}
						label="Hôte SMTP"
						placeholder="smtp.example.com"
						required
					/>
				</div>
				<div>
					<label for="smtp-port" class="text-sm font-medium text-secondary mb-1.5 block">
						Port
					</label>
					<input
						id="smtp-port"
						type="number"
						bind:value={smtpPort}
						min="1"
						max="65535"
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					/>
				</div>
			</div>

			<Input
				bind:value={smtpUsername}
				label="Utilisateur SMTP"
				placeholder="alerts@example.com"
			/>

			<div>
				<label
					for="smtp-password"
					class="text-sm font-medium text-secondary mb-1.5 block"
				>
					Mot de passe SMTP
				</label>
				{#if isEdit && !smtpPasswordDirty}
					<div class="flex items-center gap-3">
						<input
							id="smtp-password"
							type="text"
							value="[défini]"
							readonly
							disabled
							class="flex-1 bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-secondary"
						/>
						<Checkbox
							bind:checked={smtpPasswordDirty}
							label="Modifier le mot de passe"
						/>
					</div>
				{:else}
					<input
						id="smtp-password"
						type="password"
						bind:value={smtpPassword}
						placeholder="••••••••"
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					/>
				{/if}
			</div>

			<Input
				bind:value={from}
				label="From"
				type="email"
				placeholder="alerts@example.com"
				required
			/>

			<div>
				<div class="flex items-center justify-between mb-2">
					<span class="text-sm font-medium text-secondary">To</span>
					<Button
						variant="ghost"
						size="sm"
						onclick={() => addRecipient(toList, (n) => (toList = n))}
					>
						{#snippet children()}+ Ajouter{/snippet}
					</Button>
				</div>
				<div class="space-y-2">
					{#each toList as _r, i (i)}
						<div class="flex gap-2 items-start">
							<Input bind:value={toList[i]} placeholder="ops@example.com" />
							{#if toList.length > 1}
								<Button
									variant="ghost"
									size="sm"
									onclick={() =>
										removeRecipient(toList, i, (n) => (toList = n))}
									aria-label="Supprimer le destinataire"
								>
									{#snippet children()}×{/snippet}
								</Button>
							{/if}
						</div>
					{/each}
				</div>
			</div>

			<details>
				<summary class="text-sm text-secondary cursor-pointer">Options avancées</summary>
				<div class="mt-3 space-y-3 pl-2 border-l border-border-subtle">
					<div>
						<div class="flex items-center justify-between mb-2">
							<span class="text-sm font-medium text-secondary">Cc</span>
							<Button
								variant="ghost"
								size="sm"
								onclick={() => addRecipient(ccList, (n) => (ccList = n))}
							>
								{#snippet children()}+ Ajouter{/snippet}
							</Button>
						</div>
						{#each ccList as _r, i (i)}
							<div class="flex gap-2 items-start mb-2">
								<Input bind:value={ccList[i]} placeholder="audit@example.com" />
								<Button
									variant="ghost"
									size="sm"
									onclick={() =>
										removeRecipient(ccList, i, (n) => (ccList = n))}
									aria-label="Supprimer Cc"
								>
									{#snippet children()}×{/snippet}
								</Button>
							</div>
						{/each}
					</div>
					<div>
						<div class="flex items-center justify-between mb-2">
							<span class="text-sm font-medium text-secondary">Bcc</span>
							<Button
								variant="ghost"
								size="sm"
								onclick={() => addRecipient(bccList, (n) => (bccList = n))}
							>
								{#snippet children()}+ Ajouter{/snippet}
							</Button>
						</div>
						{#each bccList as _r, i (i)}
							<div class="flex gap-2 items-start mb-2">
								<Input bind:value={bccList[i]} placeholder="shadow@example.com" />
								<Button
									variant="ghost"
									size="sm"
									onclick={() =>
										removeRecipient(bccList, i, (n) => (bccList = n))}
									aria-label="Supprimer Bcc"
								>
									{#snippet children()}×{/snippet}
								</Button>
							</div>
						{/each}
					</div>
				</div>
			</details>

			<fieldset>
				<legend class="text-sm font-medium text-secondary mb-1.5">Chiffrement</legend>
				<div class="flex gap-4">
					<label class="flex items-center gap-2 text-sm">
						<input type="radio" bind:group={tlsMode} value="none" />
						Aucun
					</label>
					<label class="flex items-center gap-2 text-sm">
						<input type="radio" bind:group={tlsMode} value="starttls" />
						STARTTLS (port 587)
					</label>
					<label class="flex items-center gap-2 text-sm">
						<input type="radio" bind:group={tlsMode} value="tls" />
						TLS implicite (port 465)
					</label>
				</div>
			</fieldset>

			<div>
				<label
					for="email-subject-template"
					class="text-sm font-medium text-secondary mb-1.5 block"
				>
					Template du sujet (optionnel)
				</label>
				<input
					id="email-subject-template"
					bind:value={emailSubjectTemplate}
					placeholder={`[{{.Severity}}] {{.Subject}}`}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
			</div>

			<div>
				<label
					for="email-body-template"
					class="text-sm font-medium text-secondary mb-1.5 block"
				>
					Template du corps (optionnel)
				</label>
				<textarea
					id="email-body-template"
					bind:value={emailBodyTemplate}
					rows="4"
					placeholder={`Règle : {{.RuleName}}\nSévérité : {{.Severity}}\nDétail : {{.Body}}`}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				></textarea>
			</div>
		{/if}

		{#if validationError}
			<div
				class="p-3 rounded bg-down/10 border border-down text-down text-sm"
				role="alert"
			>
				{validationError}
			</div>
		{/if}
	</form>

	{#snippet footer()}
		{#if isEdit}
			<Button
				variant="secondary"
				onclick={onTest}
				disabled={testing || submitting}
				loading={testing}
			>
				{#snippet children()}Envoyer un test{/snippet}
			</Button>
		{/if}
		<Button variant="ghost" onclick={onClose} disabled={submitting}>
			{#snippet children()}Annuler{/snippet}
		</Button>
		<Button
			variant="primary"
			onclick={(e) => onSubmit(e as unknown as SubmitEvent)}
			disabled={submitting}
			loading={submitting}
		>
			{#snippet children()}{isEdit ? 'Enregistrer' : 'Créer'}{/snippet}
		</Button>
	{/snippet}
</Modal>
