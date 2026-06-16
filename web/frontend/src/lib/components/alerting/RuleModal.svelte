<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  AL.4.b.3 — Create / edit modal for alerting rules. Three
  dynamic sub-forms:
    1. SourceParams form, switched on the operator's Source
       choice (waf_event_rate / cert_expiry / system_health).
    2. EvalParams form, switched on the Kind choice
       (threshold / state).
    3. Channels multi-select (mandatory min 1, enforced
       client-side AND server-side via AL.3b's validator).

  Source picker is hardcoded V1 per brief D5 — the registry
  is static at boot and exposing it via an endpoint would be
  zero ergonomic gain.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import {
		alertingApi,
		SEVERITY_TOKENS,
		severityLabelFR,
		type AlertRule,
		type AlertRuleRequest,
		type AlertRuleTestResponse,
		type RuleKind
	} from '$lib/api/alerting';
	import { rulesStore, channelsStore } from '$lib/stores/alerting.svelte';
	import { listRoutes } from '$lib/api/client';
	import { ApiError } from '$lib/api/types';
	import type { Route } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import Modal from '$lib/components/Modal.svelte';
	import Button from '$lib/components/Button.svelte';
	import Input from '$lib/components/Input.svelte';
	import Checkbox from '$lib/components/Checkbox.svelte';

	interface Props {
		open: boolean;
		rule: AlertRule | null;
		onClose: () => void;
		onSaved: () => void;
	}

	let { open, rule, onClose, onSaved }: Props = $props();

	const isEdit = $derived(rule !== null);

	// --- supported sources / kinds ----------------------------

	type SourceName = 'waf_event_rate' | 'cert_expiry' | 'system_health';
	const SOURCES: { value: SourceName; label: string }[] = [
		{ value: 'waf_event_rate', label: 'Taux d’événements WAF' },
		{ value: 'cert_expiry', label: 'Expiration de certificat' },
		{ value: 'system_health', label: 'État système' }
	];

	const HEALTH_COMPONENTS: { value: string; label: string }[] = [
		{ value: '', label: 'Global (toute la santé système)' },
		{ value: 'caddy', label: 'Caddy' },
		{ value: 'boltdb', label: 'BoltDB' },
		{ value: 'metrics', label: 'Métriques' },
		{ value: 'crowdsec', label: 'CrowdSec' },
		{ value: 'certmagic', label: 'Certmagic' }
	];

	const OPERATORS = ['>', '>=', '<', '<=', '==', '!='] as const;
	type Operator = (typeof OPERATORS)[number];

	// --- common form state ------------------------------------

	let name = $state('');
	let enabled = $state(true);
	let category = $state('');
	let severity = $state(1);
	let kind = $state<RuleKind>('threshold');
	let source = $state<SourceName>('waf_event_rate');
	let channelIds = $state<string[]>([]);
	let cooldownSecs = $state(300);
	let subjectTemplate = $state('');
	let bodyTemplate = $state('');

	// --- source-specific fields -------------------------------

	// waf_event_rate
	let wafRouteId = $state('');
	let wafWindowSecs = $state(300);
	let wafAction = $state<'' | 'BLOCK' | 'DETECT'>('');

	// cert_expiry
	let certHost = $state('');
	// The seuil-en-jours number is stored on the rule's
	// EvalParams (threshold), not on SourceParams. We surface
	// it inline in the SourceParams form for UX convenience
	// when kind=threshold + source=cert_expiry; on submit we
	// route it into EvalParams.value with operator "<".
	// When kind=state or source != cert_expiry this state is
	// ignored.

	// system_health
	let healthComponent = $state('');

	// --- eval-specific fields ---------------------------------

	// threshold
	let thresholdOp = $state<Operator>('>');
	let thresholdValue = $state(50);

	// state
	let stateExpected = $state('degraded');

	// --- async deps -------------------------------------------

	let routes = $state<Route[]>([]);
	let routesLoaded = $state(false);

	const availableChannels = $derived(
		channelsStore.state.channels.filter((c) => c.enabled)
	);

	let submitting = $state(false);
	let testing = $state(false);
	let validationError = $state('');
	let testResultLine = $state(''); // inline result of "Tester la règle"

	onMount(() => {
		// Load both lookups in parallel; failures are non-fatal.
		void channelsStore.load();
		void listRoutes()
			.then((rs) => {
				routes = rs;
				routesLoaded = true;
			})
			.catch(() => {
				routesLoaded = true;
			});
	});

	// Reset / pre-populate when the modal opens or the
	// target rule changes.
	$effect(() => {
		if (!open) return;
		validationError = '';
		testResultLine = '';
		if (rule) {
			name = rule.name;
			enabled = rule.enabled;
			category = rule.category;
			severity = rule.severity;
			kind = rule.kind;
			source = (rule.source as SourceName) ?? 'waf_event_rate';
			channelIds = [...rule.channels];
			cooldownSecs = rule.cooldownSecs;
			subjectTemplate = rule.subjectTemplate ?? '';
			bodyTemplate = rule.bodyTemplate ?? '';

			// Decode source-specific params.
			const sp = (rule.sourceParams ?? {}) as Record<string, unknown>;
			if (source === 'waf_event_rate') {
				wafRouteId = typeof sp.routeId === 'string' ? sp.routeId : '';
				wafWindowSecs = typeof sp.windowSecs === 'number' ? sp.windowSecs : 300;
				wafAction = (sp.action as '' | 'BLOCK' | 'DETECT') ?? '';
			} else if (source === 'cert_expiry') {
				certHost = typeof sp.host === 'string' ? sp.host : '';
			} else if (source === 'system_health') {
				healthComponent = typeof sp.component === 'string' ? sp.component : '';
			}

			// Decode eval-specific params.
			const ep = (rule.evalParams ?? {}) as Record<string, unknown>;
			if (kind === 'threshold') {
				thresholdOp = (ep.operator as Operator) ?? '>';
				thresholdValue = typeof ep.value === 'number' ? ep.value : 50;
			} else if (kind === 'state') {
				stateExpected = typeof ep.expected === 'string' ? ep.expected : 'degraded';
			}
		} else {
			// Create defaults.
			name = '';
			enabled = true;
			category = '';
			severity = 1;
			kind = 'threshold';
			source = 'waf_event_rate';
			channelIds = [];
			cooldownSecs = 300;
			subjectTemplate = '';
			bodyTemplate = '';
			wafRouteId = '';
			wafWindowSecs = 300;
			wafAction = '';
			certHost = '';
			healthComponent = '';
			thresholdOp = '>';
			thresholdValue = 50;
			stateExpected = 'degraded';
		}
	});

	// --- channel toggle ---------------------------------------

	function toggleChannel(id: string, on: boolean) {
		if (on) {
			if (!channelIds.includes(id)) {
				channelIds = [...channelIds, id];
			}
		} else {
			channelIds = channelIds.filter((cid) => cid !== id);
		}
	}

	function isChannelSelected(id: string): boolean {
		return channelIds.includes(id);
	}

	// --- formatting helpers -----------------------------------

	function cooldownFormatted(secs: number): string {
		if (secs < 60) return `${secs} secondes`;
		if (secs < 3600) {
			const m = Math.floor(secs / 60);
			const s = secs % 60;
			return s === 0 ? `${m} minute${m > 1 ? 's' : ''}` : `${m} min ${s} s`;
		}
		const h = Math.floor(secs / 3600);
		const m = Math.floor((secs % 3600) / 60);
		return m === 0 ? `${h} heure${h > 1 ? 's' : ''}` : `${h} h ${m} min`;
	}

	// --- build request from form state ------------------------

	function buildSourceParams(): Record<string, unknown> {
		switch (source) {
			case 'waf_event_rate': {
				const p: Record<string, unknown> = { windowSecs: wafWindowSecs };
				if (wafRouteId) p.routeId = wafRouteId;
				if (wafAction) p.action = wafAction;
				return p;
			}
			case 'cert_expiry': {
				const p: Record<string, unknown> = {};
				if (certHost.trim()) p.host = certHost.trim();
				return p;
			}
			case 'system_health': {
				const p: Record<string, unknown> = {};
				if (healthComponent) p.component = healthComponent;
				return p;
			}
		}
	}

	function buildEvalParams(): Record<string, unknown> {
		if (kind === 'threshold') {
			return { operator: thresholdOp, value: thresholdValue };
		}
		return { expected: stateExpected };
	}

	function buildRequest(): AlertRuleRequest | null {
		if (!name.trim()) {
			validationError = 'Le nom est requis.';
			return null;
		}
		if (!/^[a-z0-9-]{1,64}$/.test(name.trim())) {
			validationError =
				'Le nom doit être en minuscules, alphanumérique et tirets uniquement (1-64 caractères).';
			return null;
		}
		if (cooldownSecs < 30 || cooldownSecs > 86400) {
			validationError = 'Le cooldown doit être compris entre 30 secondes et 24 heures.';
			return null;
		}
		if (channelIds.length === 0) {
			validationError = 'Sélectionnez au moins un canal.';
			return null;
		}
		if (kind === 'threshold') {
			if (!OPERATORS.includes(thresholdOp)) {
				validationError = `Opérateur ${thresholdOp} non supporté.`;
				return null;
			}
			if (!Number.isFinite(thresholdValue)) {
				validationError = 'La valeur seuil doit être numérique.';
				return null;
			}
		} else if (kind === 'state') {
			if (!stateExpected.trim()) {
				validationError = 'La valeur attendue ne peut pas être vide.';
				return null;
			}
		}
		if (source === 'waf_event_rate') {
			if (wafWindowSecs < 60 || wafWindowSecs > 86400) {
				validationError = 'La fenêtre WAF doit être comprise entre 60 secondes et 24 heures.';
				return null;
			}
		}

		return {
			name: name.trim(),
			enabled,
			kind,
			severity,
			category: category.trim(),
			source,
			sourceParams: buildSourceParams(),
			evalParams: buildEvalParams(),
			channels: channelIds,
			cooldownSecs,
			subjectTemplate: subjectTemplate.trim() || undefined,
			bodyTemplate: bodyTemplate.trim() || undefined
		};
	}

	async function onSubmit(e: SubmitEvent) {
		e.preventDefault();
		validationError = '';
		const req = buildRequest();
		if (!req) return;
		submitting = true;
		try {
			if (rule) {
				await rulesStore.update(rule.id, req);
				pushToast(`Règle "${req.name}" enregistrée.`, 'success');
			} else {
				await rulesStore.create(req);
				pushToast(`Règle "${req.name}" créée.`, 'success');
			}
			onSaved();
		} catch (err) {
			validationError = err instanceof ApiError ? err.message : 'Erreur réseau';
		} finally {
			submitting = false;
		}
	}

	function summariseTest(res: AlertRuleTestResponse): string {
		if (res.sent) {
			return `Envoi réussi sur ${res.channelsFired.length} canal/aux.`;
		}
		const lines: string[] = [];
		lines.push(`Envoyés : ${res.channelsFired.length}`);
		if (res.errors && Object.keys(res.errors).length > 0) {
			lines.push(`Échecs : ${Object.keys(res.errors).length}`);
		}
		if (res.skipped && Object.keys(res.skipped).length > 0) {
			lines.push(`Ignorés : ${Object.keys(res.skipped).length}`);
		}
		return lines.join(' · ');
	}

	async function onTest() {
		if (!rule) return;
		testing = true;
		testResultLine = '';
		try {
			const res = await alertingApi.testRule(rule.id);
			testResultLine = summariseTest(res);
			pushToast(`Règle "${rule.name}" : ${testResultLine}`, res.sent ? 'success' : 'info');
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : 'Erreur réseau';
			testResultLine = msg;
			pushToast(`Règle "${rule.name}" : ${msg}`, 'danger');
		} finally {
			testing = false;
		}
	}
</script>

<Modal {open} title={isEdit ? 'Modifier la règle' : 'Ajouter une règle'} {onClose} width="lg">
	<form onsubmit={onSubmit} class="space-y-4">
		<!-- Common: identity + severity -->
		<Input bind:value={name} label="Nom (slug)" placeholder="block-rate-elevated" required />

		<div class="flex items-center gap-4">
			<Checkbox bind:checked={enabled} label="Actif" />
		</div>

		<div class="grid grid-cols-2 gap-4">
			<Input bind:value={category} label="Catégorie" placeholder="waf / cert / system / ..." />
			<div>
				<label for="rule-severity" class="text-sm font-medium text-secondary mb-1.5 block">
					Sévérité
				</label>
				<select
					id="rule-severity"
					bind:value={severity}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
				>
					{#each SEVERITY_TOKENS as _t, i (i)}
						<option value={i}>{severityLabelFR(i)}</option>
					{/each}
				</select>
			</div>
		</div>

		<hr class="border-border-subtle" />

		<!-- Source picker + dynamic per-source form -->
		<div>
			<label for="rule-source" class="text-sm font-medium text-secondary mb-1.5 block">
				Source
			</label>
			<select
				id="rule-source"
				bind:value={source}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
			>
				{#each SOURCES as s (s.value)}
					<option value={s.value}>{s.label}</option>
				{/each}
			</select>
		</div>

		{#if source === 'waf_event_rate'}
			<div class="grid grid-cols-3 gap-4">
				<div>
					<label for="waf-route" class="text-sm font-medium text-secondary mb-1.5 block">
						Route
					</label>
					<select
						id="waf-route"
						bind:value={wafRouteId}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					>
						<option value="">Toutes les routes</option>
						{#each routes as r (r.id)}
							<option value={r.id}>{r.host}</option>
						{/each}
					</select>
				</div>
				<div>
					<label
						for="waf-window"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						Fenêtre (secondes)
					</label>
					<input
						id="waf-window"
						type="number"
						bind:value={wafWindowSecs}
						min="60"
						max="86400"
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					/>
				</div>
				<div>
					<label
						for="waf-action"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						Action
					</label>
					<select
						id="waf-action"
						bind:value={wafAction}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					>
						<option value="">Toutes</option>
						<option value="BLOCK">BLOCK</option>
						<option value="DETECT">DETECT</option>
					</select>
				</div>
			</div>
		{:else if source === 'cert_expiry'}
			<Input
				bind:value={certHost}
				label="Hôte (optionnel)"
				placeholder="vide = certificat expirant le plus tôt"
			/>
			<p class="text-xs text-secondary -mt-2">
				Combiné avec un seuil (ex : opérateur <code>&lt;</code> et valeur <code>14</code>)
				dans le formulaire d’évaluation ci-dessous, alerte quand un certificat expire
				bientôt.
			</p>
		{:else if source === 'system_health'}
			<div>
				<label
					for="health-component"
					class="text-sm font-medium text-secondary mb-1.5 block"
				>
					Composant
				</label>
				<select
					id="health-component"
					bind:value={healthComponent}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
				>
					{#each HEALTH_COMPONENTS as c (c.value)}
						<option value={c.value}>{c.label}</option>
					{/each}
				</select>
			</div>
		{/if}

		<hr class="border-border-subtle" />

		<!-- Kind picker + dynamic per-kind eval form -->
		<fieldset>
			<legend class="text-sm font-medium text-secondary mb-1.5">Type de règle</legend>
			<div class="flex gap-4">
				<label class="flex items-center gap-2 text-sm" class:opacity-50={isEdit}>
					<input
						type="radio"
						bind:group={kind}
						value="threshold"
						disabled={isEdit}
					/>
					Seuil (numérique)
				</label>
				<label class="flex items-center gap-2 text-sm" class:opacity-50={isEdit}>
					<input
						type="radio"
						bind:group={kind}
						value="state"
						disabled={isEdit}
					/>
					État (chaîne)
				</label>
			</div>
			{#if isEdit}
				<p class="text-xs text-secondary mt-1">
					Le type ne peut pas être modifié après création.
				</p>
			{/if}
		</fieldset>

		{#if kind === 'threshold'}
			<div class="grid grid-cols-2 gap-4">
				<div>
					<label
						for="threshold-op"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						Opérateur
					</label>
					<select
						id="threshold-op"
						bind:value={thresholdOp}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					>
						{#each OPERATORS as op (op)}
							<option value={op}>{op}</option>
						{/each}
					</select>
				</div>
				<div>
					<label
						for="threshold-value"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						Valeur seuil
					</label>
					<input
						id="threshold-value"
						type="number"
						bind:value={thresholdValue}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					/>
				</div>
			</div>
		{:else}
			<Input
				bind:value={stateExpected}
				label="Valeur attendue"
				placeholder="degraded / unhealthy / healthy / ..."
				required
			/>
		{/if}

		<hr class="border-border-subtle" />

		<!-- Channels multi-select -->
		<div>
			<span class="text-sm font-medium text-secondary mb-1.5 block">
				Canaux ({channelIds.length} sélectionné{channelIds.length === 1 ? '' : 's'})
			</span>
			{#if channelsStore.state.loading && availableChannels.length === 0}
				<p class="text-xs text-secondary">Chargement…</p>
			{:else if availableChannels.length === 0}
				<p class="text-xs text-secondary">
					Aucun canal actif disponible. Créez d’abord un canal dans l’onglet Canaux.
				</p>
			{:else}
				<div class="space-y-1 max-h-40 overflow-y-auto border border-border-subtle rounded p-2">
					{#each availableChannels as c (c.id)}
						<label class="flex items-center gap-2 text-sm py-1">
							<input
								type="checkbox"
								checked={isChannelSelected(c.id)}
								onchange={(e) => toggleChannel(c.id, (e.target as HTMLInputElement).checked)}
							/>
							<span class="text-primary">{c.name}</span>
							<span class="text-xs text-secondary">({c.kind})</span>
						</label>
					{/each}
				</div>
			{/if}
		</div>

		<!-- Cooldown -->
		<div>
			<label for="rule-cooldown" class="text-sm font-medium text-secondary mb-1.5 block">
				Cooldown (secondes)
			</label>
			<input
				id="rule-cooldown"
				type="number"
				bind:value={cooldownSecs}
				min="30"
				max="86400"
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
			/>
			<p class="text-xs text-secondary mt-1">≈ {cooldownFormatted(cooldownSecs)}</p>
		</div>

		<!-- Templates -->
		<details>
			<summary class="text-sm text-secondary cursor-pointer">
				Templates de notification (optionnel)
			</summary>
			<div class="mt-3 space-y-3 pl-2 border-l border-border-subtle">
				<div>
					<label
						for="rule-subject-tmpl"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						Template du sujet
					</label>
					<input
						id="rule-subject-tmpl"
						bind:value={subjectTemplate}
						placeholder={`[{{.Severity}}] {{.RuleName}}`}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
					/>
				</div>
				<div>
					<label
						for="rule-body-tmpl"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						Template du corps
					</label>
					<textarea
						id="rule-body-tmpl"
						bind:value={bodyTemplate}
						rows="3"
						placeholder={`Source {{.Source}} a déclenché à {{.Value}}`}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
					></textarea>
				</div>
				<p class="text-xs text-secondary">
					Placeholders disponibles : <code>{`{{.RuleName}}`}</code>,
					<code>{`{{.Severity}}`}</code>, <code>{`{{.Source}}`}</code>,
					<code>{`{{.Value}}`}</code>, <code>{`{{.Subject}}`}</code>.
				</p>
			</div>
		</details>

		{#if testResultLine}
			<div class="p-3 rounded bg-elevated border border-border-default text-sm text-primary">
				Résultat du test : {testResultLine}
			</div>
		{/if}

		{#if validationError}
			<div class="p-3 rounded bg-down/10 border border-down text-down text-sm" role="alert">
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
				{#snippet children()}Tester la règle{/snippet}
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
