<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  WafExcludeDialog (v2.36) — "Exclude…" on a WAF event. When the
  event names the triggering field (matchedVar, e.g. ARGS:content)
  it creates a targeted exclusion: the rule stops inspecting that
  field, by default only on the event's path. Without a field
  (older events, rules on the URL) it falls back to excluding the
  rule on the whole route, with a warning.

  Submit: POST /routes/{id}/waf-exclusions.
    200 → success toast, onSuccess(), close
    409 → "already exists" info toast, close
    other → inline error, dialog stays open
-->
<script lang="ts">
	import Modal from '$lib/components/Modal.svelte';
	import Button from '$lib/components/Button.svelte';
	import { addWafExclusion } from '$lib/api/client';
	import { ApiError, type AddWafExclusionRequest, type WafEvent } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { eventExclusionPath, isValidExclusionPath, parseWafTarget } from '$lib/utils/waf-exclusion';

	interface Props {
		open: boolean;
		event: WafEvent | null;
		/** Friendly host of the event's route (falls back to the id). */
		host?: string;
		onClose: () => void;
		onSuccess?: () => void;
	}

	let { open, event, host = '', onClose, onSuccess }: Props = $props();

	let onlyThisPath = $state(true);
	let pathPrefix = $state(false);
	let path = $state('');
	let submitting = $state(false);
	let errorMsg = $state<string | null>(null);

	const target = $derived(parseWafTarget(event?.matchedVar));
	const eventPath = $derived(event ? eventExclusionPath(event.requestPath) : '');
	const hostLabel = $derived(host || event?.routeId || '');
	const pathInvalid = $derived(target !== null && onlyThisPath && !isValidExclusionPath(path.trim()));

	// Reset on every open so a previous event does not bleed in.
	let wasOpen = false;
	$effect(() => {
		if (open && !wasOpen) {
			path = eventPath;
			onlyThisPath = eventPath !== '';
			pathPrefix = false;
			errorMsg = null;
			submitting = false;
		}
		wasOpen = open;
	});

	async function submit(): Promise<void> {
		if (!event || pathInvalid) return;
		const body: AddWafExclusionRequest = { ruleId: Number(event.ruleId) };
		if (target) {
			body.target = `${target.variable}:${target.key}`;
			if (onlyThisPath) {
				body.path = path.trim();
				if (pathPrefix) body.pathPrefix = true;
			}
		}
		submitting = true;
		errorMsg = null;
		try {
			await addWafExclusion(event.routeId, body);
			pushToast(t('wafExclude.toastAdded', { rule: event.ruleId, host: hostLabel }), 'success');
			onSuccess?.();
			onClose();
		} catch (err) {
			if (err instanceof ApiError && err.status === 409) {
				pushToast(t('wafExclude.toastExists'), 'info');
				onClose();
				return;
			}
			errorMsg = err instanceof Error && err.message ? err.message : t('wafExclude.errFailed');
		} finally {
			submitting = false;
		}
	}
</script>

<Modal
	{open}
	title={language.current && event ? t('wafExclude.title', { rule: event.ruleId }) : ''}
	onClose={() => {
		if (!submitting) onClose();
	}}
>
	{#snippet children()}
		{#if event}
			<div class="exclude-form" data-testid="waf-exclude-dialog">
				{#if target}
					<p class="intro" data-testid="waf-exclude-intro">
						{language.current &&
							t('wafExclude.intro', {
								rule: event.ruleId,
								kind: t(`wafExclude.kind.${target.variable}`),
								name: target.key
							})}
					</p>
					{#if eventPath === ''}
						<p class="hint">{language.current && t('wafExclude.noEventPath')}</p>
					{/if}
					<label class="check">
						<input type="checkbox" bind:checked={onlyThisPath} data-testid="waf-exclude-only-path" />
						{language.current && t('wafExclude.onlyThisPath')}
					</label>
					{#if onlyThisPath}
						<div class="field">
							<label for="waf-exclude-path">{language.current && t('wafExclude.pathLabel')}</label>
							<input
								id="waf-exclude-path"
								type="text"
								autocomplete="off"
								class="mono"
								bind:value={path}
								aria-invalid={pathInvalid}
								data-testid="waf-exclude-path"
							/>
							{#if pathInvalid}
								<p class="error-text" role="alert">{language.current && t('wafExclude.pathInvalid')}</p>
							{/if}
						</div>
						<label class="check">
							<input type="checkbox" bind:checked={pathPrefix} data-testid="waf-exclude-prefix" />
							{language.current && t('wafExclude.andBelow')}
						</label>
					{/if}
				{:else}
					<div class="warn-block" role="note" data-testid="waf-exclude-whole-route">
						<strong>{language.current && t('wafExclude.wholeRouteTitle')}</strong>
						<p>
							{language.current && t('wafExclude.wholeRouteBody', { rule: event.ruleId, host: hostLabel })}
						</p>
					</div>
				{/if}
				<p class="hint">{language.current && t('wafExclude.detectHint')}</p>
				{#if errorMsg}
					<div class="error-block" role="alert" data-testid="waf-exclude-error">{errorMsg}</div>
				{/if}
			</div>
		{/if}
	{/snippet}

	{#snippet footer()}
		<Button variant="ghost" type="button" onclick={onClose} disabled={submitting}>
			{language.current && t('wafExclude.cancel')}
		</Button>
		<Button
			variant="primary"
			type="button"
			onclick={() => void submit()}
			disabled={submitting || pathInvalid}
			loading={submitting}
			data-testid="waf-exclude-submit"
		>
			{language.current && t('wafExclude.submit')}
		</Button>
	{/snippet}
</Modal>

<style>
	.exclude-form {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.intro {
		margin: 0;
		line-height: 1.5;
	}
	.check {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		color: var(--text-secondary);
		cursor: pointer;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		margin-left: 1.5rem;
	}
	.field label {
		font-size: var(--text-xs, 11px);
		color: var(--text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		font-weight: 500;
	}
	.field input {
		background: var(--bg-surface);
		color: var(--text-primary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0.4rem 0.6rem;
		border-radius: 4px;
		font-size: var(--text-sm);
	}
	.field input:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 1px;
	}
	.field + .check {
		margin-left: 1.5rem;
	}
	.mono {
		font-family: var(--font-mono, monospace);
	}
	.hint {
		margin: 0;
		font-size: var(--text-xs, 11px);
		color: var(--text-muted);
	}
	.error-text {
		margin: 0;
		font-size: var(--text-xs, 11px);
		color: var(--status-down);
	}
	.warn-block {
		padding: 0.6rem 0.75rem;
		border-radius: 4px;
		background: color-mix(in oklch, var(--status-warn) 8%, transparent);
		border: 1px solid color-mix(in oklch, var(--status-warn) 35%, transparent);
	}
	.warn-block p {
		margin: 0.35rem 0 0 0;
		color: var(--text-secondary);
	}
	.error-block {
		padding: 0.6rem 0.75rem;
		border-radius: 4px;
		border: 1px solid color-mix(in oklch, var(--status-down) 30%, transparent);
		color: var(--status-down);
	}
</style>
