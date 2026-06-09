<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step CS.1 — CrowdSec bouncer settings section. Single Card,
  one form, two submit paths:

    1. "Save & apply" — persists via PUT /api/v1/settings/
       crowdsec and triggers a backend mgr.ApplyCrowdSecConfig
       which rebuilds the Caddy config + reloads — no process
       restart required.

    2. "Test connection" — probes LAPI /v1/decisions via
       POST /api/v1/settings/crowdsec/test without mutating
       state. Renders a green / red badge with the diagnostic
       string (auth failed / timeout / connection refused / …).

  Deployment-agnostic: the LAPI URL accepts ANY http(s) URL.
  apt systemd → http://127.0.0.1:8080. Docker port-mapped →
  http://127.0.0.1:8080. Docker sibling network →
  http://crowdsec:8080. See docs/setup/crowdsec.md.

  Secret discipline: apiKey field always renders empty;
  placeholder reads "••• set (leave blank to keep)" when
  configured. Submitting with blank apiKey preserves the
  stored value (server-side merge, mirror of OIDC / DNS
  provider). Submitting all blank clears the configuration
  entirely — operator's "Disable bouncer" path.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { pushToast } from '$lib/stores/toast';
	import { settingsApi } from '$lib/api/settings';
	import {
		ApiError,
		type CrowdSecSettings,
		type CrowdSecTestResponse
	} from '$lib/api/types';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';

	let settings = $state<CrowdSecSettings | null>(null);
	let loading = $state(true);
	let loadError = $state('');

	let form = $state({
		lapiUrl: 'http://127.0.0.1:8080',
		apiKey: '',
		bouncerName: 'arenet',
		timeoutSeconds: 5
	});
	let formError = $state('');
	let submitting = $state(false);

	// Test connection state. `testResult` is set after a probe
	// completes; null when no probe has run yet (or the form
	// was edited since the last probe — the UI invalidates the
	// stale badge to avoid showing "Connected" against a URL
	// the operator has since modified).
	let testResult = $state<CrowdSecTestResponse | null>(null);
	let testing = $state(false);

	async function load(): Promise<void> {
		loading = true;
		loadError = '';
		try {
			const cfg = await settingsApi.getCrowdSecSettings();
			settings = cfg;
			form.lapiUrl = cfg.lapiUrl || 'http://127.0.0.1:8080';
			form.bouncerName = cfg.bouncerName || 'arenet';
			form.timeoutSeconds = cfg.timeoutSeconds || 5;
			form.apiKey = ''; // never round-trip the secret
		} catch (err) {
			loadError = err instanceof Error ? err.message : 'Failed to load CrowdSec settings';
		} finally {
			loading = false;
		}
	}

	async function submit(): Promise<void> {
		submitting = true;
		formError = '';
		try {
			const next = await settingsApi.putCrowdSecSettings({
				lapiUrl: form.lapiUrl.trim(),
				apiKey: form.apiKey,
				bouncerName: form.bouncerName.trim(),
				timeoutSeconds: form.timeoutSeconds
			});
			settings = next;
			form.apiKey = ''; // clear so a re-visit doesn't show ghost value
			pushToast(
				next.configured
					? 'CrowdSec bouncer saved & bouncer reloaded'
					: 'CrowdSec bouncer cleared',
				'success'
			);
		} catch (err) {
			formError = err instanceof ApiError ? err.message : String(err);
		} finally {
			submitting = false;
		}
	}

	async function testConnection(): Promise<void> {
		testing = true;
		formError = '';
		try {
			// If the form has an apiKey, use it; else fall back to
			// the stored row (useStored=true). The operator may be
			// probing the saved config without editing.
			const useStored = form.apiKey === '' && (settings?.configured ?? false);
			const res = await settingsApi.testCrowdSecConnection(
				useStored
					? { useStored: true }
					: {
							lapiUrl: form.lapiUrl.trim(),
							apiKey: form.apiKey,
							timeoutSeconds: form.timeoutSeconds
					  }
			);
			testResult = res;
			if (!res.ok) {
				// Surface the error inline in the badge area; no
				// toast (the badge IS the affordance).
			}
		} catch (err) {
			formError = err instanceof ApiError ? err.message : String(err);
			testResult = null;
		} finally {
			testing = false;
		}
	}

	// Invalidate the test result whenever the operator edits
	// any URL / key / timeout — showing "Connected" against
	// values the user has since changed would be misleading.
	function onFormEdit(): void {
		testResult = null;
	}

	onMount(() => {
		void load();
	});
</script>

<div class="mb-6">
	<Card padding="p-6">
		<header
			class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4"
		>
			<div>
				<h2 class="text-xl font-semibold">CrowdSec bouncer</h2>
				<p class="text-xs text-muted mt-1">
					IP-reputation gate. Reads block decisions from the LAPI
					and rejects connections from sources CrowdSec flagged.
					Bouncer runs in-process; no extra container needed if
					CrowdSec engine is already on this host.
				</p>
			</div>
			{#if loading}
				<Spinner size="sm" />
			{:else if settings?.configured}
				<Badge variant="status-up">Configured</Badge>
			{:else}
				<Badge variant="status-warn">Not configured</Badge>
			{/if}
		</header>

		{#if loadError}
			<p class="text-sm text-down mb-3" role="alert">
				Failed to load CrowdSec settings: {loadError}
			</p>
		{/if}

		<form
			class="grid grid-cols-1 md:grid-cols-2 gap-4"
			onsubmit={(e) => {
				e.preventDefault();
				void submit();
			}}
		>
			<div class="md:col-span-2">
				<label for="cs-lapi-url" class="text-sm font-medium text-secondary block mb-1">
					LAPI URL
				</label>
				<input
					id="cs-lapi-url"
					type="text"
					bind:value={form.lapiUrl}
					oninput={onFormEdit}
					placeholder="http://crowdsec:8080 or http://127.0.0.1:8080"
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
				<p class="text-xs text-muted mt-1">
					LAPI listen URL. <code class="font-mono">http://127.0.0.1:8080</code>
					for an apt install on the same host; <code class="font-mono">http://crowdsec:8080</code>
					for a sibling Docker container in the same compose network; or any
					custom URL the deployment exposes.
				</p>
			</div>

			<div>
				<label for="cs-api-key" class="text-sm font-medium text-secondary block mb-1">
					Bouncer API key
				</label>
				<input
					id="cs-api-key"
					type="password"
					autocomplete="off"
					bind:value={form.apiKey}
					oninput={onFormEdit}
					placeholder={settings?.configured ? '••• set (leave blank to keep)' : ''}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
				<p class="text-xs text-muted mt-1">
					Generate with <code class="font-mono">cscli bouncers add arenet</code>
					on the CrowdSec host. The key is shown only once at creation; if
					lost, delete + re-add the bouncer.
				</p>
			</div>

			<div>
				<label for="cs-bouncer-name" class="text-sm font-medium text-secondary block mb-1">
					Bouncer name
				</label>
				<input
					id="cs-bouncer-name"
					type="text"
					bind:value={form.bouncerName}
					oninput={onFormEdit}
					placeholder="arenet"
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
				<p class="text-xs text-muted mt-1">
					Cosmetic identifier. Must match the name used in <code class="font-mono">cscli bouncers add</code>.
				</p>
			</div>

			<div>
				<label for="cs-timeout" class="text-sm font-medium text-secondary block mb-1">
					Connection timeout (seconds)
				</label>
				<input
					id="cs-timeout"
					type="number"
					min="1"
					max="60"
					bind:value={form.timeoutSeconds}
					oninput={onFormEdit}
					class="w-32 bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
				<p class="text-xs text-muted mt-1">
					Per-request cap on LAPI calls. Range 1–60. Default 5.
				</p>
			</div>

			{#if testResult}
				<div class="md:col-span-2">
					{#if testResult.ok}
						<div
							class="rounded border border-up/40 bg-up/10 px-3 py-2 text-sm text-up"
							role="status"
						>
							<strong class="font-semibold">Connected</strong>
							{#if testResult.version}
								to LAPI <code class="font-mono">{testResult.version}</code>
							{/if}
							{#if testResult.effectiveUrl}
								at <code class="font-mono">{testResult.effectiveUrl}</code>
							{/if}
						</div>
					{:else}
						<div
							class="rounded border border-down/40 bg-down/10 px-3 py-2 text-sm text-down"
							role="alert"
						>
							<strong class="font-semibold">Connection failed:</strong>
							{testResult.error ?? 'unknown error'}
							{#if testResult.statusCode}
								<span class="text-xs ml-1">(HTTP {testResult.statusCode})</span>
							{/if}
						</div>
					{/if}
				</div>
			{/if}

			{#if formError}
				<p class="text-sm text-down md:col-span-2" role="alert">{formError}</p>
			{/if}

			<div class="md:col-span-2 flex justify-end gap-2">
				<Button
					variant="secondary"
					type="button"
					disabled={testing || submitting}
					onclick={testConnection}
				>
					{testing ? 'Testing…' : 'Test connection'}
				</Button>
				<Button type="submit" disabled={submitting || testing}>
					{submitting ? 'Saving…' : 'Save & apply'}
				</Button>
			</div>
		</form>

		<p class="text-xs text-muted mt-4">
			Save & apply hot-reloads the embedded Caddy without a process
			restart. Active routes drop the request only after the new bouncer
			creds are live, so there's no race window. Submit with all fields
			blank to clear the configuration and disable the bouncer (operator's
			"Disable" path).
		</p>
	</Card>
</div>
