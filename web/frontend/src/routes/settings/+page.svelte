<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Settings (Step F §8.6 / §9). Three sections in a single page:

    1. Account  — display name + username (read-only), HIBP status
                  indicator (discreet — the compromised banner lives
                  in +layout.svelte, this is just an inline mirror),
                  Change password button.
    2. Appearance — theme Toggle (Chunk 1.6 wiring preserved),
                  Reduce motion read-only indicator.
    3. Sessions — DataTable (lands in Chunk 6.2).
    4. About — version / license / source (lands in Chunk 6.3).

  This file replaces the Chunk 1.6 placeholder (debug strip + footer
  note removed). The wrapper max-w-2xl is preserved — Settings is a
  configuration page, not a dashboard, so a column layout reads
  better than full-bleed.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { prefersReducedMotion } from 'svelte/motion';
	import { auth } from '$lib/stores/auth.svelte';
	import { theme, type Theme } from '$lib/stores/theme.svelte';
	import { pushToast } from '$lib/stores/toast';
	import { authApi, type Session } from '$lib/api/auth';
	import { settingsApi } from '$lib/api/settings';
	import { OVH_ENDPOINTS, type DNSProviderOVH } from '$lib/api/types';
	import { ApiError } from '$lib/api/types';
	import { listRoutes } from '$lib/api/client';
	import { relativeTime } from '$lib/utils/audit-format';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import DataTable from '$lib/components/DataTable.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import Toggle from '$lib/components/Toggle.svelte';
	import ChangePasswordModal from '$lib/components/ChangePasswordModal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';

	const options: [
		{ value: Theme; label: string },
		{ value: Theme; label: string }
	] = [
		{ value: 'dark', label: 'Dark' },
		{ value: 'light', label: 'Light' }
	];

	// Local ChangePasswordModal instance (Decision: Option B from the
	// Chunk 6 brief). The layout-shell instance handles the
	// compromised-password banner flow; this one is wired to the
	// explicit "Change password" button in the Account section.
	// Two instances of the same component, each with its own `open`
	// state — the component supports that by design.
	let changePasswordOpen = $state(false);

	async function onThemeChange(v: Theme): Promise<void> {
		try {
			await theme.set(v);
		} catch (_) {
			// theme store already reverted + toast emitted; just swallow
			// here so the smoke session sees no unhandled rejection.
		}
	}

	// --- Sessions section (Step F Chunk 6.2 / spec §9.2) -------------------

	let sessions = $state<Session[]>([]);
	let sessionsLoading = $state(true);
	let sessionsError = $state<string | null>(null);

	async function loadSessions(): Promise<void> {
		sessionsLoading = true;
		sessionsError = null;
		try {
			const res = await authApi.listSessions();
			sessions = res.sessions;
		} catch (err) {
			sessionsError = err instanceof Error ? err.message : 'Failed to load sessions';
		} finally {
			sessionsLoading = false;
		}
	}

	// Revoke confirmation state — replaces the native confirm() that
	// broke the Linear-like visual consistency. The ConfirmDialog
	// (Chunk 6.4) wraps Modal with a standard yes/no surface.
	let revokeConfirmOpen = $state(false);
	let revokeTarget = $state<Session | null>(null);

	function onRevokeClick(s: Session): void {
		// Hard safety even though the button is `disabled` on isCurrent —
		// keyboard activation on a disabled button is browser-dependent.
		if (s.isCurrent) return;
		revokeTarget = s;
		revokeConfirmOpen = true;
	}

	async function confirmRevoke(): Promise<void> {
		const target = revokeTarget;
		if (!target) return;
		try {
			await authApi.deleteSession(target.id);
			// Optimistic local filter — no re-fetch unless we hit an error.
			// The server is the source of truth, but a session listing
			// rarely diverges in the ~50 ms window between delete and
			// next request.
			sessions = sessions.filter((x) => x.id !== target.id);
			pushToast('Session revoked', 'success');
			revokeConfirmOpen = false;
			revokeTarget = null;
		} catch (_) {
			pushToast('Failed to revoke session', 'danger');
			// Re-fetch on error to recover the truth — the delete might
			// have partially succeeded or the local list might be stale.
			// Keep the dialog open so the user can retry if they want.
			void loadSessions();
		}
	}

	function truncate(s: string, max: number): string {
		if (s.length <= max) return s;
		return s.slice(0, max) + '…';
	}

	// --- DNS provider section (Step J.4 §5.4) ----------------------------

	// Snapshot of the stored OVH config. The three secret fields are
	// always empty strings on the wire (server-side redaction);
	// dnsProvider.configured is the single status flag the badge
	// binds to. Loaded on mount and refreshed after a successful PUT.
	let dnsProvider = $state<DNSProviderOVH | null>(null);
	let dnsProviderLoading = $state(true);
	let dnsProviderLoadError = $state<string | null>(null);

	// Local form state. The three secret fields are write-only:
	// blank on submit preserves the stored value (server merges
	// against the previous row). The endpoint dropdown is the only
	// non-secret field, round-trips normally.
	let dnsForm = $state({
		endpoint: 'ovh-eu',
		applicationKey: '',
		applicationSecret: '',
		consumerKey: ''
	});
	let dnsSubmitting = $state(false);
	let dnsFormError = $state<string | null>(null);

	async function loadDNSProvider(): Promise<void> {
		dnsProviderLoading = true;
		dnsProviderLoadError = null;
		try {
			const cfg = await settingsApi.getDNSProviderOVH();
			dnsProvider = cfg;
			// Pre-fill the endpoint from the stored value so the user
			// sees the active region. Secrets stay blank (the wire
			// always emits "" for them, and a blank submit preserves
			// the stored value — same UX as Step I.5 BasicAuth).
			if (cfg.endpoint !== '') {
				dnsForm.endpoint = cfg.endpoint;
			}
		} catch (err) {
			dnsProviderLoadError =
				err instanceof Error ? err.message : 'Failed to load DNS provider';
		} finally {
			dnsProviderLoading = false;
		}
	}

	async function submitDNSProvider(): Promise<void> {
		dnsSubmitting = true;
		dnsFormError = null;
		try {
			const next = await settingsApi.putDNSProviderOVH({
				endpoint: dnsForm.endpoint,
				applicationKey: dnsForm.applicationKey,
				applicationSecret: dnsForm.applicationSecret,
				consumerKey: dnsForm.consumerKey
			});
			dnsProvider = next;
			// Clear the secret inputs after a successful save so the
			// next visit doesn't show ghost values. Endpoint stays.
			dnsForm.applicationKey = '';
			dnsForm.applicationSecret = '';
			dnsForm.consumerKey = '';
			pushToast('DNS provider saved', 'success');
			void loadDNS01Status();
		} catch (err) {
			dnsFormError = err instanceof ApiError ? err.message : String(err);
		} finally {
			dnsSubmitting = false;
		}
	}

	// (β) bandeau gate on the Settings page: does any persisted
	// route already use DNS-01 ACME? If so, an incomplete provider
	// config is a live problem and gets surfaced above the form.
	let anyDNS01Route = $state(false);
	async function loadDNS01Status(): Promise<void> {
		try {
			const all = await listRoutes();
			anyDNS01Route = all.some((r) => r.acmeChallenge === 'dns-01');
		} catch {
			// Best-effort — the bandeau being absent is not a hard
			// failure (the form still works).
			anyDNS01Route = false;
		}
	}

	const dnsInconsistent = $derived(
		anyDNS01Route && dnsProvider !== null && !dnsProvider.configured
	);

	// License URL ref resolution (Step G G.2).
	// `git describe --tags --always` produces three shapes:
	//   - clean tag   → `v0.4.0-step-f`           (valid GitHub ref)
	//   - describe    → `v0.4.0-step-f-3-g7471243` (NOT a ref → 404)
	//   - bare sha    → `7471243`                  (NOT a ref → 404)
	// Also `unknown` when git is unavailable (vite.config.ts fallback).
	// Clean tag is the only shape we can safely use as a GitHub ref;
	// every other shape falls back to `main` to avoid the 404.
	const appVersion = import.meta.env.VITE_APP_VERSION;
	const isCleanTag =
		/^v[^\s]+$/.test(appVersion) && !/-\d+-g[0-9a-f]{7,40}$/.test(appVersion);
	const licenseRef = isCleanTag ? appVersion : 'main';

	onMount(() => {
		void loadSessions();
		void loadDNSProvider();
		void loadDNS01Status();
	});
</script>

<svelte:head>
	<title>Settings — Arenet</title>
</svelte:head>

<div class="mx-auto max-w-5xl">
	<PageHeader title="Settings" subtitle="Manage your account and preferences." />

	<!-- Asymmetric layout (Chunk 6.5 smoke fix):
	     - Row 1: 2-column grid (lg+) → Account + Appearance.
	       Both are form-narrow Cards (short labels, short values),
	       fit comfortably in 480 px columns.
	     - Row 2: full-width → Sessions DataTable.
	       Needs horizontal real estate for IP + UA + timestamp
	       columns; 480 px wraps it to 7+ lines per row (smoke fail).
	     - Row 3: full-width → About.
	       Short content, intentionally aerated as a "footer-meta"
	       section that closes the page.
	     The 6.4 attempt put everything in a single 2-col grid which
	     compressed Sessions to illegibility — this asymmetric form
	     is the corrective. -->

	<!-- ROW 1 — Account + Appearance (2-col on lg+, 1-col below) -->
	<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
		<!-- ACCOUNT SECTION -->
		<Card padding="p-6">
			<header class="border-b border-border-subtle pb-3 mb-4">
				<h2 class="text-xl font-semibold">Account</h2>
			</header>

			<dl class="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-3 text-sm">
				<dt class="text-secondary">Display name</dt>
				<dd class="text-primary">{auth.user?.displayName ?? '—'}</dd>

				<dt class="text-secondary">Username</dt>
				<dd class="text-primary font-mono">{auth.user?.username ?? '—'}</dd>

				<dt class="text-secondary">Password security</dt>
				<dd>
					<!-- Discreet inline indicator — the compromised banner
					     in +layout.svelte handles the urgent attention
					     path; this is just a mirror so the user can read
					     their breach status without scrolling to the top.
					     Chunk 6.4: wording switched from HIBP jargon to
					     user-friendly equivalents. -->
					{#if auth.user?.passwordCompromised}
						<span class="text-down">Found in known breaches — change required</span>
					{:else if auth.user?.hibpCheckStatus === 'clean'}
						<span class="text-up">Not found in known breaches</span>
					{:else if auth.user?.hibpCheckStatus === 'pending'}
						<span class="text-muted">Verification in progress</span>
					{:else if auth.user?.hibpCheckStatus === 'skipped'}
						<span class="text-muted">Verification skipped</span>
					{:else}
						<span class="text-muted">Status unknown</span>
					{/if}
				</dd>
			</dl>

			<div class="mt-6">
				<Button variant="secondary" onclick={() => (changePasswordOpen = true)}>
					Change password
				</Button>
			</div>
		</Card>

		<!-- APPEARANCE SECTION -->
		<Card padding="p-6">
			<header class="border-b border-border-subtle pb-3 mb-4">
				<h2 class="text-xl font-semibold">Appearance</h2>
			</header>

			<dl class="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-4 text-sm items-center">
				<dt class="text-secondary">Theme</dt>
				<dd>
					<Toggle
						ariaLabel="Theme"
						{options}
						value={theme.current}
						disabled={theme.isApplying}
						onchange={onThemeChange}
					/>
				</dd>

				<dt class="text-secondary">Reduce motion</dt>
				<dd class="text-primary">
					{prefersReducedMotion.current ? 'Enabled' : 'Disabled'}
					<span class="text-muted ml-2 text-xs">(system preference)</span>
				</dd>
			</dl>
		</Card>
	</div>

	<!-- ROW 2 — Sessions, full-width (DataTable needs the room) -->
	<div class="mb-6">
		<Card padding="p-6">
			<header class="border-b border-border-subtle pb-3 mb-4">
				<h2 class="text-xl font-semibold">Sessions</h2>
			</header>

			{#if sessionsLoading}
				<div class="flex items-center gap-2 py-4 text-secondary text-sm">
					<Spinner size="sm" /> Loading sessions…
				</div>
			{:else if sessionsError}
				<div class="py-4 text-sm" role="alert">
					<p class="text-down">Failed to load sessions: {sessionsError}</p>
					<div class="mt-3">
						<Button variant="ghost" size="sm" onclick={loadSessions}>Retry</Button>
					</div>
				</div>
			{:else}
				<!-- Sessions table is read-only: no expanded snippet, no
				     click-to-expand. Step G G.3 introduced `interactive`
				     prop on DataTable to drop cursor-pointer + role=button
				     + tabindex + hover-rail + focus-ring when interactive
				     is false. -->
				<DataTable
					headers={['Issued', 'Last activity', 'IP', 'Browser', 'Status', '']}
					items={sessions}
					interactive={false}
				>
					{#snippet row(s: Session)}
						<td class="px-4 py-3 text-sm" title={s.issuedAt}>
							{relativeTime(s.issuedAt)}
						</td>
						<td class="px-4 py-3 text-sm" title={s.lastActivity}>
							{relativeTime(s.lastActivity)}
						</td>
						<td class="px-4 py-3 text-sm font-mono text-secondary">{s.ip}</td>
						<td class="px-4 py-3 text-sm text-secondary" title={s.userAgent}>
							{truncate(s.userAgent, 40)}
						</td>
						<td class="px-4 py-3 text-sm">
							{#if s.isCurrent}
								<Badge variant="current">Current</Badge>
							{/if}
						</td>
						<td class="px-4 py-3 text-sm text-right">
							<Button
								variant="ghost"
								size="sm"
								disabled={s.isCurrent}
								onclick={() => onRevokeClick(s)}
							>
								Revoke
							</Button>
						</td>
					{/snippet}
				</DataTable>
			{/if}
		</Card>
	</div>

	<!-- ROW 2.5 — DNS provider (Step J.4 §5.4).
	     Full-width like Sessions: the three secret inputs + the
	     endpoint dropdown read better in a column. Status badge
	     binds to `dnsProvider.configured` — the single source of
	     truth on the wire. -->
	<div class="mb-6">
		<Card padding="p-6">
			<header class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4">
				<div>
					<h2 class="text-xl font-semibold">DNS provider</h2>
					<p class="text-xs text-muted mt-1">
						Required for DNS-01 ACME (wildcards). v1.0 supports OVH.
					</p>
				</div>
				{#if dnsProviderLoading}
					<Spinner size="sm" />
				{:else if dnsProvider}
					{#if dnsProvider.configured}
						<Badge variant="status-up">Configured</Badge>
					{:else}
						<Badge variant="status-warn">Not configured</Badge>
					{/if}
				{/if}
			</header>

			{#if dnsInconsistent}
				<div
					class="mb-4 rounded border border-down/40 bg-down/10 px-3 py-2 text-sm text-down"
					role="alert"
				>
					<strong class="font-semibold">DNS-01 routes are waiting on this config.</strong>
					At least one route already requests DNS-01 ACME. Until this
					provider is fully configured, certificate renewals for those
					routes will fail.
				</div>
			{/if}

			{#if dnsProviderLoadError}
				<p class="text-sm text-down mb-3" role="alert">
					Failed to load DNS provider: {dnsProviderLoadError}
				</p>
			{/if}

			<form
				class="grid grid-cols-1 md:grid-cols-2 gap-4"
				onsubmit={(e) => {
					e.preventDefault();
					void submitDNSProvider();
				}}
			>
				<div class="md:col-span-2">
					<label for="dns-endpoint" class="text-sm font-medium text-secondary block mb-1">
						OVH region
					</label>
					<select
						id="dns-endpoint"
						bind:value={dnsForm.endpoint}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					>
						{#each OVH_ENDPOINTS as ep (ep)}
							<option value={ep}>{ep}</option>
						{/each}
					</select>
				</div>

				<div>
					<label
						for="dns-application-key"
						class="text-sm font-medium text-secondary block mb-1"
					>
						Application key
					</label>
					<input
						id="dns-application-key"
						type="password"
						autocomplete="off"
						bind:value={dnsForm.applicationKey}
						placeholder={dnsProvider?.configured ? '••• set (leave blank to keep)' : ''}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
					/>
				</div>

				<div>
					<label
						for="dns-application-secret"
						class="text-sm font-medium text-secondary block mb-1"
					>
						Application secret
					</label>
					<input
						id="dns-application-secret"
						type="password"
						autocomplete="off"
						bind:value={dnsForm.applicationSecret}
						placeholder={dnsProvider?.configured ? '••• set (leave blank to keep)' : ''}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
					/>
				</div>

				<div class="md:col-span-2">
					<label
						for="dns-consumer-key"
						class="text-sm font-medium text-secondary block mb-1"
					>
						Consumer key
					</label>
					<input
						id="dns-consumer-key"
						type="password"
						autocomplete="off"
						bind:value={dnsForm.consumerKey}
						placeholder={dnsProvider?.configured ? '••• set (leave blank to keep)' : ''}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
					/>
				</div>

				{#if dnsFormError}
					<p class="text-sm text-down md:col-span-2" role="alert">{dnsFormError}</p>
				{/if}

				<div class="md:col-span-2 flex justify-end">
					<Button type="submit" disabled={dnsSubmitting}>
						{dnsSubmitting ? 'Saving…' : 'Save'}
					</Button>
				</div>
			</form>

			<p class="text-xs text-muted mt-4">
				Secrets are stored encrypted in transit but at rest in the
				BoltDB file — protected by the file's filesystem permissions.
				Restrict the data directory to the Arenet process user.
			</p>
		</Card>
	</div>

	<!-- ROW 3 — About, full-width (footer-meta, intentionally aerated) -->
	<Card padding="p-6">
		<header class="border-b border-border-subtle pb-3 mb-4">
			<h2 class="text-xl font-semibold">About</h2>
		</header>

		<dl class="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-3 text-sm">
			<dt class="text-secondary">Version</dt>
			<dd class="text-primary font-mono">{import.meta.env.VITE_APP_VERSION}</dd>

			<dt class="text-secondary">License</dt>
			<dd>
				<a
					href="https://github.com/barto95100/arenet/blob/{licenseRef}/LICENSE"
					target="_blank"
					rel="noopener noreferrer"
					class="text-cyan hover:underline"
				>
					AGPL v3
				</a>
			</dd>

			<dt class="text-secondary">Source</dt>
			<dd>
				<a
					href="https://github.com/barto95100/arenet"
					target="_blank"
					rel="noopener noreferrer"
					class="text-cyan hover:underline"
				>
					github.com/barto95100/arenet
				</a>
			</dd>
		</dl>
	</Card>

	<!-- ChangePasswordModal mounted locally (Option B). The
	     layout-level instance handles the compromised-banner flow;
	     this one handles the explicit user click in Settings. They're
	     independent instances of the same component — both safe by
	     ChangePasswordModal's `bind:open` design. -->
	<ChangePasswordModal bind:open={changePasswordOpen} />

	<!-- Revoke confirmation (Chunk 6.4 — replaces native confirm()). -->
	<ConfirmDialog
		bind:open={revokeConfirmOpen}
		title="Revoke session?"
		message="The other device will be signed out immediately."
		confirmLabel="Revoke"
		confirmVariant="danger"
		onConfirm={confirmRevoke}
	/>
</div>
