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
	import {
		AUTOMATION_SOURCES,
		AUTOMATION_SOURCE_LABELS,
		FORWARD_AUTH_PROVIDER_KINDS,
		OVH_ENDPOINTS,
		type AutomationCredentialsView,
		type AutomationRule,
		type AutomationRuleSet,
		type AutomationSource,
		type DNSProviderOVH,
		type ForwardAuthProvider,
		type ForwardAuthProviderKind,
		type ManagedDomain,
		type ManagedDomainProvider,
		type ManagedDomainRevertTo
	} from '$lib/api/types';
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
	import Modal from '$lib/components/Modal.svelte';
	import OIDCSettingsSection from '$lib/components/OIDCSettingsSection.svelte';
	import BackupSection from '$lib/components/BackupSection.svelte';

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

	// --- SSL / Certificates section (Step O.4 / spec D9.B) -------------------

	// Managed-domain list + the inline create form. Each managed
	// domain emits ONE wildcard TLS policy at the proxy edge
	// covering every route under `*.<apex>` (plus the bare apex
	// when includeApex is true, spec D2.C).
	let managedDomains = $state<ManagedDomain[]>([]);
	let managedDomainsLoading = $state(true);
	let managedDomainsLoadError = $state<string | null>(null);

	let mdForm = $state({
		apex: '',
		includeApex: true,
		provider: 'ovh' as ManagedDomainProvider
	});
	let mdSubmitting = $state(false);
	let mdFormError = $state<string | null>(null);

	// Delete-confirmation state. The operator picks the
	// post-revert ACMEChallenge value (AC #21) before
	// confirming — the dialog warns about HTTP-01 challenge
	// burst for the "" / "http-01" choices.
	let mdDeleteOpen = $state(false);
	let mdDeleteApex = $state('');
	let mdDeleteRevertTo = $state<ManagedDomainRevertTo>('');
	let mdDeleteError = $state<string | null>(null);

	async function loadManagedDomains(): Promise<void> {
		managedDomainsLoading = true;
		managedDomainsLoadError = null;
		try {
			const res = await settingsApi.listManagedDomains();
			managedDomains = res.domains;
		} catch (err) {
			managedDomainsLoadError =
				err instanceof Error ? err.message : 'Failed to load managed domains';
		} finally {
			managedDomainsLoading = false;
		}
	}

	async function submitManagedDomain(): Promise<void> {
		mdSubmitting = true;
		mdFormError = null;
		try {
			await settingsApi.createManagedDomain({
				apex: mdForm.apex.trim(),
				includeApex: mdForm.includeApex,
				provider: mdForm.provider
			});
			pushToast('Managed domain created', 'success');
			mdForm.apex = '';
			mdForm.includeApex = true;
			await loadManagedDomains();
		} catch (err) {
			mdFormError = err instanceof ApiError ? err.message : String(err);
		} finally {
			mdSubmitting = false;
		}
	}

	function openDeleteManagedDomain(apex: string): void {
		mdDeleteApex = apex;
		mdDeleteRevertTo = '';
		mdDeleteError = null;
		mdDeleteOpen = true;
	}

	async function confirmDeleteManagedDomain(): Promise<void> {
		mdDeleteError = null;
		try {
			const res = await settingsApi.deleteManagedDomain(mdDeleteApex, mdDeleteRevertTo);
			pushToast(
				res.mutatedRoutes === 0
					? 'Managed domain deleted'
					: `Managed domain deleted (${res.mutatedRoutes} route${res.mutatedRoutes === 1 ? '' : 's'} reverted)`,
				'success'
			);
			mdDeleteOpen = false;
			await loadManagedDomains();
		} catch (err) {
			mdDeleteError = err instanceof ApiError ? err.message : String(err);
		}
	}

	// SSL section is functional only when the DNS provider is
	// configured (spec D4.A: wildcards EXIGENT DNS-01, no silent
	// fallback). The banner is purely informational — the create
	// form stays enabled so the operator can stage a managed
	// domain before configuring DNS, and the backend will emit an
	// internal-CA-issuer policy until DNS lands.
	const sslDNSUnconfigured = $derived(
		dnsProvider !== null && !dnsProvider.configured
	);

	// --- Security Automation section (Step P.4 / spec D8.A) ------------------

	// Rule set (one row per Source) + credentials view. The
	// load fetches both in one GET; the persistence path is
	// two distinct PUTs so an operator who edits only rules
	// doesn't have to re-enter their watcher password.
	let automationRules = $state<AutomationRuleSet>({
		rules: {} as Record<AutomationSource, AutomationRule>
	});
	let automationCreds = $state<AutomationCredentialsView>({
		lapiUrl: '',
		machineId: '',
		configured: false
	});
	let automationLoading = $state(true);
	let automationLoadError = $state<string | null>(null);

	// Rules form working copy. The operator edits in this
	// shape (rule fields as nanosecond numbers — matches the
	// wire). On save we ship the full set; backend validate
	// rejects partial.
	let rulesDraft = $state<Record<AutomationSource, AutomationRule>>(
		{} as Record<AutomationSource, AutomationRule>
	);
	let rulesSubmitting = $state(false);
	let rulesFormError = $state<string | null>(null);

	// Credentials form. Empty password triggers the J.4
	// preserve-on-edit path (server keeps stored value).
	// Operator-visible placeholder when configured:
	// "leave blank to keep current" (P.3 commit forward
	// note #2).
	let credsForm = $state({ lapiUrl: '', machineId: '', password: '' });
	let credsSubmitting = $state(false);
	let credsFormError = $state<string | null>(null);

	async function loadAutomation(): Promise<void> {
		automationLoading = true;
		automationLoadError = null;
		try {
			const res = await settingsApi.getAutomation();
			automationRules = res.rules;
			automationCreds = res.credentials;
			// Seed the working copy from the loaded set;
			// re-runs on every load so the operator sees
			// the live state, not a stale draft.
			rulesDraft = { ...res.rules.rules };
			credsForm = {
				lapiUrl: res.credentials.lapiUrl,
				machineId: res.credentials.machineId,
				password: ''
			};
		} catch (err) {
			automationLoadError =
				err instanceof Error ? err.message : 'Failed to load automation config';
		} finally {
			automationLoading = false;
		}
	}

	async function submitAutomationRules(): Promise<void> {
		rulesSubmitting = true;
		rulesFormError = null;
		try {
			await settingsApi.putAutomationRules({
				rules: { rules: rulesDraft }
			});
			pushToast('Automation rules saved', 'success');
			await loadAutomation();
		} catch (err) {
			rulesFormError = err instanceof ApiError ? err.message : String(err);
		} finally {
			rulesSubmitting = false;
		}
	}

	async function submitAutomationCredentials(): Promise<void> {
		credsSubmitting = true;
		credsFormError = null;
		try {
			const res = await settingsApi.putAutomationCredentials({
				lapiUrl: credsForm.lapiUrl,
				machineId: credsForm.machineId,
				password: credsForm.password
			});
			automationCreds = res;
			pushToast(
				res.configured
					? 'Automation credentials saved'
					: 'Automation credentials cleared',
				'success'
			);
			credsForm.password = '';
		} catch (err) {
			credsFormError = err instanceof ApiError ? err.message : String(err);
		} finally {
			credsSubmitting = false;
		}
	}

	// Helper: ns ↔ "60s" / "4h" / "7d" round-trip. Keep the
	// UI numbers operator-friendly without abandoning the
	// wire's nanosecond format.
	function nsToHuman(ns: number): string {
		if (ns <= 0) return '0s';
		const s = Math.floor(ns / 1e9);
		if (s % 86400 === 0) return `${s / 86400}d`;
		if (s % 3600 === 0) return `${s / 3600}h`;
		if (s % 60 === 0) return `${s / 60}m`;
		return `${s}s`;
	}
	function humanToNs(s: string): number {
		const m = s.trim().match(/^(\d+)\s*([smhd]?)$/);
		if (!m) return 0;
		const n = Number(m[1]);
		switch (m[2]) {
			case 'd': return n * 86400 * 1e9;
			case 'h': return n * 3600 * 1e9;
			case 'm': return n * 60 * 1e9;
			default:  return n * 1e9; // 's' or empty = seconds
		}
	}

	// Per-rule field accessors. Svelte 5 runes work better
	// with explicit getter / setter than direct bind:value
	// on a nested map field.
	function getRule(s: AutomationSource): AutomationRule {
		return rulesDraft[s] ?? {
			enabled: false, threshold: 0, window_ns: 0, duration_ns: 0, cooldown_ns: 0
		};
	}
	function setRuleField<K extends keyof AutomationRule>(
		s: AutomationSource,
		key: K,
		value: AutomationRule[K]
	): void {
		const r = getRule(s);
		rulesDraft = { ...rulesDraft, [s]: { ...r, [key]: value } };
	}

	// --- Forward-auth providers section (Step K.1 §5.1) ----------------------

	// List + an inline form for create-or-edit. The form keeps an
	// `editingName` slot: null = create mode (POST), non-null =
	// edit mode (PUT on /providers/{name}). Same client-secret
	// preserve-on-edit pattern as the DNS provider above (empty
	// secret on PUT keeps the stored value).
	let fwdAuthList = $state<ForwardAuthProvider[]>([]);
	let fwdAuthLoading = $state(true);
	let fwdAuthListError = $state<string | null>(null);

	let fwdAuthEditingName = $state<string | null>(null);
	let fwdAuthForm = $state({
		name: '',
		kind: 'authelia' as ForwardAuthProviderKind,
		verifyUrl: '',
		authRequestUri: '/api/authz/forward-auth',
		copyHeaders: 'Remote-User, Remote-Email',
		clientSecret: '',
		authPassthroughPrefix: '',
		rewriteVerifyHost: false
	});
	let fwdAuthFormOpen = $state(false);
	let fwdAuthSubmitting = $state(false);
	let fwdAuthFormError = $state<string | null>(null);
	let fwdAuthDeleteError = $state<string | null>(null);
	// Edit-mode flag for the placeholder pattern on the secret input.
	let fwdAuthEditingSecretSet = $state(false);

	async function loadForwardAuthProviders(): Promise<void> {
		fwdAuthLoading = true;
		fwdAuthListError = null;
		try {
			fwdAuthList = await settingsApi.listForwardAuthProviders();
		} catch (err) {
			fwdAuthListError =
				err instanceof Error ? err.message : 'Failed to load forward-auth providers';
		} finally {
			fwdAuthLoading = false;
		}
	}

	function openFwdAuthCreate(): void {
		fwdAuthEditingName = null;
		fwdAuthEditingSecretSet = false;
		fwdAuthForm = {
			name: '',
			kind: 'authelia',
			verifyUrl: '',
			authRequestUri: '/api/authz/forward-auth',
			copyHeaders: 'Remote-User, Remote-Email',
			clientSecret: '',
			authPassthroughPrefix: '',
			rewriteVerifyHost: false
		};
		fwdAuthFormError = null;
		fwdAuthFormOpen = true;
	}

	function openFwdAuthEdit(p: ForwardAuthProvider): void {
		fwdAuthEditingName = p.name;
		fwdAuthEditingSecretSet = p.clientSecretSet;
		fwdAuthForm = {
			name: p.name,
			kind: p.kind,
			verifyUrl: p.verifyUrl,
			authRequestUri: p.authRequestUri,
			copyHeaders: (p.copyHeaders ?? []).join(', '),
			clientSecret: '',
			authPassthroughPrefix: p.authPassthroughPrefix ?? '',
			rewriteVerifyHost: p.rewriteVerifyHost ?? false
		};
		fwdAuthFormError = null;
		fwdAuthFormOpen = true;
	}

	async function submitFwdAuth(): Promise<void> {
		fwdAuthSubmitting = true;
		fwdAuthFormError = null;
		try {
			const passthrough = fwdAuthForm.authPassthroughPrefix.trim();
			const req = {
				name: fwdAuthForm.name.trim(),
				kind: fwdAuthForm.kind,
				verifyUrl: fwdAuthForm.verifyUrl.trim(),
				authRequestUri: fwdAuthForm.authRequestUri.trim(),
				copyHeaders: fwdAuthForm.copyHeaders
					.split(',')
					.map((h) => h.trim())
					.filter((h) => h.length > 0),
				clientSecret: fwdAuthForm.clientSecret,
				...(passthrough ? { authPassthroughPrefix: passthrough } : {}),
				...(fwdAuthForm.rewriteVerifyHost ? { rewriteVerifyHost: true } : {})
			};
			if (fwdAuthEditingName === null) {
				await settingsApi.createForwardAuthProvider(req);
				pushToast('Forward-auth provider created', 'success');
			} else {
				await settingsApi.updateForwardAuthProvider(fwdAuthEditingName, req);
				pushToast('Forward-auth provider updated', 'success');
			}
			fwdAuthFormOpen = false;
			await loadForwardAuthProviders();
		} catch (err) {
			fwdAuthFormError = err instanceof ApiError ? err.message : String(err);
		} finally {
			fwdAuthSubmitting = false;
		}
	}

	async function deleteFwdAuth(name: string): Promise<void> {
		fwdAuthDeleteError = null;
		try {
			await settingsApi.deleteForwardAuthProvider(name);
			pushToast('Forward-auth provider deleted', 'success');
			await loadForwardAuthProviders();
		} catch (err) {
			fwdAuthDeleteError = err instanceof ApiError ? err.message : String(err);
		}
	}

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
		void loadForwardAuthProviders();
		void loadManagedDomains();
		void loadAutomation();
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

	<!-- ROW 2.6 — SSL / Certificates (Step O.4 / spec D9.B).
	     New top-level Settings section, sibling of DNS provider.
	     Declares managed domains so caddymgr emits ONE wildcard
	     TLS policy per apex covering every route under
	     `*.<apex>` (plus the bare apex when includeApex is true).
	     D4.A: when the DNS provider is unconfigured, an inline
	     banner directs the operator to the DNS provider section
	     above — wildcards EXIGENT DNS-01, no silent HTTP-01
	     fallback. -->
	<div class="mb-6">
		<Card padding="p-6">
			<header class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4">
				<div>
					<h2 class="text-xl font-semibold">SSL / Certificates</h2>
					<p class="text-xs text-muted mt-1">
						Managed domains issue ONE wildcard cert per apex via DNS-01
						(covers every sub-domain route under it).
					</p>
				</div>
				{#if managedDomainsLoading}
					<Spinner size="sm" />
				{:else if managedDomains.length > 0}
					<Badge variant="status-up"
						>{managedDomains.length} managed domain{managedDomains.length === 1
							? ''
							: 's'}</Badge
					>
				{:else}
					<Badge variant="neutral">None declared</Badge>
				{/if}
			</header>

			{#if sslDNSUnconfigured}
				<div
					class="mb-4 rounded border border-warn/40 bg-warn/10 px-3 py-2 text-sm"
					role="alert"
				>
					<strong class="font-semibold">DNS provider unconfigured.</strong>
					Wildcard issuance is disabled — covered routes will serve
					self-signed certs from Caddy's internal CA until you configure
					the DNS provider in the section above.
				</div>
			{/if}

			{#if managedDomainsLoadError}
				<p class="text-sm text-down mb-3" role="alert">
					Failed to load managed domains: {managedDomainsLoadError}
				</p>
			{/if}

			<!-- Existing managed domains list -->
			{#if managedDomains.length > 0}
				<ul class="mb-4 divide-y divide-border-subtle">
					{#each managedDomains as md (md.apex)}
						<li class="flex items-center justify-between py-2">
							<div>
								<div class="font-mono text-sm">
									*.{md.apex}{#if md.includeApex}<span class="text-muted"
											>, {md.apex}</span
										>{/if}
								</div>
								<div class="text-xs text-muted">
									Provider: {md.provider}
									{#if md.includeApex}
										· includes apex
									{/if}
								</div>
							</div>
							<Button
								variant="ghost"
								onclick={() => openDeleteManagedDomain(md.apex)}
								aria-label={`Delete managed domain ${md.apex}`}
							>
								Delete
							</Button>
						</li>
					{/each}
				</ul>
			{/if}

			<!-- Inline create form -->
			<form
				class="grid grid-cols-1 md:grid-cols-2 gap-4"
				onsubmit={(e) => {
					e.preventDefault();
					void submitManagedDomain();
				}}
			>
				<div class="md:col-span-2">
					<label for="md-apex" class="text-sm font-medium text-secondary block mb-1"
						>Apex domain</label
					>
					<input
						id="md-apex"
						type="text"
						bind:value={mdForm.apex}
						placeholder="example.com"
						autocomplete="off"
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
					/>
					<p class="text-xs text-muted mt-1">
						Bare domain (no leading <code>*.</code>) — the wildcard is
						implied. Issues a cert for <code>*.{mdForm.apex || 'example.com'}</code>.
					</p>
				</div>

				<div>
					<label for="md-provider" class="text-sm font-medium text-secondary block mb-1"
						>DNS provider</label
					>
					<select
						id="md-provider"
						bind:value={mdForm.provider}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					>
						<option value="ovh">OVH</option>
					</select>
				</div>

				<div class="flex items-center gap-2 md:mt-7">
					<input
						id="md-include-apex"
						type="checkbox"
						bind:checked={mdForm.includeApex}
					/>
					<label for="md-include-apex" class="text-sm text-secondary"
						>Include bare apex in cert SAN</label
					>
				</div>

				{#if mdFormError}
					<p class="text-sm text-down md:col-span-2" role="alert">{mdFormError}</p>
				{/if}

				<div class="md:col-span-2 flex justify-end">
					<Button type="submit" disabled={mdSubmitting || mdForm.apex.trim() === ''}>
						{mdSubmitting ? 'Declaring…' : 'Declare managed domain'}
					</Button>
				</div>
			</form>

			<p class="text-xs text-muted mt-4">
				Declaring a managed domain marks every existing route under
				<code>*.&lt;apex&gt;</code> as covered by the wildcard. The route's
				per-route ACME selector is hidden in the route editor and the cert
				is provisioned once for all covered sub-domains.
			</p>
		</Card>
	</div>

	<!-- ROW 2.7 — Security Automation (Step P.4 / spec D8.A).
	     New top-level Settings section, sibling of SSL /
	     Certificates. Two forms in one Card: per-category
	     rule toggles (top) + watcher credentials (bottom).
	     The two persist via independent PUTs so an
	     operator who edits only rules doesn't re-enter
	     their watcher password. -->
	<div class="mb-6">
		<Card padding="p-6">
			<header class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4">
				<div>
					<h2 class="text-xl font-semibold">Security Automation</h2>
					<p class="text-xs text-muted mt-1">
						Push CrowdSec bans to LAPI automatically when WAF / throttle / auth-failure events cross operator-configured thresholds. Decisions appear in the CrowdSec dashboard with scenario prefix <code>arenet/</code>.
					</p>
				</div>
				{#if automationLoading}
					<Spinner size="sm" />
				{:else if automationCreds.configured}
					<Badge variant="status-up">Configured</Badge>
				{:else}
					<Badge variant="status-warn">Not configured</Badge>
				{/if}
			</header>

			{#if automationLoadError}
				<p class="text-sm text-down mb-3" role="alert">
					Failed to load automation config: {automationLoadError}
				</p>
			{/if}

			<!-- Watcher credentials sub-form -->
			<section class="mb-6">
				<h3 class="text-base font-medium mb-2">Watcher credentials</h3>
				<p class="text-xs text-muted mb-3">
					Run <code>cscli machines add arenet-writer</code> on your CrowdSec host and paste the resulting credentials here. Distinct from the read-side bouncer key (Step N): writes to LAPI require a watcher per CrowdSec's auth model.
				</p>
				<form
					class="grid grid-cols-1 md:grid-cols-2 gap-4"
					onsubmit={(e) => {
						e.preventDefault();
						void submitAutomationCredentials();
					}}
				>
					<div class="md:col-span-2">
						<label for="auto-lapi-url" class="text-sm font-medium text-secondary block mb-1">
							LAPI URL
						</label>
						<input
							id="auto-lapi-url"
							type="text"
							bind:value={credsForm.lapiUrl}
							placeholder="http://127.0.0.1:8080/"
							autocomplete="off"
							class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
						/>
					</div>
					<div>
						<label for="auto-machine-id" class="text-sm font-medium text-secondary block mb-1">
							Machine ID
						</label>
						<input
							id="auto-machine-id"
							type="text"
							bind:value={credsForm.machineId}
							placeholder="arenet-writer"
							autocomplete="off"
							class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
						/>
					</div>
					<div>
						<label for="auto-password" class="text-sm font-medium text-secondary block mb-1">
							Password
						</label>
						<input
							id="auto-password"
							type="password"
							autocomplete="off"
							bind:value={credsForm.password}
							placeholder={automationCreds.configured ? '••• set (leave blank to keep)' : ''}
							class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
						/>
					</div>
					{#if credsFormError}
						<p class="text-sm text-down md:col-span-2" role="alert">{credsFormError}</p>
					{/if}
					<div class="md:col-span-2 flex justify-end">
						<Button type="submit" disabled={credsSubmitting}>
							{credsSubmitting ? 'Saving…' : 'Save credentials'}
						</Button>
					</div>
				</form>
				<p class="text-xs text-muted mt-2">
					Submit with all three fields blank to erase the stored credentials and disable the auto-classify writer (operator may keep rules configured for a future re-enable).
				</p>
			</section>

			<!-- Per-category rule toggles -->
			<section>
				<h3 class="text-base font-medium mb-2">Trigger rules</h3>
				<p class="text-xs text-muted mb-3">
					Each category is disabled by default. When enabled, Arenet bans a source IP after <em>threshold</em> events in <em>window</em>, for <em>duration</em>, with a <em>cooldown</em> after an operator unban that suppresses re-ban for that long.
				</p>
				<form
					onsubmit={(e) => {
						e.preventDefault();
						void submitAutomationRules();
					}}
				>
					<div class="overflow-x-auto">
						<table class="w-full text-sm">
							<thead>
								<tr class="text-left text-xs text-secondary uppercase">
									<th class="py-2 pr-3">Category</th>
									<th class="py-2 px-2">Enabled</th>
									<th class="py-2 px-2">Threshold</th>
									<th class="py-2 px-2">Window</th>
									<th class="py-2 px-2">Duration</th>
									<th class="py-2 px-2">Cooldown</th>
								</tr>
							</thead>
							<tbody>
								{#each AUTOMATION_SOURCES as src (src)}
									<tr class="border-t border-border-subtle">
										<td class="py-2 pr-3 font-mono">{AUTOMATION_SOURCE_LABELS[src]}</td>
										<td class="py-2 px-2">
											<input
												type="checkbox"
												checked={getRule(src).enabled}
												onchange={(e) =>
													setRuleField(src, 'enabled', (e.target as HTMLInputElement).checked)}
												aria-label={`Enable ${AUTOMATION_SOURCE_LABELS[src]}`}
											/>
										</td>
										<td class="py-2 px-2">
											<input
												type="number"
												min="1"
												value={getRule(src).threshold}
												oninput={(e) =>
													setRuleField(src, 'threshold', Number((e.target as HTMLInputElement).value))}
												class="w-16 bg-surface border border-border-default rounded-md px-2 py-1 text-sm font-mono"
												aria-label={`Threshold for ${AUTOMATION_SOURCE_LABELS[src]}`}
											/>
										</td>
										<td class="py-2 px-2">
											<input
												type="text"
												value={nsToHuman(getRule(src).window_ns)}
												onchange={(e) =>
													setRuleField(src, 'window_ns', humanToNs((e.target as HTMLInputElement).value))}
												placeholder="60s"
												class="w-20 bg-surface border border-border-default rounded-md px-2 py-1 text-sm font-mono"
												aria-label={`Window for ${AUTOMATION_SOURCE_LABELS[src]}`}
											/>
										</td>
										<td class="py-2 px-2">
											<input
												type="text"
												value={nsToHuman(getRule(src).duration_ns)}
												onchange={(e) =>
													setRuleField(src, 'duration_ns', humanToNs((e.target as HTMLInputElement).value))}
												placeholder="4h"
												class="w-20 bg-surface border border-border-default rounded-md px-2 py-1 text-sm font-mono"
												aria-label={`Duration for ${AUTOMATION_SOURCE_LABELS[src]}`}
											/>
										</td>
										<td class="py-2 px-2">
											<input
												type="text"
												value={nsToHuman(getRule(src).cooldown_ns)}
												onchange={(e) =>
													setRuleField(src, 'cooldown_ns', humanToNs((e.target as HTMLInputElement).value))}
												placeholder="24h"
												class="w-20 bg-surface border border-border-default rounded-md px-2 py-1 text-sm font-mono"
												aria-label={`Cooldown for ${AUTOMATION_SOURCE_LABELS[src]}`}
											/>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
					{#if rulesFormError}
						<p class="text-sm text-down mt-3" role="alert">{rulesFormError}</p>
					{/if}
					<div class="flex justify-end mt-4">
						<Button type="submit" disabled={rulesSubmitting}>
							{rulesSubmitting ? 'Saving…' : 'Save rules'}
						</Button>
					</div>
				</form>
				<p class="text-xs text-muted mt-2">
					Cooldown defaults reflect category mistake-distribution: AUTH 7 days (operator unbans typically reflect real users), WAF SQLi/RCE/XSS/LFI 24 hours (suspected false positives), PROTOCOL/OTHER/Throttle 4 hours (maintenance-action unbans). Tune per-row.
				</p>
			</section>
		</Card>
	</div>

	<!-- ROW 2.75 — Forward-auth providers (Step K.1 §5.1).
	     Full-width like DNS provider: list of configured providers
	     with add/edit/delete + an inline form. The form pattern
	     mirrors the DNS provider's secret discipline — empty
	     clientSecret on PUT preserves the stored value, with the
	     "••• set (leave blank to keep)" placeholder. -->
	<div class="mb-6">
		<Card padding="p-6">
			<header class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4">
				<div>
					<h2 class="text-xl font-semibold">Forward-auth providers</h2>
					<p class="text-xs text-muted mt-1">
						Configure identity providers (Authelia / Authentik /
						Keycloak / generic) that routes delegate auth to.
					</p>
				</div>
				<Button onclick={openFwdAuthCreate}>+ Add provider</Button>
			</header>

			{#if fwdAuthLoading}
				<div class="flex items-center gap-2 py-4 text-secondary text-sm">
					<Spinner size="sm" /> Loading providers…
				</div>
			{:else if fwdAuthListError}
				<p class="text-sm text-down mb-3" role="alert">
					Failed to load forward-auth providers: {fwdAuthListError}
				</p>
			{:else if fwdAuthList.length === 0 && !fwdAuthFormOpen}
				<p class="text-sm text-secondary py-2">
					No forward-auth provider configured yet.
				</p>
			{:else}
				<div class="flex flex-col gap-2 mb-3">
					{#each fwdAuthList as p (p.name)}
						<div class="flex items-center justify-between border border-border-subtle rounded px-3 py-2">
							<div class="flex flex-col text-sm">
								<span class="font-mono text-primary">{p.name}</span>
								<span class="text-xs text-muted">
									{p.kind} · {p.verifyUrl}
									{#if p.clientSecretSet}
										· <span class="text-up">secret set</span>
									{:else}
										· <span class="text-secondary">no secret</span>
									{/if}
								</span>
							</div>
							<div class="flex items-center gap-1">
								<Button variant="ghost" size="sm" onclick={() => openFwdAuthEdit(p)}>
									Edit
								</Button>
								<Button variant="ghost" size="sm" onclick={() => deleteFwdAuth(p.name)}>
									Delete
								</Button>
							</div>
						</div>
					{/each}
				</div>
			{/if}

			{#if fwdAuthDeleteError}
				<p class="text-sm text-down mb-3" role="alert">{fwdAuthDeleteError}</p>
			{/if}

			{#if fwdAuthFormOpen}
				<form
					class="grid grid-cols-1 md:grid-cols-2 gap-4 border-t border-border-subtle pt-4"
					onsubmit={(e) => {
						e.preventDefault();
						void submitFwdAuth();
					}}
				>
					<div>
						<label for="fwdauth-name" class="text-sm font-medium text-secondary block mb-1">
							Name (slug)
						</label>
						<input
							id="fwdauth-name"
							type="text"
							bind:value={fwdAuthForm.name}
							placeholder="authelia-prod"
							disabled={fwdAuthEditingName !== null}
							class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono disabled:opacity-60 disabled:cursor-not-allowed"
						/>
						{#if fwdAuthEditingName !== null}
							<p class="text-xs text-muted mt-1">
								Name is immutable after creation.
							</p>
						{/if}
					</div>

					<div>
						<label for="fwdauth-kind" class="text-sm font-medium text-secondary block mb-1">
							Kind
						</label>
						<select
							id="fwdauth-kind"
							bind:value={fwdAuthForm.kind}
							class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
						>
							{#each FORWARD_AUTH_PROVIDER_KINDS as k (k)}
								<option value={k}>{k}</option>
							{/each}
						</select>
					</div>

					<div class="md:col-span-2">
						<label
							for="fwdauth-verify-url"
							class="text-sm font-medium text-secondary block mb-1"
						>
							Verify URL
						</label>
						<input
							id="fwdauth-verify-url"
							type="text"
							bind:value={fwdAuthForm.verifyUrl}
							placeholder="http://authelia:9091"
							class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
						/>
					</div>

					<div>
						<label
							for="fwdauth-auth-request-uri"
							class="text-sm font-medium text-secondary block mb-1"
						>
							Auth request URI
						</label>
						<input
							id="fwdauth-auth-request-uri"
							type="text"
							bind:value={fwdAuthForm.authRequestUri}
							placeholder="/api/authz/forward-auth"
							class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
						/>
					</div>

					<div>
						<label
							for="fwdauth-copy-headers"
							class="text-sm font-medium text-secondary block mb-1"
						>
							Copy headers (comma-separated)
						</label>
						<input
							id="fwdauth-copy-headers"
							type="text"
							bind:value={fwdAuthForm.copyHeaders}
							placeholder="Remote-User, Remote-Email"
							class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
						/>
					</div>

					<div class="md:col-span-2">
						<label
							for="fwdauth-client-secret"
							class="text-sm font-medium text-secondary block mb-1"
						>
							Client secret (optional)
						</label>
						<input
							id="fwdauth-client-secret"
							type="password"
							autocomplete="off"
							bind:value={fwdAuthForm.clientSecret}
							placeholder={fwdAuthEditingSecretSet
								? '••• set (leave blank to keep)'
								: ''}
							class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
						/>
					</div>

					<div class="md:col-span-2">
						<label
							for="fwdauth-passthrough"
							class="text-sm font-medium text-secondary block mb-1"
						>
							Auth passthrough prefix (optional)
						</label>
						<input
							id="fwdauth-passthrough"
							type="text"
							bind:value={fwdAuthForm.authPassthroughPrefix}
							placeholder="/outpost.goauthentik.io"
							class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
						/>
						<p class="text-xs text-muted mt-1">
							Path prefix served by the IdP itself on the
							application's host (e.g. <code class="font-mono">/outpost.goauthentik.io</code> for
							Authentik embedded outpost, <code class="font-mono">/oauth2</code> for
							oauth2-proxy). Requests under this prefix bypass
							the forward_auth gate and are reverse-proxied
							directly to the verify URL host. Leave empty for
							providers that don't need it (Authelia standalone,
							generic).
						</p>
					</div>

					<div class="md:col-span-2">
						<label class="inline-flex items-start gap-2 text-sm font-medium text-secondary">
							<input
								type="checkbox"
								bind:checked={fwdAuthForm.rewriteVerifyHost}
								class="mt-0.5 rounded border-border-default bg-surface text-cyan focus:ring-cyan"
							/>
							<span>
								Rewrite Host of verify sub-request to verify URL host
								<span class="block text-xs font-normal text-muted mt-0.5">
									Required for Authentik embedded outpost (Authentik
									routes apps by Host header on its core listener).
									Leave unchecked for Authelia, Keycloak, oauth2-proxy,
									and Authentik external outpost — they all accept the
									client's Host (canonical Caddy forward_auth shape).
								</span>
							</span>
						</label>
					</div>

					{#if fwdAuthFormError}
						<p class="text-sm text-down md:col-span-2" role="alert">{fwdAuthFormError}</p>
					{/if}

					<div class="md:col-span-2 flex justify-end gap-2">
						<Button variant="ghost" onclick={() => (fwdAuthFormOpen = false)} type="button">
							Cancel
						</Button>
						<Button type="submit" disabled={fwdAuthSubmitting}>
							{fwdAuthSubmitting
								? 'Saving…'
								: fwdAuthEditingName === null
									? 'Create'
									: 'Save'}
						</Button>
					</div>
				</form>
			{/if}
		</Card>
	</div>

	<!-- ROW 2.85 — OIDC SSO (Step K.2 §5.2). Self-contained
	     component to keep the settings page tractable. -->
	<OIDCSettingsSection />

	<!-- ROW 2.9 — Backup & restore (Step K.3 §5.3). -->
	<BackupSection />

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

	<!-- Step O.4 — delete-managed-domain dialog with revertTo
	     dropdown (AC #21). Built on Modal directly rather than
	     ConfirmDialog so the operator picks the post-revert
	     ACMEChallenge value before confirming. The warning text
	     explicitly calls out the rate-limit risk of the "" /
	     "http-01" choices when the operator has many covered
	     routes. -->
	{#if mdDeleteOpen}
		<Modal
			open={mdDeleteOpen}
			title={`Delete managed domain ${mdDeleteApex}?`}
			onClose={() => (mdDeleteOpen = false)}
		>
			{#snippet children()}
				<p class="text-sm text-secondary mb-3">
					Covered routes' ACMEChallenge will be reverted. Pick the
					post-revert challenge value below.
				</p>
				<div class="mb-3">
					<label
						for="md-delete-revert-to"
						class="text-sm font-medium text-secondary block mb-1"
					>
						Revert covered routes to
					</label>
					<select
						id="md-delete-revert-to"
						bind:value={mdDeleteRevertTo}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					>
						<option value="">Default (HTTP-01 on next reload)</option>
						<option value="http-01">Explicit HTTP-01</option>
						<option value="dns-01">Explicit DNS-01</option>
					</select>
				</div>
				{#if mdDeleteRevertTo === '' || mdDeleteRevertTo === 'http-01'}
					<p
						class="text-sm text-warn rounded border border-warn/40 bg-warn/10 px-3 py-2"
						role="alert"
					>
						<strong>Heads up.</strong> Each covered route will request its own HTTP-01
						cert on the next reload. Many routes on one apex may hit Let's
						Encrypt's per-domain rate limit (50 certs / week).
					</p>
				{/if}
				{#if mdDeleteError}
					<p class="text-sm text-down mt-3" role="alert">{mdDeleteError}</p>
				{/if}
			{/snippet}
			{#snippet footer()}
				<Button variant="ghost" onclick={() => (mdDeleteOpen = false)}>Cancel</Button>
				<Button variant="danger" onclick={() => void confirmDeleteManagedDomain()}
					>Delete</Button
				>
			{/snippet}
		</Modal>
	{/if}
</div>
