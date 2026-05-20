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

	onMount(() => {
		void loadSessions();
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
				<!-- DataTable rows are clickable by design (Chunk 3.2 expand
				     toggle) but we don't provide an expanded snippet here,
				     so the click toggles unused internal state. Cosmetic
				     dette pre-existing; tracked for Step G cleanup. -->
				<DataTable
					headers={['Issued', 'Last activity', 'IP', 'Browser', 'Status', '']}
					items={sessions}
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
					href="https://github.com/barto95100/arenet/blob/{import.meta.env
						.VITE_APP_VERSION}/LICENSE"
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
