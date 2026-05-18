<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Root layout shell (spec §6.7). Drives the auth state machine and
  hosts the always-mounted ChangePasswordModal, the conditional
  LockScreen overlay, the compromised-password banner, and the
  heartbeat lifecycle.

  State transitions:

    unknown      → centered Spinner (bootstrap pending)
    anonymous    → render children unchanged (so /login and /setup,
                   which use +layout@.svelte resets, take over)
                   + redirect non-login/setup paths to /login
    authenticated → Sidebar + main + optional banner + LockScreen=false
    locked       → Sidebar + main + LockScreen overlay (z-1000)

  Bootstrap runs once at mount. Subsequent state changes happen via
  the API client interceptors (401 → clear, 403 → setLocked) and the
  client-side idle timer.
-->
<script lang="ts">
	import '../app.css';
	import { onMount, onDestroy } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import favicon from '$lib/assets/favicon.svg';
	import Sidebar from '$lib/components/Sidebar.svelte';
	import LockScreen from '$lib/components/LockScreen.svelte';
	import ChangePasswordModal from '$lib/components/ChangePasswordModal.svelte';
	import ToastContainer from '$lib/components/ToastContainer.svelte';
	import Button from '$lib/components/Button.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import { loading } from '$lib/stores/loading';
	import { auth } from '$lib/stores/auth.svelte';
	import { idle } from '$lib/stores/idle.svelte';
	import { authApi } from '$lib/api/auth';

	const HEARTBEAT_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes (spec §6.7)
	const SIDEBAR_STORAGE_KEY = 'arenet.sidebar.collapsed';

	let { children } = $props();

	let collapsed = $state(false);
	let heartbeatId: ReturnType<typeof setInterval> | null = null;
	let changePasswordModalOpen = $state(false);

	onMount(async () => {
		// Restore sidebar collapsed preference (Step C).
		try {
			const stored = localStorage.getItem(SIDEBAR_STORAGE_KEY);
			if (stored === 'true') collapsed = true;
		} catch {
			/* localStorage unavailable (private mode, etc.) — ignore */
		}

		// Bootstrap the auth store. This call sets state to one of
		// authenticated / locked / anonymous (or leaves unknown on
		// network failure so the user can refresh).
		await auth.bootstrap();

		// Wire idle timer + heartbeat once we know we're in a session
		// (locked is still a valid session — the lock just gates
		// hard-auth endpoints).
		if (auth.state === 'authenticated' || auth.state === 'locked') {
			idle.start();
			startHeartbeat();
		}

		// Redirect anonymous users to /login unless they are already
		// on /login or /setup (avoid redirect loops). The /setup path
		// is discovered via the "First time?" link on /login per
		// spec §6.7 (no automatic detection).
		if (auth.state === 'anonymous') {
			const here = page.url.pathname;
			if (here !== '/login' && here !== '/setup') {
				void goto('/login');
			}
		}
	});

	onDestroy(() => {
		idle.stop();
		stopHeartbeat();
	});

	$effect(() => {
		// Persist sidebar collapsed preference (Step C).
		try {
			localStorage.setItem(SIDEBAR_STORAGE_KEY, String(collapsed));
		} catch {
			/* ignore */
		}
	});

	function startHeartbeat(): void {
		if (heartbeatId !== null) return;
		heartbeatId = setInterval(() => {
			// Tab-visibility gate: do nothing in background tabs.
			if (typeof document !== 'undefined' && document.visibilityState !== 'visible') {
				return;
			}
			// State gate: heartbeat only when actively authenticated
			// (locked sessions get a 403 from /heartbeat, handled by
			// the interceptor; we skip to avoid the noise).
			if (auth.state !== 'authenticated') return;
			authApi.heartbeat().catch((err) => {
				// 401 and 403 already handled by the client interceptor.
				// Anything else: log and continue.
				console.warn('heartbeat failed:', err);
			});
		}, HEARTBEAT_INTERVAL_MS);
	}

	function stopHeartbeat(): void {
		if (heartbeatId !== null) {
			clearInterval(heartbeatId);
			heartbeatId = null;
		}
	}
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>Arenet</title>
</svelte:head>

{#if auth.state === 'unknown'}
	<!-- Bootstrap in flight: minimal centered spinner, no chrome.
	     Prevents flashing /login before /me resolves. -->
	<div class="flex items-center justify-center min-h-screen bg-base">
		<Spinner size="lg" />
	</div>
{:else if auth.state === 'anonymous'}
	<!-- /login and /setup own their layout via +layout@.svelte resets.
	     For any other path we already redirected in onMount; this
	     branch covers /login and /setup as a passthrough. -->
	{@render children?.()}
	<ToastContainer />
{:else}
	<!-- authenticated or locked: full layout. Compromised-password
	     banner above; LockScreen overlay on locked. -->
	{#if auth.user?.passwordCompromised}
		<div
			class="bg-down/10 border-b border-down text-down px-6 py-3 flex items-center justify-between"
			role="alert"
		>
			<div>
				<strong>Your password has been found in a known data breach.</strong>
				Change it immediately to secure your account.
			</div>
			<Button
				variant="danger"
				size="sm"
				onclick={() => (changePasswordModalOpen = true)}
			>
				{#snippet children()}Change password{/snippet}
			</Button>
		</div>
	{/if}

	<div class="flex min-h-screen">
		<Sidebar bind:collapsed />
		<main class="flex-1 p-6 relative" aria-busy={$loading} aria-live="polite">
			{#if $loading}
				<div class="absolute left-0 right-0 top-0 h-0.5 overflow-hidden">
					<div class="h-full w-1/3 bg-cyan loading-shimmer"></div>
				</div>
			{/if}
			{@render children?.()}
		</main>
	</div>

	<ToastContainer />

	<!-- Always mounted: preserves form state across show/hide. -->
	<ChangePasswordModal bind:open={changePasswordModalOpen} />

	{#if auth.state === 'locked'}
		<LockScreen />
	{/if}
{/if}

<style>
	.loading-shimmer {
		animation: shimmer 1.5s ease-in-out infinite;
	}
	@keyframes shimmer {
		0% {
			transform: translateX(-100%);
		}
		100% {
			transform: translateX(400%);
		}
	}
</style>
