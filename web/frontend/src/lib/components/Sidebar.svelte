<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Sidebar (Step F §5.2 — Chunk 3.4 refonte). Pinned-collapsible primary
  nav + footer block with user avatar, theme indicator and the
  expand/collapse toggle. Collapsed state persists in localStorage
  under arenet_sidebar_collapsed.

  Public API (add-only per §1.3): `collapsed` (bindable boolean,
  default false). Caller can still drive it from outside; the
  store-side onMount() picks up the persisted value if any and
  overrides the default — bindable means the caller sees that.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { fade } from 'svelte/transition';
	import { page } from '$app/state';
	import StatusDot from './StatusDot.svelte';
	import Tooltip from './Tooltip.svelte';
	import { auth } from '$lib/stores/auth.svelte';
	import { theme } from '$lib/stores/theme.svelte';

	interface Props {
		collapsed?: boolean;
	}

	let { collapsed = $bindable(false) }: Props = $props();

	// Persistence (Step F §5.2). The collapsed state lives in
	// localStorage under arenet_sidebar_collapsed; it is read once
	// at mount and written on every toggle. SSR-safe via the typeof
	// guard; private-browsing failures swallow silently.
	const SIDEBAR_LS_KEY = 'arenet_sidebar_collapsed';

	onMount(() => {
		try {
			const stored = localStorage.getItem(SIDEBAR_LS_KEY);
			if (stored === 'true') collapsed = true;
			else if (stored === 'false') collapsed = false;
		} catch (_) {
			// Private-browsing / quota — keep the default (or whatever
			// the caller passed via the bindable prop).
		}
	});

	function toggleCollapsed(): void {
		collapsed = !collapsed;
		try {
			localStorage.setItem(SIDEBAR_LS_KEY, String(collapsed));
		} catch (_) {
			// Same fallback as mount — non-fatal.
		}
	}

	type IconName = 'routes' | 'audit' | 'topology' | 'security' | 'settings' | 'users';

	type Item = {
		href: string;
		label: string;
		icon: IconName;
		disabled?: boolean;
		tooltip?: string;
	};

	// Step D inserts Audit between Routes and Topology (spec §6.12).
	// Step E enables Topology and switches its icon to Lucide `network`.
	// Step F Chunk 1.6 added a placeholder /settings page (route exists
	// + cliquable), so Settings is no longer disabled. Security remains
	// disabled until Phase 2 ships an actual /security view.
	// Step K.2 adds /admin/users, admin-only — filtered out for viewers.
	const baseItems: Item[] = [
		{ href: '/routes', label: 'Routes', icon: 'routes' },
		{ href: '/audit', label: 'Audit', icon: 'audit' },
		{ href: '/topology', label: 'Topology', icon: 'topology' },
		{ href: '/security', label: 'Security', icon: 'security', disabled: true, tooltip: 'Coming soon' },
		{ href: '/admin/users', label: 'Users', icon: 'users' },
		{ href: '/settings', label: 'Settings', icon: 'settings' }
	];
	const items = $derived(
		baseItems.filter((it) => it.href !== '/admin/users' || auth.user?.role === 'admin')
	);

	const currentPath = $derived(page.url.pathname);
	const isActive = (href: string) => currentPath === href;

	// Footer block helpers (Step F §5.2 footer pinned).
	const userInitial = $derived(
		(auth.user?.displayName || auth.user?.username || '?').slice(0, 1).toUpperCase()
	);
	const userLabel = $derived(auth.user?.displayName || auth.user?.username || '');
</script>

{#snippet itemIcon(icon: IconName)}
	<svg
		class="w-[18px] h-[18px] shrink-0"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		stroke-width="2"
		stroke-linecap="round"
		stroke-linejoin="round"
		aria-hidden="true"
	>
		{#if icon === 'routes'}
			<!-- Lucide: share-2 -->
			<circle cx="18" cy="5" r="3" />
			<circle cx="6" cy="12" r="3" />
			<circle cx="18" cy="19" r="3" />
			<line x1="8.59" x2="15.42" y1="13.51" y2="17.49" />
			<line x1="15.41" x2="8.59" y1="6.51" y2="10.49" />
		{:else if icon === 'audit'}
			<!-- Lucide: activity -->
			<path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.5.5 0 0 1-.96 0L9.24 2.18a.5.5 0 0 0-.96 0l-2.35 8.36A2 2 0 0 1 4 12H2" />
		{:else if icon === 'topology'}
			<!-- Lucide: network -->
			<rect x="16" y="16" width="6" height="6" rx="1" />
			<rect x="2" y="16" width="6" height="6" rx="1" />
			<rect x="9" y="2" width="6" height="6" rx="1" />
			<path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3" />
			<path d="M12 12V8" />
		{:else if icon === 'security'}
			<!-- Lucide: shield -->
			<path
				d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"
			/>
		{:else if icon === 'settings'}
			<!-- Lucide: settings -->
			<path
				d="M9.671 4.136a2.34 2.34 0 0 1 4.659 0 2.34 2.34 0 0 0 3.319 1.915 2.34 2.34 0 0 1 2.33 4.033 2.34 2.34 0 0 0 0 3.831 2.34 2.34 0 0 1-2.33 4.033 2.34 2.34 0 0 0-3.319 1.915 2.34 2.34 0 0 1-4.659 0 2.34 2.34 0 0 0-3.32-1.915 2.34 2.34 0 0 1-2.33-4.033 2.34 2.34 0 0 0 0-3.831A2.34 2.34 0 0 1 6.35 6.051a2.34 2.34 0 0 0 3.319-1.915"
			/>
			<circle cx="12" cy="12" r="3" />
		{:else if icon === 'users'}
			<!-- Lucide: users -->
			<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
			<circle cx="9" cy="7" r="4" />
			<path d="M22 21v-2a4 4 0 0 0-3-3.87" />
			<path d="M16 3.13a4 4 0 0 1 0 7.75" />
		{/if}
	</svg>
{/snippet}

<aside
	class="sidebar flex flex-col bg-sidebar border-r border-border-subtle h-screen sticky top-0"
	style:width={collapsed ? '64px' : '256px'}
	aria-label="Primary"
>
	<div class="px-4 py-5 border-b border-border-subtle">
		<span class="font-mono text-base font-bold tracking-widest">
			<span class="text-cyan">A</span><span class:hidden={collapsed}>RENET</span>
		</span>
	</div>

	<nav class="flex-1 py-3 flex flex-col gap-1">
		{#each items as item (item.href)}
			{@const active = isActive(item.href)}
			{#if collapsed}
				<Tooltip label={item.tooltip ?? item.label} side="right">
					{#snippet children()}
						<a
							href={item.disabled ? undefined : item.href}
							aria-current={active ? 'page' : undefined}
							aria-disabled={item.disabled ? 'true' : undefined}
							tabindex={item.disabled ? -1 : 0}
							class="nav-item nav-item-collapsed mx-2 px-3 py-2 rounded-md text-sm transition-colors flex items-center gap-3"
							class:active
							class:disabled={item.disabled}
						>
							{@render itemIcon(item.icon)}
						</a>
					{/snippet}
				</Tooltip>
			{:else}
				<a
					href={item.disabled ? undefined : item.href}
					title={item.tooltip ?? item.label}
					aria-current={active ? 'page' : undefined}
					aria-disabled={item.disabled ? 'true' : undefined}
					tabindex={item.disabled ? -1 : 0}
					class="nav-item mx-2 px-3 py-2 rounded-md text-sm transition-colors flex items-center gap-3"
					class:active
					class:disabled={item.disabled}
				>
					{@render itemIcon(item.icon)}
					<span>{item.label}</span>
				</a>
			{/if}
		{/each}
	</nav>

	<!-- Footer block (Step F §5.2). Mounts with a 200 ms fade so it
	     doesn't pop in cold on first paint; the parent aside is
	     persistent so the fade fires once per session, not on every
	     route change. -->
	<div
		class="sidebar-footer px-4 py-3 border-t border-border-subtle flex flex-col gap-2"
		transition:fade={{ duration: 200 }}
	>
		<!-- Connection status. The StatusDot is small (8x8); wrapping
		     it in a 24x24 .footer-icon-slot aligns its trailing label
		     with the avatar/theme rows (Chunk 3.5 smoke fix). -->
		<div class="flex items-center gap-2 text-xs" class:justify-center={collapsed}>
			<span class="footer-icon-slot">
				<StatusDot status="up" />
			</span>
			<span class:hidden={collapsed} class="text-secondary">Connected</span>
		</div>

		<!-- User identity (avatar with initial + display name when expanded). -->
		<div class="flex items-center gap-2 text-sm" class:justify-center={collapsed}>
			<span
				class="avatar inline-flex items-center justify-center w-6 h-6 rounded-full bg-elevated border border-border-default shrink-0"
				aria-label={`Signed in as ${userLabel}`}
			>
				{userInitial}
			</span>
			<span class:hidden={collapsed} class="text-primary truncate">{userLabel}</span>
		</div>

		<!-- Theme indicator (passive — does not toggle; the active
		     control lives in Settings). Sun for light, moon for dark.
		     Reads theme.current directly so it tracks the store.
		     The icon (14x14 sun/moon) sits inside a 24x24 .footer-icon-slot
		     so the trailing label aligns with the other footer rows. -->
		<div class="flex items-center gap-2 text-xs" class:justify-center={collapsed}>
			<span class="footer-icon-slot text-muted" aria-hidden="true">
				{#if theme.current === 'light'}
					<!-- Lucide: sun -->
					<svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
						<circle cx="12" cy="12" r="4" />
						<path d="M12 2v2" />
						<path d="M12 20v2" />
						<path d="m4.93 4.93 1.41 1.41" />
						<path d="m17.66 17.66 1.41 1.41" />
						<path d="M2 12h2" />
						<path d="M20 12h2" />
						<path d="m6.34 17.66-1.41 1.41" />
						<path d="m19.07 4.93-1.41 1.41" />
					</svg>
				{:else}
					<!-- Lucide: moon -->
					<svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
						<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
					</svg>
				{/if}
			</span>
			<span class:hidden={collapsed} class="text-secondary capitalize">{theme.current}</span>
		</div>

		<!-- Expand / collapse toggle (chevron). -->
		<button
			type="button"
			class="collapse-btn text-xs text-secondary hover:text-primary self-start transition-colors"
			class:self-center={collapsed}
			aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
			onclick={toggleCollapsed}
		>
			{#if collapsed}
				<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
					<!-- Lucide: chevrons-right -->
					<path d="m6 17 5-5-5-5" />
					<path d="m13 17 5-5-5-5" />
				</svg>
			{:else}
				<span class="inline-flex items-center gap-1">
					<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
						<!-- Lucide: chevrons-left -->
						<path d="m11 17-5-5 5-5" />
						<path d="m18 17-5-5 5-5" />
					</svg>
					Collapse
				</span>
			{/if}
		</button>
	</div>
</aside>

<style>
	.sidebar {
		/* Width change drives the collapse animation; CSS transition
		 * uses var(--motion-base) so a future global tweak applies
		 * uniformly. Previously this was Tailwind's transition-[width]
		 * duration-200 utility which hardcoded 200ms; the token-based
		 * form is equivalent today but follows the design system. */
		transition: width var(--motion-base);
	}
	.nav-item {
		position: relative;
		color: var(--text-secondary);
	}
	.nav-item:hover:not(.disabled) {
		background-color: var(--bg-hover);
		color: var(--text-primary);
	}
	.nav-item.active {
		color: var(--text-primary);
		background-color: var(--bg-hover);
		box-shadow: var(--shadow-glow-cyan);
	}
	/* Cyan rail on the left edge of the active item. The fixed-position
	 * approach keeps it independent of the item's content height. */
	.nav-item.active::before {
		content: '';
		position: absolute;
		left: -8px;
		top: var(--space-2);
		bottom: var(--space-2);
		width: 4px;
		border-radius: 2px;
		background-color: var(--accent-cyan);
	}
	.nav-item.disabled {
		color: var(--text-muted);
		cursor: not-allowed;
		pointer-events: none;
	}
	/* Collapsed items center their icon (no label rendered). */
	.nav-item-collapsed {
		justify-content: center;
	}
	.avatar {
		font-size: var(--text-xs);
		font-weight: 600;
		color: var(--text-secondary);
		line-height: 1;
	}
	/* 24x24 wrapper for footer-row icons so labels (Connected /
	 * username / theme name) align under each other regardless of
	 * the icon's intrinsic size. Avatar is already 24x24 so it
	 * does not need this class; StatusDot (8x8) and the theme
	 * sun/moon SVG (14x14) do. Chunk 3.5 smoke fix. */
	.footer-icon-slot {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 24px;
		height: 24px;
		flex-shrink: 0;
	}
</style>
