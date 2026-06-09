<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Sidebar (Step R.2 refonte). Fixed-width primary nav matching the
  mock at docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html
  :655-714. Replaces the Step F collapsed/expanded sidebar with a
  fixed 232px layout — the mock is intentionally not collapsible.

  Structure: brand block (gradient mark + name + env pill) + 4
  nav-sections (Aperçu / Trafic / Sécurité / Administration) +
  10 nav items + sidebar-foot (avatar + identity + sign-out).

  Per spec D8 outcome, /security/decisions and /security/[routeId]
  are NOT exposed in the sidebar — they remain reachable via
  "Voir tout" links injected from /waf + /routes detail pages
  in R.4. Same for /admin/users which is still routed but the
  sidebar entry points to the new /users top-level route.

  Step CS.2 follow-up: /audit IS exposed (Administration
  section, after Settings). Operator-flagged gap
  (#R-AUDIT-not-in-nav from docs/backlog-crowdsec.md): the
  page existed but had no menu link, forcing operators to
  type the URL by hand. Distinct from /security/decisions
  which is intentionally hidden — /audit has no equivalent
  contextual entry point elsewhere in the app, so the sidebar
  is the right home.

  Admin-only filter: viewer-role users see Aperçu / Trafic /
  Sécurité; the Administration section is hidden in its entirety.

  Width is locked to var(--sb-width); no collapsed mode (mock has
  no collapse button, by design).
-->
<script lang="ts">
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { auth } from '$lib/stores/auth.svelte';

	type IconName =
		| 'dashboard'
		| 'topology'
		| 'map'
		| 'routes'
		| 'logs'
		| 'waf'
		| 'security'
		| 'certs'
		| 'users'
		| 'settings'
		| 'audit';

	type NavItem = {
		href: string;
		label: string;
		icon: IconName;
		adminOnly?: boolean;
	};

	type NavSection = {
		label: string;
		items: NavItem[];
		adminOnly?: boolean;
	};

	const sections: NavSection[] = [
		{
			label: 'Aperçu',
			items: [
				{ href: '/dashboard', label: 'Dashboard', icon: 'dashboard' },
				{ href: '/topology', label: 'Topology', icon: 'topology' },
				{ href: '/map', label: 'Map', icon: 'map' }
			]
		},
		{
			label: 'Trafic',
			items: [
				{ href: '/routes', label: 'Routes', icon: 'routes' },
				{ href: '/logs', label: 'Logs', icon: 'logs' }
			]
		},
		{
			label: 'Sécurité',
			items: [
				{ href: '/waf', label: 'WAF', icon: 'waf' },
				{ href: '/security', label: 'Security', icon: 'security' },
				{ href: '/certs', label: 'Certificates', icon: 'certs' }
			]
		},
		{
			label: 'Administration',
			adminOnly: true,
			items: [
				{ href: '/users', label: 'Utilisateurs', icon: 'users', adminOnly: true },
				{ href: '/settings', label: 'Settings', icon: 'settings', adminOnly: true },
				// Step CS.2 follow-up — /audit operator-flagged
				// nav gap. Page existed but had no sidebar entry,
				// so operators were forced to type the URL.
				// Placed after Settings (sibling admin surface).
				{ href: '/audit', label: 'Audit log', icon: 'audit', adminOnly: true }
			]
		}
	];

	const isAdmin = $derived(auth.user?.role === 'admin');
	const visibleSections = $derived(sections.filter((s) => !s.adminOnly || isAdmin));

	const currentPath = $derived(page.url.pathname);
	function isActive(href: string): boolean {
		// Exact-match for clean hrefs; for /security we DO want it active
		// only on the exact /security route, not on /security/decisions
		// or /security/[routeId] (those have their own context per D8).
		return currentPath === href;
	}

	// Identity block: 2-letter avatar derived from displayName / username.
	const userInitials = $derived(
		(() => {
			const name = auth.user?.displayName || auth.user?.username || '?';
			const parts = name.split(/\s+/).filter(Boolean);
			if (parts.length >= 2) {
				return (parts[0][0] + parts[1][0]).toUpperCase();
			}
			return name.slice(0, 2).toUpperCase();
		})()
	);
	const userLabel = $derived(auth.user?.displayName || auth.user?.username || '');
	const userRole = $derived(auth.user?.role ?? '');

	// Sign-out (preserved from Step F sidebar). Sign-out lives in the
	// sidebar-foot as an icon button to the right of the identity block,
	// per the mock's compact footer layout.
	let signingOut = $state(false);
	async function signOut(): Promise<void> {
		if (signingOut) return;
		signingOut = true;
		try {
			await auth.logout();
		} finally {
			signingOut = false;
			void goto('/login');
		}
	}
</script>

{#snippet itemIcon(icon: IconName)}
	<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
		{#if icon === 'dashboard'}
			<rect x="2" y="2" width="5" height="6" rx="1" />
			<rect x="9" y="2" width="5" height="4" rx="1" />
			<rect x="2" y="10" width="5" height="4" rx="1" />
			<rect x="9" y="8" width="5" height="6" rx="1" />
		{:else if icon === 'topology'}
			<circle cx="3" cy="3" r="1.5" />
			<circle cx="3" cy="13" r="1.5" />
			<circle cx="13" cy="3" r="1.5" />
			<circle cx="13" cy="13" r="1.5" />
			<circle cx="8" cy="8" r="2" />
			<path d="M4.2 4 6.5 6.6M9.5 6.6 11.8 4M4.2 12 6.5 9.4M9.5 9.4 11.8 12" />
		{:else if icon === 'map'}
			<circle cx="8" cy="8" r="6" />
			<path d="M2 8h12M8 2c2 1.8 2 10.2 0 12M8 2c-2 1.8-2 10.2 0 12" />
		{:else if icon === 'routes'}
			<circle cx="3" cy="8" r="2" />
			<circle cx="13" cy="8" r="2" />
			<path d="M5 8h6" />
		{:else if icon === 'logs'}
			<path d="M3 3h10v10H3z" />
			<path d="M5 6h6M5 8.5h6M5 11h4" />
		{:else if icon === 'waf'}
			<path d="M8 1l5 2v5c0 3.5-2.5 6-5 7-2.5-1-5-3.5-5-7V3l5-2z" />
		{:else if icon === 'security'}
			<rect x="3" y="7" width="10" height="7" rx="1" />
			<path d="M5 7V5a3 3 0 016 0v2" />
		{:else if icon === 'certs'}
			<rect x="2.5" y="3" width="11" height="8" rx="1" />
			<path d="M5.5 13l1 2 1.5-1 1.5 1 1-2" />
			<circle cx="8" cy="7" r="2" />
		{:else if icon === 'users'}
			<circle cx="6" cy="5.5" r="2.5" />
			<path d="M1.5 13.5c.5-2.5 2.4-4 4.5-4s4 1.5 4.5 4" />
			<circle cx="11.5" cy="6.5" r="1.8" />
			<path d="M11.5 10c1.7 0 3 1.1 3.2 2.8" />
		{:else if icon === 'settings'}
			<circle cx="8" cy="8" r="2" />
			<path d="M8 1v2M8 13v2M1 8h2M13 8h2M3 3l1.5 1.5M11.5 11.5L13 13M3 13l1.5-1.5M11.5 4.5L13 3" />
		{:else if icon === 'audit'}
			<!-- Clipboard / ledger glyph: document outline + clip + 3 horizontal rows. -->
			<rect x="3.5" y="3" width="9" height="11" rx="1" />
			<rect x="6" y="1.75" width="4" height="2.5" rx="0.5" fill="currentColor" stroke="none" />
			<path d="M5.5 7h5M5.5 9.25h5M5.5 11.5h3" />
		{/if}
	</svg>
{/snippet}

<aside class="sidebar" aria-label="Primary">
	<div class="brand">
		<div class="brand-mark" aria-hidden="true">A</div>
		<div class="brand-name">AreNET</div>
		<div class="brand-env">dev</div>
	</div>

	{#each visibleSections as section (section.label)}
		<div class="nav-section">{section.label}</div>
		{#each section.items as item (item.href)}
			{@const active = isActive(item.href)}
			<a
				href={item.href}
				class="nav-item"
				class:active
				aria-current={active ? 'page' : undefined}
			>
				{@render itemIcon(item.icon)}
				<span>{item.label}</span>
			</a>
		{/each}
	{/each}

	<div class="sidebar-foot">
		<div class="avatar" aria-label={`Signed in as ${userLabel}`}>{userInitials}</div>
		<div class="who">
			{userLabel}
			<small>{userRole}</small>
		</div>
		<button
			type="button"
			class="signout"
			aria-label="Sign out"
			title="Sign out"
			disabled={signingOut}
			onclick={signOut}
		>
			<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
				<path d="M6 13H4a1 1 0 01-1-1V4a1 1 0 011-1h2" />
				<path d="M10 11l3-3-3-3" />
				<line x1="13" y1="8" x2="6" y2="8" />
			</svg>
		</button>
	</div>
</aside>

<style>
	.sidebar {
		width: var(--sb-width);
		background: oklch(13% 0.005 250);
		border-right: 1px solid var(--border);
		padding: 18px 12px;
		display: flex;
		flex-direction: column;
		gap: 4px;
		position: sticky;
		top: 0;
		height: 100vh;
		flex: none;
	}

	.brand {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 6px 8px 18px;
		margin-bottom: 6px;
		border-bottom: 1px solid var(--border);
	}
	.brand-mark {
		width: 30px;
		height: 30px;
		border-radius: 7px;
		background: linear-gradient(140deg, var(--accent) 0%, oklch(52% 0.22 265) 100%);
		display: grid;
		place-items: center;
		color: #fff;
		font-family: var(--font-display);
		font-weight: 600;
		font-size: 15px;
		letter-spacing: -0.02em;
		box-shadow: inset 0 1px 0 oklch(82% 0.18 250 / 0.5), 0 1px 0 oklch(0% 0 0 / 0.4);
	}
	.brand-name {
		font-family: var(--font-display);
		font-size: 16px;
		font-weight: 600;
		letter-spacing: -0.02em;
		color: var(--fg);
	}
	.brand-env {
		margin-left: auto;
		font-family: var(--font-mono);
		font-size: 10px;
		color: var(--fg-muted);
		background: var(--surface);
		border: 1px solid var(--border);
		padding: 2px 6px;
		border-radius: 4px;
		letter-spacing: 0.04em;
		text-transform: uppercase;
	}

	.nav-section {
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.08em;
		text-transform: uppercase;
		color: var(--fg-dim);
		padding: 14px 10px 6px;
	}

	.nav-item {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 7px 10px;
		border-radius: var(--radius-sm);
		color: var(--fg-muted);
		font-size: 13.5px;
		font-weight: 450;
		text-decoration: none;
		transition: background 0.12s, color 0.12s;
	}
	.nav-item:hover {
		background: var(--surface);
		color: var(--fg);
	}
	.nav-item.active {
		background: var(--accent-soft);
		color: oklch(82% 0.16 255);
		box-shadow: inset 2px 0 0 var(--accent);
	}
	.nav-item .ic {
		width: 16px;
		height: 16px;
		flex: none;
		opacity: 0.9;
	}

	.sidebar-foot {
		margin-top: auto;
		padding: 10px;
		border-top: 1px solid var(--border);
		display: flex;
		align-items: center;
		gap: 10px;
	}
	.avatar {
		width: 28px;
		height: 28px;
		border-radius: 50%;
		background: var(--surface-hi);
		display: grid;
		place-items: center;
		font-size: 11px;
		font-weight: 500;
		color: var(--fg);
		font-family: var(--font-mono);
		flex: none;
	}
	.who {
		font-size: 12.5px;
		line-height: 1.25;
		color: var(--fg);
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.who small {
		display: block;
		color: var(--fg-dim);
		font-size: 11px;
		text-transform: capitalize;
	}
	.signout {
		width: 26px;
		height: 26px;
		display: grid;
		place-items: center;
		background: transparent;
		border: 1px solid transparent;
		border-radius: var(--radius-sm);
		color: var(--fg-muted);
		cursor: pointer;
		flex: none;
		transition: background 0.12s, color 0.12s, border-color 0.12s;
	}
	.signout:hover:not(:disabled) {
		background: var(--surface);
		color: var(--fg);
		border-color: var(--border);
	}
	.signout:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.signout svg {
		width: 14px;
		height: 14px;
	}
</style>
