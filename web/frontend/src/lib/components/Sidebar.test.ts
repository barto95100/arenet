// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Sidebar component tests (Step R.2 refonte + CS.2 follow-up).
//
// The mock at docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html
// :655-714 specifies 4 nav-sections (Aperçu / Trafic / Sécurité /
// Administration) + 10 nav items + a sidebar-foot with avatar +
// identity + sign-out icon. There is no collapsed mode (the prior
// Step F tests covered collapse+expand; those assertions are
// dropped because the feature is removed by design).
//
// CS.2 follow-up: Administration section now contains 3 items
// (Utilisateurs / Settings / Audit log) — total 11 admin-visible
// items. The /audit entry closes #R-AUDIT-not-in-nav (operator
// flagged that the page existed but had no menu link). Note
// CS.3 update: /security/decisions was deleted; its content
// moved into the CrowdSec parent tab on /security (URL
// ?tab=crowdsec). The /security entry alone covers both Vue
// d'ensemble and CrowdSec drill-down. The /security/[routeId]
// per-route page remains intentionally hidden per R.4 D8
// design rationale documented in Sidebar.svelte's header.
//
// Sidebar depends on:
//   - $app/state's `page` rune for currentPath → mocked.
//   - auth store: defaults are OK for the "renders 10 items" base
//     case (no user → role !== 'admin' → Administration hidden).
//     The admin-visibility test sets the role explicitly via the
//     store.

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('$app/state', () => ({
	page: {
		url: new URL('http://localhost/routes')
	}
}));

import { render, screen } from '@testing-library/svelte';
import Sidebar from './Sidebar.svelte';
import { auth } from '$lib/stores/auth.svelte';

describe('Sidebar', () => {
	beforeEach(() => {
		// Reset the auth store between tests so admin-visibility
		// assertions start from a known state.
		auth.user = null;
	});

	it('renders the 3 always-visible nav sections + 8 items for an anonymous/viewer user', () => {
		render(Sidebar);

		// Section labels (mock-naming).
		expect(screen.getByText('Aperçu')).toBeInTheDocument();
		expect(screen.getByText('Trafic')).toBeInTheDocument();
		expect(screen.getByText('Sécurité')).toBeInTheDocument();
		// Administration is admin-only; default = no user set in store.
		expect(screen.queryByText('Administration')).not.toBeInTheDocument();

		// 8 non-admin nav items.
		expect(screen.getByText('Dashboard')).toBeInTheDocument();
		expect(screen.getByText('Topology')).toBeInTheDocument();
		expect(screen.getByText('Map')).toBeInTheDocument();
		expect(screen.getByText('Routes')).toBeInTheDocument();
		expect(screen.getByText('Logs')).toBeInTheDocument();
		expect(screen.getByText('WAF')).toBeInTheDocument();
		expect(screen.getByText('Security')).toBeInTheDocument();
		expect(screen.getByText('Certificates')).toBeInTheDocument();

		// Admin items absent.
		expect(screen.queryByText('Utilisateurs')).not.toBeInTheDocument();
		expect(screen.queryByText('Settings')).not.toBeInTheDocument();
		expect(screen.queryByText('Audit log')).not.toBeInTheDocument();
	});

	it('renders all 4 sections + 11 items for an admin user', () => {
		auth.user = {
			username: 'admin',
			displayName: 'Admin',
			role: 'admin',
			mfa: 'none',
			passwordCompromised: false
		} as never; // shape compatibility — we only read role here.

		render(Sidebar);

		expect(screen.getByText('Administration')).toBeInTheDocument();
		expect(screen.getByText('Utilisateurs')).toBeInTheDocument();
		expect(screen.getByText('Settings')).toBeInTheDocument();
		// CS.2 follow-up — Audit log entry closes
		// #R-AUDIT-not-in-nav. Admin-only.
		expect(screen.getByText('Audit log')).toBeInTheDocument();
	});

	it('audit log link points to /audit', () => {
		auth.user = {
			username: 'admin',
			displayName: 'Admin',
			role: 'admin',
			mfa: 'none',
			passwordCompromised: false
		} as never;

		render(Sidebar);
		const auditLink = screen
			.getAllByRole('link', { hidden: false })
			.find((l) => l.textContent?.includes('Audit log'));
		expect(auditLink).toBeDefined();
		expect(auditLink).toHaveAttribute('href', '/audit');
	});

	it('keeps /security sub-routes OUT of the sidebar (R.4 D8 design)', () => {
		// CS.3 update: the regression now covers two things:
		//   1. /security/decisions stays absent (it was deleted
		//      in CS.3 Commit A; its content moved into the
		//      CrowdSec parent tab on /security)
		//   2. /security/[routeId] stays absent (R.4 D8 per-route
		//      drill-down remains intentionally hidden)
		// If a future patch adds either to the sidebar without
		// updating Sidebar.svelte's header rationale, the assertion
		// catches the silent regression.
		auth.user = {
			username: 'admin',
			displayName: 'Admin',
			role: 'admin',
			mfa: 'none',
			passwordCompromised: false
		} as never;

		render(Sidebar);
		const allLinks = screen.getAllByRole('link', { hidden: false });
		const hrefs = allLinks.map((l) => l.getAttribute('href'));
		expect(hrefs).not.toContain('/security/decisions');
		// The catch-all route /security/[routeId] doesn't
		// resolve to a single static href; just make sure no
		// link points under /security/ that isn't /security
		// itself.
		const securitySubLinks = hrefs.filter(
			(h) => h !== null && h.startsWith('/security/') && h !== '/security'
		);
		expect(securitySubLinks).toEqual([]);
	});

	it('marks the current-path item with aria-current="page"', () => {
		// Mock returns pathname='/routes' so Routes is the active item.
		render(Sidebar);

		const routes = screen
			.getAllByRole('link', { hidden: false })
			.find((l) => l.textContent?.includes('Routes'));
		expect(routes).toBeDefined();
		expect(routes).toHaveAttribute('aria-current', 'page');

		// Dashboard (non-current) should NOT have aria-current.
		const dashboard = screen
			.getAllByRole('link', { hidden: false })
			.find((l) => l.textContent?.includes('Dashboard'));
		expect(dashboard).not.toHaveAttribute('aria-current');
	});

	it('exposes a sign-out button in the sidebar-foot', () => {
		render(Sidebar);
		const signOut = screen.getByRole('button', { name: 'Sign out' });
		expect(signOut).toBeInTheDocument();
		expect(signOut).not.toBeDisabled();
	});
});
