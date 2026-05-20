// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Sidebar component tests (Step F Chunk 7.3, spec §11.3 — 4 tests).
// Behavior-based per §11.2.
//
// Sidebar depends on:
//   - $app/state's `page` rune for currentPath → must be mocked
//     because SvelteKit's runtime isn't available in jsdom.
//   - auth + theme stores: read defensively (auth.user?.) so the
//     defaults are fine in tests; no stub needed.
//   - localStorage for collapsed persistence (Chunk 3.4) — jsdom
//     provides a real localStorage by default.

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock $app/state BEFORE importing Sidebar. The page object exposes
// a `url` with a `pathname` — Sidebar reads page.url.pathname into a
// $derived. Default to '/routes' (so the Routes nav item is active);
// individual tests can override by replaying vi.doMock per render if
// needed.
vi.mock('$app/state', () => ({
	page: {
		url: new URL('http://localhost/routes')
	}
}));

import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import Sidebar from './Sidebar.svelte';

describe('Sidebar', () => {
	beforeEach(() => {
		// Clear localStorage between tests so each starts from a known
		// state (no persisted collapsed value).
		localStorage.clear();
	});

	it('renders the five nav items in spec order', () => {
		render(Sidebar);

		// Spec §6.12: Routes, Audit, Topology, Security, Settings.
		// Disabled items (Security pre-Phase-2) have an <a> with no
		// href and aria-disabled="true" — those don't satisfy ARIA
		// role="link" so testing-library skips them. Query by visible
		// text to cover both enabled and disabled items in one shot.
		expect(screen.getByText('Routes')).toBeInTheDocument();
		expect(screen.getByText('Audit')).toBeInTheDocument();
		expect(screen.getByText('Topology')).toBeInTheDocument();
		expect(screen.getByText('Security')).toBeInTheDocument();
		expect(screen.getByText('Settings')).toBeInTheDocument();
	});

	it('marks the current-path item with aria-current="page"', () => {
		// Mock returns pathname='/routes' so Routes is the active item.
		render(Sidebar);

		// Find the Routes link. It should carry aria-current="page" per
		// Sidebar's `aria-current={active ? 'page' : undefined}`.
		const routes = screen
			.getAllByRole('link', { hidden: false })
			.find((l) => l.textContent?.includes('Routes'));
		expect(routes).toBeDefined();
		expect(routes).toHaveAttribute('aria-current', 'page');

		// Audit (non-current) should NOT have aria-current.
		const audit = screen
			.getAllByRole('link', { hidden: false })
			.find((l) => l.textContent?.includes('Audit'));
		expect(audit).not.toHaveAttribute('aria-current');
	});

	it('clicking the collapse button writes the new state to localStorage', async () => {
		const user = userEvent.setup();
		render(Sidebar);

		// Initially `collapsed` defaults to false; the button label is
		// "Collapse sidebar" via aria-label.
		const collapseBtn = screen.getByRole('button', {
			name: 'Collapse sidebar'
		});
		await user.click(collapseBtn);

		// After click, Sidebar called localStorage.setItem with
		// arenet_sidebar_collapsed=true. jsdom's localStorage is a
		// real Storage instance — read it back to assert.
		expect(localStorage.getItem('arenet_sidebar_collapsed')).toBe('true');

		// The button's aria-label has flipped (collapsed=true).
		expect(
			screen.getByRole('button', { name: 'Expand sidebar' })
		).toBeInTheDocument();
	});

	it('hydrates collapsed=true from localStorage on mount', () => {
		// Seed localStorage BEFORE render — the onMount handler reads
		// arenet_sidebar_collapsed and flips the bindable accordingly.
		localStorage.setItem('arenet_sidebar_collapsed', 'true');
		render(Sidebar);

		// The button now reads "Expand sidebar" because the onMount
		// read the persisted value.
		expect(
			screen.getByRole('button', { name: 'Expand sidebar' })
		).toBeInTheDocument();
		// Conversely, "Collapse sidebar" is gone.
		expect(
			screen.queryByRole('button', { name: 'Collapse sidebar' })
		).not.toBeInTheDocument();
	});
});
