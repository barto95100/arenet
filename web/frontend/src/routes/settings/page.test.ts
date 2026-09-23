// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.41 — the settings page is five tabs, not one long scroll.
//
// What is pinned here is what the operator relies on: the five
// categories are reachable, only the active one renders, the tab
// survives in the URL, and the deep links that predate the tabs
// (#security-automation, #oidc-config, #dns-providers — used by the
// CrowdSec Decisions panel and the BanIPModal CTA) still land on the
// right tab.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';

// Every settings API is stubbed to a resolved empty value: this test
// is about the page's navigation, not about any card's contents.
vi.mock('$lib/api/settings', () => {
	// Shapes the page actually destructures; everything else falls
	// back to a resolved empty value.
	const known: Record<string, unknown> = {
		getAutomation: vi.fn().mockResolvedValue({
			rules: { rules: {} },
			credentials: { lapiUrl: '', machineId: '', configured: false }
		}),
		listForwardAuthProviders: vi.fn().mockResolvedValue([])
	};
	return {
		settingsApi: new Proxy(known, {
			get: (target, prop: string) => target[prop] ?? vi.fn().mockResolvedValue({})
		})
	};
});
vi.mock('$lib/api/system', () => ({
	systemApi: new Proxy({}, { get: () => vi.fn().mockResolvedValue({}) })
}));
vi.mock('$lib/api/auth', () => ({
	authApi: {
		listSessions: vi.fn().mockResolvedValue({ sessions: [] }),
		deleteSession: vi.fn().mockResolvedValue(undefined)
	}
}));
vi.mock('$lib/stores/toast', () => ({ pushToast: vi.fn() }));

const { afterNavigateMock } = vi.hoisted(() => ({
	afterNavigateMock: { cb: null as null | (() => void | Promise<void>) }
}));
vi.mock('$app/navigation', () => ({
	afterNavigate: (cb: () => void | Promise<void>) => {
		afterNavigateMock.cb = cb;
	},
	goto: vi.fn()
}));

import Page from './+page.svelte';

function tab(id: string): HTMLElement {
	return screen.getByTestId(`settings-tab-${id}`);
}

beforeEach(() => {
	// jsdom implements neither; the page calls both on tab change.
	Element.prototype.scrollIntoView = vi.fn();
	window.scrollTo = vi.fn();
	window.history.replaceState(null, '', '/settings');
	afterNavigateMock.cb = null;
});

afterEach(() => {
	window.history.replaceState(null, '', '/settings');
});

describe('Settings page — v2.41 categories', () => {
	it('offers the five categories and opens on the account one', async () => {
		render(Page);
		for (const id of ['account', 'security', 'network', 'backups', 'system']) {
			expect(tab(id)).toBeInTheDocument();
		}
		expect(tab('account').getAttribute('aria-selected')).toBe('true');
		expect(tab('security').getAttribute('aria-selected')).toBe('false');

		// Only the active category is rendered — the whole point of
		// the change is that the other fourteen cards are not there.
		expect(screen.queryByText('Security Automation')).toBeNull();
	});

	it('switches category and records it in the URL', async () => {
		render(Page);
		await userEvent.click(tab('security'));

		expect(tab('security').getAttribute('aria-selected')).toBe('true');
		await waitFor(() => expect(screen.getByText('Security Automation')).toBeInTheDocument());
		expect(window.location.hash).toBe('#security');

		// Back to the first category: the security cards are gone,
		// not merely scrolled out of sight.
		await userEvent.click(tab('account'));
		expect(screen.queryByText('Security Automation')).toBeNull();
		expect(window.location.hash).toBe('#account');
	});

	it('opens the tab named by the URL hash', async () => {
		window.history.replaceState(null, '', '/settings#network');
		render(Page);
		await afterNavigateMock.cb?.();
		await waitFor(() => expect(tab('network').getAttribute('aria-selected')).toBe('true'));
	});

	it('opens the tab holding a card anchor, for the links that predate the tabs', async () => {
		window.history.replaceState(null, '', '/settings#oidc-config');
		render(Page);
		await afterNavigateMock.cb?.();
		await waitFor(() => expect(tab('security').getAttribute('aria-selected')).toBe('true'));
		expect(document.getElementById('oidc-config')).not.toBeNull();
	});
});
