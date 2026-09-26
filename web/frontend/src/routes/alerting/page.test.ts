// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.41 — the alerting page used to carry its own tab bar, a
// near-verbatim copy of Tabs.svelte that had drifted on
// accessibility (aria-current="page" instead of role="tab" +
// aria-selected). It now uses the shared component.
//
// Pinned here: the three tabs are a real ARIA tablist, switching one
// swaps the panel and records the choice in the URL, and a hash deep
// link still opens the tab it names.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';

vi.mock('$lib/api/alerting', async (importOriginal) => ({
	// Keep the module's real helpers and constants (the tabs read
	// SEVERITY_TOKENS et al.); only the network surface is stubbed.
	...((await importOriginal()) as Record<string, unknown>),
	alertingApi: new Proxy({}, { get: () => vi.fn().mockResolvedValue([]) })
}));
vi.mock('$lib/stores/toast', () => ({ pushToast: vi.fn() }));
vi.mock('$lib/stores/alerting.svelte', () => {
	// The three stores expose a `state` object the tabs read
	// directly; only the shape matters here, not the data.
	const store = () => ({
		state: {
			channels: [],
			rules: [],
			events: [],
			nextCursor: '',
			loading: false,
			loadMoreLoading: false,
			loadError: '',
			degraded: false
		},
		load: vi.fn().mockResolvedValue(undefined),
		loadMore: vi.fn().mockResolvedValue(undefined),
		refresh: vi.fn().mockResolvedValue(undefined)
	});
	return { channelsStore: store(), rulesStore: store(), alertEventsStore: store() };
});

import Page from './+page.svelte';

function tab(key: string): HTMLElement {
	return screen.getByTestId(`alerting-tab-${key}`);
}

beforeEach(() => {
	window.history.replaceState(null, '', '/alerting');
});

describe('Alerting page — v2.41 shared tabs', () => {
	it('renders the three tabs as an ARIA tablist, channels first', async () => {
		render(Page);
		expect(screen.getByRole('tablist')).toBeInTheDocument();
		for (const key of ['channels', 'rules', 'history']) {
			expect(tab(key).getAttribute('role')).toBe('tab');
		}
		expect(tab('channels').getAttribute('aria-selected')).toBe('true');
		expect(tab('rules').getAttribute('aria-selected')).toBe('false');
	});

	it('switches tab and records the choice in the URL', async () => {
		render(Page);
		await userEvent.click(tab('rules'));
		await waitFor(() => expect(tab('rules').getAttribute('aria-selected')).toBe('true'));
		expect(tab('channels').getAttribute('aria-selected')).toBe('false');
		expect(window.location.hash).toBe('#rules');
	});

	it('opens the tab named by the URL hash', async () => {
		window.history.replaceState(null, '', '/alerting#history');
		render(Page);
		await waitFor(() => expect(tab('history').getAttribute('aria-selected')).toBe('true'));
	});
});
