// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.41 — /security used to have three t() calls: the header, every
// card title, the TLS grid and the security-header empty state were
// hard-coded English, and the empty state even quoted a repo path at
// the operator.
//
// This pins the outcome the way it is visible: the page follows the
// language, and the backlog path is gone.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';

vi.mock('$lib/api/settings', () => ({
	settingsApi: {
		getOIDC: vi.fn().mockResolvedValue({ enabled: false, configured: false })
	}
}));
vi.mock('$lib/stores/toast', () => ({ pushToast: vi.fn() }));
// The page reads the Kit page store for its ?tab= deep link.
vi.mock('$app/state', () => ({ page: { url: new URL('http://localhost/security') } }));
// The language store calls authApi, which imports the api client and
// with it $app/navigation; stub it so the page mounts standalone.
vi.mock('$lib/api/auth', () => ({
	authApi: { setLanguage: vi.fn().mockResolvedValue(undefined) }
}));
// The CrowdSec panel mounted by the second tab pulls the api client,
// which imports $app/navigation; stub its network surface instead.
vi.mock('$lib/api/security', () => ({
	fetchDecisions: vi.fn().mockResolvedValue({ decisions: [], total: 0 }),
	fetchLAPIDecisions: vi.fn().mockResolvedValue({ decisions: [], total: 0 }),
	fetchScenarios: vi.fn().mockResolvedValue({ scenarios: [] })
}));

import { language } from '$lib/stores/language.svelte';
import Page from './+page.svelte';

beforeEach(() => {
	window.history.replaceState(null, '', '/security');
});

afterEach(() => {
	language.applyLocally('en');
});

describe('/security — v2.41 i18n', () => {
	it('renders its cards in English by default', async () => {
		render(Page);
		await waitFor(() => expect(screen.getByText('Security headers')).toBeInTheDocument());
		expect(screen.getByText('Authentication providers')).toBeInTheDocument();
		expect(screen.getByText('Minimum version')).toBeInTheDocument();
	});

	it('renders the same cards in French, and no longer shows a repo path', async () => {
		language.applyLocally('fr');
		const { container } = render(Page);
		await waitFor(() => expect(screen.getByText('En-têtes de sécurité')).toBeInTheDocument());
		expect(screen.getByText("Fournisseurs d'authentification")).toBeInTheDocument();
		expect(screen.getByText('Version minimale')).toBeInTheDocument();
		// The empty state used to point operators at docs/backlog-step-r.md.
		expect(container.textContent ?? '').not.toContain('backlog-step-r');
	});
});
