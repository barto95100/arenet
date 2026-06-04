// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// /certs page tests — pin the contract of the #R-6 Pack A
// migration: editor mounted on /certs, auto-renewal info card
// rendered, /settings no longer carries the managed-domains UI.
//
// Test surface:
//   - Auto-renewal info card always renders post-load.
//   - Managed-domains editor mounts (add form + existing-domains
//     list with inline Delete) on /certs.
//   - The editor uses the same settingsApi endpoints as the
//     pre-migration /settings UI (createManagedDomain,
//     deleteManagedDomain, listManagedDomains, getDNSProviderOVH).
//   - DNS-provider-unconfigured warning surfaces when the
//     configured flag is false.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen, fireEvent } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';

// Mocks. Same vi.hoisted pattern as the Routes page tests so the
// module imports happen after the mock factories are in place.
const { toastMock, apiMock, settingsMock } = vi.hoisted(() => ({
	toastMock: { pushToast: vi.fn() },
	apiMock: {
		listRoutes: vi.fn(),
	},
	settingsMock: {
		settingsApi: {
			listManagedDomains: vi.fn(),
			createManagedDomain: vi.fn(),
			deleteManagedDomain: vi.fn(),
			getDNSProviderOVH: vi.fn(),
		},
	},
}));

vi.mock('$lib/stores/toast', () => toastMock);
vi.mock('$lib/api/client', () => apiMock);
vi.mock('$lib/api/settings', () => settingsMock);

import Page from './+page.svelte';

beforeEach(() => {
	toastMock.pushToast.mockReset();
	apiMock.listRoutes.mockReset();
	settingsMock.settingsApi.listManagedDomains.mockReset();
	settingsMock.settingsApi.createManagedDomain.mockReset();
	settingsMock.settingsApi.deleteManagedDomain.mockReset();
	settingsMock.settingsApi.getDNSProviderOVH.mockReset();

	// Sensible defaults: no routes, no domains, DNS provider
	// configured. Individual tests override these.
	apiMock.listRoutes.mockResolvedValue([]);
	settingsMock.settingsApi.listManagedDomains.mockResolvedValue({
		domains: [],
	});
	settingsMock.settingsApi.getDNSProviderOVH.mockResolvedValue({
		endpoint: 'ovh-eu',
		applicationKey: '',
		applicationSecret: '',
		consumerKey: '',
		configured: true,
	});
});

describe('/certs — auto-renewal info card', () => {
	it('renders the auto-renewal info card post-load', async () => {
		render(Page);

		// The card is keyed on its data-testid so any future
		// copy edit doesn't break the test. The localized title
		// is also asserted so a regression that removes the
		// French copy still fails loudly.
		const card = await screen.findByTestId('auto-renewal-card');
		expect(card).toBeInTheDocument();
		expect(screen.getByText('Renouvellement automatique')).toBeInTheDocument();
		expect(card.textContent ?? '').toMatch(/certmagic/i);
		expect(card.textContent ?? '').toMatch(/30 jours/);
	});
});

describe('/certs — managed-domains editor (migrated from /settings in #R-6 Pack A)', () => {
	it('mounts the create form with all three controls', async () => {
		render(Page);

		// Wait for the page to settle (loading spinner gone).
		// Wait until the editor is mounted (post-load) — the
		// submit button is the most stable signal because it's
		// only in the DOM inside the `{:else}` branch after
		// loading flips to false. Plain text like "Managed
		// domains" also appears in the PageHeader subtitle, so
		// using it as a wait-anchor would resolve too early.
		await screen.findByRole('button', { name: /declare managed domain/i });

		expect(screen.getByLabelText('Apex domain')).toBeInTheDocument();
		expect(screen.getByLabelText('DNS provider')).toBeInTheDocument();
		expect(
			screen.getByLabelText('Include bare apex in cert SAN'),
		).toBeInTheDocument();
		expect(
			screen.getByRole('button', { name: /declare managed domain/i }),
		).toBeInTheDocument();
	});

	it('renders existing managed domains with inline Delete buttons', async () => {
		settingsMock.settingsApi.listManagedDomains.mockResolvedValue({
			domains: [
				{
					apex: 'example.com',
					includeApex: true,
					provider: 'ovh',
				},
				{
					apex: 'other.example',
					includeApex: false,
					provider: 'ovh',
				},
			],
		});

		render(Page);

		// Each domain renders as `*.<apex>` (with optional bare
		// apex suffix when includeApex). The Delete button has a
		// per-domain aria-label so we can target both. Use
		// findByRole on the Delete button as the wait anchor
		// because it's only mounted post-load; matching on the
		// apex text can be ambiguous when includeApex doubles
		// the text occurrences in the same row.
		expect(
			await screen.findByRole('button', {
				name: 'Delete managed domain example.com',
			}),
		).toBeInTheDocument();
		expect(
			screen.getByRole('button', { name: 'Delete managed domain other.example' }),
		).toBeInTheDocument();
	});

	it('submitting the form calls settingsApi.createManagedDomain with trimmed apex', async () => {
		settingsMock.settingsApi.createManagedDomain.mockResolvedValue({
			apex: 'new.example',
			includeApex: true,
			provider: 'ovh',
		});

		render(Page);
		// Wait until the editor is mounted (post-load) — the
		// submit button is the most stable signal because it's
		// only in the DOM inside the `{:else}` branch after
		// loading flips to false. Plain text like "Managed
		// domains" also appears in the PageHeader subtitle, so
		// using it as a wait-anchor would resolve too early.
		await screen.findByRole('button', { name: /declare managed domain/i });

		const apexInput = screen.getByLabelText('Apex domain') as HTMLInputElement;
		await userEvent.type(apexInput, '  new.example  ');

		const submitBtn = screen.getByRole('button', {
			name: /declare managed domain/i,
		});
		// fireEvent.submit on the form to bypass the user-event
		// click-Enter dance — the form has onsubmit + the button
		// is type=submit, so a direct submit on the form node is
		// the cleanest path to fire the handler.
		const form = submitBtn.closest('form')!;
		await fireEvent.submit(form);
		await tick();

		expect(settingsMock.settingsApi.createManagedDomain).toHaveBeenCalledWith({
			apex: 'new.example',
			includeApex: true,
			provider: 'ovh',
		});
	});

	it('clicking Delete on a domain opens the revertTo modal', async () => {
		settingsMock.settingsApi.listManagedDomains.mockResolvedValue({
			domains: [
				{
					apex: 'example.com',
					includeApex: true,
					provider: 'ovh',
				},
			],
		});

		render(Page);
		// Wait via the per-domain Delete button — unique
		// anchor, only mounted post-load.
		const deleteBtn = await screen.findByRole('button', {
			name: 'Delete managed domain example.com',
		});

		// Modal not mounted before the delete click.
		expect(
			screen.queryByLabelText('Revert covered routes to'),
		).not.toBeInTheDocument();

		await userEvent.click(deleteBtn);
		await tick();

		// The dialog mounts with the revertTo select + the
		// per-modal Cancel/Delete buttons. The title carries the
		// apex so the operator sees what they're about to delete.
		expect(
			screen.getByLabelText('Revert covered routes to'),
		).toBeInTheDocument();
		expect(
			screen.getByText(/delete managed domain example\.com/i),
		).toBeInTheDocument();
	});
});

describe('/certs — DNS-provider-unconfigured warning', () => {
	it('renders the warning when configured=false', async () => {
		settingsMock.settingsApi.getDNSProviderOVH.mockResolvedValue({
			endpoint: '',
			applicationKey: '',
			applicationSecret: '',
			consumerKey: '',
			configured: false,
		});

		render(Page);
		// Wait until the editor is mounted (post-load) — the
		// submit button is the most stable signal because it's
		// only in the DOM inside the `{:else}` branch after
		// loading flips to false. Plain text like "Managed
		// domains" also appears in the PageHeader subtitle, so
		// using it as a wait-anchor would resolve too early.
		await screen.findByRole('button', { name: /declare managed domain/i });

		// The warning text is a sentence the test pins partially
		// so a future copy edit doesn't break the contract.
		expect(
			screen.getByText(/DNS provider unconfigured/i),
		).toBeInTheDocument();
	});

	it('hides the warning when configured=true', async () => {
		// Default beforeEach sets configured=true; this test
		// pins the negative-path explicitly.
		render(Page);
		// Wait until the editor is mounted (post-load) — the
		// submit button is the most stable signal because it's
		// only in the DOM inside the `{:else}` branch after
		// loading flips to false. Plain text like "Managed
		// domains" also appears in the PageHeader subtitle, so
		// using it as a wait-anchor would resolve too early.
		await screen.findByRole('button', { name: /declare managed domain/i });

		expect(
			screen.queryByText(/DNS provider unconfigured/i),
		).not.toBeInTheDocument();
	});
});
