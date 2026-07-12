// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Unit tests for the Step T T.5 wizard. Verifies the open/close/
// submit/error contracts in isolation so the page-level integration
// tests can stay narrow (they just verify the trigger mounts the
// wizard).
//
// Why unit-test here instead of through the page: JSDOM doesn't
// drive the Web Animations API the way browsers do, so Modal's
// out-transition (fly + fade, 400ms) leaves the dialog node in
// the DOM after `open` flips to false. Asserting "form unmounts"
// at the page level is flaky for that reason; asserting "onClose
// was called" at the component level is the actual behavioural
// contract.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { ApiError } from '$lib/api/types';
import type { DNSProvider } from '$lib/api/types';

const { settingsMock } = vi.hoisted(() => ({
	settingsMock: {
		settingsApi: {
			createManagedDomain: vi.fn(),
			listDNSProviders: vi.fn(),
		},
	},
}));
vi.mock('$lib/api/settings', () => settingsMock);

import WildcardApexWizard from './WildcardApexWizard.svelte';

function provider(over: Partial<DNSProvider> = {}): DNSProvider {
	return {
		id: 'id-1',
		label: 'OVH perso',
		type: 'ovh',
		endpoint: 'ovh-eu',
		configured: true,
		usedBy: [],
		...over,
	};
}

beforeEach(() => {
	settingsMock.settingsApi.createManagedDomain.mockReset();
	settingsMock.settingsApi.listDNSProviders.mockReset();
	// Default: one configured provider so existing submit/close tests
	// have a providerId to send.
	settingsMock.settingsApi.listDNSProviders.mockResolvedValue([provider()]);
});

describe('WildcardApexWizard', () => {
	it('renders nothing when open=false', () => {
		render(WildcardApexWizard, { open: false, onClose: vi.fn() });
		expect(screen.queryByTestId('wildcard-wizard-form')).not.toBeInTheDocument();
	});

	it('mounts the three form controls when open=true', async () => {
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		expect(screen.getByLabelText('Apex domain')).toBeInTheDocument();
		// The DNS provider dropdown mounts after listDNSProviders resolves.
		await waitFor(() =>
			expect(screen.getByLabelText('DNS provider')).toBeInTheDocument(),
		);
		expect(
			screen.getByLabelText('Include bare apex in cert SAN'),
		).toBeInTheDocument();
	});

	it('Cancel button fires onClose without submitting', async () => {
		const onClose = vi.fn();
		render(WildcardApexWizard, {
			open: true,
			onClose,
		});
		await userEvent.click(screen.getByRole('button', { name: /cancel/i }));
		expect(onClose).toHaveBeenCalledTimes(1);
		expect(settingsMock.settingsApi.createManagedDomain).not.toHaveBeenCalled();
	});

	it('Escape key fires onClose (via Modal focus-trap handler)', async () => {
		const onClose = vi.fn();
		render(WildcardApexWizard, { open: true, onClose });
		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(onClose).toHaveBeenCalled();
		expect(settingsMock.settingsApi.createManagedDomain).not.toHaveBeenCalled();
	});

	it('submitting with empty apex shows a validation error instead of calling the API', async () => {
		const onClose = vi.fn();
		render(WildcardApexWizard, { open: true, onClose });
		// Wait for the provider fetch so the empty-provider submit guard
		// doesn't short-circuit before the apex-required check.
		await waitFor(() =>
			expect(screen.getByLabelText('DNS provider')).toBeInTheDocument(),
		);
		const form = screen.getByTestId('wildcard-wizard-form');
		await fireEvent.submit(form);
		await tick();
		expect(screen.getByTestId('wizard-error').textContent ?? '').toMatch(
			/required/i,
		);
		expect(settingsMock.settingsApi.createManagedDomain).not.toHaveBeenCalled();
		expect(onClose).not.toHaveBeenCalled();
	});

	it('successful submit calls API with trimmed apex, onCreated, then onClose', async () => {
		const onClose = vi.fn();
		const onCreated = vi.fn();
		settingsMock.settingsApi.createManagedDomain.mockResolvedValue({
			apex: 'new.example',
			includeApex: true,
			providerId: 'id-1',
		});
		render(WildcardApexWizard, { open: true, onClose, onCreated });

		// Wait for the provider fetch so providerId is populated.
		await waitFor(() =>
			expect(screen.getByLabelText('DNS provider')).toBeInTheDocument(),
		);

		const input = screen.getByLabelText('Apex domain') as HTMLInputElement;
		await userEvent.type(input, '  new.example  ');
		const form = screen.getByTestId('wildcard-wizard-form');
		await fireEvent.submit(form);
		await tick();
		await tick();

		expect(settingsMock.settingsApi.createManagedDomain).toHaveBeenCalledWith({
			apex: 'new.example',
			includeApex: true,
			providerId: 'id-1',
		});
		expect(onCreated).toHaveBeenCalled();
		expect(onClose).toHaveBeenCalled();
	});

	it('populates the provider dropdown from listDNSProviders', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([
			provider({ id: 'id-1', label: 'OVH perso', endpoint: 'ovh-eu' }),
			provider({ id: 'id-2', label: 'OVH pro', endpoint: 'ovh-ca' }),
		]);
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		await waitFor(() =>
			expect(screen.getByText(/OVH perso/)).toBeInTheDocument(),
		);
		expect(screen.getByText(/OVH pro/)).toBeInTheDocument();
	});

	it('sends providerId on submit', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([
			provider({ id: 'id-1' }),
		]);
		settingsMock.settingsApi.createManagedDomain.mockResolvedValue({});
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		await waitFor(() =>
			expect(screen.getByLabelText('DNS provider')).toBeInTheDocument(),
		);
		await fireEvent.input(screen.getByLabelText('Apex domain'), {
			target: { value: 'example.com' },
		});
		await fireEvent.submit(screen.getByTestId('wildcard-wizard-form'));
		await waitFor(() =>
			expect(settingsMock.settingsApi.createManagedDomain).toHaveBeenCalledWith(
				expect.objectContaining({ apex: 'example.com', providerId: 'id-1' }),
			),
		);
	});

	it('shows an empty-state CTA when no provider is configured and blocks submit', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([]);
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		await waitFor(() =>
			expect(
				screen.getByText(/configure.*dns provider|configurer.*fournisseur/i),
			).toBeInTheDocument(),
		);
		// No dropdown rendered.
		expect(screen.queryByLabelText('DNS provider')).not.toBeInTheDocument();
		// Submitting must not reach the API.
		await fireEvent.submit(screen.getByTestId('wildcard-wizard-form'));
		await tick();
		expect(settingsMock.settingsApi.createManagedDomain).not.toHaveBeenCalled();
	});

	it('failed submit shows the error in the modal and keeps onClose un-called', async () => {
		const onClose = vi.fn();
		settingsMock.settingsApi.createManagedDomain.mockRejectedValue(
			new ApiError('apex already declared', 409, 'validation'),
		);
		render(WildcardApexWizard, { open: true, onClose });

		const input = screen.getByLabelText('Apex domain') as HTMLInputElement;
		await userEvent.type(input, 'taken.example');
		const form = screen.getByTestId('wildcard-wizard-form');
		await fireEvent.submit(form);
		await tick();
		await tick();

		expect(screen.getByTestId('wizard-error').textContent ?? '').toMatch(
			/apex already declared/,
		);
		expect(onClose).not.toHaveBeenCalled();
	});

	it('Declare button is disabled until apex is non-empty', async () => {
		// v2.9.21 i18n — submit button migrated to t() → "Declare"
		// in EN bundle (test boot default).
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		const declareBtn = screen.getByRole('button', { name: /^declare$/i });
		expect(declareBtn).toBeDisabled();

		const input = screen.getByLabelText('Apex domain') as HTMLInputElement;
		await userEvent.type(input, 'x.example');
		expect(declareBtn).not.toBeDisabled();
	});
});
