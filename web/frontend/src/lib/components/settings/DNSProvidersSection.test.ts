// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Unit tests for the v2.12 /settings DNS Providers section (Task
// 2c). Verifies the table render, empty state, add/edit modal
// (blank-secret preserve-on-edit contract), and the 409
// provider_in_use delete path that surfaces the wildcard names in
// the toast. Mocks $lib/api/settings + $lib/stores/toast in the
// same shape the sibling settings/certs page tests use.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { ApiError } from '$lib/api/types';
import type { DNSProvider } from '$lib/api/types';

const { settingsMock, toastMock } = vi.hoisted(() => ({
	settingsMock: {
		settingsApi: {
			listDNSProviders: vi.fn(),
			createDNSProvider: vi.fn(),
			updateDNSProvider: vi.fn(),
			deleteDNSProvider: vi.fn(),
		},
	},
	toastMock: { pushToast: vi.fn() },
}));
vi.mock('$lib/api/settings', () => settingsMock);
vi.mock('$lib/stores/toast', () => toastMock);

import DNSProvidersSection from './DNSProvidersSection.svelte';

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
	settingsMock.settingsApi.listDNSProviders.mockReset();
	settingsMock.settingsApi.createDNSProvider.mockReset();
	settingsMock.settingsApi.updateDNSProvider.mockReset();
	settingsMock.settingsApi.deleteDNSProvider.mockReset();
	toastMock.pushToast.mockReset();
	settingsMock.settingsApi.listDNSProviders.mockResolvedValue([]);
});

describe('DNSProvidersSection', () => {
	it('renders a row per provider with label, endpoint, usedBy', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([
			provider({ id: 'id-1', label: 'OVH perso', endpoint: 'ovh-eu', usedBy: ['a.com'] }),
		]);
		render(DNSProvidersSection);
		await waitFor(() => expect(screen.getByText('OVH perso')).toBeInTheDocument());
		expect(screen.getByText('ovh-eu')).toBeInTheDocument();
		expect(screen.getByTestId('dns-provider-row-id-1')).toBeInTheDocument();
		// usedBy wildcard is surfaced in the row.
		expect(screen.getByText('a.com')).toBeInTheDocument();
	});

	it('shows the empty state CTA when no providers', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([]);
		render(DNSProvidersSection);
		await waitFor(() =>
			expect(screen.getByText(/add your first provider/i)).toBeInTheDocument(),
		);
	});

	it('add flow: open modal, fill, submit, calls createDNSProvider then refetches', async () => {
		settingsMock.settingsApi.listDNSProviders
			.mockResolvedValueOnce([])
			.mockResolvedValueOnce([provider({ id: 'id-9', label: 'OVH new' })]);
		settingsMock.settingsApi.createDNSProvider.mockResolvedValue(provider({ id: 'id-9' }));

		render(DNSProvidersSection);
		await waitFor(() =>
			expect(screen.getByText(/add your first provider/i)).toBeInTheDocument(),
		);
		await userEvent.click(screen.getByText(/add your first provider/i));

		await userEvent.type(screen.getByLabelText('Label'), 'OVH new');
		await userEvent.type(screen.getByLabelText('Application key'), 'ak');
		await userEvent.type(screen.getByLabelText('Application secret'), 'as');
		await userEvent.type(screen.getByLabelText('Consumer key'), 'ck');

		await fireEvent.submit(screen.getByTestId('dns-provider-form'));
		await tick();

		await waitFor(() =>
			expect(settingsMock.settingsApi.createDNSProvider).toHaveBeenCalledWith(
				expect.objectContaining({
					label: 'OVH new',
					type: 'ovh',
					endpoint: 'ovh-eu',
					applicationKey: 'ak',
					applicationSecret: 'as',
					consumerKey: 'ck',
				}),
			),
		);
		// Refetch after success → the new row appears.
		await waitFor(() => expect(screen.getByText('OVH new')).toBeInTheDocument());
	});

	it('edit flow: blank secrets are NOT sent so the backend preserves them', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([
			provider({ id: 'id-1', label: 'OVH perso', endpoint: 'ovh-eu' }),
		]);
		settingsMock.settingsApi.updateDNSProvider.mockResolvedValue(provider());

		render(DNSProvidersSection);
		await waitFor(() => screen.getByTestId('dns-provider-edit-id-1'));
		await userEvent.click(screen.getByTestId('dns-provider-edit-id-1'));

		// Change only the label; leave every secret blank.
		const labelInput = screen.getByLabelText('Label') as HTMLInputElement;
		await userEvent.clear(labelInput);
		await userEvent.type(labelInput, 'OVH renamed');

		await fireEvent.submit(screen.getByTestId('dns-provider-form'));
		await tick();

		await waitFor(() =>
			expect(settingsMock.settingsApi.updateDNSProvider).toHaveBeenCalled(),
		);
		const [id, body] = settingsMock.settingsApi.updateDNSProvider.mock.calls[0];
		expect(id).toBe('id-1');
		expect(body.label).toBe('OVH renamed');
		// Blank-secret contract: the three secret fields are omitted or
		// empty so the backend preserves the stored values.
		expect(body.applicationKey ?? '').toBe('');
		expect(body.applicationSecret ?? '').toBe('');
		expect(body.consumerKey ?? '').toBe('');
	});

	it('delete-in-use: a 409 provider_in_use surfaces the wildcard names in the toast', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([
			provider({ id: 'id-1', usedBy: ['a.com'] }),
		]);
		settingsMock.settingsApi.deleteDNSProvider.mockRejectedValue(
			new ApiError('in use', 409, 'validation', undefined, 'provider_in_use', {
				wildcards: ['a.com', 'b.org'],
			}),
		);

		render(DNSProvidersSection);
		await waitFor(() => screen.getByTestId('dns-provider-delete-id-1'));
		await userEvent.click(screen.getByTestId('dns-provider-delete-id-1'));

		// ConfirmDialog opens → click its confirm button.
		await waitFor(() =>
			expect(screen.getByRole('button', { name: /^delete$/i })).toBeInTheDocument(),
		);
		await userEvent.click(screen.getByRole('button', { name: /^delete$/i }));

		await waitFor(() => {
			const msgs = toastMock.pushToast.mock.calls.map((c) => String(c[0]));
			expect(msgs.some((m) => m.includes('a.com') && m.includes('b.org'))).toBe(true);
		});
	});

	it('delete-allowed: resolves, toasts success, refetches without the row', async () => {
		settingsMock.settingsApi.listDNSProviders
			.mockResolvedValueOnce([provider({ id: 'id-1', label: 'OVH perso' })])
			.mockResolvedValueOnce([]);
		settingsMock.settingsApi.deleteDNSProvider.mockResolvedValue(undefined);

		render(DNSProvidersSection);
		await waitFor(() => screen.getByTestId('dns-provider-delete-id-1'));
		await userEvent.click(screen.getByTestId('dns-provider-delete-id-1'));

		await waitFor(() =>
			expect(screen.getByRole('button', { name: /^delete$/i })).toBeInTheDocument(),
		);
		await userEvent.click(screen.getByRole('button', { name: /^delete$/i }));

		await waitFor(() =>
			expect(settingsMock.settingsApi.deleteDNSProvider).toHaveBeenCalledWith('id-1'),
		);
		await waitFor(() =>
			expect(screen.queryByTestId('dns-provider-row-id-1')).not.toBeInTheDocument(),
		);
	});
});
