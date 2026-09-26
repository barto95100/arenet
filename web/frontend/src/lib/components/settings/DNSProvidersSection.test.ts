// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Unit tests for the v2.12 /settings DNS Providers section (Task
// 2c). Verifies the table render, empty state, add/edit modal
// (blank-secret preserve-on-edit contract), and the 409
// provider_in_use delete path that surfaces the wildcard names in
// the toast. Mocks $lib/api/settings + $lib/stores/toast in the
// same shape the sibling settings/certs page tests use.
//
// v2.26: the form is generated from the provider-type registry
// (listDNSProviderTypes), and each row has a connection test.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { ApiError } from '$lib/api/types';
import type { DNSProvider, DNSProviderType } from '$lib/api/types';

const { settingsMock, toastMock } = vi.hoisted(() => ({
	settingsMock: {
		settingsApi: {
			listDNSProviders: vi.fn(),
			createDNSProvider: vi.fn(),
			updateDNSProvider: vi.fn(),
			deleteDNSProvider: vi.fn(),
			listDNSProviderTypes: vi.fn(),
			testDNSProvider: vi.fn(),
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
		fields: { endpoint: 'ovh-eu' },
		secretsSet: { application_key: true, application_secret: true, consumer_key: true },
		usedBy: [],
		...over,
	};
}

// Registry subset mirroring storage/dns_provider_types.go.
const TYPES: DNSProviderType[] = [
	{
		type: 'ovh',
		label: 'OVHcloud',
		docsUrl: 'https://www.ovh.com/auth/api/createToken',
		fields: [
			{ key: 'endpoint', label: 'Endpoint', secret: false, required: true, enum: ['ovh-eu', 'ovh-ca'], default: 'ovh-eu' },
			{ key: 'application_key', label: 'Application key', secret: true, required: true },
			{ key: 'application_secret', label: 'Application secret', secret: true, required: true },
			{ key: 'consumer_key', label: 'Consumer key', secret: true, required: true },
		],
	},
	{
		type: 'cloudflare',
		label: 'Cloudflare',
		docsUrl: 'https://dash.cloudflare.com/profile/api-tokens',
		fields: [
			{ key: 'api_token', label: 'API token (Zone.DNS:Edit)', secret: true, required: true },
			{ key: 'zone_token', label: 'Zone token (Zone:Read, optional)', secret: true, required: false },
		],
	},
];

beforeEach(() => {
	settingsMock.settingsApi.listDNSProviders.mockReset();
	settingsMock.settingsApi.createDNSProvider.mockReset();
	settingsMock.settingsApi.updateDNSProvider.mockReset();
	settingsMock.settingsApi.deleteDNSProvider.mockReset();
	settingsMock.settingsApi.listDNSProviderTypes.mockReset();
	settingsMock.settingsApi.testDNSProvider.mockReset();
	toastMock.pushToast.mockReset();
	settingsMock.settingsApi.listDNSProviders.mockResolvedValue([]);
	settingsMock.settingsApi.listDNSProviderTypes.mockResolvedValue(TYPES);
});

describe('DNSProvidersSection', () => {
	it('renders a row per provider with label, type label, details, usedBy', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([
			provider({ id: 'id-1', label: 'OVH perso', endpoint: 'ovh-eu', usedBy: ['a.com'] }),
		]);
		render(DNSProvidersSection);
		await waitFor(() => expect(screen.getByText('OVH perso')).toBeInTheDocument());
		expect(screen.getByText('ovh-eu')).toBeInTheDocument();
		expect(screen.getByText('OVHcloud')).toBeInTheDocument();
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
		await userEvent.type(screen.getByLabelText(/^Application key/), 'ak');
		await userEvent.type(screen.getByLabelText(/^Application secret/), 'as');
		await userEvent.type(screen.getByLabelText(/^Consumer key/), 'ck');

		await fireEvent.submit(screen.getByTestId('dns-provider-form'));
		await tick();

		await waitFor(() =>
			expect(settingsMock.settingsApi.createDNSProvider).toHaveBeenCalledWith(
				{
					label: 'OVH new',
					type: 'ovh',
					credentials: {
						endpoint: 'ovh-eu',
						application_key: 'ak',
						application_secret: 'as',
						consumer_key: 'ck',
					},
				},
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
		// Blank-secret contract: the secret fields are omitted so the
		// backend preserves the stored values; the non-secret endpoint
		// round-trips.
		expect(body.type).toBe('ovh');
		expect(body.credentials).toEqual({ endpoint: 'ovh-eu' });
		// The type is locked on edit.
		expect(screen.getByTestId('dns-provider-type')).toBeDisabled();
	});

	it('add flow: switching the type regenerates the fields (Cloudflare)', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([]);
		settingsMock.settingsApi.createDNSProvider.mockResolvedValue(provider({ type: 'cloudflare' }));

		render(DNSProvidersSection);
		await waitFor(() => screen.getByTestId('dns-provider-empty-add'));
		await userEvent.click(screen.getByTestId('dns-provider-empty-add'));
		await userEvent.selectOptions(screen.getByTestId('dns-provider-type'), 'cloudflare');

		expect(screen.queryByLabelText(/^Application key/)).not.toBeInTheDocument();
		expect(screen.getByTestId('dns-provider-docs-link')).toHaveAttribute(
			'href',
			'https://dash.cloudflare.com/profile/api-tokens',
		);
		const token = screen.getByLabelText(/^API token/) as HTMLInputElement;
		expect(token.type).toBe('password');

		await userEvent.type(screen.getByLabelText('Label'), 'CF');
		await userEvent.type(token, 'cf-token');
		await fireEvent.submit(screen.getByTestId('dns-provider-form'));
		await tick();

		// The empty optional zone_token is not sent.
		await waitFor(() =>
			expect(settingsMock.settingsApi.createDNSProvider).toHaveBeenCalledWith({
				label: 'CF',
				type: 'cloudflare',
				credentials: { api_token: 'cf-token' },
			}),
		);
	});

	it('add flow: a missing required credential is caught client-side', async () => {
		render(DNSProvidersSection);
		await waitFor(() => screen.getByTestId('dns-provider-empty-add'));
		await userEvent.click(screen.getByTestId('dns-provider-empty-add'));
		await userEvent.selectOptions(screen.getByTestId('dns-provider-type'), 'cloudflare');
		await userEvent.type(screen.getByLabelText('Label'), 'CF');
		await fireEvent.submit(screen.getByTestId('dns-provider-form'));
		await tick();

		expect(screen.getByTestId('dns-provider-form-error')).toHaveTextContent(/API token/);
		expect(settingsMock.settingsApi.createDNSProvider).not.toHaveBeenCalled();
	});

	it('connection test: prefills the bound zone and shows the record count', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([
			provider({ id: 'id-1', usedBy: ['example.com'] }),
		]);
		settingsMock.settingsApi.testDNSProvider.mockResolvedValue({
			ok: true,
			zone: 'example.com',
			records: 12,
		});

		render(DNSProvidersSection);
		await waitFor(() => screen.getByTestId('dns-provider-test-id-1'));
		await userEvent.click(screen.getByTestId('dns-provider-test-id-1'));
		expect((screen.getByLabelText('Zone') as HTMLInputElement).value).toBe('example.com');
		await userEvent.click(screen.getByTestId('dns-provider-test-run'));

		await waitFor(() =>
			expect(screen.getByTestId('dns-provider-test-ok')).toHaveTextContent('12'),
		);
		expect(settingsMock.settingsApi.testDNSProvider).toHaveBeenCalledWith('id-1', 'example.com');
	});

	it('connection test: surfaces the provider error and the zone_required code', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([provider({ id: 'id-1' })]);
		settingsMock.settingsApi.testDNSProvider
			.mockResolvedValueOnce({ ok: false, zone: 'example.com', records: 0, error: '403 Forbidden' })
			.mockRejectedValueOnce(
				new ApiError('zone', 400, 'validation', undefined, 'zone_required', {}),
			);

		render(DNSProvidersSection);
		await waitFor(() => screen.getByTestId('dns-provider-test-id-1'));
		await userEvent.click(screen.getByTestId('dns-provider-test-id-1'));
		await userEvent.type(screen.getByLabelText('Zone'), 'example.com');
		await userEvent.click(screen.getByTestId('dns-provider-test-run'));
		await waitFor(() =>
			expect(screen.getByTestId('dns-provider-test-failed')).toHaveTextContent('403 Forbidden'),
		);

		await userEvent.clear(screen.getByLabelText('Zone'));
		await userEvent.click(screen.getByTestId('dns-provider-test-run'));
		await waitFor(() =>
			expect(screen.getByTestId('dns-provider-test-failed')).toHaveTextContent(/zone/i),
		);
	});

	it('connection test is disabled for a provider missing credentials', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([
			provider({ id: 'id-1', configured: false }),
		]);
		render(DNSProvidersSection);
		await waitFor(() => screen.getByTestId('dns-provider-test-id-1'));
		expect(screen.getByTestId('dns-provider-test-id-1')).toBeDisabled();
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

	it('delete-blocked-by-routes: a 409 provider_in_use_by_routes surfaces the route hosts in the toast', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([
			provider({ id: 'id-1', usedBy: [] }),
		]);
		settingsMock.settingsApi.deleteDNSProvider.mockRejectedValue(
			new ApiError('in use by routes', 409, 'validation', undefined, 'provider_in_use_by_routes', {
				routes: ['app.example.com', 'api.example.com'],
			}),
		);

		render(DNSProvidersSection);
		await waitFor(() => screen.getByTestId('dns-provider-delete-id-1'));
		await userEvent.click(screen.getByTestId('dns-provider-delete-id-1'));
		await waitFor(() =>
			expect(screen.getByRole('button', { name: /^delete$/i })).toBeInTheDocument(),
		);
		await userEvent.click(screen.getByRole('button', { name: /^delete$/i }));

		await waitFor(() => {
			const msgs = toastMock.pushToast.mock.calls.map((c) => String(c[0]));
			expect(
				msgs.some((m) => m.includes('app.example.com') && m.includes('api.example.com')),
			).toBe(true);
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
