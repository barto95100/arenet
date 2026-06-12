// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Phase 2 Users-page refactor — OIDCConfigSummary tests.
//
// Covers the sidebar's Phase 2 polish:
//   - provider title resolved from kind via oidcProviderLabel
//   - CONNECTÉ outline badge rendered when enabled
//   - "Tester la connexion" success path → success toast
//   - "Tester la connexion" scopes-mismatch → danger toast with
//     the explicit missing list
//   - "Modifier la config" navigates to /settings#oidc-config

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import type { OIDCConfig, OIDCTestResult } from '$lib/api/types';

const getOIDCConfigMock = vi.fn<() => Promise<OIDCConfig>>();
const testOIDCConnectionMock = vi.fn<() => Promise<OIDCTestResult>>();

vi.mock('$lib/api/settings', () => ({
	settingsApi: {
		getOIDCConfig: () => getOIDCConfigMock(),
		testOIDCConnection: () => testOIDCConnectionMock()
	}
}));

const pushToastMock = vi.fn();
vi.mock('$lib/stores/toast', () => ({
	pushToast: (message: string, variant?: string) => pushToastMock(message, variant)
}));

const configuredEnabled: OIDCConfig = {
	enabled: true,
	configured: true,
	issuerUrl: 'https://authentik.arenet.fr',
	clientId: 'arenet-admin',
	clientSecret: '',
	clientSecretSet: true,
	allowedIdentities: [],
	scopes: ['openid', 'profile', 'email', 'groups'],
	redirectUrl: 'https://arenet.example/api/v1/auth/oidc/callback',
	acceptUnverifiedEmail: false,
	kind: 'authentik'
};

beforeEach(() => {
	getOIDCConfigMock.mockReset();
	testOIDCConnectionMock.mockReset();
	pushToastMock.mockReset();
});

describe('OIDCConfigSummary — Phase 2 polish', () => {
	it('renders the GoAuthentik title + hostname subtitle + CONNECTÉ badge', async () => {
		getOIDCConfigMock.mockResolvedValue(configuredEnabled);
		const Component = (await import('./OIDCConfigSummary.svelte')).default;
		render(Component);

		await waitFor(() => expect(getOIDCConfigMock).toHaveBeenCalled());
		await waitFor(() => expect(screen.getByText('GoAuthentik')).toBeTruthy());

		expect(screen.getByText('OIDC · authentik.arenet.fr')).toBeTruthy();
		expect(screen.getByText('CONNECTÉ')).toBeTruthy();
	});

	it('fires a success toast on a reachable probe with matching scopes', async () => {
		getOIDCConfigMock.mockResolvedValue(configuredEnabled);
		testOIDCConnectionMock.mockResolvedValue({
			reachable: true,
			issuer: 'https://authentik.arenet.fr',
			supportedScopes: ['email', 'groups', 'openid', 'profile'],
			scopesMatch: true,
			latencyMs: 42
		});

		const Component = (await import('./OIDCConfigSummary.svelte')).default;
		render(Component);
		await waitFor(() => screen.getByText('Tester la connexion'));

		await fireEvent.click(screen.getByTestId('oidc-test-button'));

		await waitFor(() => expect(pushToastMock).toHaveBeenCalled());
		expect(pushToastMock).toHaveBeenCalledWith(
			expect.stringContaining('42 ms'),
			'success'
		);
	});

	it('fires a danger toast with the explicit missing-scopes list on mismatch', async () => {
		getOIDCConfigMock.mockResolvedValue(configuredEnabled);
		testOIDCConnectionMock.mockResolvedValue({
			reachable: true,
			issuer: 'https://authentik.arenet.fr',
			supportedScopes: ['openid', 'profile'],
			scopesMatch: false,
			missingScopes: ['email', 'groups'],
			latencyMs: 18
		});

		const Component = (await import('./OIDCConfigSummary.svelte')).default;
		render(Component);
		await waitFor(() => screen.getByText('Tester la connexion'));

		await fireEvent.click(screen.getByTestId('oidc-test-button'));

		await waitFor(() => expect(pushToastMock).toHaveBeenCalled());
		const [msg, variant] = pushToastMock.mock.calls[0];
		expect(variant).toBe('danger');
		expect(msg).toContain('email, groups');
	});

	it('fires a danger toast when the probe returns reachable=false', async () => {
		getOIDCConfigMock.mockResolvedValue(configuredEnabled);
		testOIDCConnectionMock.mockResolvedValue({
			reachable: false,
			scopesMatch: false,
			latencyMs: 5000,
			error: 'context deadline exceeded'
		});

		const Component = (await import('./OIDCConfigSummary.svelte')).default;
		render(Component);
		await waitFor(() => screen.getByText('Tester la connexion'));

		await fireEvent.click(screen.getByTestId('oidc-test-button'));

		await waitFor(() => expect(pushToastMock).toHaveBeenCalled());
		expect(pushToastMock).toHaveBeenCalledWith(
			expect.stringContaining('context deadline exceeded'),
			'danger'
		);
	});

	it('renders a "Configurer" CTA when OIDC is not configured', async () => {
		getOIDCConfigMock.mockResolvedValue({
			...configuredEnabled,
			enabled: false,
			configured: false,
			issuerUrl: '',
			clientId: ''
		});

		const Component = (await import('./OIDCConfigSummary.svelte')).default;
		render(Component);

		await waitFor(() => expect(screen.getByText('Configurer')).toBeTruthy());
		expect(screen.queryByText('Tester la connexion')).toBeNull();
	});
});
