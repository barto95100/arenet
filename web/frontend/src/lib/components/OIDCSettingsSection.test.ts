// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.72 — this component had no test file at all, and it is the
// largest form in settings: eleven bound fields, one of them a client
// secret. The tests here cover the unsaved-input predicate added for
// the settings-tab guard (spec 2026-10-13), which is what the page
// consults before unmounting the section.
//
// Gate 3 of that spec is the load-bearing one: a save must leave the
// form clean. submitConfig assigns `config = saved` but does NOT
// re-copy the text fields, so the predicate compares them after the
// same trim the submit applies — otherwise a trailing space would
// read as unsaved work forever and the dialog would cry wolf.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import type { OIDCConfig, OIDCConfigRequest, OIDCAllowedIdentity } from '$lib/api/types';
import {
	hasUnsaved,
	unsavedIds,
	resetUnsavedRegistry
} from '$lib/stores/unsaved.svelte';

const getConfigMock = vi.fn<() => Promise<OIDCConfig>>();
const putConfigMock = vi.fn<(r: OIDCConfigRequest) => Promise<OIDCConfig>>();
const listAllowlistMock = vi.fn<() => Promise<OIDCAllowedIdentity[]>>();
const addAllowlistMock = vi.fn();
const deleteAllowlistMock = vi.fn();

vi.mock('$lib/api/settings', () => ({
	settingsApi: {
		getOIDCConfig: () => getConfigMock(),
		putOIDCConfig: (r: OIDCConfigRequest) => putConfigMock(r),
		listOIDCAllowlist: () => listAllowlistMock(),
		addOIDCAllowlist: (b: unknown) => addAllowlistMock(b),
		deleteOIDCAllowlist: (e: string) => deleteAllowlistMock(e)
	}
}));

vi.mock('$lib/stores/toast', () => ({ pushToast: vi.fn() }));

const { default: OIDCSettingsSection } = await import('./OIDCSettingsSection.svelte');

const storedConfig: OIDCConfig = {
	enabled: true,
	issuerUrl: 'https://auth.example.com/application/o/arenet/',
	clientId: 'arenet',
	clientSecret: '', // redacted on the wire
	clientSecretSet: true,
	scopes: ['openid', 'profile', 'email'],
	redirectUrl: 'https://arenet.example.com/api/v1/auth/oidc/callback',
	acceptUnverifiedEmail: false,
	kind: 'authentik'
} as OIDCConfig;

beforeEach(() => {
	resetUnsavedRegistry();
	getConfigMock.mockReset();
	putConfigMock.mockReset();
	listAllowlistMock.mockReset();
	addAllowlistMock.mockReset();
	deleteAllowlistMock.mockReset();
	getConfigMock.mockResolvedValue({ ...storedConfig });
	listAllowlistMock.mockResolvedValue([]);
});

async function renderLoaded() {
	render(OIDCSettingsSection);
	await waitFor(() => expect(screen.getByLabelText(/Issuer URL/i)).toBeInTheDocument());
}

describe('OIDCSettingsSection — unsaved input', () => {
	it('reports nothing on a freshly loaded form', async () => {
		await renderLoaded();

		expect(hasUnsaved()).toBe(false);
	});

	it('reports a typed client secret, which has nothing to compare against', async () => {
		await renderLoaded();

		await fireEvent.input(screen.getByLabelText(/Client secret/i), {
			target: { value: 'rotated' }
		});

		expect(unsavedIds()).toEqual(['oidc']);
	});

	it('reports a changed issuer and forgets it once typed back', async () => {
		await renderLoaded();
		const issuer = screen.getByLabelText(/Issuer URL/i) as HTMLInputElement;

		await fireEvent.input(issuer, { target: { value: 'https://other.example.com/' } });
		expect(hasUnsaved()).toBe(true);

		await fireEvent.input(issuer, { target: { value: storedConfig.issuerUrl } });
		expect(hasUnsaved()).toBe(false);
	});

	it('ignores whitespace the submit would trim anyway', async () => {
		// The submit sends issuerUrl.trim(), so a trailing space is not
		// a change the server would record. Reporting it would make the
		// dialog appear for input that cannot be saved.
		await renderLoaded();

		await fireEvent.input(screen.getByLabelText(/Issuer URL/i), {
			target: { value: `  ${storedConfig.issuerUrl}  ` }
		});

		expect(hasUnsaved()).toBe(false);
	});

	it('ignores scope spacing the submit would normalise', async () => {
		// Scopes travel as a list; the form is a single string split on
		// whitespace and commas. Extra separators are not a change.
		await renderLoaded();

		await fireEvent.input(screen.getByLabelText(/Scopes/i), {
			target: { value: 'openid,  profile   email' }
		});

		expect(hasUnsaved()).toBe(false);
	});

	it('reports a real scope change', async () => {
		await renderLoaded();

		await fireEvent.input(screen.getByLabelText(/Scopes/i), {
			target: { value: 'openid profile' }
		});

		expect(hasUnsaved()).toBe(true);
	});

	it('is clean after a successful save', async () => {
		await renderLoaded();
		putConfigMock.mockResolvedValue({
			...storedConfig,
			issuerUrl: 'https://other.example.com/'
		});

		await fireEvent.input(screen.getByLabelText(/Issuer URL/i), {
			target: { value: 'https://other.example.com/' }
		});
		await fireEvent.input(screen.getByLabelText(/Client secret/i), {
			target: { value: 'rotated' }
		});
		expect(hasUnsaved()).toBe(true);

		await fireEvent.click(screen.getByRole('button', { name: /^Save$/i }));
		await waitFor(() => expect(putConfigMock).toHaveBeenCalled());

		await waitFor(() => expect(hasUnsaved()).toBe(false));
	});

	it('reports a half-typed allowlist row', async () => {
		// It is typed input in this tab, and the unmount takes it with
		// everything else.
		await renderLoaded();

		await fireEvent.input(screen.getByLabelText(/^Email$/i), {
			target: { value: 'ops@example.com' }
		});

		expect(hasUnsaved()).toBe(true);
	});

	it('unregisters when the section is destroyed', async () => {
		const { unmount } = render(OIDCSettingsSection);
		await waitFor(() => expect(screen.getByLabelText(/Issuer URL/i)).toBeInTheDocument());
		await fireEvent.input(screen.getByLabelText(/Client secret/i), {
			target: { value: 'rotated' }
		});
		expect(hasUnsaved()).toBe(true);

		unmount();

		expect(hasUnsaved()).toBe(false);
	});

	it('says nothing when the config never loaded', async () => {
		// A failed load leaves an empty form. Comparing it against
		// nothing would report every field as unsaved work and block
		// the tab for an operator who typed nothing at all.
		getConfigMock.mockRejectedValue(new Error('boom'));
		render(OIDCSettingsSection);
		await waitFor(() => expect(getConfigMock).toHaveBeenCalled());

		expect(hasUnsaved()).toBe(false);
	});
});
