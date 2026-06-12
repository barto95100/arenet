// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Users-page Phase 1 refactor — vitest coverage for the
// /utilisateurs rewrite (commit 2). Pins:
//   - KPI counts derive correctly from a multi-user fixture
//   - Filters (search + role + source) narrow as expected
//   - Online/Actif/Hors-ligne render from lastActivityAt +
//     activeSessionCount thresholds
//   - BREAK-GLASS badge only shows on local admins when
//     OIDC is currently active
//   - Delete confirm dialog → API call → row removed
//   - Self-row Delete button hidden (UX guard)

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen, fireEvent } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';

const { settingsMock, authMock, toastMock, authStoreMock } = vi.hoisted(() => ({
	settingsMock: {
		listAdminUsers: vi.fn(),
		updateUserRole: vi.fn(),
		deleteAdminUser: vi.fn(),
		getOIDCConfig: vi.fn()
	},
	authMock: {
		oidcStatus: vi.fn()
	},
	toastMock: { pushToast: vi.fn() },
	authStoreMock: {
		state: 'authenticated' as 'authenticated' | 'unauthenticated',
		user: { id: 'self-id', role: 'admin' as 'admin' | 'viewer' }
	}
}));

vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$lib/stores/toast', () => ({ pushToast: toastMock.pushToast }));
vi.mock('$lib/stores/auth.svelte', () => ({ auth: authStoreMock }));
vi.mock('$lib/api/settings', () => ({
	settingsApi: {
		listAdminUsers: (...a: unknown[]) => settingsMock.listAdminUsers(...a),
		updateUserRole: (...a: unknown[]) => settingsMock.updateUserRole(...a),
		deleteAdminUser: (...a: unknown[]) => settingsMock.deleteAdminUser(...a),
		getOIDCConfig: (...a: unknown[]) => settingsMock.getOIDCConfig(...a)
	}
}));
vi.mock('$lib/api/auth', () => ({
	authApi: {
		oidcStatus: (...a: unknown[]) => authMock.oidcStatus(...a)
	}
}));

import Page from './+page.svelte';
import type { AdminUser } from '$lib/api/types';

function user(over: Partial<AdminUser> = {}): AdminUser {
	return {
		id: 'u-' + Math.random().toString(36).slice(2, 8),
		username: 'alice',
		displayName: 'Alice',
		email: 'alice@example.test',
		authSource: 'local',
		oidcLinked: false,
		role: 'admin',
		createdAt: '2026-01-01T00:00:00Z',
		updatedAt: '2026-06-01T00:00:00Z',
		activeSessionCount: 0,
		...over
	};
}

const now = Date.now();
function isoMinutesAgo(min: number): string {
	return new Date(now - min * 60_000).toISOString();
}

beforeEach(() => {
	settingsMock.listAdminUsers.mockReset();
	settingsMock.updateUserRole.mockReset();
	settingsMock.deleteAdminUser.mockReset();
	settingsMock.getOIDCConfig.mockReset();
	authMock.oidcStatus.mockReset();
	toastMock.pushToast.mockReset();
	authStoreMock.state = 'authenticated';
	authStoreMock.user = { id: 'self-id', role: 'admin' };

	settingsMock.getOIDCConfig.mockResolvedValue({
		enabled: false,
		configured: false,
		issuerUrl: '',
		clientId: '',
		clientSecret: '',
		clientSecretSet: false,
		scopes: [],
		redirectUrl: '',
		acceptUnverifiedEmail: false,
		kind: '',
		allowedIdentities: []
	});
	authMock.oidcStatus.mockResolvedValue({ enabled: false });
});

describe('/utilisateurs — KPI strip', () => {
	it('derives total / admins / sso / local counts from users[]', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', role: 'admin', authSource: 'local' }),
			user({ id: 'u2', role: 'admin', authSource: 'oidc' }),
			user({ id: 'u3', role: 'viewer', authSource: 'oidc' }),
			user({ id: 'u4', role: 'viewer', authSource: 'oidc' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		const strip = screen.getByTestId('users-kpi-strip');
		// Total = 4, Admins = 2, OIDC = 3, Local = 1.
		expect(strip.textContent).toContain('4');
		expect(strip.textContent).toContain('2');
		expect(strip.textContent).toContain('3');
		expect(strip.textContent).toContain('1');
	});
});

describe('/utilisateurs — filters', () => {
	it('search matches username, email, and role substring', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({
				id: 'u1',
				username: 'alice',
				displayName: 'Alice',
				email: 'alice@x.test',
				role: 'admin'
			}),
			user({
				id: 'u2',
				username: 'bob',
				displayName: 'Bob',
				email: 'bob@x.test',
				role: 'viewer'
			})
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('user-row-u1')).toBeTruthy();
		expect(screen.getByTestId('user-row-u2')).toBeTruthy();

		const search = screen.getByLabelText('Filter users');
		await userEvent.type(search, 'alice');
		await tick();

		expect(screen.getByTestId('user-row-u1')).toBeTruthy();
		expect(screen.queryByTestId('user-row-u2')).toBeNull();
	});

	it('role chips narrow to admins / viewers', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', role: 'admin' }),
			user({ id: 'u2', role: 'viewer' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		const roleFilter = screen.getByTestId('role-filter');
		await userEvent.click(roleFilter.querySelector('button:nth-child(2)') as HTMLElement);
		await tick();

		expect(screen.getByTestId('user-row-u1')).toBeTruthy();
		expect(screen.queryByTestId('user-row-u2')).toBeNull();
	});

	it('source chips narrow to local / oidc', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', authSource: 'local' }),
			user({ id: 'u2', authSource: 'oidc' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		const sourceFilter = screen.getByTestId('source-filter');
		await userEvent.click(sourceFilter.querySelector('button:nth-child(3)') as HTMLElement);
		await tick();

		expect(screen.queryByTestId('user-row-u1')).toBeNull();
		expect(screen.getByTestId('user-row-u2')).toBeTruthy();
	});
});

describe('/utilisateurs — activity indicator', () => {
	it('renders En ligne when lastActivityAt is recent + sessions exist', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({
				id: 'u1',
				activeSessionCount: 1,
				lastActivityAt: isoMinutesAgo(2)
			})
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		const row = screen.getByTestId('user-row-u1');
		expect(row.textContent).toContain('En ligne');
	});

	it('renders Actif when activity is between 5 and 60 min', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({
				id: 'u1',
				activeSessionCount: 1,
				lastActivityAt: isoMinutesAgo(30)
			})
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('user-row-u1').textContent).toContain('Actif');
	});

	it('renders Hors-ligne when no active session', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', activeSessionCount: 0 })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('user-row-u1').textContent).toContain('Hors-ligne');
	});
});

describe('/utilisateurs — break-glass badge', () => {
	it('renders BREAK-GLASS on local admin when OIDC is enabled', async () => {
		authMock.oidcStatus.mockResolvedValue({ enabled: true });
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', role: 'admin', authSource: 'local' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('break-glass-badge-u1')).toBeTruthy();
	});

	it('does NOT render BREAK-GLASS when OIDC is disabled', async () => {
		authMock.oidcStatus.mockResolvedValue({ enabled: false });
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', role: 'admin', authSource: 'local' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.queryByTestId('break-glass-badge-u1')).toBeNull();
	});

	it('does NOT render BREAK-GLASS on OIDC admins', async () => {
		authMock.oidcStatus.mockResolvedValue({ enabled: true });
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', role: 'admin', authSource: 'oidc' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.queryByTestId('break-glass-badge-u1')).toBeNull();
	});

	it('does NOT render BREAK-GLASS on viewers', async () => {
		authMock.oidcStatus.mockResolvedValue({ enabled: true });
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', role: 'viewer', authSource: 'local' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.queryByTestId('break-glass-badge-u1')).toBeNull();
	});
});

describe('/utilisateurs — delete flow', () => {
	it('hides Delete button on self row', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'self-id', username: 'me' }),
			user({ id: 'other-id', username: 'other' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.queryByTestId('delete-btn-self-id')).toBeNull();
		expect(screen.getByTestId('delete-btn-other-id')).toBeTruthy();
	});

	it('confirm dialog → API → row removed', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', username: 'alice' }),
			user({ id: 'u2', username: 'bob' })
		]);
		settingsMock.deleteAdminUser.mockResolvedValue(undefined);
		render(Page);
		await tick();
		await tick();
		await tick();

		await userEvent.click(screen.getByTestId('delete-btn-u1'));
		await tick();

		// ConfirmDialog renders a "Supprimer" confirm button.
		const confirmBtn = screen
			.getAllByRole('button', { name: /Supprimer/ })
			.find((b) => !b.dataset.testid?.startsWith('delete-btn-'));
		expect(confirmBtn).toBeTruthy();
		await userEvent.click(confirmBtn!);
		await tick();
		await tick();

		expect(settingsMock.deleteAdminUser).toHaveBeenCalledWith('u1');
		expect(screen.queryByTestId('user-row-u1')).toBeNull();
		expect(screen.getByTestId('user-row-u2')).toBeTruthy();
	});
});
