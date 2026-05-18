// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock the underlying ./client.request so we can assert the
// (method, path, body) tuple without making real HTTP calls.
const requestMock = vi.fn();
vi.mock('./client', () => ({ request: requestMock }));

const { authApi } = await import('./auth');

beforeEach(() => {
	requestMock.mockReset();
	requestMock.mockResolvedValue(undefined);
});

describe('authApi wrappers: method + path + body', () => {
	it('setup POSTs /auth/setup with all 4 fields', async () => {
		await authApi.setup('tok', 'admin', 'Admin', 'pw');
		expect(requestMock).toHaveBeenCalledWith('POST', '/auth/setup', {
			setupToken: 'tok',
			username: 'admin',
			displayName: 'Admin',
			password: 'pw'
		});
	});

	it('login POSTs /auth/login with rememberMe', async () => {
		await authApi.login('admin', 'pw', true);
		expect(requestMock).toHaveBeenCalledWith('POST', '/auth/login', {
			username: 'admin',
			password: 'pw',
			rememberMe: true
		});
	});

	it('logout POSTs /auth/logout with no body', async () => {
		await authApi.logout();
		expect(requestMock).toHaveBeenCalledWith('POST', '/auth/logout');
	});

	it('me GETs /auth/me', async () => {
		await authApi.me();
		expect(requestMock).toHaveBeenCalledWith('GET', '/auth/me');
	});

	it('unlock POSTs /auth/unlock with the password', async () => {
		await authApi.unlock('pw');
		expect(requestMock).toHaveBeenCalledWith('POST', '/auth/unlock', { password: 'pw' });
	});

	it('heartbeat POSTs /auth/heartbeat with no body', async () => {
		await authApi.heartbeat();
		expect(requestMock).toHaveBeenCalledWith('POST', '/auth/heartbeat');
	});

	it('listSessions GETs /auth/sessions', async () => {
		await authApi.listSessions();
		expect(requestMock).toHaveBeenCalledWith('GET', '/auth/sessions');
	});

	it('deleteSession DELETEs /auth/sessions/{id}', async () => {
		await authApi.deleteSession('sess-1');
		expect(requestMock).toHaveBeenCalledWith('DELETE', '/auth/sessions/sess-1');
	});

	it('changePassword POSTs /auth/me/password with both passwords', async () => {
		await authApi.changePassword('old', 'new');
		expect(requestMock).toHaveBeenCalledWith('POST', '/auth/me/password', {
			currentPassword: 'old',
			newPassword: 'new'
		});
	});
});

describe('authApi: error propagation', () => {
	it('propagates rejection from request unchanged', async () => {
		const boom = new Error('boom');
		requestMock.mockRejectedValueOnce(boom);
		await expect(authApi.me()).rejects.toBe(boom);
	});
});
