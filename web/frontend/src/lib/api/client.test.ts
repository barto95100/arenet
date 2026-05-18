// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock $lib/stores/auth so the interceptor tests can spy on
// clear() and setLocked() without exercising the real store.
const authMock = {
	user: null,
	state: 'authenticated' as 'authenticated' | 'anonymous' | 'locked' | 'unknown',
	clear: vi.fn(),
	setLocked: vi.fn()
};
vi.mock('$lib/stores/auth.svelte', () => ({ auth: authMock }));

// Mock $lib/stores/idle to spy on idle.reset() invocations.
const idleMock = { reset: vi.fn() };
vi.mock('$lib/stores/idle.svelte', () => ({ idle: idleMock }));

// Mock $lib/stores/toast (pushToast) for 429 toast tests.
const toastMock = { pushToast: vi.fn() };
vi.mock('$lib/stores/toast', () => ({
	pushToast: toastMock.pushToast
}));

// Mock $lib/stores/loading for beginRequest/endRequest no-op.
vi.mock('$lib/stores/loading', () => ({
	beginRequest: vi.fn(),
	endRequest: vi.fn()
}));

const { request } = await import('./client');
const { ApiError } = await import('./types');
type ApiErrorType = InstanceType<typeof ApiError>;
const { goto } = await import('$app/navigation');

// Helper: install a mock fetch returning the given response.
function mockFetch(status: number, body: unknown | undefined, headers: Record<string, string> = {}): void {
	(globalThis as { fetch?: unknown }).fetch = vi.fn(async () => {
		return new Response(body === undefined ? null : JSON.stringify(body), {
			status,
			headers: { 'Content-Type': 'application/json', ...headers }
		});
	});
}

beforeEach(() => {
	authMock.state = 'authenticated';
	authMock.clear.mockReset();
	authMock.setLocked.mockReset();
	idleMock.reset.mockReset();
	toastMock.pushToast.mockReset();
	(goto as ReturnType<typeof vi.fn>).mockReset();
	// Default to a path that is not /login or /setup so 401 triggers goto.
	Object.defineProperty(window, 'location', {
		value: { pathname: '/routes' },
		writable: true
	});
});

describe('request: credentials always included', () => {
	it('sets credentials: include in the fetch init', async () => {
		const fetchSpy = vi.fn(
			async (_input: RequestInfo | URL, _init?: RequestInit) =>
				new Response(JSON.stringify({}), {
					status: 200,
					headers: { 'Content-Type': 'application/json' }
				})
		);
		(globalThis as { fetch?: unknown }).fetch = fetchSpy;
		await request('GET', '/routes');
		expect(fetchSpy).toHaveBeenCalledTimes(1);
		const init = fetchSpy.mock.calls[0][1];
		expect(init?.credentials).toBe('include');
	});
});

describe('request: 401 interceptor', () => {
	it('clears auth and navigates to /login', async () => {
		mockFetch(401, { error: 'no active session' });
		await expect(request('GET', '/routes')).rejects.toMatchObject({ status: 401, kind: 'auth' });
		expect(authMock.clear).toHaveBeenCalledTimes(1);
		expect(goto).toHaveBeenCalledWith('/login');
	});

	it('does NOT goto when already on /login (no redirect loop)', async () => {
		Object.defineProperty(window, 'location', {
			value: { pathname: '/login' },
			writable: true
		});
		mockFetch(401, { error: 'no active session' });
		await expect(request('POST', '/auth/login', { username: 'a', password: 'b' })).rejects.toMatchObject({
			status: 401
		});
		expect(goto).not.toHaveBeenCalled();
	});

	it('does NOT goto when already on /setup', async () => {
		Object.defineProperty(window, 'location', {
			value: { pathname: '/setup' },
			writable: true
		});
		mockFetch(401, { error: 'no active session' });
		await expect(request('POST', '/auth/setup', {})).rejects.toMatchObject({ status: 401 });
		expect(goto).not.toHaveBeenCalled();
	});
});

describe('request: 403 interceptor', () => {
	it('calls auth.setLocked when body is "session locked"', async () => {
		mockFetch(403, { error: 'session locked' });
		await expect(request('GET', '/routes')).rejects.toMatchObject({
			status: 403,
			kind: 'forbidden',
			message: 'session locked'
		});
		expect(authMock.setLocked).toHaveBeenCalledTimes(1);
	});

	it('does NOT call setLocked for other 403 messages (forward-compat with Phase 2 role-based 403)', async () => {
		mockFetch(403, { error: 'forbidden by role' });
		await expect(request('GET', '/routes')).rejects.toMatchObject({ status: 403, kind: 'forbidden' });
		expect(authMock.setLocked).not.toHaveBeenCalled();
	});
});

describe('request: 429 interceptor', () => {
	it('pushes a toast and surfaces retryAfterSeconds from Retry-After header', async () => {
		mockFetch(
			429,
			{ error: 'too many attempts, retry after 15 minutes' },
			{ 'Retry-After': '900' }
		);
		let err: ApiErrorType | undefined;
		try {
			await request('POST', '/auth/login', { username: 'a', password: 'b' });
		} catch (e) {
			err = e as ApiErrorType;
		}
		expect(err).toBeInstanceOf(ApiError);
		expect(err?.status).toBe(429);
		expect(err?.kind).toBe('rate_limited');
		expect(err?.retryAfterSeconds).toBe(900);
		expect(toastMock.pushToast).toHaveBeenCalledTimes(1);
	});

	it('tolerates missing Retry-After header (retryAfterSeconds=0)', async () => {
		mockFetch(429, { error: 'too many attempts' });
		let err: ApiErrorType | undefined;
		try {
			await request('POST', '/auth/login', {});
		} catch (e) {
			err = e as ApiErrorType;
		}
		expect(err?.status).toBe(429);
		expect(err?.retryAfterSeconds).toBe(0);
	});
});

describe('request: idle timer reset gate', () => {
	it('calls idle.reset on 200 success', async () => {
		mockFetch(200, { ok: true });
		await request('GET', '/routes');
		expect(idleMock.reset).toHaveBeenCalledTimes(1);
	});

	it('calls idle.reset on 4xx (excluding the auth-related interceptor branches)', async () => {
		// 400 — validation. Must still count as server interaction.
		mockFetch(400, { error: 'validation' });
		await expect(request('POST', '/routes', {})).rejects.toMatchObject({ status: 400 });
		expect(idleMock.reset).toHaveBeenCalledTimes(1);
	});

	it('does NOT call idle.reset on 5xx', async () => {
		mockFetch(500, { error: 'server error' });
		await expect(request('GET', '/routes')).rejects.toMatchObject({ status: 500 });
		expect(idleMock.reset).not.toHaveBeenCalled();
	});

	it('does NOT call idle.reset on network failure (status 0)', async () => {
		(globalThis as { fetch?: unknown }).fetch = vi.fn(async () => {
			throw new Error('boom');
		});
		await expect(request('GET', '/routes')).rejects.toMatchObject({ status: 0 });
		expect(idleMock.reset).not.toHaveBeenCalled();
	});

	it('does NOT call idle.reset on 401 (interceptor returns early)', async () => {
		mockFetch(401, { error: 'no active session' });
		await expect(request('GET', '/routes')).rejects.toMatchObject({ status: 401 });
		expect(idleMock.reset).not.toHaveBeenCalled();
	});
});

describe('request: 204 No Content', () => {
	it('returns undefined for 204 responses', async () => {
		mockFetch(204, undefined);
		const out = await request<void>('POST', '/auth/logout');
		expect(out).toBeUndefined();
	});
});
