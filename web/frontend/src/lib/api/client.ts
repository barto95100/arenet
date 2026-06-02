// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// HTTP client for /api/v1/*. Step C handled routes; Step D extends it
// with auth-aware interceptors (spec §6.4):
//   1. credentials: 'include' on every request (sends the
//      arenet_session cookie even cross-origin in dev).
//   2. 401 → auth.clear() + redirect to /login (unless already there).
//   3. 403 with body "session locked" → auth.setLocked().
//   4. 429 → toast notification with Retry-After.
//   5. Successful responses (status < 500) reset the idle timer.
//
// The signature request(method, path, body?) is unchanged from Step C
// so existing call sites in lib/api/client.ts and beyond keep working.

import type { Route, RouteRequest } from './types';
import { ApiError } from './types';
import { beginRequest, endRequest } from '$lib/stores/loading';
import { auth } from '$lib/stores/auth.svelte';
import { idle } from '$lib/stores/idle.svelte';
import { pushToast } from '$lib/stores/toast';
import { goto } from '$app/navigation';

// In production (the binary serves both API and frontend), always use
// same-origin paths regardless of any VITE_API_BASE_URL value baked
// into the bundle. Step #S-21 fix: without this guard, a non-empty
// VITE_API_BASE_URL in .env (intentional for dev — see vite.config
// proxy) gets compiled into the prod bundle, breaking every admin
// context other than localhost (LAN HTTP admin, FQDN admin, etc.)
// with cross-origin fetches that the binary cannot satisfy via CORS.
const BASE: string = import.meta.env.DEV
	? ((import.meta.env.VITE_API_BASE_URL ?? '') as string)
	: '';
/**
 * Send an HTTP request to /api/v1/<path> with JSON body/response
 * semantics. Generic on the response type T. Throws ApiError on any
 * non-2xx outcome (or on network failure with status 0).
 *
 * Exported so the new Step D modules (lib/api/auth.ts, lib/api/audit.ts)
 * can compose typed wrappers on top.
 */
export async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
	beginRequest();
	try {
		const init: RequestInit = {
			method,
			credentials: 'include'
		};
		if (body !== undefined) {
			init.headers = { 'Content-Type': 'application/json' };
			init.body = JSON.stringify(body);
		}
		let res: Response;
		try {
			res = await fetch(`${BASE}/api/v1${path}`, init);
		} catch (err) {
			throw new ApiError(`network error: ${(err as Error).message}`, 0, 'system');
		}

		// Step D interceptors BEFORE body parsing.
		if (res.status === 401) {
			auth.clear();
			// Avoid redirect loops: only navigate when not already on
			// an unauthenticated entry page.
			const here = typeof window !== 'undefined' ? window.location.pathname : '';
			if (here !== '/login' && here !== '/setup') {
				void goto('/login');
			}
			throw new ApiError('authentication required', 401, 'auth');
		}

		if (res.status === 403) {
			// Step D has exactly one cause for 403 (session locked).
			// Phase 2 may introduce role-based 403s; this is where we'd
			// disambiguate by body.error.
			const body403 = await safeJSON(res);
			const msg = typeof body403?.error === 'string' ? body403.error : 'forbidden';
			if (msg === 'session locked') {
				auth.setLocked();
				throw new ApiError('session locked', 403, 'forbidden');
			}
			throw new ApiError(msg, 403, 'forbidden');
		}

		if (res.status === 429) {
			const retryHdr = res.headers.get('Retry-After') ?? '0';
			const retryAfter = parseInt(retryHdr, 10) || 0;
			const body429 = await safeJSON(res);
			const msg = typeof body429?.error === 'string' ? body429.error : 'rate limited';
			pushToast(msg, 'danger');
			throw new ApiError(msg, 429, 'rate_limited', retryAfter);
		}

		// Idle reset gate: any response < 500 counts as server interaction.
		// 5xx and network errors (status 0) do not reset (spec §6.4).
		if (res.status < 500) {
			idle.reset();
		}

		if (!res.ok) {
			// 4xx (other than 401/403/429) → validation error.
			// 5xx → system error.
			const errBody = await safeJSON(res);
			const msg =
				typeof errBody?.error === 'string' ? errBody.error : `HTTP ${res.status}`;
			const kind = res.status >= 500 ? 'system' : 'validation';
			throw new ApiError(msg, res.status, kind);
		}

		if (res.status === 204) return undefined as T;
		return (await res.json()) as T;
	} finally {
		endRequest();
	}
}

/** safeJSON returns the parsed JSON body or null if parsing fails. */
async function safeJSON(res: Response): Promise<Record<string, unknown> | null> {
	try {
		return (await res.json()) as Record<string, unknown>;
	} catch {
		return null;
	}
}

// Step C route operations preserved verbatim — call sites in the UI
// keep working unchanged.
export const listRoutes = (): Promise<Route[]> => request<Route[]>('GET', '/routes');
export const getRoute = (id: string): Promise<Route> => request<Route>('GET', `/routes/${id}`);
export const createRoute = (r: RouteRequest): Promise<Route> =>
	request<Route>('POST', '/routes', r);
export const updateRoute = (id: string, r: RouteRequest): Promise<Route> =>
	request<Route>('PUT', `/routes/${id}`, r);
export const deleteRoute = (id: string): Promise<void> => request<void>('DELETE', `/routes/${id}`);
