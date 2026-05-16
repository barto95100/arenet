// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import type { Route, RouteRequest } from './types';
import { ApiError } from './types';

const BASE: string = (import.meta.env.VITE_API_BASE_URL ?? '') as string;

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
	const init: RequestInit = { method };
	if (body !== undefined) {
		init.headers = { 'Content-Type': 'application/json' };
		init.body = JSON.stringify(body);
	}
	let res: Response;
	try {
		res = await fetch(`${BASE}/api/v1${path}`, init);
	} catch (err) {
		throw new ApiError(`network error: ${(err as Error).message}`, 0);
	}
	if (!res.ok) {
		let msg = `HTTP ${res.status}`;
		try {
			const payload = await res.json();
			if (payload && typeof payload.error === 'string') msg = payload.error;
		} catch {
			/* leave default msg */
		}
		throw new ApiError(msg, res.status);
	}
	if (res.status === 204) return undefined as T;
	return (await res.json()) as T;
}

export const listRoutes = (): Promise<Route[]> => request<Route[]>('GET', '/routes');
export const getRoute = (id: string): Promise<Route> => request<Route>('GET', `/routes/${id}`);
export const createRoute = (r: RouteRequest): Promise<Route> =>
	request<Route>('POST', '/routes', r);
export const updateRoute = (id: string, r: RouteRequest): Promise<Route> =>
	request<Route>('PUT', `/routes/${id}`, r);
export const deleteRoute = (id: string): Promise<void> => request<void>('DELETE', `/routes/${id}`);
