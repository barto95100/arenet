// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step M.3 — typed client wrapper around GET /api/v1/security/events.
// The backend wire shape lives in
// internal/api/security_handlers.go; the response type is
// declared in lib/api/types.ts.

import { request } from './client';
import type { OwaspCategory, WafEventsResponse } from './types';

export interface FetchEventsParams {
	limit?: number;
	route?: string;
	category?: OwaspCategory;
}

/**
 * Fetch recent WAF events from /api/v1/security/events.
 *
 * Filters are optional:
 *   - `limit` is clamped server-side at 100; values > 100 are
 *     silently capped (no error).
 *   - `route` filters to a single route UUID.
 *   - `category` filters to one OWASP category string.
 *
 * AC #13 degraded-mode path: when the observability subsystem
 * failed at boot, the response carries `disabled: true` and an
 * empty `events` array. Callers should surface a clean empty
 * state in that case, not a hostile error toast.
 */
export function fetchEvents(params: FetchEventsParams = {}): Promise<WafEventsResponse> {
	const qs = new URLSearchParams();
	if (params.limit !== undefined) qs.set('limit', String(params.limit));
	if (params.route) qs.set('route', params.route);
	if (params.category) qs.set('category', params.category);
	const suffix = qs.toString() ? `?${qs.toString()}` : '';
	return request<WafEventsResponse>('GET', `/security/events${suffix}`);
}
