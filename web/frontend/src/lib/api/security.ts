// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step M.3 — typed client wrapper around GET /api/v1/security/events.
// The backend wire shape lives in
// internal/api/security_handlers.go; the response type is
// declared in lib/api/types.ts.

import { request } from './client';
import type {
	AttackersSummaryResponse,
	AuthFailuresResponse,
	DecisionsResponse,
	MetricWindow,
	OwaspCategory,
	ThrottleEventsResponse,
	WafEventsByRuleResponse,
	WafEventsResponse
} from './types';

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

/**
 * Per-(rule, category) aggregate over the window. Used by
 * the M.4 drill-down's per-rule breakdown table; server-
 * side aggregation avoids the most-recent-100 truncation
 * that client-side group-by would silently produce on a 30d
 * window.
 *
 * Both parameters are REQUIRED — the backend returns 400 if
 * either is missing.
 */
export function fetchEventsByRule(
	route: string,
	window: MetricWindow
): Promise<WafEventsByRuleResponse> {
	const qs = new URLSearchParams({ route, window });
	return request<WafEventsByRuleResponse>('GET', `/security/events/by-rule?${qs.toString()}`);
}

/**
 * Step Q.3 — typed client wrapper around GET
 * /api/v1/security/throttle-events.
 *
 * Filters are optional:
 *   - `limit` is clamped server-side at 100.
 *   - `srcIp` filters to a single source IP (exact match).
 *   - `tier` filters to tier 1 or 2; any other value is
 *     rejected by the backend with a 400.
 *
 * AC #14 degraded-mode path: when the observability subsystem
 * failed at boot, the response carries `disabled: true` and an
 * empty `events` array. Same shape contract as fetchEvents.
 */
export interface FetchThrottleEventsParams {
	limit?: number;
	srcIp?: string;
	tier?: 1 | 2;
}

export function fetchThrottleEvents(
	params: FetchThrottleEventsParams = {}
): Promise<ThrottleEventsResponse> {
	const qs = new URLSearchParams();
	if (params.limit !== undefined) qs.set('limit', String(params.limit));
	if (params.srcIp) qs.set('srcIp', params.srcIp);
	if (params.tier !== undefined) qs.set('tier', String(params.tier));
	const suffix = qs.toString() ? `?${qs.toString()}` : '';
	return request<ThrottleEventsResponse>('GET', `/security/throttle-events${suffix}`);
}

/**
 * Step Q.2 — typed client wrapper around GET
 * /api/v1/security/auth-failures.
 *
 * `window` is REQUIRED (backend returns 400 on missing). The
 * response carries BOTH a per-minute timeseries for the
 * dashboard chart AND a recent feed for the mixed-events
 * widget — single audit-scan, two projections (D4.B).
 *
 * `partial: true` signals the scan hit its 200-row cap before
 * reaching the window's `from`. AC #14 disabled contract on
 * nil reader.
 */
export function fetchAuthFailures(window: MetricWindow): Promise<AuthFailuresResponse> {
	const qs = new URLSearchParams({ window });
	return request<AuthFailuresResponse>('GET', `/security/auth-failures?${qs.toString()}`);
}

/**
 * Step Q.3 — typed client wrapper around GET
 * /api/v1/security/attackers-summary. Server-side union over
 * WAF + throttle + audit source-IP sets over the window.
 *
 * Three-state disabled/partial contract: ALL readers nil →
 * disabled; subset nil → partial; all present → neither.
 * Caller renders an "incomplete data" hint when `partial`
 * is true.
 */
export function fetchAttackersSummary(window: MetricWindow): Promise<AttackersSummaryResponse> {
	const qs = new URLSearchParams({ window });
	return request<AttackersSummaryResponse>('GET', `/security/attackers-summary?${qs.toString()}`);
}

/**
 * Step N.3 — typed client wrapper around GET
 * /api/v1/security/decisions.
 *
 * Filters are optional:
 *   - `limit` is clamped server-side at 100.
 *   - `scope` filters to a single LAPI scope (`ip`, `range`,
 *     `country`, `as` — free-form string for forward-compat).
 *   - `srcIp` is exact-match on the decision's `value`
 *     field (named `srcIp` for operator-mental-model
 *     consistency with the throttle-events endpoint).
 *   - `scenario` filters on the LAPI scenario name
 *     (e.g. `crowdsecurity/http-probing`).
 *   - `onlyActive` excludes rows whose `expiresAt` is in
 *     the past — i.e. revoked or expired decisions.
 *     Default false: include forensic "what WAS banned
 *     yesterday" rows.
 *
 * AC #15 degraded-mode path: when the LAPI key isn't
 * configured OR the observability subsystem failed at boot,
 * the response carries `disabled: true` and an empty
 * `events` array.
 */
export interface FetchDecisionsParams {
	limit?: number;
	scope?: string;
	srcIp?: string;
	scenario?: string;
	onlyActive?: boolean;
}

export function fetchDecisions(
	params: FetchDecisionsParams = {}
): Promise<DecisionsResponse> {
	const qs = new URLSearchParams();
	if (params.limit !== undefined) qs.set('limit', String(params.limit));
	if (params.scope) qs.set('scope', params.scope);
	if (params.srcIp) qs.set('srcIp', params.srcIp);
	if (params.scenario) qs.set('scenario', params.scenario);
	if (params.onlyActive) qs.set('onlyActive', 'true');
	const suffix = qs.toString() ? `?${qs.toString()}` : '';
	return request<DecisionsResponse>('GET', `/security/decisions${suffix}`);
}
