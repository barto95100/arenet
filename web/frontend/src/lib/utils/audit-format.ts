// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Audit display helpers (spec §9). Kept in a plain .ts module so they
// can be unit-tested directly without rendering Svelte components.
//
// v2.9.22 i18n — relativeTime() pulls the active locale from the
// language store so the rendered output ("2 days ago" / "il y a 2
// jours") respects the operator's choice. Pre-v2.9.22 the
// Intl.RelativeTimeFormat constructor was called with `undefined`
// for the locale arg which falls back to the browser/OS default —
// on FR-locale browsers that locked the output to French regardless
// of the in-app language preference (operator-reported 2026-06-26).

import { language } from '$lib/stores/language.svelte';

export type AuditCategory = 'auth' | 'mutation' | 'security' | 'hibp' | 'meta' | 'unknown';

// Mapping per spec §9.4 row badge categories.
const ACTION_CATEGORY: Record<string, AuditCategory> = {
	// Auth (cyan)
	login_success: 'auth',
	login_failure: 'auth',
	logout: 'auth',
	unlock_success: 'auth',
	unlock_failure: 'auth',
	// Mutation (amber)
	route_created: 'mutation',
	route_updated: 'mutation',
	route_deleted: 'mutation',
	password_changed: 'mutation',
	setup_admin_created: 'mutation',
	// Security (red)
	session_revoked: 'security',
	password_compromised_detected: 'security',
	// HIBP (violet)
	password_hibp_clean: 'hibp',
	password_hibp_pending: 'hibp',
	// Meta (slate)
	audit_viewed: 'meta'
};

/** categoryOf returns the spec §9.4 category for a given action. */
export function categoryOf(action: string): AuditCategory {
	return ACTION_CATEGORY[action] ?? 'unknown';
}

/**
 * relativeTime renders a short human-relative timestamp ("2 hours ago",
 * "yesterday", "3 days ago") using the platform's Intl.RelativeTimeFormat.
 *
 * Computed from a UTC ISO string; the resulting locale-relative text
 * stays anchored to UTC (spec §9.4 + §9.9).
 *
 * v2.9.22 i18n — the locale param defaults to `language.current` so
 * the output respects the in-app language preference. Callers can
 * pass an explicit locale string for tests that need a deterministic
 * EN baseline regardless of the runtime store state.
 *
 * Callers that need reactive updates on language switch should wrap
 * the call in a `$derived(language.current && relativeTime(iso))` so
 * Svelte 5 registers the dependency. Otherwise the cell stays at the
 * locale captured at first render.
 */
export function relativeTime(
	isoTimestamp: string,
	now: Date = new Date(),
	locale: string = language.current
): string {
	const then = new Date(isoTimestamp);
	if (Number.isNaN(then.getTime())) return isoTimestamp;
	const diffMs = then.getTime() - now.getTime(); // negative for past
	const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' });
	const absSec = Math.abs(diffMs) / 1000;
	if (absSec < 60) return rtf.format(Math.round(diffMs / 1000), 'second');
	if (absSec < 3600) return rtf.format(Math.round(diffMs / 60000), 'minute');
	if (absSec < 86400) return rtf.format(Math.round(diffMs / 3600000), 'hour');
	if (absSec < 86400 * 30) return rtf.format(Math.round(diffMs / 86400000), 'day');
	if (absSec < 86400 * 365) return rtf.format(Math.round(diffMs / (86400000 * 30)), 'month');
	return rtf.format(Math.round(diffMs / (86400000 * 365)), 'year');
}

/**
 * truncateMiddle keeps the first `keep` characters of a UUID-like
 * string and appends a Unicode ellipsis. Spec §9.4 uses 8 chars for
 * the collapsed-row target representation.
 */
export function truncateMiddle(s: string, keep: number = 8): string {
	if (s.length <= keep) return s;
	return s.slice(0, keep) + '…';
}

/**
 * formatJson renders a value for the expanded-row Before/After
 * <pre> block. Returns "(null)" for null/undefined and a defensive
 * placeholder for unmarshalable values (circular refs etc.).
 *
 * Spec §9.8: no syntax highlighting; the admin reads raw JSON.
 */
export function formatJson(value: unknown): string {
	if (value === null || value === undefined) return '(null)';
	try {
		return JSON.stringify(value, null, 2);
	} catch {
		return '(unable to render JSON)';
	}
}

/**
 * formatJsonWithFold truncates JSON longer than `maxLines` to the
 * first `maxLines` lines plus a foldable marker. Returns
 * { display, foldable } so the caller decides whether to render a
 * "Show more" link (spec §9.8).
 */
export function formatJsonWithFold(
	value: unknown,
	maxLines: number = 50
): { display: string; foldable: boolean; full: string } {
	const full = formatJson(value);
	const lines = full.split('\n');
	if (lines.length <= maxLines) {
		return { display: full, foldable: false, full };
	}
	return {
		display: lines.slice(0, maxLines).join('\n') + '\n... (truncated, click to expand)',
		foldable: true,
		full
	};
}

/**
 * actorDisplayShort returns the actor representation for the
 * collapsed-row view (spec §9.4).
 *
 * Authenticated event → `displayName` (or `username` fallback).
 * Anonymous event (login_failure pre-match) → `usernameSnapshot` in italic
 *   (caller styles this; we just return the string).
 */
export function actorDisplayShort(args: {
	actorUserId: string;
	actorUsernameSnapshot: string;
	displayName?: string;
	username?: string;
}): { text: string; anonymous: boolean } {
	if (args.actorUserId) {
		return {
			text: args.displayName || args.username || args.actorUsernameSnapshot || args.actorUserId,
			anonymous: false
		};
	}
	return {
		text: args.actorUsernameSnapshot || '(anonymous)',
		anonymous: true
	};
}

/**
 * targetDisplayShort returns the collapsed-row target representation
 * (spec §9.4). Empty target → "(none)".
 */
export function targetDisplayShort(targetType: string, targetId: string): string {
	if (!targetType && !targetId) return '(none)';
	if (!targetId) return targetType;
	return `${targetType}: ${truncateMiddle(targetId)}`;
}
