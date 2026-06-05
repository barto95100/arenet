// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step T T.4 — helpers for rendering Certificate runtime metadata
// in the /certs Domaines table. The Badge variant mapping is the
// AC #10 LOCKED contract (spec §1.4 + AC #10); the renewal-window
// constant matches the backend's RenewalMargin in
// internal/certinfo/tracker.go (30 days).

import type { Certificate, CertificateStatus, CertificateSource } from '$lib/api/types';

/**
 * Days before notAfter at which the frontend treats a cert as
 * "Expirent bientôt" for the tab filter AND switches the EXPIRE
 * DANS column to the amber warning tone. Mirrors
 * certinfo.RenewalMargin (30 * 24h) on the backend; kept as a
 * named constant so the future change-window-policy step touches
 * one place per side.
 */
export const RENEWAL_WINDOW_DAYS = 30;

/**
 * Badge variant the AC #10 status → color table maps to. The
 * Badge component (web/frontend/src/lib/components/Badge.svelte)
 * has no dedicated cert variants — we reuse the existing
 * status-up / status-warn / status-down / neutral palette so the
 * Routes-page C11 badge precedent stays consistent.
 */
export type CertificateBadgeVariant =
	| 'status-up' // VALID
	| 'status-warn' // RENEWAL_PENDING
	| 'status-down' // EXPIRED, OBTAIN_FAILED
	| 'neutral'; // UNKNOWN

/**
 * Maps a CertificateStatus to the Badge variant the Domaines
 * table renders. Pure function — no I/O, no clock reads — so
 * the unit test doesn't need date stubbing.
 *
 * The mapping is the spec §1.4 + AC #10 locked vocabulary:
 *   VALID            → green   (status-up)
 *   RENEWAL_PENDING  → amber   (status-warn)
 *   EXPIRED          → red     (status-down)
 *   OBTAIN_FAILED    → red     (status-down)
 *   UNKNOWN          → grey    (neutral)
 */
export function certificateStatusToBadgeVariant(
	status: CertificateStatus
): CertificateBadgeVariant {
	switch (status) {
		case 'VALID':
			return 'status-up';
		case 'RENEWAL_PENDING':
			return 'status-warn';
		case 'EXPIRED':
		case 'OBTAIN_FAILED':
			return 'status-down';
		case 'UNKNOWN':
		default:
			return 'neutral';
	}
}

/**
 * Operator-facing French label for the status badge. Locked
 * copy: changes here must be paired with a spec amendment, since
 * the labels are part of the AC #10 contract (the spec's "VALIDE
 * / RENOUV. AUTO / EXPIRÉ / ÉCHEC / —" vocabulary).
 */
export function certificateStatusLabel(status: CertificateStatus): string {
	switch (status) {
		case 'VALID':
			return 'VALIDE';
		case 'RENEWAL_PENDING':
			return 'RENOUV. AUTO';
		case 'EXPIRED':
			return 'EXPIRÉ';
		case 'OBTAIN_FAILED':
			return 'ÉCHEC';
		case 'UNKNOWN':
		default:
			return '—';
	}
}

/**
 * Operator-facing French label for the source classifier
 * (rendered under the DOMAINE column).
 */
export function certificateSourceLabel(source: CertificateSource): string {
	switch (source) {
		case 'wildcard':
			return 'wildcard';
		case 'apex':
			return 'apex';
		case 'specific':
		default:
			return 'spécifique';
	}
}

/**
 * Best-guess ACME challenge label for the sub-line under DOMAINE.
 * Wildcard-source certs go through DNS-01 (the only way certmagic
 * can fulfill *.x). Specific / apex certs default to HTTP-01.
 *
 * This is a UX heuristic — the backend doesn't currently surface
 * the actual challenge used per cert (would require certmagic
 * Issuer introspection). A future Step T+N could promote this to
 * a real backend-supplied field; today the heuristic is operator-
 * correct in 100% of AreNET-configured paths.
 */
export function inferChallengeLabel(source: CertificateSource): string {
	if (source === 'wildcard') return 'DNS-01';
	return 'HTTP-01';
}

/**
 * Whole-day count between now and the cert's notAfter. Positive
 * for future expiries (the typical case); negative when the cert
 * has already expired. Used by both the EXPIRE DANS column and
 * the "Expirent bientôt" tab filter.
 *
 * Rounding: floor on positive, ceil on negative — so "in 0 days"
 * means "expires today" and "-1 days" means "expired yesterday".
 */
export function daysUntilExpiry(cert: Certificate, now: Date = new Date()): number {
	const notAfter = new Date(cert.notAfter);
	if (Number.isNaN(notAfter.getTime())) return 0;
	const diffMs = notAfter.getTime() - now.getTime();
	const days = diffMs / (1000 * 60 * 60 * 24);
	return diffMs >= 0 ? Math.floor(days) : Math.ceil(days);
}

/**
 * Predicate: cert is "expiring soon" per the AC #6 tab filter
 * vocabulary. Defined as "notAfter <= now + RENEWAL_WINDOW_DAYS"
 * — matches the backend's RENEWAL_PENDING status derivation so
 * the tab surfaces the same set the badge highlights.
 *
 * Includes already-expired certs (the operator surely wants to
 * see those in the "expiring soon" bucket too).
 */
export function isExpiringSoon(cert: Certificate, now: Date = new Date()): boolean {
	return daysUntilExpiry(cert, now) <= RENEWAL_WINDOW_DAYS;
}

/**
 * Most-common Issuer string across the cert list. Used for the
 * "Émetteur principal" KPI. Returns '—' for an empty list.
 *
 * Tie-breaker: alphabetical (deterministic for snapshot tests).
 * In practice every AreNET install uses a single issuer, so the
 * tiebreaker path is exercised only by fixtures.
 */
export function dominantIssuer(certs: Certificate[]): string {
	if (certs.length === 0) return '—';
	const counts = new Map<string, number>();
	for (const c of certs) {
		const k = c.issuer || '—';
		counts.set(k, (counts.get(k) ?? 0) + 1);
	}
	let best = '';
	let bestCount = -1;
	for (const [issuer, count] of counts) {
		if (count > bestCount || (count === bestCount && issuer < best)) {
			best = issuer;
			bestCount = count;
		}
	}
	return best;
}
