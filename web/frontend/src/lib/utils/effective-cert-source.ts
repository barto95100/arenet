// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Sujet 2 (2026-06-17) — parser for the Route.effectiveCertSource
// wire string.
//
// The backend (internal/api/handler.go:1407 computeEffectiveCert-
// Source) encodes the (kind, coveringApex) pair as a single
// string with a colon-prefix scheme that pre-dates this helper :
//
//   "managed-domain:<apex>"   — covered by a wildcard / apex MD
//   "per-route-acme:dns-01"   — dedicated dns-01 cert
//   "per-route-acme:http-01"  — dedicated http-01 cert
//   "per-route-internal"      — Caddy internal CA (private host)
//   ""                        — no inference (omitted on wire)
//
// Pre-Sujet-2 the routes table parsed the prefix inline (see
// src/routes/routes/+page.svelte:1623) and surfaced only a
// "wildcard" badge with the apex hidden in the title attribute.
// Operators with multiple managed domains couldn't tell at a
// glance WHICH wildcard covered a route, which is the gap
// Sujet 2 closes.
//
// The parser stays purely in TypeScript : the wire shape is
// stable and the colon-prefix scheme is unambiguous so a
// frontend parse is byte-equal to a (hypothetical) explicit
// coveringApex field, with the upside of not breaking the
// existing 7 Go tests pinning the string shape (see
// internal/api/managed_domain_test.go).

/** Discriminated union — every variant of effectiveCertSource. */
export type ParsedCertSource =
	| { kind: 'managed-domain'; coveringApex: string }
	| { kind: 'per-route-acme'; challenge: 'dns-01' | 'http-01' }
	| { kind: 'per-route-internal' }
	| { kind: 'none' };

/**
 * Parse the wire string into its structured shape.
 *
 *   parse(undefined) === { kind: 'none' }
 *   parse("")        === { kind: 'none' }
 *   parse("managed-domain:example.com")
 *     === { kind: 'managed-domain', coveringApex: 'example.com' }
 *   parse("managed-domain:")   // defensive — empty apex
 *     === { kind: 'none' }
 *   parse("per-route-acme:dns-01")
 *     === { kind: 'per-route-acme', challenge: 'dns-01' }
 *   parse("per-route-acme:http-01")
 *     === { kind: 'per-route-acme', challenge: 'http-01' }
 *   parse("per-route-internal")
 *     === { kind: 'per-route-internal' }
 *   parse("unknown:value")
 *     === { kind: 'none' }
 */
export function parseEffectiveCertSource(raw: string | undefined | null): ParsedCertSource {
	if (!raw) return { kind: 'none' };
	if (raw.startsWith('managed-domain:')) {
		const apex = raw.slice('managed-domain:'.length).trim();
		if (apex === '') return { kind: 'none' };
		return { kind: 'managed-domain', coveringApex: apex };
	}
	if (raw === 'per-route-acme:dns-01') {
		return { kind: 'per-route-acme', challenge: 'dns-01' };
	}
	if (raw === 'per-route-acme:http-01') {
		return { kind: 'per-route-acme', challenge: 'http-01' };
	}
	if (raw === 'per-route-internal') {
		return { kind: 'per-route-internal' };
	}
	// Unknown shape — degrade gracefully. A future backend that
	// adds a fifth source would not crash the route list; the
	// dashboard would simply omit the badge until the frontend is
	// taught the new variant.
	return { kind: 'none' };
}

/**
 * Operator-facing French label for a parsed cert source. Used
 * by the CertSourceBadge component and any other surface that
 * needs the same wording (e.g. a future details panel rewrite).
 *
 * Single source of truth for the copy so the routes list and
 * other surfaces stay aligned.
 */
export function certSourceLabel(parsed: ParsedCertSource): string {
	switch (parsed.kind) {
		case 'managed-domain':
			return `Couvert par *.${parsed.coveringApex}`;
		case 'per-route-acme':
			return parsed.challenge === 'dns-01' ? 'Cert dédié (DNS-01)' : 'Cert dédié (HTTP-01)';
		case 'per-route-internal':
			return 'Cert interne';
		case 'none':
			return '';
	}
}

/**
 * Long-form tooltip explaining the cert source. Surfaces the
 * RFC 6125 single-label rule on managed-domain matches so the
 * operator can debug "why isn't my deep.sub.example.com
 * covered" without leaving the page.
 */
export function certSourceTooltip(parsed: ParsedCertSource): string {
	switch (parsed.kind) {
		case 'managed-domain':
			return (
				`Cette route est servie par le certificat wildcard *.${parsed.coveringApex} ` +
				`géré dans SSL / Certificates. ` +
				`Règle RFC 6125 : un seul label DNS entre le hostname et l'apex (un sous-domaine direct).`
			);
		case 'per-route-acme':
			return parsed.challenge === 'dns-01'
				? 'Certificat dédié à cette route, émis via le challenge ACME DNS-01.'
				: 'Certificat dédié à cette route, émis via le challenge ACME HTTP-01.';
		case 'per-route-internal':
			return (
				"Certificat émis par l'autorité interne de Caddy (auto-signé). " +
				'Typique des hostnames privés (LAN, *.local) qui ne qualifient pas pour un cert public.'
			);
		case 'none':
			return '';
	}
}
