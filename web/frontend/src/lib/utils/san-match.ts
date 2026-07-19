// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.19.0 external-certs SOCLE (Task 8) — RFC 6125 host↔SAN matcher.
//
// Byte-for-byte mirror of the Go reference storage.HostMatchesSAN
// (internal/storage/routes.go:585). The route-form cert picker uses
// it to filter uploaded external certs down to those whose SANs
// actually cover the route host, so the operator never picks a cert
// the backend would reject (the backend re-checks with the same rule
// in handler.go:1870, so this is a client-side pre-filter, not the
// authority).
//
// Wildcard semantics (RFC 6125 §6.4.3): a leading `*.` label matches
// EXACTLY ONE DNS label — `*.example.com` covers `app.example.com`
// but NOT `sub.app.example.com` (two labels) and NOT the bare apex
// `example.com`. Matching is case-insensitive and tolerates a
// trailing dot (FQDN root) on either side.

/**
 * Report whether `host` is covered by any SAN in `sans`, using
 * RFC 6125 single-label wildcard rules. Case-insensitive; a
 * trailing dot on host or SAN is ignored.
 *
 *   hostMatchesSAN('app.example.com', ['app.example.com'])   → true
 *   hostMatchesSAN('app.example.com', ['*.example.com'])     → true
 *   hostMatchesSAN('sub.app.example.com', ['*.example.com'])  → false
 *   hostMatchesSAN('example.com', ['*.example.com'])          → false
 *   hostMatchesSAN('APP.example.com', ['app.example.com'])    → true
 */
export function hostMatchesSAN(host: string, sans: string[]): boolean {
	const h = host.toLowerCase().replace(/\.$/, '');
	for (const raw of sans) {
		const san = raw.toLowerCase().replace(/\.$/, '');
		if (san === h) {
			return true;
		}
		if (san.startsWith('*.')) {
			const suffix = san.slice(1); // ".example.com"
			if (h.endsWith(suffix)) {
				const label = h.slice(0, h.length - suffix.length);
				if (label !== '' && !label.includes('.')) {
					return true;
				}
			}
		}
	}
	return false;
}
