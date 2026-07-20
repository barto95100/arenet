// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Resolves the display name shown on a route's manual-cert badge
// (CertSourceBadge, kind "manual"). The backend's effectiveCertSource
// wire string is the bare "per-route-manual" with no name, so the
// routes list resolves the referenced ExternalCertificate (via
// route.cert_id) and derives a human label:
//
//   - wildcard cert (a SAN like "*.worldgeekwide.fr") → "*.worldgeekwide.fr"
//     so a manual wildcard reads like the ACME wildcard badge.
//   - otherwise → the cert's display name.
//   - cert not found (orphaned cert_id) → undefined, so the badge
//     falls back to a bare "Cert manuel".

import type { ExternalCertificate } from '$lib/api/types';

/** Returns the first wildcard SAN ("*.apex") on the cert, or null. */
function firstWildcardSAN(dnsNames: string[] | undefined): string | null {
	if (!dnsNames) return null;
	for (const name of dnsNames) {
		if (name.startsWith('*.') && name.length > 2) return name;
	}
	return null;
}

/**
 * Derive the manual-cert badge display name from the route's cert_id
 * and the loaded external-cert list. Returns undefined when the id is
 * absent or unresolved, letting the badge render a bare "Cert manuel".
 *
 * A wildcard cert surfaces its "*.apex" SAN (matching the ACME-wildcard
 * badge convention); any other cert surfaces its display name.
 */
export function manualCertDisplayName(
	certId: string | undefined | null,
	certs: ExternalCertificate[]
): string | undefined {
	if (!certId) return undefined;
	const cert = certs.find((c) => c.id === certId);
	if (!cert) return undefined;
	const wildcard = firstWildcardSAN(cert.dnsNames);
	if (wildcard) return wildcard;
	return cert.name || undefined;
}
