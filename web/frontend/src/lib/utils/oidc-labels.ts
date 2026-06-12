// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Phase 2 Users-page refactor — provider-kind → operator-facing
// label mapping. The storage Kind enum is normalised lowercase
// for machine matching ('authentik', 'keycloak', 'authelia',
// 'generic'); the sidebar header in the OIDCConfigSummary
// renders the prettier brand-cased form shown in the mockup.
//
// Unknown / empty kinds fall back to a Title-cased echo of the
// raw value so an operator who hand-edits storage with a typo
// still sees their input rather than a generic placeholder.

import type { OIDCProviderKind } from '$lib/api/types';

const KIND_LABELS: Record<string, string> = {
	authentik: 'GoAuthentik',
	keycloak: 'Keycloak',
	authelia: 'Authelia',
	generic: 'OIDC générique'
};

export function oidcProviderLabel(kind: OIDCProviderKind | string | undefined): string {
	const k = (kind || '').toLowerCase();
	if (k in KIND_LABELS) return KIND_LABELS[k];
	if (!k) return 'OIDC générique';
	// Title-case echo for unknown kinds.
	return k.charAt(0).toUpperCase() + k.slice(1);
}

// hostnameOf extracts the host portion of an issuer URL for the
// sidebar subtitle ("OIDC · authentik.arenet.fr"). Returns the
// raw input if it doesn't parse — better than a blank subtitle
// when an admin has saved a malformed URL.
export function hostnameOf(issuerUrl: string): string {
	if (!issuerUrl) return '';
	try {
		return new URL(issuerUrl).hostname;
	} catch {
		return issuerUrl;
	}
}
