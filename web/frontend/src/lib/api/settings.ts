// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Typed wrappers for the Settings endpoints
// (`/api/v1/settings/...`). Step J.4 added DNS provider; Step K.1
// adds forward-auth provider CRUD. Future Settings endpoints
// (OIDC, theme defaults, ...) land here.

import { request } from './client';
import type {
	AdminUser,
	DNSProviderOVH,
	DNSProviderOVHRequest,
	ForwardAuthProvider,
	ForwardAuthProviderRequest,
	OIDCAllowedIdentity,
	OIDCAllowlistAddRequest,
	OIDCConfig,
	OIDCConfigRequest,
	UpdateUserRoleRequest
} from './types';

export const settingsApi = {
	getDNSProviderOVH: (): Promise<DNSProviderOVH> =>
		request<DNSProviderOVH>('GET', '/settings/dns-providers/ovh'),
	putDNSProviderOVH: (r: DNSProviderOVHRequest): Promise<DNSProviderOVH> =>
		request<DNSProviderOVH>('PUT', '/settings/dns-providers/ovh', r),

	// Step K.1 — forward-auth provider CRUD.
	listForwardAuthProviders: (): Promise<ForwardAuthProvider[]> =>
		request<ForwardAuthProvider[]>('GET', '/settings/forward-auth/providers'),
	getForwardAuthProvider: (name: string): Promise<ForwardAuthProvider> =>
		request<ForwardAuthProvider>(
			'GET',
			`/settings/forward-auth/providers/${encodeURIComponent(name)}`
		),
	createForwardAuthProvider: (r: ForwardAuthProviderRequest): Promise<ForwardAuthProvider> =>
		request<ForwardAuthProvider>('POST', '/settings/forward-auth/providers', r),
	updateForwardAuthProvider: (
		name: string,
		r: ForwardAuthProviderRequest
	): Promise<ForwardAuthProvider> =>
		request<ForwardAuthProvider>(
			'PUT',
			`/settings/forward-auth/providers/${encodeURIComponent(name)}`,
			r
		),
	deleteForwardAuthProvider: (name: string): Promise<void> =>
		request<void>('DELETE', `/settings/forward-auth/providers/${encodeURIComponent(name)}`),

	// Step K.2 — OIDC config (single row, "default" key on the
	// backend). PUT preserves the clientSecret when empty (J.4
	// preserve-on-edit). The allowlist is preserved across config
	// edits server-side; mutate it via the /allowlist endpoints.
	getOIDCConfig: (): Promise<OIDCConfig> => request<OIDCConfig>('GET', '/settings/oidc'),
	putOIDCConfig: (r: OIDCConfigRequest): Promise<OIDCConfig> =>
		request<OIDCConfig>('PUT', '/settings/oidc', r),

	// Step K.2 — OIDC allowlist. add lower-cases the email; delete
	// is keyed by the same lower-cased email. The Sub canonicalises
	// on first login (§5.2).
	listOIDCAllowlist: (): Promise<OIDCAllowedIdentity[]> =>
		request<OIDCAllowedIdentity[]>('GET', '/settings/oidc/allowlist'),
	addOIDCAllowlist: (r: OIDCAllowlistAddRequest): Promise<OIDCAllowedIdentity> =>
		request<OIDCAllowedIdentity>('POST', '/settings/oidc/allowlist', r),
	deleteOIDCAllowlist: (email: string): Promise<void> =>
		request<void>('DELETE', `/settings/oidc/allowlist/${encodeURIComponent(email)}`),

	// Step K.2 — admin Users management. The list response omits
	// PasswordHash and surfaces OIDCSub as a boolean (oidcLinked).
	listAdminUsers: (): Promise<AdminUser[]> => request<AdminUser[]>('GET', '/admin/users'),
	updateUserRole: (id: string, r: UpdateUserRoleRequest): Promise<AdminUser> =>
		request<AdminUser>('POST', `/admin/users/${encodeURIComponent(id)}/role`, r)
};
