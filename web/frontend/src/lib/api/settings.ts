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
	AutomationCredentialsRequest,
	AutomationCredentialsView,
	AutomationResponse,
	AutomationRulesRequest,
	AutomationRuleSet,
	DNSProviderOVH,
	DNSProviderOVHRequest,
	ForwardAuthProvider,
	ForwardAuthProviderRequest,
	ManagedDomain,
	ManagedDomainDeleteResponse,
	ManagedDomainRequest,
	ManagedDomainRevertTo,
	ManagedDomainsListResponse,
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

	// Step O.3 — managed-domain (wildcard certificate) CRUD.
	// Viewer-accessible GET; admin-only POST + DELETE. The
	// DELETE endpoint accepts an explicit `revertTo` query
	// parameter so the operator chooses the post-revert
	// ACMEChallenge value for the covered routes (AC #21).
	listManagedDomains: (): Promise<ManagedDomainsListResponse> =>
		request<ManagedDomainsListResponse>('GET', '/settings/managed-domains'),
	createManagedDomain: (r: ManagedDomainRequest): Promise<ManagedDomain> =>
		request<ManagedDomain>('POST', '/settings/managed-domains', r),
	deleteManagedDomain: (
		apex: string,
		revertTo: ManagedDomainRevertTo
	): Promise<ManagedDomainDeleteResponse> => {
		const qs = revertTo ? `?revertTo=${encodeURIComponent(revertTo)}` : '';
		return request<ManagedDomainDeleteResponse>(
			'DELETE',
			`/settings/managed-domains/${encodeURIComponent(apex)}${qs}`
		);
	},

	// Step P.3 — auto-classify (write-back to LAPI) config.
	// GET is viewer-accessible (returns rules + credentials.
	// configured boolean). The two PUTs are admin-only:
	// /rules atomically swaps the live RuleSet; /credentials
	// recreate-and-swaps the live WatcherClient (J.4
	// preserve-on-empty-password).
	getAutomation: (): Promise<AutomationResponse> =>
		request<AutomationResponse>('GET', '/settings/automation'),
	putAutomationRules: (r: AutomationRulesRequest): Promise<AutomationRulesRequest> =>
		request<AutomationRulesRequest>('PUT', '/settings/automation/rules', r),
	putAutomationCredentials: (
		r: AutomationCredentialsRequest
	): Promise<AutomationCredentialsView> =>
		request<AutomationCredentialsView>('PUT', '/settings/automation/credentials', r),

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
		request<AdminUser>('POST', `/admin/users/${encodeURIComponent(id)}/role`, r),

	// Step K.3 — backup / restore. The export endpoint streams a
	// JSON file; we don't go through the typed `request` helper
	// because we want the raw Response so we can save the file via
	// blob+anchor. The restore endpoint accepts the JSON body
	// uploaded by the operator.
	exportBackupURL: (includeSecrets: boolean): string => {
		const qp = includeSecrets ? '?include-secrets=true' : '';
		return `/api/v1/admin/backup${qp}`;
	},
	postRestore: (
		body: unknown,
		opts: { allowIncompleteRestore?: boolean; allowEmptyUsers?: boolean }
	): Promise<RestoreReport> => {
		const params = new URLSearchParams();
		if (opts.allowIncompleteRestore) params.set('allow-incomplete-restore', 'true');
		if (opts.allowEmptyUsers) params.set('allow-empty-users', 'true');
		const qs = params.toString();
		const url = qs ? `/admin/restore?${qs}` : '/admin/restore';
		return request<RestoreReport>('POST', url, body);
	}
};

// RestoreReport is the wire shape returned by POST /admin/restore.
// Mirrors the Go restoreResponse struct in
// internal/api/backup_handlers.go.
export interface RestoreReport {
	routesImported: number;
	usersImported: number;
	dnsProvidersImported: number;
	forwardAuthProvidersImported: number;
	oidcConfigImported: boolean;
	sentinelsInheritedTotal: number;
	sentinelsUnresolvedTotal: number;
	incompleteRows: number;
}
