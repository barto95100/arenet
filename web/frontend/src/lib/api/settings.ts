// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Typed wrappers for the Settings endpoints
// (`/api/v1/settings/...`). Step J.4 added DNS provider; Step K.1
// adds forward-auth provider CRUD. Future Settings endpoints
// (OIDC, theme defaults, ...) land here.

import { request } from './client';
import type {
	DNSProviderOVH,
	DNSProviderOVHRequest,
	ForwardAuthProvider,
	ForwardAuthProviderRequest
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
		request<void>('DELETE', `/settings/forward-auth/providers/${encodeURIComponent(name)}`)
};
