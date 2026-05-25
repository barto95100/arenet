// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step J.4 — typed wrappers for the Settings endpoints
// (`/api/v1/settings/...`). v1.0 ships only the DNS provider
// surface; future Settings endpoints (theme defaults, retention,
// ...) land here.

import { request } from './client';
import type { DNSProviderOVH, DNSProviderOVHRequest } from './types';

export const settingsApi = {
	getDNSProviderOVH: (): Promise<DNSProviderOVH> =>
		request<DNSProviderOVH>('GET', '/settings/dns-providers/ovh'),
	putDNSProviderOVH: (r: DNSProviderOVHRequest): Promise<DNSProviderOVH> =>
		request<DNSProviderOVH>('PUT', '/settings/dns-providers/ovh', r)
};
