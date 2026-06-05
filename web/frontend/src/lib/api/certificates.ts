// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Typed wrapper for the GET /api/v1/certificates endpoint shipped
// by Step T T.1 (commit 1350777). Mirrors the settings.ts pattern —
// a thin object exposing one method per endpoint, returning typed
// promises through the shared request() helper.

import { request } from './client';
import type { Certificate } from './types';

export const certificatesApi = {
	/**
	 * GET /api/v1/certificates — returns every cert the backend
	 * certinfo tracker knows about, sorted by NotAfter ascending
	 * (closest-to-expiry first). Degraded mode: when the backend
	 * tracker is unavailable the endpoint returns 200 with an
	 * empty array rather than 5xx (AC #13).
	 */
	list: (): Promise<Certificate[]> => request<Certificate[]>('GET', '/certificates'),
};
