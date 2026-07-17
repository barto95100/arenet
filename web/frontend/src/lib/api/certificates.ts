// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Typed wrapper for the GET /api/v1/certificates endpoint shipped
// by Step T T.1 (commit 1350777). Mirrors the settings.ts pattern —
// a thin object exposing one method per endpoint, returning typed
// promises through the shared request() helper.

import { request } from './client';
import type { Certificate, CertificateDeleteResult } from './types';

// Task 5 — same BASE/`/api/v1` prefix + credentials convention as the
// shared request() helper in ./client (see client.ts for the DEV vs
// prod origin guard rationale). deleteCertificate can't route through
// request() unmodified: the 409 body from DELETE
// /api/v1/certificates/{domain} (internal/api/certificates_delete.go)
// is `{error, blockingRoutes}` — blockingRoutes is a FLAT top-level
// field, not nested under `params` the way the provider_in_use family
// is (writeErrorCode). request()'s generic error path only surfaces
// `code`/`params`, so blockingRoutes would be silently dropped. This
// dedicated fetch preserves the same base URL / credentials handling
// while translating the 409 body verbatim onto the thrown error.
const BASE: string = import.meta.env.DEV
	? ((import.meta.env.VITE_API_BASE_URL ?? '') as string)
	: '';

export const certificatesApi = {
	/**
	 * GET /api/v1/certificates — returns every cert the backend
	 * certinfo tracker knows about, sorted by NotAfter ascending
	 * (closest-to-expiry first). Degraded mode: when the backend
	 * tracker is unavailable the endpoint returns 200 with an
	 * empty array rather than 5xx (AC #13).
	 */
	list: (): Promise<Certificate[]> => request<Certificate[]>('GET', '/certificates'),

	/**
	 * DELETE /api/v1/certificates/{domain} — removes an orphan
	 * certificate's on-disk material + tracker entry. `domain` is
	 * URL-encoded so wildcard subjects ("*.darro.ovh") survive as
	 * a path segment. On 200, returns `{domain, deleted}` (count of
	 * files removed). On 409 (still referenced by a route or a
	 * managed-domain wildcard), throws an Error augmented with
	 * `status: 409` and `blockingRoutes: string[]` so the /certs
	 * page can render the blocked-delete dialog with the offending
	 * hosts.
	 */
	deleteCertificate: async (domain: string): Promise<CertificateDeleteResult> => {
		const res = await fetch(`${BASE}/api/v1/certificates/${encodeURIComponent(domain)}`, {
			method: 'DELETE',
			credentials: 'include'
		});
		if (!res.ok) {
			const body = await res.json().catch(() => ({}) as Record<string, unknown>);
			const message = typeof body.error === 'string' ? body.error : 'delete failed';
			throw Object.assign(new Error(message), {
				status: res.status,
				blockingRoutes: Array.isArray(body.blockingRoutes) ? body.blockingRoutes : []
			});
		}
		return res.json() as Promise<CertificateDeleteResult>;
	}
};
