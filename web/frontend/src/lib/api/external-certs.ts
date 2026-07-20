// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.19.0 external-certs SOCLE (Task 7) — typed wrappers for the
// admin-only bring-your-own-certificate CRUD:
//   - GET    /api/v1/certificates/external        (list, keyPEM redacted)
//   - GET    /api/v1/certificates/external/{id}   (detail, keyPEM redacted)
//   - POST   /api/v1/certificates/external        (upload)
//   - DELETE /api/v1/certificates/external/{id}   (200, or 409 w/ blockingRoutes)
//
// Backend mirror: internal/api/external_certs.go.
//
// list/get/upload route through the shared request() helper. remove()
// uses a dedicated fetch (like certificatesApi.deleteCertificate in
// ./certificates) because the 409 body from DELETE is
// `{error, blockingRoutes}` — blockingRoutes is a FLAT top-level field,
// NOT nested under `params` the way the provider_in_use family is
// (writeErrorCode). request()'s generic error path only surfaces
// `code`/`params`, so blockingRoutes would be silently dropped. This
// dedicated fetch preserves the same base URL / credentials handling
// while translating the 409 body verbatim onto the thrown error.

import { request } from './client';
import type {
	CertWarning,
	CSRSubject,
	ExternalCertificate,
	ExternalCertUploadRequest,
	GenerateCSRRequest
} from './types';

// Re-export the types so callers can import them alongside the client
// (mirrors error-templates.ts, which co-locates its types).
export type {
	CertWarning,
	CSRSubject,
	ExternalCertificate,
	ExternalCertUploadRequest,
	GenerateCSRRequest
};

// Same BASE / `/api/v1` prefix + credentials convention as the shared
// request() helper in ./client (see client.ts for the DEV vs prod
// origin guard rationale).
const BASE: string = import.meta.env.DEV
	? ((import.meta.env.VITE_API_BASE_URL ?? '') as string)
	: '';

export const externalCertsApi = {
	/**
	 * GET /api/v1/certificates/external — every uploaded external
	 * certificate, keyPEM redacted, already sorted by notAfter
	 * ascending (closest-to-expiry first) server-side. Preserve that
	 * order at the call site — do NOT re-sort.
	 */
	list(): Promise<ExternalCertificate[]> {
		return request<ExternalCertificate[]>('GET', '/certificates/external');
	},

	/**
	 * GET /api/v1/certificates/external/{id} — a single uploaded
	 * certificate's parsed metadata (keyPEM redacted).
	 */
	get(id: string): Promise<ExternalCertificate> {
		return request<ExternalCertificate>(
			'GET',
			`/certificates/external/${encodeURIComponent(id)}`
		);
	},

	/**
	 * POST /api/v1/certificates/external — upload a bring-your-own
	 * certificate. Returns 201 with the parsed metadata + any
	 * non-blocking `warnings` (keyPEM redacted on the echo).
	 */
	upload(req: ExternalCertUploadRequest): Promise<ExternalCertificate> {
		return request<ExternalCertificate>('POST', '/certificates/external', req);
	},

	/**
	 * PUT /api/v1/certificates/external/{id} — re-import / edit an
	 * existing certificate. `keyPEM: ''` preserves the stored key
	 * (secret preserve-on-edit — the frontend never re-sends a private
	 * key it does not have, e.g. the cert-only re-import onto a
	 * `pending_csr` row). `certPEM: ''` likewise preserves the stored
	 * leaf. Re-importing a signed cert onto a `pending_csr` row (the
	 * stored key matched via `tls.X509KeyPair`) flips `status` back to
	 * `''` server-side and the response may carry non-blocking
	 * subject/SANs diff `warnings`.
	 */
	update(id: string, req: ExternalCertUploadRequest): Promise<ExternalCertificate> {
		return request<ExternalCertificate>(
			'PUT',
			`/certificates/external/${encodeURIComponent(id)}`,
			req
		);
	},

	/**
	 * DELETE /api/v1/certificates/external/{id} — removes the uploaded
	 * certificate from Arenet (does NOT revoke it with the issuing CA).
	 * On 200 resolves void. On 409 (still referenced by a route),
	 * throws an Error augmented with `status: 409` and
	 * `blockingRoutes: string[]` so the UI can render the blocked-delete
	 * dialog with the offending hosts.
	 */
	async remove(id: string): Promise<void> {
		const res = await fetch(
			`${BASE}/api/v1/certificates/external/${encodeURIComponent(id)}`,
			{ method: 'DELETE', credentials: 'include' }
		);
		if (!res.ok) {
			const body = await res.json().catch(() => ({}) as Record<string, unknown>);
			const message = typeof body.error === 'string' ? body.error : 'delete failed';
			throw Object.assign(new Error(message), {
				status: res.status,
				blockingRoutes: Array.isArray(body.blockingRoutes) ? body.blockingRoutes : []
			});
		}
	},

	/**
	 * POST /api/v1/certificates/external/csr — generate a key + CSR and
	 * create a pending_csr row. Returns 201 with csrPEM populated (keyPEM
	 * redacted). Backend: internal/api/external_certs.go createExternalCertCSR.
	 */
	generateCSR(req: GenerateCSRRequest): Promise<ExternalCertificate> {
		return request<ExternalCertificate>('POST', '/certificates/external/csr', req);
	},

	/**
	 * Download URL for the stored CSR PEM (text/plain attachment). The CSR
	 * is public; the private key is never served. Anchor the <a href> at
	 * this URL rather than fetching, so the browser handles the download.
	 */
	csrDownloadUrl(id: string): string {
		return `${BASE}/api/v1/certificates/external/${encodeURIComponent(id)}/csr`;
	}
};
