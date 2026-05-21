// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

export interface Route {
	id: string;
	host: string;
	upstreamUrl: string;
	tlsEnabled: boolean;
	/**
	 * Step I.1 (wired by I.2): when true and tlsEnabled is also true,
	 * HTTP requests on :80 are 301-redirected to https://. Ignored when
	 * tlsEnabled is false.
	 */
	redirectToHttps: boolean;
	/**
	 * Step I.3: additional hostnames served by the same upstream + same
	 * TLS cert (multi-SAN). The server normalizes the wire shape to an
	 * empty array (never null), so callers can read .length without a
	 * null check.
	 */
	aliases: string[];
	/**
	 * Step I.5: per-route Basic Auth. The plaintext password and the
	 * argon2id hash are NEVER on the wire response. basicAuthPasswordSet
	 * tells the UI whether a hash exists so it can render the
	 * "••• set" placeholder on Edit.
	 */
	basicAuthEnabled: boolean;
	basicAuthUsername: string;
	basicAuthPasswordSet: boolean;
	wafEnabled: boolean;
	createdAt: string;
	updatedAt: string;
}

export interface RouteRequest {
	host: string;
	upstreamUrl: string;
	tlsEnabled: boolean;
	redirectToHttps: boolean;
	aliases: string[];
	/**
	 * Step I.5 — Basic Auth fields on the request side. basicAuthPassword
	 * is write-only: leave it empty on Edit to keep the existing hash,
	 * provide a fresh value to rotate. The server hashes it with
	 * argon2id; the plaintext is never persisted or echoed back.
	 */
	basicAuthEnabled: boolean;
	basicAuthUsername: string;
	basicAuthPassword: string;
	wafEnabled: boolean;
}

/**
 * Discriminated kind of an ApiError so the UI can decide presentation:
 *   - validation: inline near the offending field (4xx other than auth/rate)
 *   - system:     toast or full-page error (network, 5xx)
 *   - auth:       401 — caller redirected to /login by the interceptor
 *   - forbidden:  403 — session locked (lock screen overlay)
 *   - rate_limited: 429 — caller shown a toast by the interceptor
 *
 * Step D adds the auth/forbidden/rate_limited kinds (spec §6.4); Step C
 * shipped only validation/system.
 */
export type ErrorKind = 'validation' | 'system' | 'auth' | 'forbidden' | 'rate_limited';

export class ApiError extends Error {
	status: number;
	kind: ErrorKind;
	retryAfterSeconds?: number;

	constructor(message: string, status: number, kind?: ErrorKind, retryAfterSeconds?: number) {
		super(message);
		this.status = status;
		if (kind !== undefined) {
			this.kind = kind;
		} else {
			// Step C compat: derive kind from status when caller omits it.
			this.kind = status === 400 || status === 409 ? 'validation' : 'system';
		}
		this.retryAfterSeconds = retryAfterSeconds;
	}
}
