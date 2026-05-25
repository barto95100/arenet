// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

/**
 * Step J.1: one backend in a Route's upstream pool. Replaces the
 * pre-J.1 single upstreamUrl string. Weight defaults to 1 and is
 * only consulted by the weighted_round_robin LB policy; other
 * policies ignore it.
 */
export interface Upstream {
	url: string;
	weight: number;
}

/**
 * Step J.1: load-balancing selection policy enum. Must match the
 * six storage.LBPolicy* constants on the backend exactly; drift
 * would be caught by the route create / update returning a 400.
 */
export type LBPolicy =
	| 'round_robin'
	| 'weighted_round_robin'
	| 'least_conn'
	| 'ip_hash'
	| 'random'
	| 'first';

export interface Route {
	id: string;
	host: string;
	/**
	 * Step J.1: pool of backends. Always non-empty (the backend's
	 * storage.validate() guarantees it). A migrated pre-J.1 route
	 * carries a one-element pool with the legacy URL at index 0.
	 */
	upstreams: Upstream[];
	/**
	 * Step J.1: LB selection policy. Always one of the six LBPolicy
	 * enum values on a stored route.
	 */
	lbPolicy: LBPolicy;
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
	/**
	 * Step I.6 — custom headers applied to the proxied request /
	 * response. Map of name → value (single value per name in v1.0).
	 * Server normalizes nil → empty object on the wire, so callers
	 * iterate Object.keys without a null check.
	 */
	requestHeaders: Record<string, string>;
	responseHeaders: Record<string, string>;
	/**
	 * Step I.4 — WAF mode. Replaces the pre-I.4 wafEnabled bool with
	 * a three-valued enum:
	 *   - "off":    no WAF inspection.
	 *   - "detect": Coraza/OWASP CRS inspects and logs matches but
	 *               lets traffic through (FortiWeb-style safe-shadow,
	 *               the recommended starting point).
	 *   - "block":  Coraza returns 403 on match.
	 */
	wafMode: 'off' | 'detect' | 'block';
	createdAt: string;
	updatedAt: string;
}

export interface RouteRequest {
	host: string;
	/**
	 * Step J.1: pool of backends. The J.1→J.3 transitional UI in
	 * routes/+page.svelte sends a one-element pool built from the
	 * single Upstream URL input; J.3 will replace that with a real
	 * repeater. Either way the backend materialises Weight=0 → 1
	 * before validation, so an omitted weight is fine.
	 */
	upstreams: Upstream[]; // Step J.1 — see Route.upstreams.
	/**
	 * Step J.1: LB selection policy. Empty string on POST means
	 * "give me the default round_robin"; empty on PUT preserves the
	 * previously stored value (same UX as wafMode). The J.1→J.3
	 * transitional UI always sends "" so the backend default
	 * applies; J.3 will add a real selector.
	 */
	lbPolicy: LBPolicy | '';
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
	requestHeaders: Record<string, string>;
	responseHeaders: Record<string, string>;
	/**
	 * Step I.4 — WAF mode. On POST, empty string is normalized to
	 * "detect" by the server. On PUT, empty string preserves the
	 * previously stored value (mirrors the I.5 password preserve UX).
	 */
	wafMode: 'off' | 'detect' | 'block' | '';
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
