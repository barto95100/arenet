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

/**
 * Step J.2: per-route active health check. Mirrors storage.HealthCheck
 * (9 fields). When Enabled is false the other eight fields are inert
 * — the server emits no Caddy `health_checks` block.
 *
 * The five defaultable fields (method, interval, timeout, passes,
 * fails) are materialised by the server before validation. URI is
 * the one field operators must always supply when Enabled is true.
 *
 * Wire semantics on PUT (J.2 decision): the block is preserve-or-
 * replace, never partial. Send the complete 9-field block (full
 * replacement) OR omit the block entirely (preserve previous);
 * never a partial block, because every omitted sub-field resets to
 * its server-side default. See docs/backlog-step-j.md "J.3 frontend
 * — health-check is preserve-or-replace, never partial".
 */
export interface HealthCheck {
	enabled: boolean;
	uri: string;
	method: 'GET' | 'HEAD' | '';
	interval: string;
	timeout: string;
	expectStatus: number;
	expectBody: string;
	passes: number;
	fails: number;
}

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
	 * Step K.1 — per-route auth mode. Replaces the Step I.5 flat
	 * basicAuthEnabled boolean with a three-valued radio enum:
	 *   - "none":        no auth gate on the route.
	 *   - "basic":       Step I.5 HTTP Basic Auth, preserved.
	 *   - "forward_auth": delegated to an external IdP via Caddy
	 *                    forward_auth (Authelia / Authentik /
	 *                    Keycloak / generic).
	 * Mutually exclusive (§1.3 decision 2). The server normalises
	 * the storage zero value "" to "none" so the wire always
	 * carries an explicit enum value.
	 */
	authMode: RouteAuthMode;
	/**
	 * Step K.1 — Basic Auth response sub-shape (replaces the flat
	 * Step I.5 basicAuthEnabled / basicAuthUsername /
	 * basicAuthPasswordSet triplet). Active only when authMode ==
	 * "basic". The plaintext password and the argon2id hash are
	 * NEVER on the wire response; passwordSet tells the UI whether
	 * a hash exists so it can render the "••• set" placeholder on
	 * Edit.
	 */
	basicAuth: BasicAuthResponse;
	/**
	 * Step K.1 — Forward-auth response sub-shape. Active only when
	 * authMode == "forward_auth". Carries the reference to the
	 * instance-level provider (configured via Settings).
	 */
	forwardAuth: ForwardAuthResponse;
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
	/**
	 * Step J.2 — active health check. Always present on a stored
	 * route (storage.HealthCheck has no omitempty); a route created
	 * pre-J.2 reads back with the zero-value HealthCheck (Enabled
	 * false, every sub-field at zero).
	 */
	healthCheck: HealthCheck;
	/**
	 * Step J.4 — ACME challenge type. The backend normalises the
	 * pre-J.4 storage zero value "" to "http-01" before serialising,
	 * so callers always see one of the two enum values on the wire.
	 */
	acmeChallenge: ACMEChallenge;
	createdAt: string;
	updatedAt: string;
}

/**
 * Step J.4 — per-route ACME challenge type. "http-01" is the
 * default (and the pre-J.4 behaviour). "dns-01" is required for
 * wildcard hosts and depends on a configured DNS provider in
 * Settings.
 */
export type ACMEChallenge = 'http-01' | 'dns-01';

/**
 * Step K.1 — per-route auth mode enum. See Route.authMode for
 * the per-value semantics.
 */
export type RouteAuthMode = 'none' | 'basic' | 'forward_auth';

/**
 * Step K.1 — Basic Auth response shape. Surfaces username +
 * passwordSet flag; the hash and plaintext are never on the wire.
 */
export interface BasicAuthResponse {
	username: string;
	passwordSet: boolean;
}

/**
 * Step K.1 — Forward-auth response shape. Carries only the
 * provider reference; the provider configuration itself is
 * GET'd via the Settings endpoint.
 */
export interface ForwardAuthResponse {
	providerName: string;
}

/**
 * Step K.1 — Basic Auth request shape. password is the PLAIN
 * text on the wire (write-only): leave empty on Edit to keep
 * the existing hash; provide a fresh value to rotate.
 */
export interface BasicAuthRequest {
	username: string;
	password: string;
}

/**
 * Step K.1 — Forward-auth request shape. Mirrors the response
 * shape — only the provider reference.
 */
export interface ForwardAuthRequest {
	providerName: string;
}

/**
 * Step K.1 — instance-level forward-auth provider as returned by
 * the Settings API. The client_secret is always blanked on the
 * wire; clientSecretSet flags the UI to render the "••• set"
 * placeholder. Mirrors the J.4 DNS-provider redaction shape.
 */
export interface ForwardAuthProvider {
	name: string;
	kind: ForwardAuthProviderKind;
	verifyUrl: string;
	authRequestUri: string;
	copyHeaders: string[];
	clientSecret: string; // always "" on the wire (redacted)
	clientSecretSet: boolean;
	/**
	 * Step K.4 — optional path prefix served by the IdP itself
	 * on the application's external host. Non-empty makes the
	 * generator emit a passthrough route bypassing the
	 * forward_auth gate for that subtree (required for the
	 * Authentik embedded outpost pattern + oauth2-proxy).
	 * Empty = legacy K.1 behaviour.
	 */
	authPassthroughPrefix: string;
	createdAt: string;
	updatedAt: string;
}

/**
 * Step K.1 — wire shape for POST / PUT
 * /api/v1/settings/forward-auth/providers. The clientSecret is
 * write-only; empty on PUT preserves the previously stored
 * value (Step J.4 preserve-on-edit pattern).
 */
export interface ForwardAuthProviderRequest {
	name: string;
	kind: ForwardAuthProviderKind;
	verifyUrl: string;
	authRequestUri: string;
	copyHeaders: string[];
	clientSecret: string;
	authPassthroughPrefix?: string;
}

/**
 * Step K.1 — supported forward-auth provider kinds. Drives UI
 * presets (default verify URL, default copy-headers list);
 * server stores the enum as-is.
 */
export type ForwardAuthProviderKind = 'authelia' | 'authentik' | 'keycloak' | 'generic';

export const FORWARD_AUTH_PROVIDER_KINDS: readonly ForwardAuthProviderKind[] = [
	'authelia',
	'authentik',
	'keycloak',
	'generic'
] as const;

export interface RouteRequest {
	host: string;
	/**
	 * Step J.1: pool of backends. Repeater on the form; at least one
	 * entry; per-element URL + weight. Server materialises Weight=0
	 * → 1 before validation, so an omitted weight is fine.
	 */
	upstreams: Upstream[];
	/**
	 * Step J.1: LB selection policy. Empty string on POST means
	 * "give me the default round_robin"; empty on PUT preserves the
	 * previously stored value (same UX as wafMode). The form sends
	 * the explicit value when the LB selector is visible (pool size
	 * ≥ 2), otherwise sends "" so the backend default applies.
	 */
	lbPolicy: LBPolicy | '';
	tlsEnabled: boolean;
	redirectToHttps: boolean;
	aliases: string[];
	/**
	 * Step K.1 — per-route auth mode. Empty string on POST is
	 * normalised to "none" by the server; empty on PUT preserves
	 * the previously stored value (same UX as wafMode).
	 */
	authMode: RouteAuthMode | '';
	/**
	 * Step K.1 — Basic Auth request shape. Active only when
	 * authMode == "basic". password is write-only (empty on Edit
	 * keeps the existing hash; new value rotates). When authMode
	 * != "basic", set username/password to "" (the server
	 * enforces this mutual exclusion at the validation layer).
	 */
	basicAuth: BasicAuthRequest;
	/**
	 * Step K.1 — Forward-auth request shape. Active only when
	 * authMode == "forward_auth". When authMode != "forward_auth",
	 * providerName must be "" (mutual exclusion).
	 */
	forwardAuth: ForwardAuthRequest;
	requestHeaders: Record<string, string>;
	responseHeaders: Record<string, string>;
	/**
	 * Step I.4 — WAF mode. On POST, empty string is normalized to
	 * "detect" by the server. On PUT, empty string preserves the
	 * previously stored value (mirrors the I.5 password preserve UX).
	 */
	wafMode: 'off' | 'detect' | 'block' | '';
	/**
	 * Step J.2 — active health check. OPTIONAL field with
	 * preserve-or-replace semantics on PUT (J.2 decision):
	 *   - omitted (undefined)         → preserve previously stored
	 *     HealthCheck verbatim. The form uses this when the user did
	 *     not touch the HC sub-form.
	 *   - present with all 9 fields   → full replacement. The server
	 *     materialises the five defaultable fields if blank.
	 *
	 * Never ship a partial block: every omitted sub-field of a
	 * present block resets to its server-side default. See
	 * docs/backlog-step-j.md.
	 */
	healthCheck?: HealthCheck;
	/**
	 * Step J.4 — ACME challenge type. Empty string on POST/PUT is
	 * normalised by the backend to "http-01" (no preserve-on-omit
	 * semantic — the value carries no secret and is naturally
	 * supplied on every form submit).
	 */
	acmeChallenge: ACMEChallenge | '';
}

/**
 * Step J.4 — instance-level DNS provider configuration for the OVH
 * provider (v1.0 supports OVH only). The three secret fields are
 * always emitted as empty strings on the wire (server-side
 * redaction, like the Step I.5 BasicAuthPasswordHash). Configured
 * is the single status flag the UI binds to.
 */
export interface DNSProviderOVH {
	endpoint: string;
	applicationKey: string; // always "" on the wire (redacted)
	applicationSecret: string; // always "" on the wire (redacted)
	consumerKey: string; // always "" on the wire (redacted)
	configured: boolean;
}

/**
 * Step J.4 — wire shape for PUT /api/v1/settings/dns-providers/ovh.
 * Empty secret fields trigger the preserve-on-edit path (the
 * stored value is kept); non-empty overwrites. Endpoint must be
 * non-empty and one of the seven OVH region IDs.
 */
export interface DNSProviderOVHRequest {
	endpoint: string;
	applicationKey: string;
	applicationSecret: string;
	consumerKey: string;
}

/**
 * Step J.4 — the seven OVH endpoint identifiers accepted by the
 * go-ovh SDK. Mirrors storage.OVHEndpoints; the UI dropdown
 * populates from this list.
 */
export const OVH_ENDPOINTS: readonly string[] = [
	'ovh-eu',
	'ovh-ca',
	'ovh-us',
	'kimsufi-eu',
	'kimsufi-ca',
	'soyoustart-eu',
	'soyoustart-ca'
] as const;

/**
 * Step K.2 — OIDC SSO configuration as returned by GET
 * /api/v1/settings/oidc. The clientSecret is always blanked on the
 * wire (server-side redaction, mirrors the J.4 DNS-provider and
 * K.1 forward-auth pattern). clientSecretSet flags the UI to
 * render the "••• set" placeholder on Edit.
 */
export interface OIDCConfig {
	enabled: boolean;
	issuerUrl: string;
	clientId: string;
	clientSecret: string; // always "" on the wire (redacted)
	clientSecretSet: boolean;
	scopes: string[];
	redirectUrl: string;
	allowedIdentities: OIDCAllowedIdentity[];
	configured: boolean;
}

/**
 * Step K.2 — wire shape for PUT /api/v1/settings/oidc. clientSecret
 * is write-only; empty preserves the previously stored value
 * (Step J.4 preserve-on-edit pattern). The allowlist is NOT
 * mutated by this endpoint — use the /allowlist sub-endpoints.
 */
export interface OIDCConfigRequest {
	enabled: boolean;
	issuerUrl: string;
	clientId: string;
	clientSecret: string;
	scopes: string[];
	redirectUrl: string;
}

/**
 * Step K.2 — one allowlisted identity. Sub is empty until the
 * user's first successful login canonicalises the entry (§5.2);
 * firstLoginAt is the timestamp of that canonicalisation. The UI
 * uses the empty-Sub state to render a "pending" badge.
 */
export interface OIDCAllowedIdentity {
	email: string;
	displayName: string;
	sub: string;
	addedAt: string;
	firstLoginAt?: string;
}

/**
 * Step K.2 — POST /api/v1/settings/oidc/allowlist body. Server
 * lower-cases the email and rejects duplicates.
 *
 * Spec-1 — optional pre-filled `sub`. Non-empty installs the
 * entry as already-canonicalised, bypassing the email-bootstrap
 * path (Δ7 guard not invoked). Required for IdPs that don't
 * emit `email_verified=true` (Authentik admin-created accounts).
 * Empty (default) keeps the pending behaviour: first login goes
 * through the email-bootstrap Pass 2 with the email_verified
 * guard.
 */
export interface OIDCAllowlistAddRequest {
	email: string;
	displayName: string;
	sub?: string;
}

/**
 * Step K.2 — anonymous status endpoint shape (GET /api/v1/auth/
 * oidc/status). The login page reads this to decide whether to
 * render the "Continue with SSO" button. NEVER carries operational
 * details (no issuer URL, no allowlist).
 */
export interface OIDCStatus {
	enabled: boolean;
}

/**
 * Step K.2 — admin user list entry as returned by GET
 * /api/v1/admin/users. The wire surface OMITS PasswordHash and
 * surfaces OIDCSub only as a boolean (oidcLinked); the raw sub is
 * operational metadata for the storage layer only.
 */
export interface AdminUser {
	id: string;
	username: string;
	displayName: string;
	authSource: 'local' | 'oidc';
	oidcLinked: boolean;
	role: UserRole;
	createdAt: string;
	updatedAt: string;
	lastLoginAt?: string;
}

/**
 * Step K.2 — admin role enum. "admin" has full CRUD on routes /
 * settings / users; "viewer" has read-only access to the admin UI.
 * Mutually exclusive. The server enforces a last-LOCAL-admin
 * guard against demoting the only break-glass channel.
 */
export type UserRole = 'viewer' | 'admin';

/**
 * Step K.2 — POST /api/v1/admin/users/{id}/role body. Empty role
 * or values outside the UserRole enum return a 400 from the
 * server.
 */
export interface UpdateUserRoleRequest {
	role: UserRole;
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
