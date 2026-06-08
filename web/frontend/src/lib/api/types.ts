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
	 * so callers always see one of the enum values on the wire.
	 * Step O.1 adds "inherited" for routes covered by a managed-
	 * domain wildcard; the frontend hides the ACME selector and
	 * shows an inheritance badge instead.
	 */
	acmeChallenge: ACMEChallenge;
	/**
	 * Step O.1 — per-route opt-out from a covering managed-domain
	 * wildcard (spec D1.B). When true on a covered route, the route
	 * emits its own per-route ACME cert alongside the wildcard.
	 * Omitted on the wire for pre-O routes (`omitempty` on the Go
	 * side); default false.
	 */
	useDedicatedCert?: boolean;
	/**
	 * Step O.3 — derived field telling the operator which TLS policy
	 * actually serves this route's cert (spec AC #4). One of:
	 *   - "managed-domain:<apex>"
	 *   - "per-route-acme:dns-01"
	 *   - "per-route-acme:http-01"
	 *   - "per-route-internal"
	 * Empty / omitted for routes without TLS (the dashboard hides
	 * the badge in that case).
	 */
	effectiveCertSource?: string;
	/**
	 * Critique 11 Pack A (2026-06-05) — derived per-route health
	 * rollup the Routes API computes from the Stage B HC tracker.
	 *   "healthy"  — HC enabled AND every upstream healthy
	 *   "degraded" — HC enabled, at least one unhealthy upstream
	 *   "down"     — HC enabled AND every upstream unhealthy
	 *   "unknown"  — HC disabled, OR warm-up window with no
	 *                unhealthy signal yet
	 * Always present on a route response. See the backend
	 * `computeRouteAggregateHealth` docstring for the full
	 * precedence table.
	 */
	aggregateStatus: 'healthy' | 'degraded' | 'down' | 'unknown';
	/**
	 * Count of upstreams the HC tracker has observed as healthy.
	 * Zero on routes without HC configured (the C13 gate doesn't
	 * peek at tracker state). Used by the Routes table to render
	 * "N/M sains" when the pool has multiple upstreams.
	 */
	healthyUpstreamCount: number;
	totalUpstreamCount: number;
	createdAt: string;
	updatedAt: string;
}

/**
 * Step J.4 — per-route ACME challenge type. "http-01" is the
 * default (and the pre-J.4 behaviour). "dns-01" is required for
 * wildcard hosts and depends on a configured DNS provider in
 * Settings. Step O.1 adds "inherited" for routes covered by a
 * managed-domain wildcard.
 */
export type ACMEChallenge = 'http-01' | 'dns-01' | 'inherited';

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
	/**
	 * Step K.4 parity fix — when true, the forward_auth sub-
	 * request's Host header is rewritten to the verify URL's
	 * host. Required for IdPs that route apps by Host
	 * (Authentik embedded outpost). Default false = canonical
	 * Caddy expansion (client Host propagated).
	 */
	rewriteVerifyHost: boolean;
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
	rewriteVerifyHost?: boolean;
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
	 * supplied on every form submit). The backend (O.3) may
	 * rewrite the value to "inherited" if the host is covered by
	 * a managed domain AND useDedicatedCert is false; the
	 * frontend doesn't send "inherited" directly.
	 */
	acmeChallenge: ACMEChallenge | '';
	/**
	 * Step O.1 — opt-out from a covering managed-domain wildcard
	 * (spec D1.B). Default false. Omitting the field on the wire
	 * is equivalent to false. When true on a route whose host is
	 * covered by a managed domain, the route emits its own
	 * per-route ACME cert alongside the wildcard. Sending true on
	 * an uncovered route is rejected by the backend with 400.
	 */
	useDedicatedCert?: boolean;
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
 * Step O.1 — managed-domain declaration. One row per apex; the
 * caddymgr emits ONE wildcard TLS policy covering every route
 * whose host is `<single-label>.<apex>` (plus the bare apex
 * when `includeApex` is true, per spec D2.C).
 *
 * The `provider` enum value space is currently {"ovh"} (D3.B
 * forward-compat); future Cloudflare / Route53 additions are
 * additive without migration.
 */
export interface ManagedDomain {
	apex: string;
	includeApex: boolean;
	provider: ManagedDomainProvider;
}

/**
 * Step O.1 — POST /api/v1/settings/managed-domains body shape.
 * `includeApex` is optional on the wire (the backend defaults
 * to `true` per spec D2.C when the field is omitted);
 * `provider` defaults to "ovh" when omitted.
 */
export interface ManagedDomainRequest {
	apex: string;
	includeApex?: boolean;
	provider?: ManagedDomainProvider;
}

/**
 * Step O.1 — managed-domain provider enum. v1.2 value space is
 * {"ovh"}; the type is open-ended (`string` widened via the
 * union below) so future Cloudflare / Route53 values don't
 * require a frontend type rebuild at the same time as the
 * backend enum extension.
 */
export type ManagedDomainProvider = 'ovh';

/**
 * Step O.3 — GET /api/v1/settings/managed-domains envelope.
 * Wrapping in `{ domains: [] }` rather than returning a bare
 * array leaves room for future top-level fields (e.g. a
 * `disabled` flag for AC #13 carry-forward) without breaking
 * the wire contract.
 */
export interface ManagedDomainsListResponse {
	domains: ManagedDomain[];
}

/**
 * Step T T.1 — runtime status enum surfaced by GET /api/certificates.
 * Mirrors internal/certinfo/types.go Status. Locked vocabulary per
 * spec §2 AC #2; the frontend renders one badge variant per value
 * (see web/frontend/src/lib/utils/certificate-format.ts).
 */
export type CertificateStatus =
	| 'VALID'
	| 'RENEWAL_PENDING'
	| 'EXPIRED'
	| 'OBTAIN_FAILED'
	| 'UNKNOWN';

/**
 * Step T T.1 — cert provenance classification. Drives the
 * "<source> · <challenge>" sub-line under the DOMAINE column of
 * the Domaines table. Mirrors internal/certinfo/types.go Source.
 */
export type CertificateSource = 'wildcard' | 'apex' | 'specific';

/**
 * Step T T.1 — GET /api/certificates row shape. Field-by-field
 * mirror of internal/certinfo.CertRuntimeInfo (JSON tags pinned
 * in internal/certinfo/types.go).
 *
 * notBefore / notAfter / lastErrorAt are RFC3339 strings on the
 * wire (Go time.Time JSON encoding). lastError and lastErrorAt
 * are present only when status === 'OBTAIN_FAILED' AND the
 * failure happened within the 24h freshness window enforced
 * server-side; otherwise both fields are omitted.
 */
export interface Certificate {
	domain: string;
	/**
	 * Subject Alternative Names. Pre-hotfix the backend could
	 * marshal this as JSON `null` for OBTAIN_FAILED entries that
	 * never reached the cert_obtained code path (Go nil-slice
	 * gotcha — see internal/certinfo/tracker.go snapshot()). The
	 * backend now coerces nil to [], but the type stays nullable
	 * so older Arenet builds + any future regression are absorbed
	 * by frontend readers via `cert.sanList ?? []`.
	 */
	sanList: string[] | null;
	issuer: string;
	notBefore: string;
	notAfter: string;
	status: CertificateStatus;
	source: CertificateSource;
	lastError?: string;
	lastErrorAt?: string;
}

/**
 * Step O.3 — DELETE /api/v1/settings/managed-domains/{apex}
 * response shape. The `mutatedRoutes` count tells the frontend
 * how many covered routes had their ACMEChallenge reverted, so
 * the post-action toast can surface "N routes reverted to
 * <revertTo>" honestly. Mirrors the audit event's message.
 */
export interface ManagedDomainDeleteResponse {
	mutatedRoutes: number;
}

/**
 * Step O.3 — `revertTo` query parameter value space for
 * DELETE (AC #21). The operator picks at delete time:
 *   - "" → covered routes revert to "" (project default, J-era
 *     fallback → HTTP-01 on next reload).
 *   - "http-01" → explicit per-route HTTP-01 (same effect as
 *     "" but the audit + route detail surface a deliberate
 *     choice).
 *   - "dns-01" → explicit per-route DNS-01 (requires the DNS
 *     provider to remain configured; otherwise the route
 *     serves internal-CA until provider returns).
 */
export type ManagedDomainRevertTo = '' | 'http-01' | 'dns-01';

/**
 * Step P.3 — auto-classify Source enum (mirror of
 * automation.Source in Go). Nine categories: 6 WAF + 2
 * throttle + auth-burst. The frontend renders one Rule row
 * per Source under the Security Automation Card.
 */
export type AutomationSource =
	| 'waf-sqli'
	| 'waf-xss'
	| 'waf-rce'
	| 'waf-lfi'
	| 'waf-protocol'
	| 'waf-other'
	| 'throttle-tier1'
	| 'throttle-tier2'
	| 'auth-burst';

/**
 * Step P.3 — per-Source rule. Mirrors automation.Rule's JSON
 * tags. Threshold / Window / Duration / Cooldown values are
 * inert when Enabled is false (the backend's Validate skips
 * non-enabled rules so a disabled-by-default operator can
 * leave the inputs blank without errors).
 *
 * Durations are nanoseconds on the wire (Go's
 * time.Duration MarshalJSON default). The Settings UI
 * presents human-friendly forms ("60s", "4h") that we
 * convert on submit.
 */
export interface AutomationRule {
	enabled: boolean;
	threshold: number;
	window_ns: number;
	duration_ns: number;
	cooldown_ns: number;
}

/**
 * Step P.3 — the operator-facing rule set. One Rule per
 * Source; the backend's DefaultRuleSet pre-populates every
 * Source on a fresh install, so the map is always full.
 */
export interface AutomationRuleSet {
	rules: Record<AutomationSource, AutomationRule>;
}

/**
 * Step P.3 — GET /api/v1/settings/automation response shape.
 * Rules + credentials in one round-trip so the Settings UI
 * renders the full section state without a second request.
 * Password is ALWAYS redacted (configured flag is the single
 * source of truth for "is the writer wired").
 */
export interface AutomationResponse {
	rules: AutomationRuleSet;
	credentials: AutomationCredentialsView;
}

export interface AutomationCredentialsView {
	lapiUrl: string;
	machineId: string;
	configured: boolean;
}

/**
 * Step P.3 — PUT /api/v1/settings/automation/credentials body.
 * Empty password triggers the preserve-on-edit path (J.4
 * pattern); non-empty overwrites. All-blank fields erase the
 * row + ClearCredentials on the running engine.
 */
export interface AutomationCredentialsRequest {
	lapiUrl: string;
	machineId: string;
	password: string;
}

/**
 * Step P.3 — PUT /api/v1/settings/automation/rules envelope.
 * The single `rules` key mirrors the GET response shape so
 * the same body can be round-tripped without surgery.
 */
export interface AutomationRulesRequest {
	rules: AutomationRuleSet;
}

/**
 * Step P.3 — all known Source values, in the same order the
 * Go AllSources() emits. UI lists rules in this order so the
 * operator-facing layout is deterministic.
 */
export const AUTOMATION_SOURCES: readonly AutomationSource[] = [
	'waf-sqli',
	'waf-xss',
	'waf-rce',
	'waf-lfi',
	'waf-protocol',
	'waf-other',
	'throttle-tier1',
	'throttle-tier2',
	'auth-burst'
] as const;

/**
 * Step P.3 — operator-friendly Source labels for the
 * Settings UI. Keep concise (column header width); the
 * Tooltip / aria-label can carry the longer description.
 */
export const AUTOMATION_SOURCE_LABELS: Record<AutomationSource, string> = {
	'waf-sqli': 'WAF · SQLi',
	'waf-xss': 'WAF · XSS',
	'waf-rce': 'WAF · RCE',
	'waf-lfi': 'WAF · LFI',
	'waf-protocol': 'WAF · Protocol',
	'waf-other': 'WAF · Other',
	'throttle-tier1': 'Throttle · Tier 1',
	'throttle-tier2': 'Throttle · Tier 2',
	'auth-burst': 'Auth · Burst'
};

/**
 * Step P.4 — provenance helper. Returns true iff a CrowdSec
 * decision's scenario was emitted by Arenet's auto-classify
 * loop (D3.3.A prefix convention). Used by /security/decisions
 * + MixedEventList to render the "auto" badge.
 */
export function isArenetAutoScenario(scenario: string): boolean {
	return scenario.startsWith('arenet/');
}

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
	/**
     * Step #S-17 — opt-in: relax the §1.6 Δ7 guard (email_verified
     * required on Pass 2 bootstrap) for IdPs that don't emit
     * email_verified=true by default (Authentik admin-created
     * accounts being the typical case). Always emitted by the
     * server (default false). Required field on this response
     * shape so the GUI checkbox can reflect the current state.
     */
    acceptUnverifiedEmail: boolean;	
	/**
	 * Provider kind (optional) — drives the SSO button logo on
	 * the login page. Empty = "generic" fallback. Mirrors the
	 * ForwardAuthProviderKind enum.
	 */
	kind: OIDCProviderKind;
	allowedIdentities: OIDCAllowedIdentity[];
	configured: boolean;
}

export type OIDCProviderKind = '' | 'authentik' | 'keycloak' | 'authelia' | 'generic';

export const OIDC_PROVIDER_KINDS: readonly OIDCProviderKind[] = [
	'',
	'authentik',
	'keycloak',
	'authelia',
	'generic'
] as const;

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
    /**
     * Step #S-17 — opt-in: see OIDCConfig.acceptUnverifiedEmail.
     * Optional on the request shape (the backend defaults to
     * false when omitted, matching the OIDCConfig zero value).
     */
    acceptUnverifiedEmail?: boolean;	
	kind?: OIDCProviderKind;
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
	/**
	 * Provider kind (optional, may be absent in JSON when empty/
	 * disabled). The login page uses it to pick the right SSO
	 * button logo via SSOProviderLogo. Absent → "generic".
	 */
	kind?: OIDCProviderKind;
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
	// Optional machine-readable code from the response body
	// (e.g. "oidc_unlock_unsupported"). Step #S-24 — first
	// consumer is LockScreen, which redirects OIDC users to a
	// fresh SSO sign-in when password-based unlock is rejected.
	code?: string;
	
	constructor(message: string, status: number, kind?: ErrorKind, retryAfterSeconds?: number, code?: string) {
		super(message);
		this.status = status;
		if (kind !== undefined) {
			this.kind = kind;
		} else {
			// Step C compat: derive kind from status when caller omits it.
			this.kind = status === 400 || status === 409 ? 'validation' : 'system';
		}
		this.retryAfterSeconds = retryAfterSeconds;
		this.code = code;
	}
}

// --- Step L observability types ---------------------------------------------

// The five metrics the timeseries endpoint accepts. Mirrors the
// Go-side `metricName` enum in internal/api/metrics_handlers.go.
// `waf_block_rate` was added in Step M.2 — it's a count metric
// (gap-fill = 0 for missing buckets, not null).
export type MetricName =
	| 'req_per_sec'
	| 'four_xx_rate'
	| 'five_xx_rate'
	| 'p95_latency_ms'
	| 'waf_block_rate'
	// Step Q.3 — rate-limit (throttle) blocks per minute.
	// Reads bucket.ThrottleBlockCount; spec §3.5 stores under
	// the sentinel route_id "_throttle", so the dashboard
	// passes route="_throttle" for the global series.
	| 'throttle_block_rate'
	// Step Q.3 — auth-failure rate. Server-side detour via
	// the audit log (D4.B: single source of truth, no bucket
	// counter). route="all" returns the system-wide series;
	// route=<uuid> returns all-zero (AC #10 — neither signal
	// is per-route).
	| 'auth_failure_rate'
	// Step N.3 — CrowdSec decision rate. Reads
	// bucket.CrowdSecDecisionCount via the QueryAggregated
	// SUM path on route="all" (which includes the sentinel
	// "_crowdsec" row — same trick as throttle). route=<uuid>
	// returns all-zero (mirror of throttle).
	| 'crowdsec_decision_rate';

export type MetricWindow = '24h' | '30d';

// One point on the timeline. `value` is `number | null` — null
// marks a missing-data gap that the chart MUST NOT connect
// across (AC #5: a null p95 must render as a break in the
// line, never as 0 ms which would draw a fake latency dip).
//
// Tied at the type level so a downstream consumer cannot
// accidentally `value: 0` a null point — TypeScript narrows
// `value` only after a `!== null` check.
export interface TimeseriesPoint {
	ts: string;
	value: number | null;
}

export interface TimeseriesResponse {
	routeId: string;
	metric: MetricName;
	window: MetricWindow;
	bucketSizeSeconds: number;
	// AC #13: when the observability subsystem failed at boot,
	// the API returns disabled=true + an empty points array.
	// The dashboard renders an "unavailable" empty state, not
	// an error toast.
	disabled?: boolean;
	points: TimeseriesPoint[];
}

export interface SummaryRoute {
	routeId: string;
	host: string;
	reqsPerMin: number;
	fourxxPerMin: number;
	fivexxPerMin: number;
	// Step M.2 — per-route WAF blocks over the just-closed
	// minute. Independent of fourxxPerMin/fivexxPerMin (AC
	// #3): a WAF-blocked 403 does NOT inflate the 4xx count.
	wafBlockedPerMin: number;
}

export interface SummaryResponse {
	generatedAt: string;
	windowSeconds: number;
	disabled?: boolean;
	totalReqPerMin: number;
	totalFourXxPerMin: number;
	totalFiveXxPerMin: number;
	// Step M.2 — system-wide WAF blocks counter + per-OWASP-
	// category breakdown. Independent of the L 4xx/5xx
	// totals (AC #3 reciprocal). wafBlocksByCategory is
	// always a (possibly empty) map; an empty map means
	// either no events landed in the window, or the WAF
	// event reader is unavailable (degraded mode).
	totalWafBlockedPerMin: number;
	// Step Q.3 — rate-limit (throttle) blocks counted by the
	// auth handler over the just-closed minute, system-wide.
	// AC #15: independent of totalWafBlockedPerMin and the
	// L 4xx/5xx totals — a Tier-1 / Tier-2 block does NOT
	// inflate any of those fields.
	totalThrottlePerMin: number;
	// Step Q.3 — count of authentication-failure audit events
	// over the just-closed minute. Source: server-side audit-
	// scan (D2.B/D4.B). Same independence contract as
	// totalThrottlePerMin.
	totalAuthFailuresPerMin: number;
	// Step Q.3 — server-side union of distinct source IPs
	// across WAF + throttle + audit auth-failure events over
	// the just-closed minute. An IP that hit multiple
	// sources counts ONCE. The dashboard renders this as
	// the "ATTACKER IPs unique" headline card.
	//
	// Step N.3 extension: the union now spans 4 sources
	// (waf + throttle + audit + crowdsec). The number can
	// be larger than pre-N if a CrowdSec community
	// blocklist contributes IPs not seen by the other gates.
	attackerIpsUnique: number;
	// Step N.3 — total CrowdSec decisions captured by the
	// parallel StreamBouncer consumer over the just-closed
	// minute (dedupe-before-bump per N spec D4.A — counts
	// NEW decisions, not re-polled active ones). Read from
	// the sentinel "_crowdsec" bucket row. AC #N.24:
	// independent of every other counter.
	totalCrowdSecDecisionsPerMin: number;
	// Step N.3 — count of distinct decision `value` strings
	// (IP / CIDR / country / AS) in the just-closed minute.
	// Includes non-IP scopes intentionally; the dashboard's
	// "Active CrowdSec attackers" card surfaces this number.
	activeCrowdSecIpsUnique: number;
	wafBlocksByCategory: Record<string, number>;
	// Null when no traffic landed in the window — same
	// no-fake-dip rule as TimeseriesPoint.value.
	globalP95LatencyMs: number | null;
	activeRouteCount: number;
	topRoutes: SummaryRoute[];
	// Step M.2 amendment — single most-attacked route over the
	// window, ranked by wafBlockedPerMin across ALL routes
	// (NOT filtered to topRoutes). null when no WAF activity.
	// Spec §1.3 D8 — the M.3 dashboard headline reads from
	// this field so a targeted attack on a low-traffic admin
	// surface stays visible.
	topAttackedRoute: SummaryRoute | null;
}

// --- Step M security types --------------------------------------------------

// OWASP category strings emitted by the WAF event sink.
// Mirrors internal/waf/event.go OwaspCategory enum.
// `OTHER` is the catch-all for rules that don't match any
// known CRS range.
export type OwaspCategory = 'SQLi' | 'XSS' | 'RCE' | 'LFI' | 'PROTOCOL' | 'OTHER';

// All categories in dashboard-display order. Frontend uses
// this to render the CategoryDistribution strip with stable
// left-to-right ordering even when a category has 0 events.
export const ALL_OWASP_CATEGORIES: readonly OwaspCategory[] = [
	'SQLi',
	'XSS',
	'RCE',
	'LFI',
	'PROTOCOL',
	'OTHER'
];

// One WAF event row as returned by GET /api/v1/security/events.
// Field shapes mirror observability.WafEvent via the M.2 wire
// type — see internal/api/security_handlers.go for the source
// of truth.
export interface WafEvent {
	id: number;
	ts: string;
	routeId: string;
	ruleId: string;
	category: OwaspCategory;
	severity: number;
	srcIp: string;
	requestMethod: string;
	requestPath: string;
	payloadSample: string;
	// W.bugfix Fix #1 — mode-aware label fields. "BLOCK" =
	// the WAF returned statusCode (403 today); "DETECT" =
	// the rule fired but the request passed to the upstream
	// (statusCode is 0; UI renders "—"). Pre-fix rows persisted
	// in the legacy schema are backfilled to ("BLOCK", 403).
	action: 'BLOCK' | 'DETECT';
	statusCode: number;
}

export interface WafEventsResponse {
	disabled?: boolean;
	events: WafEvent[];
}

// One row of the per-rule aggregate returned by
// GET /api/v1/security/events/by-rule (M.2 amendment #2).
// Used by the M.4 drill-down's per-rule breakdown table.
// `lastSeen` is the most-recent event ts for the (ruleId,
// category) tuple over the window.
export interface WafEventRuleAggregate {
	ruleId: string;
	category: OwaspCategory;
	count: number;
	lastSeen: string;
}

export interface WafEventsByRuleResponse {
	disabled?: boolean;
	rows: WafEventRuleAggregate[];
}

// --- Step Q security types --------------------------------------------------

/**
 * One rate-limit (throttle) block event as returned by
 * GET /api/v1/security/throttle-events. Mirrors the Go
 * wire type securityThrottleEvent in
 * internal/api/security_handlers.go.
 *
 * Tier is 1 (5 fails / 5 min → 15 min block) or 2 (10 fails
 * / 1 h → 1 h block) per spec D1.A. BlockDurationSeconds is
 * the original duration assigned when the block fired —
 * preserved verbatim so the UI can format "blocked for X"
 * without rounding the live `blockedUntil` countdown.
 *
 * AttemptedUsername is captured-verbatim per spec D8.A:
 * parity with the existing audit log's exposure. The
 * dashboard renders it as the "user attempted" hint so an
 * operator under credential-stuffing sees which usernames
 * the attacker is spraying.
 */
export interface ThrottleEvent {
	id: number;
	ts: string;
	tier: 1 | 2;
	srcIp: string;
	attemptedUsername: string;
	blockedUntil: string;
	blockDurationSeconds: number;
}

export interface ThrottleEventsResponse {
	disabled?: boolean;
	events: ThrottleEvent[];
}

/**
 * One audit-derived auth-failure event as returned in the
 * `recent` slice of GET /api/v1/security/auth-failures.
 * Action is one of the four audit constants the backend
 * surfaces via audit.AuthFailureActions(): login_failure,
 * unlock_failure, oidc_login_rejected, oidc_callback_invalid.
 *
 * username + srcIp + message may be empty strings (the audit
 * record may have been written without them — e.g. the IP
 * extractor failed, spec §8.5). Frontend renders "—" in
 * that case rather than blanking the row.
 */
export type AuthFailureAction =
	| 'login_failure'
	| 'unlock_failure'
	| 'oidc_login_rejected'
	| 'oidc_callback_invalid';

export interface AuthFailureRecentEvent {
	ts: string;
	action: AuthFailureAction;
	username: string;
	srcIp: string;
	message: string;
}

/**
 * GET /api/v1/security/auth-failures response.
 *
 * `timeseries` is the per-minute count over the window
 * (1440 buckets for 24h), gap-filled with 0. Same wire
 * shape as the L metrics timeseries minus the
 * disabled/null cells — auth-failures is a count metric.
 *
 * `recent` is the head-of-feed for the mixed-events widget,
 * ts-descending, capped at 100 server-side.
 *
 * `partial: true` is set when the audit-bucket scan hit its
 * 200-row internal cap before reaching the window's `from`
 * boundary. Operator hint that earlier matching events
 * exist but were not surfaced — rare in practice (spec D4
 * volume), exposed for honesty.
 */
export interface AuthFailureTimeseriesPoint {
	ts: string;
	value: number;
}

export interface AuthFailuresResponse {
	disabled?: boolean;
	window: MetricWindow;
	timeseries: AuthFailureTimeseriesPoint[];
	recent: AuthFailureRecentEvent[];
	partial?: boolean;
}

/**
 * GET /api/v1/security/attackers-summary response.
 *
 * `uniqueIps` is the server-side union count across WAF,
 * throttle, and audit auth-failure source-IP sets over the
 * window. An IP that hit multiple sources counts ONCE.
 *
 * `byBucketSource` is the per-source pre-union breakdown —
 * the dashboard's "by source" widget. SUM(byBucketSource)
 * ≥ uniqueIps (equal when no overlap).
 *
 * Four-state disabled / partial contract (Step N.3 extended
 * the original Q.3 three-state to four):
 *   - All four backend readers nil → disabled=true, empty
 *     bodies.
 *   - At least one nil but not all → partial=true, the
 *     union reflects the readers that DID respond.
 *   - All four present → neither flag set.
 *
 * The frontend uses `partial` to drive an "incomplete data"
 * affordance — same convention as
 * AuthFailuresResponse.partial.
 */
export interface AttackersByBucketSource {
	waf: number;
	throttle: number;
	audit: number;
	// Step N.3 — 4th source: distinct CrowdSec decision
	// `value` strings (IP / CIDR / country / AS). Includes
	// non-IP scopes intentionally — a Range-scoped community
	// blocklist entry is just as much an attacker indicator
	// as a single IP.
	crowdsec: number;
}

export interface AttackersSummaryResponse {
	disabled?: boolean;
	partial?: boolean;
	window: MetricWindow;
	uniqueIps: number;
	byBucketSource: AttackersByBucketSource;
}

// --- Step N CrowdSec types --------------------------------------------------

/**
 * LAPI decision scope. Strings are free-form on the wire
 * (the LAPI vocabulary is operator-controlled; new scopes
 * could appear via custom community scenarios), but the
 * documented values are the four below.
 */
export type DecisionScope = 'ip' | 'range' | 'country' | 'as';

/**
 * LAPI decision action type. The bouncer translates these
 * to HTTP responses:
 *   - `ban`: 403 (default).
 *   - `captcha`: 403 (no captcha challenge implemented in
 *     caddy-crowdsec-bouncer v0.12.1; functionally a ban —
 *     upstream issue #46).
 *   - `throttle`: 429 + Retry-After header.
 *
 * Free-form string on the wire for forward-compat with
 * future LAPI extensions.
 */
export type DecisionType = 'ban' | 'captcha' | 'throttle';

/**
 * One CrowdSec LAPI decision row, mirror of
 * observability.DecisionEvent (storage) + N spec D5.B
 * operator-facing subset.
 *
 * UUID is LAPI's stable cross-instance identifier (drift-
 * safe across CrowdSec restarts; the LAPI server-local `id`
 * was intentionally dropped at the storage layer for
 * stability — see N spec §1.3 D5.B).
 *
 * Scope + Value together describe WHAT the decision targets:
 *   - "ip" + "1.2.3.4"            → single IP.
 *   - "range" + "185.142.86.0/24" → CIDR (community blocklist).
 *   - "country" + "RU"            → all IPs from a country.
 *   - "as" + "AS12345"            → all IPs from an AS.
 *
 * ExpiresAt is the absolute moment the decision becomes
 * inactive. The retention layer (server-side) prunes rows
 * 30d after ExpiresAt per N spec D8.A.
 */
export interface Decision {
	id: number;
	uuid: string;
	ts: string;
	scope: string;
	value: string;
	type: string;
	scenario: string;
	expiresAt: string;
	durationSeconds: number;
}

export interface DecisionsResponse {
	disabled?: boolean;
	events: Decision[];
}

// --- Step U cert event types --------------------------------------------------

/**
 * Level of a cert lifecycle event in the Activity log.
 * Matches the backend's CertEventLevel.String() output
 * (internal/observability/cert_event.go). INFO covers
 * cert_obtained; ERROR covers cert_failed + cert_ocsp_revoked
 * (the latter is a security-relevant signal per Step U spec
 * §3.6).
 */
export type CertEventLevel = 'INFO' | 'ERROR';

/**
 * Event type lineage from certmagic. The frontend renders
 * each as a different row variant in the Activity log table.
 * Matches CertEventType.String() output verbatim so an
 * operator searching the table textbox for "cert_failed"
 * matches the typed token. cert_obtaining is NOT persisted
 * per spec §3.3 — it never appears in the wire shape.
 */
export type CertEventType = 'cert_obtained' | 'cert_failed' | 'cert_ocsp_revoked';

/**
 * One cert lifecycle event row as returned by
 * GET /api/v1/observability/cert-events. Field shapes mirror
 * observability.CertEvent via the U.3 wire type
 * certEventResponseItem in
 * internal/api/cert_events_handler.go (the camelCase JSON
 * tags map 1-to-1 to the snake_case columns in cert_event).
 *
 * Empty-string defaults match the U.1 schema NOT NULL
 * DEFAULT '' constraints: a producer that omits issuer (e.g.
 * a cert_failed row) sends "" not null. The Activity log
 * mapper treats empty strings as "no data" rather than
 * rendering blank pills.
 *
 * Per the U.3 handler's omitempty discipline, only Timestamp,
 * Level, EventType, and Domain are guaranteed present on
 * every row; the other fields may be absent (omitempty) when
 * empty. TypeScript declares them as required for clarity
 * but the runtime tolerates missing fields (treated as "").
 */
export interface CertEvent {
	timestamp: string;
	level: CertEventLevel;
	eventType: CertEventType;
	domain: string;
	issuer: string;
	challenge: '' | 'DNS-01' | 'HTTP-01';
	renewal: boolean;
	error: string;
	details: string;
}

/**
 * Wire shape of GET /api/v1/observability/cert-events.
 *
 * `total` is the count of rows matching the filter ignoring
 * limit (CountCertEvents in the U.3 backend) — lets the UI
 * surface "showing N of M".
 *
 * `hasMore` is true iff total > events.length — pagination
 * hint for a future load-more affordance; U.5 doesn't
 * implement load-more, but the frontend type carries the
 * field so a future increment can wire it without a
 * type-level migration.
 *
 * `degraded` is omitted on the happy path (omitempty); true
 * when the backend reader was nil (boot failure or missed
 * wire-up). Mirrors the `disabled?` field on WAF / throttle
 * / decision responses for operator mental-model uniformity.
 * AC #13 degraded-mode contract carried forward from Step T.
 */
export interface CertEventsResponse {
	events: CertEvent[];
	total: number;
	hasMore: boolean;
	degraded?: boolean;
}

/**
 * Step V — geographic threat map.
 *
 * Wire shape of GET /api/v1/observability/server-position
 * (spec §5.1). Locked to the V.4 backend handler in
 * internal/api/server_position_handler.go's
 * serverPositionResponse — camelCase JSON tags map to the
 * snake_case storage columns 1-to-1.
 *
 * `mode` is "auto" when the V.1 ipify-then-GeoIP path
 * produced the position, "manual" when the operator
 * persisted an override via PUT.
 *
 * `degraded` is true when no GeoIP MMDB is loaded AND no
 * manual override exists. In that case `lat`, `lon`, `city`,
 * `country`, `sourceIp`, `detectedAt` collapse to their
 * zero values per the spec §5.1 degraded shape — the
 * frontend renders a banner + falls back to a world-
 * centered Mercator.
 *
 * `sourceIp` and `detectedAt` are omitted by the backend
 * (omitempty) on the manual override path. Declared
 * optional on the wire so the typecheck doesn't require
 * the frontend to assert non-emptiness it can never
 * guarantee.
 */
export interface ServerPosition {
	lat: number;
	lon: number;
	city: string;
	country: string;
	mode: 'auto' | 'manual';
	sourceIp?: string;
	detectedAt?: string;
	degraded?: boolean;
}

/**
 * Step V — GeoEvent wire shape (spec §5.6). Locked enum on
 * `category`: 5 values, no `cert` — cert events live in the
 * Activity log via Step U, NOT in the geo map (the V.2
 * decision honored §5.6 line 515's locked enum over §6
 * AC #2's mention of cert enrichment).
 *
 * `sourceLat` / `sourceLon` are 0 when the GeoIP lookup is
 * degraded (no MMDB) or when the source IP is RFC1918 (LAN
 * sources render at the Arenet position with an `(LAN)`
 * label per spec §3.8). `sourceCountry` is `"UNK"` in the
 * degraded case.
 *
 * `isLan` is true for RFC1918 / loopback / link-local
 * addresses. The frontend uses this flag to render the
 * Arenet-centered loop arc instead of a real source-to-
 * Arenet arc.
 *
 * `statusCode` / `routeId` / `details` are operator-facing
 * tooltip metadata; populated when known, empty otherwise.
 */
export type GeoEventCategory = 'normal' | 'throttle' | 'waf' | 'crowdsec' | 'auth';

export interface GeoEvent {
	timestamp: string;
	category: GeoEventCategory;
	sourceIp: string;
	sourceLat: number;
	sourceLon: number;
	sourceCountry: string;
	sourceCity: string;
	isLan: boolean;
	statusCode?: number;
	routeId?: string;
	details: string;
}

/**
 * Wire shape of GET /api/v1/observability/geo-events (V.3
 * replay endpoint, spec §5.4). `total` is the ring buffer's
 * current size — events do NOT persist across restart
 * (in-memory N=500 per spec §3.5).
 *
 * `degraded` is true when the GeoIP lookup is degraded —
 * events still flow but with empty country/lat/lon.
 */
export interface GeoEventsResponse {
	events: GeoEvent[];
	total: number;
	degraded?: boolean;
}
