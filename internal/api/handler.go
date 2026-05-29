// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

package api

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/storage"
)

// timestampFormat is RFC 3339 with millisecond precision, trailing zeros
// stripped. Matches the wire shape defined in spec §5.2.
const timestampFormat = "2006-01-02T15:04:05.999Z07:00"

// CaddyReloader is the subset of internal/caddymgr the API depends on. Defined
// here (consumer side) so tests can inject a fake without booting Caddy.
type CaddyReloader interface {
	ReloadFromStore(ctx context.Context) error
}

// MetricsReader is the read surface the /api/v1/metrics/* handlers
// depend on. Defined here (consumer side) so tests can inject a
// fake that simulates the AC #13 degraded paths — store=nil
// (boot failure) or Query returning an error (locked / corrupt
// DB at runtime).
//
// *observability.Store satisfies this interface. The API layer
// holds the interface type rather than the concrete *Store so the
// handler tolerates a nil sentinel cleanly (no nil-pointer
// dereference on method dispatch).
//
// QueryAggregated (Spec-1 §10.1) is the system-wide view: one
// MetricBucket per ts with SUM-aggregated counters and weighted
// p95 across all routes. Used by the dashboard's three timeline
// charts so they line up with the global stat cards.
type MetricsReader interface {
	Query(ctx context.Context, gran observability.Granularity, routeID string, from, to time.Time) ([]observability.MetricBucket, error)
	QueryAggregated(ctx context.Context, gran observability.Granularity, from, to time.Time) ([]observability.MetricBucket, error)
}

// WafEventReader is the read surface the Step M security
// handlers depend on: per-event WAF rows with optional
// filters (route, category, time range). Defined here
// (consumer side) so tests inject a fake without spinning
// up SQLite, same pattern as MetricsReader.
//
// *observability.Store satisfies this interface. A nil
// reader is the AC #13 degraded-mode case (boot-failed
// observability subsystem); handlers detect nil and return
// 200 with disabled=true rather than 500.
type WafEventReader interface {
	QueryWafEvents(ctx context.Context, filter observability.WafEventFilter) ([]observability.WafEvent, error)
}

// AuditAppender is the subset of internal/audit the API depends on. Defined
// here (consumer side, decision D4) so tests can inject a fake without
// booting bbolt. *audit.Store naturally satisfies this interface.
//
// The interface exposes both Append (used by handlers post-success) and
// List (used by /audit endpoint, Commit C). The name AuditAppender is
// kept for Step C/Chunk 3 backwards compatibility despite now covering
// reads as well; a future rename to AuditStore is out of scope for Step D.
type AuditAppender interface {
	Append(ctx context.Context, evt audit.Event) error
	List(ctx context.Context, f audit.Filter) ([]audit.Event, string, error)
}

// Handler owns every dependency the admin API needs (storage, Caddy
// reload, audit, auth stores, HIBP, rate limiter, setup token) and
// exposes the HTTP handlers.
type Handler struct {
	store       *storage.Store
	caddy       CaddyReloader
	audit       AuditAppender
	users       *auth.UserStore
	sessions    *auth.SessionStore
	hibp        *auth.HIBPClient
	rateLimiter *auth.RateLimiter
	setupToken  *SetupTokenHolder
	// oidc (Step K.2) owns the OIDC client state — discovery
	// doc cache, verifier, oauth2 config. Built lazily on first
	// enabled-config PUT. nil-safe: a non-OIDC code path never
	// touches it.
	oidc    *OIDCManager
	devMode bool
	logger  *slog.Logger
	// uiOrigin (Step K.2 dev) — when non-empty, the OIDC
	// callback's redirects are emitted as absolute URLs
	// against this origin (e.g. http://localhost:5173) so the
	// browser lands on the Vite dev server, not on the API.
	// Empty in prod: relative redirects resolved against the
	// API origin where the static SPA is served. Set via
	// SetUIOrigin after construction.
	uiOrigin string
	// startTime is captured at NewHandler-time and reported by the
	// /healthz endpoint as uptime_seconds (Step H.3). Read-only after
	// construction.
	startTime time.Time
	// metrics (Step L L.2) is the read surface for per-route
	// metrics history. Set via SetMetricsReader after
	// construction (same pattern as uiOrigin). nil means the
	// observability subsystem failed to open at boot (AC #13
	// degraded-mode) or that this Handler was built in a test
	// that does not exercise the /metrics endpoints — both are
	// expected; the handlers detect nil and emit the
	// "disabled" response without panicking.
	metrics MetricsReader
	// wafEvents (Step M.2) is the read surface for the
	// /api/v1/security/events endpoint + the WafBlocksByCategory
	// field on /metrics/summary. Same nil-tolerance contract as
	// `metrics` — boot-failed observability → degraded-mode
	// response, not 500.
	wafEvents WafEventReader
}

// NewHandler constructs a Handler. All non-bool arguments must be non-nil.
func NewHandler(
	store *storage.Store,
	caddy CaddyReloader,
	auditAppender AuditAppender,
	users *auth.UserStore,
	sessions *auth.SessionStore,
	hibp *auth.HIBPClient,
	rateLimiter *auth.RateLimiter,
	setupToken *SetupTokenHolder,
	devMode bool,
	logger *slog.Logger,
) *Handler {
	switch {
	case store == nil:
		panic("api.NewHandler: store is nil")
	case caddy == nil:
		panic("api.NewHandler: caddy is nil")
	case auditAppender == nil:
		panic("api.NewHandler: audit is nil")
	case users == nil:
		panic("api.NewHandler: users is nil")
	case sessions == nil:
		panic("api.NewHandler: sessions is nil")
	case hibp == nil:
		panic("api.NewHandler: hibp is nil")
	case rateLimiter == nil:
		panic("api.NewHandler: rateLimiter is nil")
	case setupToken == nil:
		panic("api.NewHandler: setupToken is nil")
	case logger == nil:
		panic("api.NewHandler: logger is nil")
	}
	return &Handler{
		store:       store,
		caddy:       caddy,
		audit:       auditAppender,
		users:       users,
		sessions:    sessions,
		hibp:        hibp,
		rateLimiter: rateLimiter,
		setupToken:  setupToken,
		// Step K.2 — always present; the OIDC handlers tolerate a
		// "never built" state (lazy build on first enabled-config
		// PUT or first login initiate). Tests that don't exercise
		// the OIDC flow leave this untouched; no nil checks needed
		// at the call sites.
		oidc:      NewOIDCManager(),
		devMode:   devMode,
		logger:    logger,
		startTime: time.Now(),
	}
}

// SetUIOrigin (Step K.2 dev) configures the SPA origin to use
// for the OIDC callback redirects. Empty (default) keeps
// relative redirects, suitable for production where the static
// SPA is served by Arenet at the same origin as the API.
// Non-empty (e.g. "http://localhost:5173") prefixes every
// callback redirect so the browser lands on the dev server.
// Trailing slashes are stripped; the value is used as-is for
// concatenation with "/routes" / "/login?error=...".
//
// Intentionally a setter (not a NewHandler arg) so the existing
// test scaffolding stays signature-compatible.
func (h *Handler) SetUIOrigin(origin string) {
	h.uiOrigin = strings.TrimRight(strings.TrimSpace(origin), "/")
}

// SetMetricsReader (Step L L.2) attaches the per-route metrics
// history reader. Pass nil if observability boot failed — the
// /api/v1/metrics/* endpoints will return the "disabled"
// response cleanly rather than crashing (AC #13 degraded-mode
// API half).
//
// Intentionally a setter (not a NewHandler arg) so the existing
// test scaffolding stays signature-compatible — same convention
// as SetUIOrigin.
func (h *Handler) SetMetricsReader(m MetricsReader) {
	h.metrics = m
}

// SetWafEventReader (Step M.2) attaches the WAF event reader
// used by /api/v1/security/events + the WafBlocksByCategory
// field of /metrics/summary. Same nil-tolerance contract as
// SetMetricsReader: pass nil if observability boot failed; the
// security endpoints will return disabled-mode responses.
func (h *Handler) SetWafEventReader(r WafEventReader) {
	h.wafEvents = r
}

// uiURL returns the URL to redirect to for the given SPA path
// (must start with "/"). If uiOrigin is empty, path is returned
// as-is (relative). Otherwise the origin is prefixed.
func (h *Handler) uiURL(path string) string {
	if h.uiOrigin == "" {
		return path
	}
	return h.uiOrigin + path
}

// upstreamReq is the per-element wire shape inside the routeRequest
// upstreams pool. Mirrors storage.Upstream verbatim (URL + Weight)
// but lives in the api package so the wire layer is decoupled from
// the storage struct — pattern Step I established for routeRequest
// vs storage.Route. createRoute / updateRoute map upstreamReq slices
// to storage.Upstream slices before validation; the API materialises
// Weight=0 → 1 in that mapping (§5.1, §1.3 decision 1).
type upstreamReq struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

// basicAuthReq is the Step K.1 wire shape for per-route Basic
// Auth on the request side. Password is the PLAIN text on the
// wire — write-only (the response never echoes it; the storage
// hash is derived from it via auth.HashRoutePassword); Username
// round-trips normally.
//
// Active iff routeRequest.AuthMode == "basic". When the parent's
// AuthMode is "none" or "forward_auth", BasicAuth fields are
// ignored by createRoute / updateRoute (the API validates this
// mutual exclusivity at the §1.3 decision 2 boundary).
//
// Preserve-on-edit: Password empty on PUT keeps the existing
// hash — same UX as Step I.5 + Step J.4 secrets.
type basicAuthReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// forwardAuthReq is the Step K.1 wire shape for per-route
// forward-auth on the request side. Carries the reference to one
// of the instance-level providers (the providers themselves are
// CRUD'd via /api/v1/settings/forward-auth/providers).
//
// Active iff routeRequest.AuthMode == "forward_auth". Empty
// ProviderName on PUT preserves the previously stored
// reference; mutually-exclusive with the basic auth fields.
type forwardAuthReq struct {
	ProviderName string `json:"providerName"`
}

// routeRequest is the wire shape accepted by POST and PUT /routes. JSON tags
// are camelCase per the spec.
type routeRequest struct {
	Host string `json:"host"`
	// Step J.1 — pool of backends. Replaces the pre-J.1 single
	// UpstreamURL string. At least one element; per-element URL is
	// validated by validateUpstreamURL (the existing Step I logic,
	// applied per element). Per-element Weight defaults to 1 if
	// omitted/zero — materialised by the API before the storage
	// write so the storage validate() rule weight >= 1 is satisfied.
	Upstreams []upstreamReq `json:"upstreams"`
	// Step J.1 — LB selection policy. One of the six storage
	// .LBPolicy* values. Empty on POST is normalised to
	// "round_robin" (the default per §5.1, materialised before
	// validation so the storage row carries the explicit value).
	// Empty on PUT means "preserve the previously stored value",
	// same UX as WAFMode below.
	LBPolicy        string   `json:"lbPolicy"`
	TLSEnabled      bool     `json:"tlsEnabled"`
	RedirectToHTTPS bool     `json:"redirectToHttps"`
	Aliases         []string `json:"aliases"`
	// Step K.1 — per-route auth mode. One of "" / "none" / "basic"
	// / "forward_auth". On POST, empty is normalised to "none". On
	// PUT, empty preserves the previously stored value (same UX as
	// WAFMode). The radio-group enum is materialised before
	// validation so the storage row carries the explicit value.
	AuthMode string `json:"authMode"`
	// Step K.1 — Basic Auth sub-shape (replaces the Step I.5 flat
	// BasicAuthEnabled / BasicAuthUsername / BasicAuthPassword
	// triplet). Active only when AuthMode == "basic". BasicAuth.Password
	// is the PLAIN password, write-only on the wire (the response
	// never echoes it, the storage layer holds only the argon2id
	// PHC hash). On Edit, leaving this empty means "keep the
	// existing hash" — same UX preserve-on-edit pattern Step I.5
	// established.
	BasicAuth basicAuthReq `json:"basicAuth"`
	// Step K.1 — Forward-auth sub-shape. Active only when AuthMode
	// == "forward_auth". The reference to one of the configured
	// instance-level providers (Settings page).
	ForwardAuth forwardAuthReq `json:"forwardAuth"`
	// Step I.6 — custom headers applied to the proxied request /
	// response. Map[name → value] (single value per name in v1.0).
	// Validation rejects CR/LF/control characters and hop-by-hop /
	// framing-critical names — see validateHeaders.
	RequestHeaders  map[string]string `json:"requestHeaders"`
	ResponseHeaders map[string]string `json:"responseHeaders"`
	// Step I.4 — WAF mode, one of "off" / "detect" / "block".
	// On POST, empty string is normalized to "detect" (the FortiWeb
	// safe-shadow default, L6). On PUT, empty string MEANS "preserve
	// the previously stored value" — mirrors the I.5 password
	// preserve UX so admins can flip unrelated fields without
	// re-typing the WAF mode every time.
	WAFMode string `json:"wafMode"`
	// Step J.4 — ACME challenge type for this route's TLS cert.
	// One of "" / "http-01" / "dns-01". On POST and PUT, empty
	// string is normalised to "http-01" (the §5.4 default and the
	// pre-J.4 behaviour) — there is no preserve-on-omit semantic
	// like wafMode, because the value carries no secret and the
	// per-route ACME challenge is naturally specified on every
	// edit (TLS section of the form).
	ACMEChallenge string `json:"acmeChallenge"`
	// Step J.2 — active health check, pointer so nil distinguishes
	// "block absent from JSON" from "block present with explicit
	// disabled" (see healthCheckReq doc-comment). createRoute: nil
	// = HC zero-value (disabled); non-nil = materialise + validate
	// then map to storage. updateRoute: nil = preserve previous
	// stored HealthCheck; non-nil = full replacement. The latter
	// rule matches Step I.5 BasicAuth + Step I.4 WAFMode
	// preserve-on-omission patterns.
	HealthCheck *healthCheckReq `json:"healthCheck,omitempty"`
}

// upstreamResp is the per-element wire shape inside the routeResponse
// upstreams pool. Symmetric to upstreamReq — URL + Weight.
type upstreamResp struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

// healthCheckReq is the per-route active health check on the API
// request side (Step J.2). Mirrors storage.HealthCheck verbatim
// except the JSON tags are camelCase (the api wire convention)
// rather than snake_case (the storage convention) — pattern Step I
// established for routeRequest vs storage.Route. createRoute /
// updateRoute map healthCheckReq to storage.HealthCheck after
// materialising the five defaultable sub-fields (Method, Interval,
// Timeout, Passes, Fails) and uppercasing Method (§5.2).
//
// On routeRequest the field is a POINTER (*healthCheckReq) so the
// JSON decoder distinguishes:
//   - block ABSENT (`healthCheck` key missing) → ptr is nil →
//     updateRoute preserves the previously stored HealthCheck;
//     createRoute treats as zero-value (disabled).
//   - block PRESENT (any value, including {"enabled": false}) →
//     ptr is non-nil → full replacement (§J.3-backlog).
//
// The "omission ≠ clear" semantic mirrors Step I.5 (empty password
// preserves hash) and Step I.4 (empty wafMode preserves mode).
type healthCheckReq struct {
	Enabled      bool   `json:"enabled"`
	URI          string `json:"uri"`
	Method       string `json:"method"`
	Interval     string `json:"interval"`
	Timeout      string `json:"timeout"`
	ExpectStatus int    `json:"expectStatus"`
	ExpectBody   string `json:"expectBody"`
	Passes       int    `json:"passes"`
	Fails        int    `json:"fails"`
}

// healthCheckResp is the per-route active health check on the API
// response side. Always non-pointer on the response (storage
// guarantees a HealthCheck field always exists on a stored Route)
// and the camelCase tags mirror healthCheckReq.
type healthCheckResp struct {
	Enabled      bool   `json:"enabled"`
	URI          string `json:"uri"`
	Method       string `json:"method"`
	Interval     string `json:"interval"`
	Timeout      string `json:"timeout"`
	ExpectStatus int    `json:"expectStatus"`
	ExpectBody   string `json:"expectBody"`
	Passes       int    `json:"passes"`
	Fails        int    `json:"fails"`
}

// basicAuthResp is the Step K.1 wire shape for per-route Basic
// Auth on the response side. PasswordSet is the secret-redaction
// signal (true if a hash exists in storage; the UI renders the
// "••• set" placeholder accordingly) — Step I.5 pattern preserved
// through K.1.
type basicAuthResp struct {
	Username    string `json:"username"`
	PasswordSet bool   `json:"passwordSet"`
}

// forwardAuthResp is the Step K.1 wire shape for per-route
// forward-auth on the response side. Mirrors forwardAuthReq —
// only the provider reference, no secrets (those live in the
// provider config endpoint).
type forwardAuthResp struct {
	ProviderName string `json:"providerName"`
}

// routeResponse is the wire shape returned by GET / POST / PUT /routes. The
// JSON tags must match routeRequest's camelCase scheme.
type routeResponse struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	// Step J.1 — pool surfaced on the wire. Always at least one
	// element on a stored route (storage.validate guarantees it).
	Upstreams []upstreamResp `json:"upstreams"`
	// Step J.1 — LB selection policy. Always a non-empty enum value
	// on a stored route (storage.validate guarantees it).
	LBPolicy        string `json:"lbPolicy"`
	TLSEnabled      bool   `json:"tlsEnabled"`
	RedirectToHTTPS bool   `json:"redirectToHttps"`
	// Aliases (Step I.3) is normalized to an empty slice (never nil)
	// so the JSON wire shape is consistently `"aliases": []` rather
	// than `"aliases": null` — frontend callers can read .length
	// without a null check.
	Aliases []string `json:"aliases"`
	// Step K.1 — per-route auth mode. The normalised value is
	// always one of "none" / "basic" / "forward_auth" on the
	// wire (storage zero-value "" is rewritten to "none" by
	// toResponse so the frontend renders a single consistent
	// state).
	AuthMode string `json:"authMode"`
	// Step K.1 — Basic Auth response sub-shape. Active only when
	// AuthMode == "basic". The plaintext password is NEVER
	// echoed; the hash is NEVER echoed either. PasswordSet is a
	// boolean derived from "is the hash non-empty?" so the UI
	// can render the placeholder "••• set" hint in Edit mode
	// without ever seeing the secret. (Step I.5 redaction
	// pattern preserved through K.1.)
	BasicAuth basicAuthResp `json:"basicAuth"`
	// Step K.1 — Forward-auth response sub-shape. Active only
	// when AuthMode == "forward_auth". Carries the provider
	// reference; the provider configuration itself (URL, secret,
	// copy headers) is GET'd via the Settings endpoint.
	ForwardAuth forwardAuthResp `json:"forwardAuth"`
	// Step I.6 — custom headers, normalized to empty maps (never
	// nil) so the JSON wire shape is always {} and frontend can
	// iterate without a null check.
	RequestHeaders  map[string]string `json:"requestHeaders"`
	ResponseHeaders map[string]string `json:"responseHeaders"`
	// Step I.4 — WAF mode, one of "off" / "detect" / "block".
	WAFMode string `json:"wafMode"`
	// Step J.4 — ACME challenge type, one of "http-01" / "dns-01".
	// Surfaced as the normalised value (a pre-J.4 row read back
	// reports "http-01", not the storage "" zero value), so the
	// frontend has a single, consistent state to render.
	ACMEChallenge string `json:"acmeChallenge"`
	// Step J.2 — active health check. Always present on a stored
	// route (storage.HealthCheck has no omitempty); when Enabled
	// is false the rest of the sub-fields carry zero values and
	// the generator omits the Caddy `health_checks` block.
	HealthCheck healthCheckResp `json:"healthCheck"`
	CreatedAt   string          `json:"createdAt"`
	UpdatedAt   string          `json:"updatedAt"`
}

// toResponse converts a storage.Route to its API wire form (RFC 3339 with
// millisecond precision, UTC).
func toResponse(r storage.Route) routeResponse {
	aliases := r.Aliases
	if aliases == nil {
		aliases = []string{} // S6: never emit `"aliases": null` on the wire.
	}
	// Step I.6 — normalize nil maps to empty so the wire JSON never
	// emits `null`. Frontend reads .length / Object.keys safely.
	reqHeaders := r.RequestHeaders
	if reqHeaders == nil {
		reqHeaders = map[string]string{}
	}
	respHeaders := r.ResponseHeaders
	if respHeaders == nil {
		respHeaders = map[string]string{}
	}
	// Step J.1 — surface the upstream pool 1:1 from storage.
	// storage.validate() guarantees at least one element, so the
	// returned slice is always non-empty for a stored route.
	upstreamsResp := make([]upstreamResp, len(r.Upstreams))
	for i, u := range r.Upstreams {
		upstreamsResp[i] = upstreamResp{URL: u.URL, Weight: u.Weight}
	}
	// Step J.4: surface the normalised ACMEChallenge — a stored row
	// with the zero value "" reads back as "http-01" so the
	// frontend renders a single consistent value (pre-J.4 rows
	// behave identically to a fresh post-J.4 default).
	acmeChallenge := r.ACMEChallenge
	if acmeChallenge == "" {
		acmeChallenge = storage.ACMEChallengeHTTP01
	}
	// Step K.1: surface the normalised AuthMode — a stored row
	// with the zero value "" (a row that somehow bypassed the
	// boot migration) reads back as "none" so the frontend
	// always renders a defined radio-group state.
	authMode := r.AuthMode
	if authMode == "" {
		authMode = storage.RouteAuthNone
	}
	return routeResponse{
		ID:              r.ID,
		Host:            r.Host,
		Upstreams:       upstreamsResp,
		LBPolicy:        r.LBPolicy,
		TLSEnabled:      r.TLSEnabled,
		RedirectToHTTPS: r.RedirectToHTTPS,
		Aliases:         aliases,
		AuthMode:        authMode,
		BasicAuth: basicAuthResp{
			Username:    r.BasicAuth.Username,
			PasswordSet: r.BasicAuth.PasswordHash != "",
		},
		ForwardAuth: forwardAuthResp{
			ProviderName: r.ForwardAuth.ProviderName,
		},
		RequestHeaders:  reqHeaders,
		ResponseHeaders: respHeaders,
		WAFMode:         r.WAFMode,
		ACMEChallenge:   acmeChallenge,
		HealthCheck: healthCheckResp{
			Enabled:      r.HealthCheck.Enabled,
			URI:          r.HealthCheck.URI,
			Method:       r.HealthCheck.Method,
			Interval:     r.HealthCheck.Interval,
			Timeout:      r.HealthCheck.Timeout,
			ExpectStatus: r.HealthCheck.ExpectStatus,
			ExpectBody:   r.HealthCheck.ExpectBody,
			Passes:       r.HealthCheck.Passes,
			Fails:        r.HealthCheck.Fails,
		},
		CreatedAt: r.CreatedAt.UTC().Format(timestampFormat),
		UpdatedAt: r.UpdatedAt.UTC().Format(timestampFormat),
	}
}
