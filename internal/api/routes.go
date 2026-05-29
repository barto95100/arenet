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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// NewRouter builds the chi router for the admin API. When dev is true a
// permissive CORS middleware is mounted for http://localhost:5173.
//
// Step D wires the IP extractor near the top (after Recoverer) so
// every downstream handler reads the resolved IP from context. The
// /api/v1/auth/* subtree is then rate-limited per-IP; business
// endpoints under /api/v1 stay unrated (authenticated callers are
// trusted per spec §5.2).
//
// Step E adds the optional ws handler: when non-nil, it is mounted
// at GET /api/v1/ws/topology inside the hard-auth subgroup
// (spec §5.1 + §7.1). Tests that do not exercise the topology
// endpoint pass nil — the route is then simply not registered.
func NewRouter(h *Handler, dev bool, ipExtractor *auth.IPExtractor, ws *WSTopologyHandler) chi.Router {
	if ipExtractor == nil {
		panic("api.NewRouter: ipExtractor is nil")
	}
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(slogLogger(h.logger))
	r.Use(chimw.Recoverer)
	if dev {
		r.Use(devCORS("http://localhost:5173"))
	}
	r.Use(auth.IPExtractMiddleware(ipExtractor))

	// /healthz: mounted at the root (NOT /api/v1/...) so the probe
	// path stays stable across API versions. No auth wrapper because
	// orchestrator probes carry no credentials. No audit either —
	// audit is per-handler in Arenet, not a middleware, so /healthz
	// is implicitly silent. Step H.3 — see internal/api/health.go
	// for full design rationale. The middleware stack above does
	// apply (chi enforces "all middlewares before any route"), so
	// probe hits land in the structured log; that is an acceptable
	// trade-off for the homelab single-instance deployment target.
	r.Get("/healthz", h.healthz)

	r.Route("/api/v1", func(r chi.Router) {
		// Auth subtree: rate-limited per IP (spec §5.2).
		r.Route("/auth", func(r chi.Router) {
			r.Use(h.rateLimiter.Middleware())

			// No-auth subgroup: /setup, /login + OIDC login flow
			// (the login IS the auth — these endpoints can't
			// require a session). Step K.2 §5.2.
			r.Post("/setup", h.setup)
			r.Get("/setup/status", h.setupStatus)
			r.Post("/login", h.login)
			r.Get("/oidc/login", h.oidcInitiateLogin)
			r.Get("/oidc/callback", h.oidcCallback)
			r.Get("/oidc/status", h.oidcStatus)

			// Soft-auth subgroup: /logout, /me, /unlock.
			r.Group(func(r chi.Router) {
				r.Use(auth.SoftAuthMiddleware(h.sessions, h.users, h.devMode))
				r.Post("/logout", h.logout)
				r.Get("/me", h.me)
				r.Post("/unlock", h.unlock)
			})

			// Hard-auth subgroup: /heartbeat, /sessions, DELETE /sessions/{id},
			// /me/password, /me/theme. All viewer-accessible (the user
			// rotates their OWN password / theme, not someone else's).
			r.Group(func(r chi.Router) {
				r.Use(auth.HardAuthMiddleware(h.sessions, h.users, h.devMode))
				r.Post("/heartbeat", h.heartbeat)
				r.Get("/sessions", h.listSessions)
				r.Delete("/sessions/{id}", h.deleteSession)
				r.Post("/me/password", h.changePassword)
				r.Post("/me/theme", h.updateTheme)
			})
		})

		// Business endpoints — hard-auth gated per spec §5.2.
		// Step K.2 §1.3 #12: viewer-accessible endpoints
		// (read-only on routes / audit / topology / metrics) sit
		// at this level. The admin-only sub-group below adds the
		// role gate for write endpoints + settings + admin users.
		r.Group(func(r chi.Router) {
			r.Use(auth.HardAuthMiddleware(h.sessions, h.users, h.devMode))
			r.Get("/routes", h.listRoutes)
			r.Get("/routes/{id}", h.getRoute)
			r.Get("/audit", h.listAudit)
			// Step L L.2 — per-route metrics history.
			// Read-only; viewer-accessible per AC #17. No
			// write surface (there is nothing to write —
			// metrics are produced by the in-process
			// aggregator, never accepted via the API).
			r.Get("/metrics/timeseries", h.metricsTimeseries)
			r.Get("/metrics/summary", h.metricsSummary)
			// Step M.2 — WAF event log. Read-only,
			// viewer-accessible per AC #12. Same auth shape
			// as /metrics; the data is event-shaped
			// (sparse per-block rows) rather than bucketed
			// timeseries, which is why it gets its own
			// endpoint despite living under the /security/
			// prefix (spec §1.3 D2 carve-out).
			r.Get("/security/events", h.securityEvents)
			// M.2 amendment #2 — per-(rule, category)
			// aggregate over the window. Used by the M.4
			// drill-down's per-rule table; replaces the
			// client-side group-by that silently truncated
			// to the most-recent 100 events on the 30d
			// window.
			r.Get("/security/events/by-rule", h.securityEventsByRule)
			// Step Q.2 — auth-failure timeline derived from
			// the audit log. Single audit-scan projected to
			// per-minute timeseries + recent feed (spec
			// §1.3 D4.B: single source of truth). Same
			// viewer-accessible gate as the other /security
			// endpoints.
			r.Get("/security/auth-failures", h.securityAuthFailures)
			// Step Q.3 — rate-limit (throttle) event log.
			// Pure event-shaped read of the throttle_event
			// table, mirror of /security/events. Optional
			// srcIp / tier filters. Same AC #14 contract.
			r.Get("/security/throttle-events", h.securityThrottleEvents)
			// Step Q.3 — attackers summary. Server-side
			// union over WAF + throttle + audit source-IP
			// sets (D6.A). One headline `uniqueIps` stat +
			// a per-source breakdown for the dashboard's
			// "by source" widget.
			r.Get("/security/attackers-summary", h.securityAttackersSummary)
			// Step N.3 — CrowdSec decision event log. Pure
			// event-shaped read of the decision_event table.
			// Optional scope / srcIp / scenario / onlyActive
			// filters. Same AC #15 contract.
			r.Get("/security/decisions", h.securityDecisions)
			// Step E: live-metrics WebSocket. HardAuthMiddleware
			// rejects the handshake (401 / 403) BEFORE the upgrade,
			// so an unauthorized peer never sees an open WS frame
			// — spec §5.1 + §7.1.
			if ws != nil {
				r.Get("/ws/topology", ws.ServeHTTP)
			}

			// Admin-only sub-group (Step K.2 §1.3 decision 12).
			// Viewer is rejected with 403 "admin role required".
			r.Group(func(r chi.Router) {
				r.Use(auth.RequireAdminMiddleware())
				r.Post("/routes", h.createRoute)
				r.Put("/routes/{id}", h.updateRoute)
				r.Delete("/routes/{id}", h.deleteRoute)
				// Step J.4 — DNS provider config.
				r.Get("/settings/dns-providers/ovh", h.getDNSProviderOVH)
				r.Put("/settings/dns-providers/ovh", h.putDNSProviderOVH)
				// Step K.1 — forward-auth provider CRUD.
				r.Get("/settings/forward-auth/providers", h.listForwardAuthProviders)
				r.Post("/settings/forward-auth/providers", h.createForwardAuthProvider)
				r.Get("/settings/forward-auth/providers/{name}", h.getForwardAuthProvider)
				r.Put("/settings/forward-auth/providers/{name}", h.updateForwardAuthProvider)
				r.Delete("/settings/forward-auth/providers/{name}", h.deleteForwardAuthProvider)
				// Step K.2 — OIDC settings + allowlist + admin
				// users management.
				r.Get("/settings/oidc", h.getOIDCConfig)
				r.Put("/settings/oidc", h.putOIDCConfig)
				r.Get("/settings/oidc/allowlist", h.listOIDCAllowlist)
				r.Post("/settings/oidc/allowlist", h.addOIDCAllowlist)
				r.Delete("/settings/oidc/allowlist/{email}", h.deleteOIDCAllowlist)
				r.Get("/admin/users", h.listAdminUsers)
				r.Post("/admin/users/{id}/role", h.updateUserRole)
				// Step K.3 — backup / restore.
				r.Get("/admin/backup", h.getBackup)
				r.Post("/admin/restore", h.postRestore)
			})
		})
	})
	return r
}

func (h *Handler) listRoutes(w http.ResponseWriter, r *http.Request) {
	routes, err := h.store.ListRoutes(r.Context())
	if err != nil {
		h.logger.Error("list routes", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list routes")
		return
	}
	out := make([]routeResponse, 0, len(routes))
	for _, rt := range routes {
		out = append(out, toResponse(rt))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) getRoute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rt, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("get route", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to get route")
		return
	}
	writeJSON(w, http.StatusOK, toResponse(rt))
}

// validateAliasesStructural runs the same hostname rule used for the
// primary Host (RFC 1035 grammar + length) on every alias supplied
// by the user. It also enforces the two intra-route invariants from
// Step I.3 S3: no alias may duplicate the primary host, and no
// alias may duplicate another alias in the same request.
//
// Returns the first failure with a user-facing message. The
// duplicate checks here mirror the storage-layer defense in
// storage.Route.validate; the API copy gives a friendlier message
// (with the offending alias quoted) before the storage layer would
// reject it anonymously.
func validateAliasesStructural(host string, aliases []string) error {
	seen := make(map[string]struct{}, len(aliases))
	for _, a := range aliases {
		if a == "" {
			return errors.New("alias must not be empty")
		}
		if err := validateHost(a); err != nil {
			return fmt.Errorf("alias %q: %s", a, err.Error())
		}
		if a == host {
			return fmt.Errorf("alias %q duplicates the primary host", a)
		}
		if _, dup := seen[a]; dup {
			return fmt.Errorf("alias %q duplicates within the same route", a)
		}
		seen[a] = struct{}{}
	}
	return nil
}

// collectAllHostsExcept walks existing routes and returns a map from
// hostname to owning route ID, including every primary Host AND every
// alias. The excludeID, when non-empty, skips the route currently
// being updated (so it doesn't collide with its own existing aliases).
// Used by createRoute and updateRoute to enforce cross-route uniqueness
// across the union of (Host, Aliases) per Step I.3 Q1.
func collectAllHostsExcept(routes []storage.Route, excludeID string) map[string]string {
	owners := make(map[string]string, len(routes))
	for _, rt := range routes {
		if rt.ID == excludeID {
			continue
		}
		for _, h := range rt.AllHosts() {
			owners[h] = rt.ID
		}
	}
	return owners
}

// hostnamesEqual reports whether two hostname slices contain the same
// hosts in the same order. Used by updateRoute to short-circuit the
// uniqueness check when nothing changed (avoids a needless ListRoutes
// + map build on every PUT that flips, say, only WAFEnabled).
func hostnamesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Step I.5 — Basic Auth helpers.

// basicAuthUsernameMaxLen caps the username at a reasonable length.
// 64 chars covers admin usernames + service accounts; longer values
// hint at confused inputs (e.g. an email or a token pasted into the
// wrong field).
const basicAuthUsernameMaxLen = 64

// basicAuthPasswordMaxBytes caps the plaintext password at 64 bytes.
// argon2id doesn't have bcrypt's 72-byte ceiling but a soft cap
// protects against DoS via very long passwords (each hash costs
// ~100 ms; a 1 MB password could lock a goroutine).
const basicAuthPasswordMaxBytes = 64

// validateBasicAuth enforces the per-route Basic Auth invariants
// (Step I.5 rules preserved through K.1 — the nested BasicAuth
// struct of K.1 carries the same Username / Password fields).
// Called ONLY when req.AuthMode == storage.RouteAuthBasic;
// callers MUST guard. existingHash carries the hash already
// stored for this route on PUT — empty on POST. When the user
// picks AuthMode "basic", they must supply a username AND either
// a fresh password (POST, or PUT to rotate) or rely on the
// existing hash (PUT, leaving the password field blank to keep it).
func validateBasicAuth(req routeRequest, existingHash string) error {
	if req.BasicAuth.Username == "" {
		return errors.New("basicAuth.username must not be empty when authMode is \"basic\"")
	}
	if len(req.BasicAuth.Username) > basicAuthUsernameMaxLen {
		return fmt.Errorf("basicAuth.username must not exceed %d characters", basicAuthUsernameMaxLen)
	}
	// RFC 7617: ':' is the Basic Auth separator inside the
	// "user:password" payload — embedding it in the username would
	// break the protocol. Reject early with a clear message.
	if strings.ContainsRune(req.BasicAuth.Username, ':') {
		return errors.New("basicAuth.username must not contain ':' (Basic Auth separator)")
	}
	for _, r := range req.BasicAuth.Username {
		// Reject control / whitespace characters: they make log
		// injection trivial and rarely belong in an admin username.
		if r < 0x21 || r == 0x7F {
			return errors.New("basicAuth.username must not contain whitespace or control characters")
		}
	}
	if req.BasicAuth.Password == "" && existingHash == "" {
		return errors.New("basicAuth.password required when enabling basic auth on a route without an existing password")
	}
	if len(req.BasicAuth.Password) > basicAuthPasswordMaxBytes {
		return fmt.Errorf("basicAuth.password must not exceed %d bytes", basicAuthPasswordMaxBytes)
	}
	return nil
}

// routeForAudit returns a copy of r with the per-route Basic
// Auth password hash blanked. Audit events are persisted under
// the assumption that they hold NO secrets (D3 / spec §1.6 #3);
// the argon2id PHC of a route's Basic Auth must never reach the
// audit bucket. Apply to every storage.Route passed into
// appendAudit's AfterJSON / BeforeJSON since Step I.5 — refactored
// in K.1 to read through the nested BasicAuth struct.
func routeForAudit(r storage.Route) storage.Route {
	r.BasicAuth.PasswordHash = ""
	return r
}

// Step I.6 — Custom request/response headers.

const (
	headerNameMaxLen  = 128
	headerValueMaxLen = 1024
)

// headerNameTokenRE matches an RFC 7230 token: ALPHA / DIGIT plus
// the punctuation set explicitly listed in the grammar. No space,
// no ':', no control character — those are filtered by the regex
// itself (negative match) and made explicit by validateHeaderName's
// error message.
var headerNameTokenRE = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+\-.^_` + "`" + `|~]+$`)

// reservedHeaderNames lists HTTP header names the user MUST NOT
// override per Step I.6 Q3 / spec §1.6 #2: hop-by-hop fields (RFC
// 7230 §6.1) plus Host and the framing-critical Content-Length /
// Content-Encoding which Caddy's reverse_proxy manages on the
// operator's behalf. Comparison is case-insensitive (HTTP header
// names are case-insensitive); the lookup uses strings.ToLower(name).
var reservedHeaderNames = map[string]struct{}{
	"host":              {},
	"connection":        {},
	"keep-alive":        {},
	"transfer-encoding": {},
	"te":                {},
	"trailer":           {},
	"upgrade":           {},
	"content-length":    {},
	"content-encoding":  {},
}

// validateHeaderName enforces the RFC 7230 token grammar + the
// reserved blacklist + the length cap. Empty name is rejected with
// a separate message (the caller usually catches it earlier when
// building the map, but defense in depth).
func validateHeaderName(name string) error {
	if name == "" {
		return errors.New("header name must not be empty")
	}
	if len(name) > headerNameMaxLen {
		return fmt.Errorf("header name %q exceeds %d characters", name, headerNameMaxLen)
	}
	if !headerNameTokenRE.MatchString(name) {
		return fmt.Errorf("header name %q is not a valid HTTP token (RFC 7230)", name)
	}
	if _, reserved := reservedHeaderNames[strings.ToLower(name)]; reserved {
		return fmt.Errorf("header name %q is reserved (managed by Caddy or required for framing)", name)
	}
	return nil
}

// validateHeaderValue catches HTTP header injection (CR / LF inside
// the value would break the wire framing — see spec §1.6 #2 and
// I.6 audit finding F1) plus NUL and other ASCII control characters
// except HTAB. Visible-ASCII + SP + HTAB are the RFC 7230 field-
// value VCHAR / WSP set. Empty values are ALLOWED (Step I.6
// Ajustement 2: some upstreams check header presence, not value).
func validateHeaderValue(name, value string) error {
	if len(value) > headerValueMaxLen {
		return fmt.Errorf("header %q value exceeds %d characters", name, headerValueMaxLen)
	}
	for i, r := range value {
		if r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7F {
			return fmt.Errorf("header %q value contains a control character at offset %d (CR/LF/NUL are forbidden)", name, i)
		}
	}
	return nil
}

// Step I.4 — WAF mode validation.

// WAFMode allowed values. Empty string is NOT in this set: empty is a
// per-handler signal ("default to detect on POST" / "preserve on
// PUT") that callers handle before invoking validateWAFMode.
var wafModeValues = map[string]struct{}{
	"off":    {},
	"detect": {},
	"block":  {},
}

// validateWAFMode rejects any value not in the enum {off, detect, block}.
// The empty string is treated as INVALID at this layer; createRoute and
// updateRoute apply the "default to detect" / "preserve previous"
// semantics BEFORE calling this, so by the time validateWAFMode runs the
// caller has either supplied a value or wants it rejected.
func validateWAFMode(mode string) error {
	if _, ok := wafModeValues[mode]; !ok {
		return fmt.Errorf("wafMode %q is invalid (must be one of: off, detect, block)", mode)
	}
	return nil
}

// validateHeaders walks a request- or response-header map and runs
// validateHeaderName + validateHeaderValue on every entry. The
// direction argument ("request" / "response") is interpolated into
// error messages so the user knows which section to fix. Returns
// the first failure (fail-fast — typing helps when iterating in
// the form).
//
// Note (Step I.6 Ajustement 1): no intra-request duplicate check.
// JSON object key duplicates are last-wins per Go's json.Decode;
// the frontend repeater prevents this in the normal flow but a
// hand-crafted curl could trigger silent merge. Documented in the
// I.6 commit message; Step J may add an ordered-decoder-based
// duplicate check if user feedback warrants it.
func validateHeaders(headers map[string]string, direction string) error {
	for name, value := range headers {
		if err := validateHeaderName(name); err != nil {
			return fmt.Errorf("%s %s", direction, err.Error())
		}
		if err := validateHeaderValue(name, value); err != nil {
			return fmt.Errorf("%s %s", direction, err.Error())
		}
	}
	return nil
}

func (h *Handler) createRoute(w http.ResponseWriter, r *http.Request) {
	var req routeRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := validateHost(req.Host); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Step J.1: materialise the per-Upstream default Weight=1 BEFORE
	// pool validation. The storage validate() rule weight >= 1 (the
	// last line of defence) would otherwise reject any pool element
	// the caller submitted without a weight. §1.3 decision 1: weight
	// defaults to 1 and is only consulted by weighted_round_robin.
	for i := range req.Upstreams {
		if req.Upstreams[i].Weight == 0 {
			req.Upstreams[i].Weight = 1
		}
	}
	if err := validateUpstreamPool(req.Upstreams); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Step J.1: materialise the default LBPolicy on POST. Empty means
	// "give me the default round_robin" (§5.1). updateRoute uses a
	// different rule (preserve previous), hence the per-handler
	// normalisation here.
	if req.LBPolicy == "" {
		req.LBPolicy = storage.LBPolicyRoundRobin
	}
	if err := validateLBPolicy(req.LBPolicy); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := validateAliasesStructural(req.Host, req.Aliases); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Step K.1: AuthMode default + validation. Empty on POST is
	// normalised to "none" (no per-route auth — the most permissive
	// default, operator opts in to basic / forward_auth explicitly).
	if req.AuthMode == "" {
		req.AuthMode = storage.RouteAuthNone
	}
	if err := validateAuthMode(req.AuthMode); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Step K.1: per-mode validation + cross-field mutual-exclusion
	// check (§1.3 decision 2). The wire shape allows the operator
	// to populate BasicAuth + ForwardAuth simultaneously by hand-
	// crafted JSON — we reject that even if the AuthMode picks
	// just one of the two, so direct API clients can't smuggle a
	// confused row past the radio-group UI.
	if err := validateAuthFieldsMutex(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.AuthMode == storage.RouteAuthBasic {
		if err := validateBasicAuth(req, ""); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.AuthMode == storage.RouteAuthForwardAuth {
		if err := h.validateForwardAuthProvider(r.Context(), req.ForwardAuth.ProviderName); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := validateHeaders(req.RequestHeaders, "request"); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateHeaders(req.ResponseHeaders, "response"); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Step I.4: WAF mode default — POST with empty wafMode means
	// "give me the safe-shadow default" (spec L6). updateRoute
	// applies a different rule (preserve previous), hence the
	// per-handler normalization rather than a centralized one.
	if req.WAFMode == "" {
		req.WAFMode = "detect"
	}
	if err := validateWAFMode(req.WAFMode); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Step J.4: ACMEChallenge default + validation. Empty string is
	// normalised to "http-01" (the default and the pre-J.4
	// behaviour). validateACMEChallenge then enforces the enum +
	// the "wildcard ⇒ dns-01" cross-rule. The dns-01-requires-a-
	// configured-provider rule needs the store and lives below.
	if req.ACMEChallenge == "" {
		req.ACMEChallenge = storage.ACMEChallengeHTTP01
	}
	if err := validateACMEChallenge(req.ACMEChallenge, req.Host, req.Aliases); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ACMEChallenge == storage.ACMEChallengeDNS01 {
		cfg, err := h.store.GetDNSProviderOVH(r.Context())
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			h.logger.Error("read dns provider", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to verify dns provider")
			return
		}
		if errors.Is(err, storage.ErrNotFound) || !dnsProviderComplete(cfg) {
			writeError(w, http.StatusBadRequest,
				"acmeChallenge \"dns-01\" requires a configured DNS provider — see Settings")
			return
		}
	}

	// Step J.2: materialise health-check defaults + uppercase
	// Method, then validate (gated on Enabled). The "block absent
	// vs present" distinction (the *healthCheckReq pointer) is the
	// load-bearing detail of the J.2 wire: nil = no HC block on
	// the request = no probe runs (createRoute treats as
	// zero-value disabled). When non-nil with Enabled=true, the
	// caller meant a real probe — materialise the five defaults
	// (uri is not defaultable) and validate.
	if req.HealthCheck != nil && req.HealthCheck.Enabled {
		hc := materialiseHealthCheck(*req.HealthCheck)
		if err := validateHealthCheck(hc); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.HealthCheck = &hc
	}

	// Step I.7 hotfix (Finding #5): RedirectToHTTPS is meaningless
	// without TLS. Normalize to false when TLS is off so the stored
	// row never carries a latent redirect that would silently
	// activate if the admin later flips TLS on. Backend is the
	// source of truth — this also covers direct API clients that
	// bypass the frontend, and naturally heals legacy routes the
	// next time they are updated (no separate migration needed).
	if !req.TLSEnabled {
		req.RedirectToHTTPS = false
	}

	// Step K.1 (was Step I.5): hash the plaintext password BEFORE
	// the uniqueness check + the storage write. Done outside the
	// bbolt transaction so the ~100 ms argon2id cost doesn't hold
	// the single-writer lock. Only computed when AuthMode is
	// "basic"; "none" and "forward_auth" do not carry a password.
	var basicAuthHash string
	if req.AuthMode == storage.RouteAuthBasic {
		hash, hashErr := auth.HashRoutePassword(req.BasicAuth.Password)
		if hashErr != nil {
			h.logger.Error("hash basic auth password", "err", hashErr)
			writeError(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		basicAuthHash = hash
	}

	// Uniqueness check across the union of (Host ∪ Aliases) per
	// Step I.3 Q1. Caddy dispatches by host match, so any duplicate
	// hostname across two routes would yield non-deterministic
	// routing — reject at the API layer.
	//
	// NOTE: this is not atomic with the subsequent CreateRoute call —
	// two concurrent POSTs with the same host could both pass this
	// loop. Safe under the homelab single-writer assumption codified
	// in spec §3 Q3; revisit when real concurrency is introduced.
	existing, err := h.store.ListRoutes(r.Context())
	if err != nil {
		h.logger.Error("uniqueness list", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to verify uniqueness")
		return
	}
	owners := collectAllHostsExcept(existing, "")
	// Step J.1: map the wire pool to storage.Upstream verbatim.
	// Defaults (Weight=1, LBPolicy=round_robin) have already been
	// materialised above so the storage row carries explicit values.
	storeUpstreams := make([]storage.Upstream, len(req.Upstreams))
	for i, u := range req.Upstreams {
		storeUpstreams[i] = storage.Upstream{URL: u.URL, Weight: u.Weight}
	}
	// Step J.2: map the optional wire HealthCheck to storage. nil
	// pointer or Enabled=false both produce a zero-value
	// storage.HealthCheck (no probe runs).
	var storeHC storage.HealthCheck
	if req.HealthCheck != nil {
		storeHC = storage.HealthCheck{
			Enabled:      req.HealthCheck.Enabled,
			URI:          req.HealthCheck.URI,
			Method:       req.HealthCheck.Method,
			Interval:     req.HealthCheck.Interval,
			Timeout:      req.HealthCheck.Timeout,
			ExpectStatus: req.HealthCheck.ExpectStatus,
			ExpectBody:   req.HealthCheck.ExpectBody,
			Passes:       req.HealthCheck.Passes,
			Fails:        req.HealthCheck.Fails,
		}
	}
	newRoute := storage.Route{
		Host:            req.Host,
		Upstreams:       storeUpstreams,
		LBPolicy:        req.LBPolicy,
		TLSEnabled:      req.TLSEnabled,
		RedirectToHTTPS: req.RedirectToHTTPS,
		Aliases:         req.Aliases,
		AuthMode:        req.AuthMode,
		BasicAuth: storage.BasicAuthRouteConfig{
			Username:     req.BasicAuth.Username,
			PasswordHash: basicAuthHash,
		},
		ForwardAuth: storage.ForwardAuthRouteConfig{
			ProviderName: req.ForwardAuth.ProviderName,
		},
		RequestHeaders:  req.RequestHeaders,
		ResponseHeaders: req.ResponseHeaders,
		WAFMode:         req.WAFMode,
		ACMEChallenge:   req.ACMEChallenge,
		HealthCheck:     storeHC,
	}
	// Step K.1: when AuthMode != "basic" / "forward_auth", clear
	// the corresponding sub-struct (storage trusts the API to
	// not persist orphan credentials).
	if newRoute.AuthMode != storage.RouteAuthBasic {
		newRoute.BasicAuth = storage.BasicAuthRouteConfig{}
	}
	if newRoute.AuthMode != storage.RouteAuthForwardAuth {
		newRoute.ForwardAuth = storage.ForwardAuthRouteConfig{}
	}
	for _, h := range newRoute.AllHosts() {
		if ownerID, taken := owners[h]; taken {
			writeError(w, http.StatusConflict, fmt.Sprintf("hostname %q already configured on route %s", h, ownerID))
			return
		}
	}

	created, err := h.store.CreateRoute(r.Context(), newRoute)
	if err != nil {
		h.logger.Error("create route", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create route")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after create — rolling back", "err", err, "id", created.ID)
		if delErr := h.store.DeleteRoute(r.Context(), created.ID); delErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", delErr, "id", created.ID)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	// Emit route_created audit event AFTER the Caddy reload succeeds
	// (Plan §4.4 / D2). On reload failure the early return above skips
	// this emission.
	//
	// Step I.5 / F1: the storage.Route now carries
	// BasicAuthPasswordHash, an argon2id PHC string that must NEVER
	// reach the audit log (D3 / spec §1.6 #3). routeForAudit clones
	// the route with that field blanked before mustMarshalForAudit
	// serializes it.
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionRouteCreated,
		TargetType: "route",
		TargetID:   created.ID,
		AfterJSON:  mustMarshalForAudit(routeForAudit(created)),
	})

	writeJSON(w, http.StatusCreated, toResponse(created))
}

func (h *Handler) updateRoute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req routeRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := validateHost(req.Host); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Step J.1: materialise the per-Upstream default Weight=1 before
	// pool validation. Same rule as createRoute (storage validate()
	// rejects weight < 1).
	for i := range req.Upstreams {
		if req.Upstreams[i].Weight == 0 {
			req.Upstreams[i].Weight = 1
		}
	}
	if err := validateUpstreamPool(req.Upstreams); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateAliasesStructural(req.Host, req.Aliases); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	previous, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("get route for update", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load route")
		return
	}

	// Step K.1: AuthMode resolution on PUT — same preserve-
	// previous semantics as WAFMode below. Empty means "keep the
	// stored value", explicit value goes through validateAuthMode.
	// A row persisted without AuthMode (a row a code path bypassed
	// the migration on, e.g. test seeds calling storage.CreateRoute
	// directly) reads back as previous.AuthMode == "" — treat as
	// "none" so the preserve path yields a valid state.
	if req.AuthMode == "" {
		req.AuthMode = previous.AuthMode
		if req.AuthMode == "" {
			req.AuthMode = storage.RouteAuthNone
		}
	}
	if err := validateAuthMode(req.AuthMode); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateAuthFieldsMutex(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Step K.1: per-mode validation. For "basic", validateBasicAuth
	// takes the previous hash into account so toggling-on a route
	// that already has a hash works without re-typing the password
	// (Step I.5 preserve UX preserved through K.1).
	if req.AuthMode == storage.RouteAuthBasic {
		if err := validateBasicAuth(req, previous.BasicAuth.PasswordHash); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.AuthMode == storage.RouteAuthForwardAuth {
		if err := h.validateForwardAuthProvider(r.Context(), req.ForwardAuth.ProviderName); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := validateHeaders(req.RequestHeaders, "request"); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateHeaders(req.ResponseHeaders, "response"); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Step J.1: LBPolicy resolution on PUT — same preserve-previous
	// semantics as WAFMode below. Empty means "keep the stored
	// value", explicit value goes through validateLBPolicy. A row
	// persisted without LBPolicy is a programming-error case (pool
	// migration guarantees it) but we recover to "round_robin" to
	// avoid a 500 if it ever happens.
	if req.LBPolicy == "" {
		req.LBPolicy = previous.LBPolicy
		if req.LBPolicy == "" {
			req.LBPolicy = storage.LBPolicyRoundRobin
		}
	}
	if err := validateLBPolicy(req.LBPolicy); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Step I.4: WAF mode resolution on PUT (Q6 override). Empty
	// wafMode means "preserve the previously stored value", mirroring
	// the I.5 password preserve UX — admins can flip unrelated
	// fields without re-stating the WAF mode. Explicit value still
	// goes through validateWAFMode to catch typos.
	//
	// Edge case: a route that was persisted without WAFMode (a row
	// that should have been touched by the boot migration but was
	// created by a code path that bypassed it — typically test seed
	// fixtures using storage.CreateRoute directly) reads back as
	// previous.WAFMode == "". Treat that as "off" so the preserve
	// path produces a valid state, equivalent to the L7 mapping
	// (WAFEnabled=false → off).
	if req.WAFMode == "" {
		req.WAFMode = previous.WAFMode
		if req.WAFMode == "" {
			req.WAFMode = "off"
		}
	}
	if err := validateWAFMode(req.WAFMode); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Step J.4: ACMEChallenge — same default + validation as on
	// POST. The field carries no secret and the per-route ACME
	// choice is naturally specified on every edit, so we don't use
	// the wafMode-style preserve-previous-on-empty rule; an empty
	// value on PUT means "default", and a pre-J.4 stored row
	// (zero value "") also reads back through toResponse as
	// "http-01" so the frontend submits an explicit value on every
	// round-trip.
	if req.ACMEChallenge == "" {
		req.ACMEChallenge = storage.ACMEChallengeHTTP01
	}
	if err := validateACMEChallenge(req.ACMEChallenge, req.Host, req.Aliases); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ACMEChallenge == storage.ACMEChallengeDNS01 {
		cfg, err := h.store.GetDNSProviderOVH(r.Context())
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			h.logger.Error("read dns provider (update)", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to verify dns provider")
			return
		}
		if errors.Is(err, storage.ErrNotFound) || !dnsProviderComplete(cfg) {
			writeError(w, http.StatusBadRequest,
				"acmeChallenge \"dns-01\" requires a configured DNS provider — see Settings")
			return
		}
	}

	// Step J.2: HealthCheck resolution on PUT — preserve-or-replace,
	// driven by the wire's nil-vs-present distinction (see
	// healthCheckReq doc-comment on routeRequest).
	//
	//   - req.HealthCheck == nil (block absent from PUT) → preserve
	//     the previously stored HealthCheck verbatim. Matches the
	//     Step I.5 BasicAuth password-blank-preserves-hash pattern
	//     and the Step I.4 WAFMode empty-preserves-mode pattern.
	//     The previous HealthCheck is already validated (storage
	//     accepted it at the original write); no need to
	//     re-materialise or re-validate. Copied straight into
	//     storeHC below at the assembly site.
	//
	//   - req.HealthCheck != nil (block present, any value) → full
	//     replacement (decision #4). When Enabled is true,
	//     materialise the five defaults + uppercase Method then
	//     validate; the stored row carries the explicit values.
	//     When Enabled is false the rest of the block is inert and
	//     the storage row carries a zero HealthCheck (disabled).
	//
	// J.3 form must ship one or the other — never a partial block.
	// See docs/backlog-step-j.md "J.3 frontend — health-check is
	// preserve-or-replace, never partial".
	if req.HealthCheck != nil && req.HealthCheck.Enabled {
		hc := materialiseHealthCheck(*req.HealthCheck)
		if err := validateHealthCheck(hc); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.HealthCheck = &hc
	}

	// Step I.7 hotfix (Finding #5): RedirectToHTTPS is meaningless
	// without TLS — normalize on PUT too so a route losing its TLS
	// also loses its redirect. Also self-heals legacy rows that
	// were persisted with redirect=true + tls=false before the fix
	// landed (no separate migration needed: any update to such a
	// row clears the latent flag).
	if !req.TLSEnabled {
		req.RedirectToHTTPS = false
	}

	// Step K.1 password resolution (refactor of the Step I.5 Q5
	// rule under the new AuthMode enum):
	//   - AuthMode != "basic"            → no hash stored, fields cleared.
	//   - new password supplied          → re-hash, replacing whatever
	//                                      was there before (rotation).
	//   - empty password on PUT (basic)  → keep the existing hash. The
	//                                      "edit anything else without
	//                                      re-typing the secret" path.
	var basicAuthHash string
	switch {
	case req.AuthMode != storage.RouteAuthBasic:
		basicAuthHash = ""
	case req.BasicAuth.Password != "":
		hash, hashErr := auth.HashRoutePassword(req.BasicAuth.Password)
		if hashErr != nil {
			h.logger.Error("hash basic auth password (update)", "err", hashErr)
			writeError(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		basicAuthHash = hash
	default:
		basicAuthHash = previous.BasicAuth.PasswordHash
	}

	// Uniqueness check across (Host ∪ Aliases) when ANY hostname has
	// changed since the stored copy (Step I.3 Q1). The pre-Step-I.3
	// optimization that compared only Host is no longer sufficient —
	// adding a new alias must still trigger the cross-route check.
	// Step J.1: map the wire pool to storage.Upstream verbatim, same
	// as createRoute.
	storeUpstreams := make([]storage.Upstream, len(req.Upstreams))
	for i, u := range req.Upstreams {
		storeUpstreams[i] = storage.Upstream{URL: u.URL, Weight: u.Weight}
	}
	// Step J.2: map the HealthCheck to storage.
	//   - req.HealthCheck == nil  → preserve previous verbatim
	//     (no re-materialise, no re-validate; previous is already
	//     valid by construction).
	//   - req.HealthCheck != nil  → full replacement, mapped from
	//     the materialised+validated value built above.
	var storeHC storage.HealthCheck
	if req.HealthCheck == nil {
		storeHC = previous.HealthCheck
	} else {
		storeHC = storage.HealthCheck{
			Enabled:      req.HealthCheck.Enabled,
			URI:          req.HealthCheck.URI,
			Method:       req.HealthCheck.Method,
			Interval:     req.HealthCheck.Interval,
			Timeout:      req.HealthCheck.Timeout,
			ExpectStatus: req.HealthCheck.ExpectStatus,
			ExpectBody:   req.HealthCheck.ExpectBody,
			Passes:       req.HealthCheck.Passes,
			Fails:        req.HealthCheck.Fails,
		}
	}
	newRoute := storage.Route{
		ID:              id,
		Host:            req.Host,
		Upstreams:       storeUpstreams,
		LBPolicy:        req.LBPolicy,
		TLSEnabled:      req.TLSEnabled,
		RedirectToHTTPS: req.RedirectToHTTPS,
		Aliases:         req.Aliases,
		AuthMode:        req.AuthMode,
		BasicAuth: storage.BasicAuthRouteConfig{
			Username:     req.BasicAuth.Username,
			PasswordHash: basicAuthHash,
		},
		ForwardAuth: storage.ForwardAuthRouteConfig{
			ProviderName: req.ForwardAuth.ProviderName,
		},
		RequestHeaders:  req.RequestHeaders,
		ResponseHeaders: req.ResponseHeaders,
		WAFMode:         req.WAFMode,
		ACMEChallenge:   req.ACMEChallenge,
		HealthCheck:     storeHC,
	}
	if newRoute.AuthMode != storage.RouteAuthBasic {
		newRoute.BasicAuth = storage.BasicAuthRouteConfig{}
	}
	if newRoute.AuthMode != storage.RouteAuthForwardAuth {
		newRoute.ForwardAuth = storage.ForwardAuthRouteConfig{}
	}
	if !hostnamesEqual(newRoute.AllHosts(), previous.AllHosts()) {
		existing, err := h.store.ListRoutes(r.Context())
		if err != nil {
			h.logger.Error("uniqueness list (update)", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to verify uniqueness")
			return
		}
		owners := collectAllHostsExcept(existing, id)
		for _, h := range newRoute.AllHosts() {
			if ownerID, taken := owners[h]; taken {
				writeError(w, http.StatusConflict, fmt.Sprintf("hostname %q already configured on route %s", h, ownerID))
				return
			}
		}
	}

	updated, err := h.store.UpdateRoute(r.Context(), newRoute)
	if err != nil {
		h.logger.Error("update route", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to update route")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after update — rolling back", "err", err, "id", id)
		// UpdateRoute is used here (not RestoreRoute) per spec §9: RestoreRoute
		// is reserved for DELETE rollback. Side-effect: UpdatedAt reflects the
		// rollback time, not previous.UpdatedAt. Acceptable under single-writer.
		if _, rbErr := h.store.UpdateRoute(r.Context(), previous); rbErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", rbErr, "id", id)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	// Emit route_updated audit event AFTER the Caddy reload succeeds
	// (Plan §4.4 / D2). Step I.5 / F1: strip BasicAuthPasswordHash
	// from both Before and After via routeForAudit — the argon2id PHC
	// is a secret that must never reach the audit log (D3).
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionRouteUpdated,
		TargetType: "route",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(routeForAudit(previous)),
		AfterJSON:  mustMarshalForAudit(routeForAudit(updated)),
	})

	writeJSON(w, http.StatusOK, toResponse(updated))
}

func (h *Handler) deleteRoute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	previous, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("get route for delete", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load route")
		return
	}

	if err := h.store.DeleteRoute(r.Context(), id); err != nil {
		h.logger.Error("delete route", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to delete route")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after delete — rolling back", "err", err, "id", id)
		if rbErr := h.store.RestoreRoute(r.Context(), previous); rbErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", rbErr, "id", id)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	// Emit route_deleted audit event AFTER the Caddy reload succeeds
	// (Plan §4.4 / D2). BeforeJSON captures the deleted route's last
	// state; AfterJSON is intentionally nil. Step I.5 / F1: strip
	// BasicAuthPasswordHash via routeForAudit so the deletion record
	// never holds the secret.
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionRouteDeleted,
		TargetType: "route",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(routeForAudit(previous)),
	})

	w.WriteHeader(http.StatusNoContent)
}
