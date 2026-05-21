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

// Package caddymgr embeds Caddy v2 as a library and translates Arenet's
// stored routes into Caddy JSON configuration applied via caddy.Load.
package caddymgr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"

	// Side-effect import: registers every standard Caddy module
	// (reverse_proxy, host matcher, internal TLS issuer, ...).
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// Side-effect import: registers the arenet_routemetrics module so
	// the JSON config produced by buildConfigJSON (referencing it as
	// a handler) is accepted by caddy.Load. Step E spec §3.
	"github.com/barto95100/arenet/internal/metrics"

	"github.com/barto95100/arenet/internal/storage"
)

// Listen addresses by mode (Step I.1).
//
// Dev keeps the high ports so a non-root developer can bind without
// CAP_NET_BIND_SERVICE. Prod uses the standard reverse-proxy ports —
// ACME HTTP-01 challenges arrive on :80 and Let's Encrypt-issued
// certs serve on :443. Operators that cannot bind :80 / :443 must
// either run the binary as root or `setcap cap_net_bind_service+ep`
// on it; documented in the Step I.1 commit message.
const (
	httpListenDev   = ":8080"
	httpsListenDev  = ":8443"
	httpListenProd  = ":80"
	httpsListenProd = ":443"
)

// ACME directory URLs (Step I.1).
//
// `--dev` mode targets Let's Encrypt **staging** so iteration on the
// reverse-proxy config doesn't burn the production rate limit
// (50 certs / week / domain). Prod mode targets the real directory.
const (
	acmeProdURL    = "https://acme-v02.api.letsencrypt.org/directory"
	acmeStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// CaddyManager owns the lifecycle of the embedded Caddy instance and
// reloads it from the persisted routes.
//
// The optional registry, when non-nil, is reconciled with the canonical
// route IDs after each successful caddy.Load (spec §11.5 + §4.1). When
// nil (typical for unit tests that only exercise buildConfigJSON or
// catch-all behavior), the metrics layer is fully bypassed.
//
// devMode (Step I.1) selects the listen ports (:8080/:8443 vs :80/:443)
// and the ACME directory (staging vs production). acmeEmail is the
// contact email passed to the ACME issuer; empty is accepted by
// Let's Encrypt but discouraged (no expiry reminders).
type CaddyManager struct {
	store     *storage.Store
	logger    *slog.Logger
	registry  *metrics.Registry
	devMode   bool
	acmeEmail string

	mu      sync.Mutex
	started bool
}

// New constructs a CaddyManager. The store and logger must be non-nil.
// The registry may be nil; passing a non-nil registry enables the
// per-reload Sync call that keeps the metrics counter map in step
// with the current set of routes.
//
// devMode and acmeEmail were added in Step I.1:
//   - devMode=true selects high listen ports (:8080/:8443) and the
//     Let's Encrypt staging directory; devMode=false picks :80/:443
//     and the production directory.
//   - acmeEmail is the contact passed to the ACME issuer when a route
//     has TLSEnabled=true. Empty is accepted but Let's Encrypt won't
//     send expiry reminders; caller is responsible for logging a
//     WARN at boot if appropriate.
func New(store *storage.Store, logger *slog.Logger, registry *metrics.Registry, devMode bool, acmeEmail string) (*CaddyManager, error) {
	if store == nil {
		return nil, errors.New("caddymgr: store must not be nil")
	}
	if logger == nil {
		return nil, errors.New("caddymgr: logger must not be nil")
	}
	return &CaddyManager{
		store:     store,
		logger:    logger,
		registry:  registry,
		devMode:   devMode,
		acmeEmail: acmeEmail,
	}, nil
}

// Start launches the embedded Caddy with the config derived from the store.
// It is safe to call Start exactly once per CaddyManager instance.
func (m *CaddyManager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.started {
		return errors.New("caddymgr: already started")
	}

	if err := m.applyLocked(ctx); err != nil {
		return fmt.Errorf("initial caddy load: %w", err)
	}
	m.started = true
	m.logger.Info("Caddy started", "http", m.httpListen(), "https", m.httpsListen(), "dev", m.devMode)
	return nil
}

// httpListen returns the HTTP listen address based on devMode.
// Step I.1: dev picks :8080, prod picks :80 (for ACME HTTP-01 +
// the I.2 redirect).
func (m *CaddyManager) httpListen() string {
	if m.devMode {
		return httpListenDev
	}
	return httpListenProd
}

// httpsListen returns the HTTPS listen address based on devMode.
func (m *CaddyManager) httpsListen() string {
	if m.devMode {
		return httpsListenDev
	}
	return httpsListenProd
}

// Stop halts the embedded Caddy. Safe to call when Start was never invoked.
func (m *CaddyManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.started {
		return nil
	}
	m.started = false
	if err := caddy.Stop(); err != nil {
		return fmt.Errorf("caddy stop: %w", err)
	}
	m.logger.Info("Caddy stopped")
	return nil
}

// ReloadFromStore rebuilds the Caddy config from the persisted routes and
// hot-reloads the running server.
func (m *CaddyManager) ReloadFromStore(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyLocked(ctx)
}

// applyLocked must be called with m.mu held. It reads routes from the store,
// renders the Caddy JSON config and applies it.
//
// After a successful caddy.Load, syncs the metrics registry (if any)
// with the canonical route IDs so the per-route counters are aligned
// with the live config (spec §11.5). The Sync happens AFTER the
// reload succeeds — same pattern as audit emission for /routes
// mutations (Step D Bug 1 / D2): on reload failure the storage is
// rolled back by the caller (handlers in internal/api/routes.go),
// so the registry already reflects the pre-attempt state, and we
// must not re-sync against a state that was rejected.
func (m *CaddyManager) applyLocked(ctx context.Context) error {
	routes, err := m.store.ListRoutes(ctx)
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}

	cfgJSON, err := buildConfigJSON(routes, buildOpts{
		DevMode:   m.devMode,
		ACMEEmail: m.acmeEmail,
	})
	if err != nil {
		return fmt.Errorf("build config: %w", err)
	}

	m.logger.Debug("applying caddy config", "routes", len(routes), "bytes", len(cfgJSON))
	if err := caddy.Load(cfgJSON, true); err != nil {
		return fmt.Errorf("caddy.Load: %w", err)
	}

	// Reload succeeded — sync the metrics registry with the live
	// route IDs. Nil registry (typical for unit tests) skips the
	// sync. Extracted into syncRegistry so the no-Caddy unit test
	// (TestApplyLocked_SyncCalledAfterSuccess) can exercise the
	// Sync path directly without spinning up an embedded Caddy.
	m.syncRegistry(routes)
	return nil
}

// syncRegistry reconciles the metrics registry's cells with the
// canonical route IDs. No-op when m.registry is nil. Pulled out of
// applyLocked so tests can exercise it without going through
// caddy.Load.
func (m *CaddyManager) syncRegistry(routes []storage.Route) {
	if m.registry == nil {
		return
	}
	ids := make([]string, len(routes))
	for i, r := range routes {
		ids[i] = r.ID
	}
	m.registry.Sync(ids)
}

// caddyConfig models the subset of Caddy JSON we need.
type caddyConfig struct {
	Admin *adminConfig   `json:"admin,omitempty"`
	Apps  appsConfig     `json:"apps"`
	Logs  *loggingConfig `json:"logging,omitempty"`
}

type adminConfig struct {
	Disabled bool `json:"disabled"`
}

type loggingConfig struct {
	// Empty for now — keep room for explicit log routing in a later step.
}

type appsConfig struct {
	HTTP httpApp `json:"http"`
}

type httpApp struct {
	Servers map[string]httpServer `json:"servers"`
}

type httpServer struct {
	Listen          []string              `json:"listen"`
	Routes          []httpRoute           `json:"routes,omitempty"`
	AutomaticHTTPS  *automaticHTTPSConfig `json:"automatic_https,omitempty"`
	TLSConnPolicies []tlsConnectionPolicy `json:"tls_connection_policies,omitempty"`
}

type automaticHTTPSConfig struct {
	Disable             bool `json:"disable"`
	DisableRedirects    bool `json:"disable_redirects,omitempty"`
	DisableCertificates bool `json:"disable_certificates,omitempty"`
	SkipCerts           bool `json:"skip,omitempty"`
}

type tlsConnectionPolicy struct {
	// Empty policy = use Caddy defaults; relies on the tls app to issue certs.
}

type httpRoute struct {
	Match  []matcherSet     `json:"match,omitempty"`
	Handle []map[string]any `json:"handle"`
}

type matcherSet struct {
	Host []string `json:"host,omitempty"`
}

// buildOpts configures buildConfigJSON's environment-dependent
// behaviors. Step I.1 introduced it so the manager can pass devMode
// + acmeEmail down without buildConfigJSON growing a long parameter
// list. Tests pass a value-typed default (zero values) when they
// only exercise the catch-all + internal-issuer path.
type buildOpts struct {
	// DevMode selects listen ports (:8080/:8443 vs :80/:443) and
	// the ACME directory URL (staging vs production).
	DevMode bool
	// ACMEEmail is forwarded to the ACME issuer when at least one
	// route has TLSEnabled=true. Empty is accepted (Let's Encrypt
	// won't send expiry reminders).
	ACMEEmail string
}

// buildConfigJSON renders the full Caddy config for the given routes.
//
// Step I.1 wires real ACME: routes with TLSEnabled=true produce a
// dedicated tls.automation.policies entry pointing at Let's Encrypt
// (staging in dev mode, prod otherwise). The historical catch-all
// "internal" policy stays as the LAST policy so any host not bound
// to an ACME policy (localhost, .local, IP literals) still receives
// a self-signed cert and Caddy can answer HTTPS at all.
//
// AutomaticHTTPS remains disabled at the server level: Caddy's
// built-in port-80 redirect logic and the implicit cert magic are
// replaced by Arenet's own explicit translation (per-route opt-in,
// I.2 redirect handler). Keeps the JSON deterministic and testable.
func buildConfigJSON(routes []storage.Route, opts buildOpts) ([]byte, error) {
	httpRoutes := make([]httpRoute, 0, len(routes)+1)
	httpsRoutes := make([]httpRoute, 0, len(routes)+1)
	// Hosts that opted into TLS — used to build the ACME policy
	// subjects list. Collected in route iteration order; emitted as
	// a single policy (one issuer, many subjects) rather than one
	// policy per host to keep the Caddy config readable.
	acmeSubjects := make([]string, 0, len(routes))

	for _, r := range routes {
		dial, err := upstreamDial(r.UpstreamURL)
		if err != nil {
			return nil, fmt.Errorf("route %s (%s): %w", r.ID, r.Host, err)
		}

		// Handler chain order (spec §11.5) — the metrics handler MUST
		// run before reverse_proxy so it observes the upstream's status
		// code via the deferred Inc. Reversing this order makes the
		// metric record 200 for every request.
		//
		// The "handler" string is exactly metrics.HandlerName
		// ("arenet_routemetrics", no dot, no http.handlers. prefix).
		// Caddy's JSON config convention uses the last-segment form;
		// passing the dotted ModuleID silently fails config load
		// (spec §3.5). Tests in this package guard both invariants.
		metricsHandler := map[string]any{
			"handler":  metrics.HandlerName,
			"route_id": r.ID,
		}
		proxyHandler := map[string]any{
			"handler": "reverse_proxy",
			"upstreams": []map[string]any{
				{"dial": dial},
			},
		}

		// Step I.5 — Basic Auth. The `authentication` handler with
		// the http_basic provider gates the route at HTTP layer:
		// missing or wrong credentials yield a 401 before the
		// request reaches the proxy chain. argon2id is selected via
		// the hash module map; Caddy's caddyhttp/caddyauth ships it
		// in the standard module set so no plugin is needed.
		//
		// Realm carries the primary Host so the browser scopes its
		// cached credentials per virtual host (a switch from one
		// route to another re-prompts as expected).
		//
		// Step I.6 — custom request/response headers (`headers`
		// handler) slot between basicauth and the proxy. Modifying
		// headers on a request that's about to be 401'd is wasted
		// work, hence ordering AFTER basicauth; modifying them
		// BEFORE the proxy is required so request changes reach the
		// upstream and response changes are applied on the way back.
		//
		// Handler chain order (spec §3.2): [metrics, basicauth?,
		// headers?, reverse_proxy]. Metrics MUST stay first to
		// observe the final status code (§11.5 invariant).
		handlers := []map[string]any{metricsHandler}
		if r.BasicAuthEnabled {
			handlers = append(handlers, map[string]any{
				"handler": "authentication",
				"providers": map[string]any{
					"http_basic": map[string]any{
						"hash":  map[string]any{"algorithm": "argon2id"},
						"realm": fmt.Sprintf("Arenet route %s", r.Host),
						"accounts": []map[string]any{
							{
								"username": r.BasicAuthUsername,
								"password": r.BasicAuthPasswordHash,
							},
						},
					},
				},
			})
		}
		if headersHandler := buildHeadersHandler(r.RequestHeaders, r.ResponseHeaders); headersHandler != nil {
			handlers = append(handlers, headersHandler)
		}
		handlers = append(handlers, proxyHandler)

		// Step I.3: Match.Host carries the full hostname set
		// (primary + aliases) so Caddy dispatches the same route to
		// any of them. acmeSubjects collects every TLS-enabled host
		// individually so a single multi-SAN cert covers them all.
		allHosts := r.AllHosts()
		route := httpRoute{
			Match:  []matcherSet{{Host: allHosts}},
			Handle: handlers,
		}

		// Step I.2: when TLS is on AND the operator asked for an
		// automatic HTTP→HTTPS upgrade, the HTTP-side route serves
		// a 301 instead of the proxy. The HTTPS-side keeps the
		// normal proxy chain. RedirectToHTTPS is a NO-OP when TLS
		// is off (the field is meaningless without a target HTTPS
		// listener) — L3 in the Step I spec.
		//
		// Caddy injects the ACME HTTP-01 challenge handler ABOVE
		// these user routes at load time (apps.tls.automation owns
		// that side), so /.well-known/acme-challenge/* is never
		// shadowed by the 301 — verified by the smoke pass on
		// staging at I.7.
		if r.TLSEnabled && r.RedirectToHTTPS {
			httpRoutes = append(httpRoutes, buildRedirectRoute(allHosts))
		} else {
			httpRoutes = append(httpRoutes, route)
		}
		if r.TLSEnabled {
			httpsRoutes = append(httpsRoutes, route)
			acmeSubjects = append(acmeSubjects, allHosts...)
		}
	}

	// Final catch-all: must be the LAST route. No match block = matches every
	// request that none of the prior host-matched routes handled.
	httpRoutes = append(httpRoutes, catchAllRoute())

	httpListen, httpsListen := listenPortsFor(opts.DevMode)

	servers := map[string]httpServer{
		"arenet_http": {
			Listen: []string{httpListen},
			AutomaticHTTPS: &automaticHTTPSConfig{
				Disable:          true,
				DisableRedirects: true,
			},
			Routes: httpRoutes,
		},
	}

	if len(httpsRoutes) > 0 {
		httpsRoutes = append(httpsRoutes, catchAllRoute())
		servers["arenet_https"] = httpServer{
			Listen: []string{httpsListen},
			AutomaticHTTPS: &automaticHTTPSConfig{
				Disable:          true,
				DisableRedirects: true,
			},
			TLSConnPolicies: []tlsConnectionPolicy{{}},
			Routes:          httpsRoutes,
		}
	}

	cfg := caddyConfig{
		Apps: appsConfig{
			HTTP: httpApp{Servers: servers},
		},
	}

	full := map[string]any{
		"apps": map[string]any{
			"http": cfg.Apps.HTTP,
			"tls": map[string]any{
				"automation": map[string]any{
					"policies": buildTLSPolicies(acmeSubjects, opts),
				},
			},
		},
	}

	return json.MarshalIndent(full, "", "  ")
}

// buildTLSPolicies returns the tls.automation.policies array.
//
// Order matters for Caddy: the FIRST policy whose subjects list
// matches a host wins. A policy without `subjects` matches anything.
// We therefore emit the ACME policy (subject-bound) first and the
// internal catch-all last, so:
//   - hosts in `acmeSubjects` get an ACME cert,
//   - any other host (localhost, .local, IP literal, etc.) falls
//     back to Caddy's internal CA — same behavior as pre-Step-I.1.
//
// If no route has TLSEnabled=true, we emit only the catch-all
// internal policy, preserving the exact pre-Step-I.1 wire shape so
// existing tests of that path keep passing.
func buildTLSPolicies(acmeSubjects []string, opts buildOpts) []map[string]any {
	internalPolicy := map[string]any{
		"issuers": []map[string]any{
			{"module": "internal"},
		},
	}
	if len(acmeSubjects) == 0 {
		return []map[string]any{internalPolicy}
	}
	acmeIssuer := map[string]any{
		"module": "acme",
		"ca":     acmeDirectoryURL(opts.DevMode),
	}
	if opts.ACMEEmail != "" {
		acmeIssuer["email"] = opts.ACMEEmail
	}
	acmePolicy := map[string]any{
		"subjects": acmeSubjects,
		"issuers":  []map[string]any{acmeIssuer},
	}
	return []map[string]any{acmePolicy, internalPolicy}
}

// acmeDirectoryURL returns the Let's Encrypt directory URL for the
// current mode. Dev mode uses staging (no rate limit on cert
// issuance for iteration); prod uses the real directory.
func acmeDirectoryURL(devMode bool) string {
	if devMode {
		return acmeStagingURL
	}
	return acmeProdURL
}

// listenPortsFor returns the (HTTP, HTTPS) listen addresses based
// on mode. Step I.1: dev keeps :8080/:8443, prod uses :80/:443.
func listenPortsFor(devMode bool) (string, string) {
	if devMode {
		return httpListenDev, httpsListenDev
	}
	return httpListenProd, httpsListenProd
}

// buildRedirectRoute returns the HTTP-side route entry that serves
// a 301 redirect to the HTTPS scheme for the given hostname set
// (Step I.2, extended to multi-host in I.3).
//
// Caddy's `{http.request.host}` and `{http.request.uri}` placeholders
// are resolved at request time:
//   - {http.request.host} preserves the actual Host header the
//     client used — so a hit on an alias is redirected to that same
//     alias on HTTPS, not to the primary host. The match.host array
//     here covers every alias; the placeholder echoes whichever one
//     hit.
//   - {http.request.uri} preserves both path and query string, so
//     a hit on http://x/foo?bar=1 redirects to https://x/foo?bar=1
//     (AC #2 verification).
//
// `close: true` is not set: HTTP/1.1 keep-alive is fine for a 301
// (the client retries on TLS regardless, no connection reuse for
// the redirected request).
func buildRedirectRoute(hosts []string) httpRoute {
	return httpRoute{
		Match: []matcherSet{{Host: hosts}},
		Handle: []map[string]any{
			{
				"handler":     "static_response",
				"status_code": 301,
				"headers": map[string]any{
					"Location": []string{"https://{http.request.host}{http.request.uri}"},
				},
			},
		},
	}
}

// buildHeadersHandler returns the Caddy `headers` handler config for
// the given (request, response) header maps, or nil when BOTH maps
// are empty (so the caller skips appending anything to the handler
// chain). Step I.6.
//
// Caddy's headers handler expects `request.set` and `response.set`
// to be `http.Header` shaped — i.e. map[string][]string. Arenet's
// schema carries single-valued map[string]string entries; the
// conversion wraps each value in a one-element slice. Multi-value
// headers are not exposed in v1.0 (acceptable trade-off; cookies
// and CORS lists are usually single-value in homelab proxying).
//
// Each side (`request` / `response`) is OMITTED from the emitted
// JSON when its source map is empty (Caddy treats both as
// `omitempty`); this keeps the wire config minimal and the smoke
// diff readable.
func buildHeadersHandler(reqHeaders, respHeaders map[string]string) map[string]any {
	if len(reqHeaders) == 0 && len(respHeaders) == 0 {
		return nil
	}
	handler := map[string]any{"handler": "headers"}
	if len(reqHeaders) > 0 {
		handler["request"] = map[string]any{
			"set": wrapHeaderValues(reqHeaders),
		}
	}
	if len(respHeaders) > 0 {
		handler["response"] = map[string]any{
			"set": wrapHeaderValues(respHeaders),
		}
	}
	return handler
}

// wrapHeaderValues turns a map[string]string into the
// map[string][]string shape Caddy's headers handler consumes.
// Each value becomes a one-element slice.
func wrapHeaderValues(m map[string]string) map[string][]string {
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = []string{v}
	}
	return out
}

// catchAllRoute builds the final 404 catch-all route: no match block (matches
// every remaining request) with a static_response handler.
func catchAllRoute() httpRoute {
	return httpRoute{
		Handle: []map[string]any{
			{
				"handler":     "static_response",
				"status_code": 404,
				"body":        "Not Found - no route configured for this host",
			},
		},
	}
}

// HasHTTPSServer reports whether the current store contents would produce an
// HTTPS server in the Caddy config (i.e. at least one route has TLSEnabled).
func (m *CaddyManager) HasHTTPSServer(ctx context.Context) (bool, error) {
	routes, err := m.store.ListRoutes(ctx)
	if err != nil {
		return false, err
	}
	for _, r := range routes {
		if r.TLSEnabled {
			return true, nil
		}
	}
	return false, nil
}

// upstreamDial converts an UpstreamURL ("http://127.0.0.1:9999") into the
// host:port form Caddy's reverse_proxy expects in the "dial" field.
func upstreamDial(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("upstream_url is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse upstream_url %q: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("upstream_url %q has no host", raw)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		switch strings.ToLower(u.Scheme) {
		case "https":
			host += ":443"
		default:
			host += ":80"
		}
	}
	return host, nil
}
