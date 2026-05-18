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

// Default listen addresses for the public proxy in dev mode.
const (
	httpListen  = ":8080"
	httpsListen = ":8443"
)

// CaddyManager owns the lifecycle of the embedded Caddy instance and
// reloads it from the persisted routes.
//
// The optional registry, when non-nil, is reconciled with the canonical
// route IDs after each successful caddy.Load (spec §11.5 + §4.1). When
// nil (typical for unit tests that only exercise buildConfigJSON or
// catch-all behavior), the metrics layer is fully bypassed.
type CaddyManager struct {
	store    *storage.Store
	logger   *slog.Logger
	registry *metrics.Registry

	mu      sync.Mutex
	started bool
}

// New constructs a CaddyManager. The store and logger must be non-nil.
// The registry may be nil; passing a non-nil registry enables the
// per-reload Sync call that keeps the metrics counter map in step
// with the current set of routes.
func New(store *storage.Store, logger *slog.Logger, registry *metrics.Registry) (*CaddyManager, error) {
	if store == nil {
		return nil, errors.New("caddymgr: store must not be nil")
	}
	if logger == nil {
		return nil, errors.New("caddymgr: logger must not be nil")
	}
	return &CaddyManager{store: store, logger: logger, registry: registry}, nil
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
	m.logger.Info("Caddy started", "http", httpListen, "https", httpsListen)
	return nil
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

	cfgJSON, err := buildConfigJSON(routes)
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
	Admin *adminConfig    `json:"admin,omitempty"`
	Apps  appsConfig      `json:"apps"`
	Logs  *loggingConfig  `json:"logging,omitempty"`
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
	Listen              []string                `json:"listen"`
	Routes              []httpRoute             `json:"routes,omitempty"`
	AutomaticHTTPS      *automaticHTTPSConfig   `json:"automatic_https,omitempty"`
	TLSConnPolicies     []tlsConnectionPolicy   `json:"tls_connection_policies,omitempty"`
}

type automaticHTTPSConfig struct {
	Disable                bool `json:"disable"`
	DisableRedirects       bool `json:"disable_redirects,omitempty"`
	DisableCertificates    bool `json:"disable_certificates,omitempty"`
	SkipCerts              bool `json:"skip,omitempty"`
}

type tlsConnectionPolicy struct {
	// Empty policy = use Caddy defaults; relies on the tls app to issue certs.
}

type httpRoute struct {
	Match []matcherSet     `json:"match,omitempty"`
	Handle []map[string]any `json:"handle"`
}

type matcherSet struct {
	Host []string `json:"host,omitempty"`
}

// buildConfigJSON renders the full Caddy config for the given routes.
// In dev mode (current Phase 1), automatic ACME is fully disabled; HTTPS on
// :8443 uses Caddy's internal local CA via the `tls` app issuer "internal".
func buildConfigJSON(routes []storage.Route) ([]byte, error) {
	httpRoutes := make([]httpRoute, 0, len(routes)+1)
	httpsRoutes := make([]httpRoute, 0, len(routes)+1)

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

		route := httpRoute{
			Match:  []matcherSet{{Host: []string{r.Host}}},
			Handle: []map[string]any{metricsHandler, proxyHandler},
		}

		httpRoutes = append(httpRoutes, route)
		if r.TLSEnabled {
			httpsRoutes = append(httpsRoutes, route)
		}
	}

	// Final catch-all: must be the LAST route. No match block = matches every
	// request that none of the prior host-matched routes handled.
	httpRoutes = append(httpRoutes, catchAllRoute())

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

	// TLS app providing the "internal" issuer for self-signed local certs
	// must live under apps.tls — model it as a generic map to keep the
	// dependency on Caddy's internal types minimal.
	full := map[string]any{
		"apps": map[string]any{
			"http": cfg.Apps.HTTP,
			"tls": map[string]any{
				"automation": map[string]any{
					"policies": []map[string]any{
						{
							"issuers": []map[string]any{
								{"module": "internal"},
							},
						},
					},
				},
			},
		},
	}

	return json.MarshalIndent(full, "", "  ")
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
