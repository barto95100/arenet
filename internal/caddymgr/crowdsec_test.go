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

package caddymgr

import (
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"

	"github.com/barto95100/arenet/internal/storage"
)

// newCrowdSecTestMgr builds a CaddyManager backed by a temp
// BoltDB store, with a silent logger and no metrics registry —
// the minimum scaffolding the SetCrowdSecConfig round-trip
// tests need. Inline rather than shared in a helpers.go so the
// Step N tests stay self-contained.
func newCrowdSecTestMgr(t *testing.T) *CaddyManager {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := New(store, logger, nil, true, "")
	if err != nil {
		t.Fatalf("caddymgr.New: %v", err)
	}
	return mgr
}

// fixtureCrowdSecRoute is the minimum-shape route used across
// the Step N.1 tests. One route, no TLS, no auth, no WAF — the
// chain reduces to [metrics, (crowdsec?), reverse_proxy] which
// lets us assert the bouncer prepend (or its absence) without
// noise from M's WAF handler or K's auth handlers.
func fixtureCrowdSecRoute() []storage.Route {
	return []storage.Route{
		{
			ID:        "rid-cs",
			Host:      "cs.local",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9999", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
		},
	}
}

// crowdSecAppFromJSON extracts apps.crowdsec from the emitted
// config, or nil when the key is absent. Returning nil-vs-map
// lets the tests assert presence/absence cleanly.
func crowdSecAppFromJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}
	apps, ok := cfg["apps"].(map[string]any)
	if !ok {
		t.Fatalf("config has no apps block:\n%s", raw)
	}
	if v, ok := apps["crowdsec"]; ok {
		return v.(map[string]any)
	}
	return nil
}

func TestBuildConfigJSON_WithoutCrowdSec_NoAppsBlock(t *testing.T) {
	// AC #13 fail-open-at-boot: empty API key must NOT emit the
	// apps.crowdsec block. Anti-regression for the AC #15/#16
	// invariant — pre-N consumers (Step M / Q anti-regression)
	// see byte-identical config when CrowdSec is disabled.
	raw, err := buildConfigJSON(fixtureCrowdSecRoute(), buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	if app := crowdSecAppFromJSON(t, raw); app != nil {
		t.Errorf("apps.crowdsec present when API key is empty: %+v", app)
	}
}

func TestBuildConfigJSON_WithoutCrowdSec_HandlerNotPrepended(t *testing.T) {
	// AC #13 fail-open + handler-chain symmetry: no apps.crowdsec
	// means no per-route handler prepend either. Chain reduces
	// to [metrics, reverse_proxy] exactly as pre-N.
	raw, err := buildConfigJSON(fixtureCrowdSecRoute(), buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	if len(httpRoutes) < 1 {
		t.Fatalf("no http routes emitted")
	}
	handlers := unwrapHandlers(httpRoutes[0])
	for _, h := range handlers {
		hm, _ := h.(map[string]any)
		if hm["handler"] == "crowdsec" {
			t.Errorf("crowdsec handler present in chain when API key is empty: %+v", handlers)
		}
	}
}

func TestBuildConfigJSON_WithCrowdSec_EmitsApp(t *testing.T) {
	// AC #14 invariant: an emitted config WITH a configured key
	// MUST carry the apps.crowdsec block. Pins the per-field
	// JSON tags so a future field-rename in the bouncer
	// surfaces here as a Validate failure rather than a silent
	// drop.
	raw, err := buildConfigJSON(fixtureCrowdSecRoute(), buildOpts{
		DevMode: true,
		CrowdSec: crowdsecConfig{
			apiURL: "http://127.0.0.1:8080/",
			apiKey: "smoke-test-key",
		},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	app := crowdSecAppFromJSON(t, raw)
	if app == nil {
		t.Fatalf("apps.crowdsec missing despite configured key:\n%s", raw)
	}
	if app["api_url"] != "http://127.0.0.1:8080/" {
		t.Errorf("api_url = %v, want http://127.0.0.1:8080/", app["api_url"])
	}
	if app["api_key"] != "smoke-test-key" {
		t.Errorf("api_key = %v, want smoke-test-key", app["api_key"])
	}
	if app["ticker_interval"] != "60s" {
		t.Errorf("ticker_interval = %v, want 60s (Step N spec D7.A)", app["ticker_interval"])
	}
	if app["enable_streaming"] != true {
		t.Errorf("enable_streaming = %v, want true (Step N spec D1.A)", app["enable_streaming"])
	}
	if app["enable_hard_fails"] != false {
		t.Errorf("enable_hard_fails = %v, want false (Step N spec D2.A fail-open)", app["enable_hard_fails"])
	}
}

func TestBuildConfigJSON_WithCrowdSec_DefaultsAPIURL(t *testing.T) {
	// Operator who sets ARENET_CROWDSEC_API_KEY without
	// ARENET_CROWDSEC_API_URL gets the bouncer's documented
	// default LAPI address (loopback :8080). Matches the
	// bouncer's own Provision-time default at
	// crowdsec/crowdsec.go:116-118.
	raw, err := buildConfigJSON(fixtureCrowdSecRoute(), buildOpts{
		DevMode:  true,
		CrowdSec: crowdsecConfig{apiKey: "k"},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	app := crowdSecAppFromJSON(t, raw)
	if app["api_url"] != "http://127.0.0.1:8080/" {
		t.Errorf("api_url with empty URL = %v, want default", app["api_url"])
	}
}

func TestBuildConfigJSON_WithCrowdSec_HandlerPrepended(t *testing.T) {
	// AC #14 reload-trap invariant: every route's handler chain
	// MUST start with [metrics, crowdsec, ...] when the key is
	// set. Tests both routes to confirm the prepend isn't a
	// one-off.
	routes := []storage.Route{
		{ID: "rid-1", Host: "a.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
		{ID: "rid-2", Host: "b.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9002", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
	}
	raw, err := buildConfigJSON(routes, buildOpts{
		DevMode:  true,
		CrowdSec: crowdsecConfig{apiKey: "k"},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	if len(httpRoutes) < 3 {
		t.Fatalf("expected ≥3 routes (2 user + catch-all), got %d", len(httpRoutes))
	}
	for i, route := range httpRoutes[:2] {
		handlers := unwrapHandlers(route)
		if len(handlers) < 3 {
			t.Fatalf("route %d: expected ≥3 handlers (metrics + crowdsec + reverse_proxy), got %d: %+v", i, len(handlers), handlers)
		}
		second, _ := handlers[1].(map[string]any)
		if second["handler"] != "crowdsec" {
			t.Errorf("route %d: handler[1] = %v, want crowdsec (must slot between metrics and reverse_proxy)", i, second["handler"])
		}
	}
}

func TestBuildConfigJSON_WithCrowdSec_HandlerSlotsAfterMetrics(t *testing.T) {
	// Exact-order assertion for the §11.5 + Step N spec §3.4
	// combined invariant: metrics is first (observes the final
	// status, including crowdsec 403s), crowdsec is second
	// (first wall), reverse_proxy is last. No other gates in
	// the fixture, so handlers[2] must be reverse_proxy.
	raw, err := buildConfigJSON(fixtureCrowdSecRoute(), buildOpts{
		DevMode:  true,
		CrowdSec: crowdsecConfig{apiKey: "k"},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers := unwrapHandlers(httpRoutes[0])
	if len(handlers) != 3 {
		t.Fatalf("expected exactly 3 handlers (metrics + crowdsec + reverse_proxy), got %d: %+v", len(handlers), handlers)
	}
	expected := []string{"arenet_routemetrics", "crowdsec", "reverse_proxy"}
	for i, want := range expected {
		got, _ := handlers[i].(map[string]any)["handler"].(string)
		if got != want {
			t.Errorf("handler[%d] = %q, want %q", i, got, want)
		}
	}
}

func TestBuildConfigJSON_WithCrowdSec_ReloadPreserves(t *testing.T) {
	// AC #14 anti-regression for the Caddy reload trap (Step N
	// spec §3.4). caddymgr.applyLocked rebuilds the full config
	// on every route mutation; the apps.crowdsec block MUST
	// reappear in every emitted config. Simulate two reloads
	// (initial + post-mutation) and confirm both carry the
	// block.
	first, err := buildConfigJSON(fixtureCrowdSecRoute(), buildOpts{
		DevMode:  true,
		CrowdSec: crowdsecConfig{apiKey: "k1"},
	})
	if err != nil {
		t.Fatalf("first buildConfigJSON: %v", err)
	}
	if crowdSecAppFromJSON(t, first) == nil {
		t.Fatalf("first config missing apps.crowdsec")
	}
	// Simulate a route mutation: add a second route, rebuild.
	moreRoutes := append(fixtureCrowdSecRoute(), storage.Route{
		ID: "rid-2", Host: "b.local",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9002", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	})
	second, err := buildConfigJSON(moreRoutes, buildOpts{
		DevMode:  true,
		CrowdSec: crowdsecConfig{apiKey: "k1"},
	})
	if err != nil {
		t.Fatalf("second buildConfigJSON: %v", err)
	}
	if crowdSecAppFromJSON(t, second) == nil {
		t.Fatalf("post-mutation reload silently dropped apps.crowdsec — AC #14 violation:\n%s", second)
	}
}

func TestCaddyManager_SetCrowdSecConfig_RoundTrip(t *testing.T) {
	// Round-trip the setter via the public surface. Trims
	// whitespace (operator pastes a key with a trailing
	// newline from `cscli bouncers add`).
	mgr := newCrowdSecTestMgr(t)
	if mgr.crowdSecEnabled() {
		t.Fatalf("freshly-built manager should report crowdsec disabled")
	}
	mgr.SetCrowdSecConfig("  http://10.0.0.5:8080/  ", "  paste-with-trailing-ws\n")
	if !mgr.crowdSecEnabled() {
		t.Fatalf("crowdsec not enabled after SetCrowdSecConfig with non-empty key")
	}
	if mgr.crowdsec.apiURL != "http://10.0.0.5:8080/" {
		t.Errorf("apiURL not trimmed: %q", mgr.crowdsec.apiURL)
	}
	if mgr.crowdsec.apiKey != "paste-with-trailing-ws" {
		t.Errorf("apiKey not trimmed: %q", mgr.crowdsec.apiKey)
	}
}

// TestBuildConfigJSON_LoadsCleanly_WithCrowdSec is the AC #14 +
// Step I.7 Finding #2 anti-regression guard for the CrowdSec
// surface: build the full Caddy config including apps.crowdsec
// + per-route handler prepend. We confirm the module IDs the
// emitted JSON references (`crowdsec` app, `http.handlers.
// crowdsec` handler) DID make it into the manifest by checking
// caddy.GetModule by ID — a lighter-weight smoke than the full
// caddy.Validate (which would attempt to dial LAPI on
// Provision and add network flakiness to the unit test).
//
// The full caddy.Validate path is exercised at N.5 live smoke
// against a real LAPI; this unit test pins the JSON-shape +
// module-registration correctness.
func TestBuildConfigJSON_LoadsCleanly_WithCrowdSec(t *testing.T) {
	// Confirm the blank imports in crowdsec_imports.go did
	// register both module IDs with Caddy. If a future commit
	// drops the import path, GetModule returns an error and
	// this test fails BEFORE the live-smoke reaches LAPI.
	if _, err := caddy.GetModule("crowdsec"); err != nil {
		t.Fatalf("caddy module `crowdsec` (app) not registered: %v — check internal/caddymgr/crowdsec_imports.go", err)
	}
	if _, err := caddy.GetModule("http.handlers.crowdsec"); err != nil {
		t.Fatalf("caddy module `http.handlers.crowdsec` not registered: %v — check internal/caddymgr/crowdsec_imports.go", err)
	}

	// JSON-shape side: the emitted config carries the apps.
	// crowdsec block + the handler prepend. Done via the
	// existing test helpers; no caddy.Validate to avoid LAPI
	// network dependencies in unit tests.
	raw, err := buildConfigJSON(fixtureCrowdSecRoute(), buildOpts{
		DevMode:  true,
		CrowdSec: crowdsecConfig{apiKey: "k", apiURL: "http://127.0.0.1:8080/"},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	if app := crowdSecAppFromJSON(t, raw); app == nil {
		t.Errorf("emitted config has no apps.crowdsec block:\n%s", raw)
	}
}

func TestCaddyManager_SetCrowdSecConfig_EmptyKeyClears(t *testing.T) {
	// Operator removing the env var on reboot → empty key →
	// manager reports disabled even after a prior set call.
	// Defence-in-depth: catches a future bug where
	// SetCrowdSecConfig might only assign on non-empty
	// values.
	mgr := newCrowdSecTestMgr(t)
	mgr.SetCrowdSecConfig("http://127.0.0.1:8080/", "key-value")
	if !mgr.crowdSecEnabled() {
		t.Fatalf("expected enabled after non-empty set")
	}
	mgr.SetCrowdSecConfig("", "")
	if mgr.crowdSecEnabled() {
		t.Fatalf("expected disabled after empty set")
	}
}
