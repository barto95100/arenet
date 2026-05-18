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
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/metrics"
	"github.com/barto95100/arenet/internal/storage"
)

func TestBuildConfigJSON_TestRoute(t *testing.T) {
	routes := []storage.Route{
		{ID: "fixture", Host: "test.local", UpstreamURL: "http://127.0.0.1:9999"},
	}

	raw, err := buildConfigJSON(routes)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}

	for _, sub := range []string{
		`"listen"`,
		`":8080"`,
		`"host"`,
		`"test.local"`,
		`"reverse_proxy"`,
		`"127.0.0.1:9999"`,
		`"automatic_https"`,
		`"internal"`,
	} {
		if !strings.Contains(string(raw), sub) {
			t.Errorf("config JSON missing %q\n%s", sub, raw)
		}
	}
}

// httpRoutesFromConfig digs into the parsed JSON to extract the arenet_http
// server's route slice — keeps assertions readable in the catch-all test.
func httpRoutesFromConfig(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	server := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["arenet_http"].(map[string]any)
	rawRoutes := server["routes"].([]any)
	routes := make([]map[string]any, len(rawRoutes))
	for i, r := range rawRoutes {
		routes[i] = r.(map[string]any)
	}
	return routes
}

func TestBuildConfigJSON_CatchAllAppended(t *testing.T) {
	routes := []storage.Route{
		{ID: "a", Host: "a.local", UpstreamURL: "http://127.0.0.1:9001"},
		{ID: "b", Host: "b.local", UpstreamURL: "http://127.0.0.1:9002"},
	}

	raw, err := buildConfigJSON(routes)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	httpRoutes := httpRoutesFromConfig(t, raw)
	if want := len(routes) + 1; len(httpRoutes) != want {
		t.Fatalf("got %d routes, want %d (user routes + catch-all)", len(httpRoutes), want)
	}

	catchAll := httpRoutes[len(httpRoutes)-1]
	if _, hasMatch := catchAll["match"]; hasMatch {
		t.Errorf("catch-all route must have no match block, got: %v", catchAll["match"])
	}

	handlers, ok := catchAll["handle"].([]any)
	if !ok || len(handlers) != 1 {
		t.Fatalf("catch-all handle malformed: %v", catchAll["handle"])
	}
	h := handlers[0].(map[string]any)
	if h["handler"] != "static_response" {
		t.Errorf("catch-all handler = %v, want static_response", h["handler"])
	}
	if status, _ := h["status_code"].(float64); int(status) != 404 {
		t.Errorf("catch-all status_code = %v, want 404", h["status_code"])
	}
	if body, _ := h["body"].(string); body != "Not Found - no route configured for this host" {
		t.Errorf("catch-all body = %q, want fixed sentence", body)
	}

	// User routes (a.local, b.local) must come BEFORE the catch-all so they
	// are still matched first.
	for i := 0; i < len(httpRoutes)-1; i++ {
		if _, ok := httpRoutes[i]["match"]; !ok {
			t.Errorf("route %d is missing a match block — would shadow catch-all", i)
		}
	}
}

func TestBuildConfigJSON_CatchAllOnHTTPSServer(t *testing.T) {
	routes := []storage.Route{
		{ID: "a", Host: "secure.local", UpstreamURL: "http://127.0.0.1:9001", TLSEnabled: true},
	}
	raw, err := buildConfigJSON(routes)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	httpsServer, ok := servers["arenet_https"].(map[string]any)
	if !ok {
		t.Fatal("arenet_https server missing despite TLSEnabled route")
	}
	httpsRoutes := httpsServer["routes"].([]any)
	if len(httpsRoutes) != 2 {
		t.Fatalf("got %d routes on HTTPS server, want 2 (user + catch-all)", len(httpsRoutes))
	}
	last := httpsRoutes[len(httpsRoutes)-1].(map[string]any)
	if _, hasMatch := last["match"]; hasMatch {
		t.Errorf("HTTPS catch-all must have no match block")
	}
}

// --- Step E (Chunk 2 Étape C) ---------------------------------------------

// TestBuildConfigJSON_HandlerChainOrder verifies spec §11.5: the
// arenet_routemetrics handler MUST be at index 0 of each route's
// Handle slice, BEFORE reverse_proxy. Otherwise reverse_proxy writes
// the response status before the metrics handler observes it, and
// every request is counted as 200.
func TestBuildConfigJSON_HandlerChainOrder(t *testing.T) {
	routes := []storage.Route{
		{ID: "rid-1", Host: "a.local", UpstreamURL: "http://127.0.0.1:9001"},
		{ID: "rid-2", Host: "b.local", UpstreamURL: "http://127.0.0.1:9002"},
	}

	raw, err := buildConfigJSON(routes)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	httpRoutes := httpRoutesFromConfig(t, raw)
	// Skip the catch-all (last entry); only inspect user routes.
	if len(httpRoutes) < 3 {
		t.Fatalf("expected ≥3 routes (2 user + catch-all), got %d", len(httpRoutes))
	}

	for i, route := range httpRoutes[:2] {
		handlers, ok := route["handle"].([]any)
		if !ok {
			t.Fatalf("route %d: handle field missing or wrong type", i)
		}
		if len(handlers) != 2 {
			t.Fatalf("route %d: expected 2 handlers (metrics + reverse_proxy), got %d", i, len(handlers))
		}
		first, _ := handlers[0].(map[string]any)
		second, _ := handlers[1].(map[string]any)
		if first["handler"] != metrics.HandlerName {
			t.Errorf("route %d: handler[0]=%v, want %q (metrics MUST be first per §11.5)", i, first["handler"], metrics.HandlerName)
		}
		if second["handler"] != "reverse_proxy" {
			t.Errorf("route %d: handler[1]=%v, want reverse_proxy", i, second["handler"])
		}
	}
}

// TestBuildConfigJSON_HandlerJSONName verifies spec §3.5: the
// "handler" field in JSON config is exactly "arenet_routemetrics"
// (no dot, no http.handlers. prefix). Mixing forms silently fails
// caddy.Load with an unhelpful "unknown handler" error.
func TestBuildConfigJSON_HandlerJSONName(t *testing.T) {
	routes := []storage.Route{
		{ID: "rid-1", Host: "a.local", UpstreamURL: "http://127.0.0.1:9001"},
	}
	raw, err := buildConfigJSON(routes)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers := httpRoutes[0]["handle"].([]any)
	first := handlers[0].(map[string]any)
	got, _ := first["handler"].(string)

	if got != "arenet_routemetrics" {
		t.Errorf("handler name = %q, want exactly %q (no dot, no prefix)", got, "arenet_routemetrics")
	}
	// Also guard against the most common typo: the dotted ModuleID form.
	if got == metrics.ModuleID {
		t.Errorf("handler name = %q, but ModuleID form is wrong in JSON config (§3.5)", got)
	}
	// And the route_id must be the route's storage UUID.
	if first["route_id"] != "rid-1" {
		t.Errorf("route_id=%v, want %q", first["route_id"], "rid-1")
	}
}

// TestBuildConfigJSON_HandlerJSONName_HTTPSToo guards that the
// handler chain order and JSON name are correct on the HTTPS server
// too. The HTTPS routes are a copy of the HTTP routes in the
// current implementation; if a future refactor decouples them, this
// test catches a regression where TLS routes might lose the
// metrics handler.
func TestBuildConfigJSON_HandlerJSONName_HTTPSToo(t *testing.T) {
	routes := []storage.Route{
		{ID: "rid-tls", Host: "secure.local", UpstreamURL: "http://127.0.0.1:9001", TLSEnabled: true},
	}
	raw, err := buildConfigJSON(routes)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	httpsServer, ok := servers["arenet_https"].(map[string]any)
	if !ok {
		t.Fatal("arenet_https server missing")
	}
	httpsRoutes := httpsServer["routes"].([]any)
	first := httpsRoutes[0].(map[string]any)
	handlers := first["handle"].([]any)
	if len(handlers) != 2 {
		t.Fatalf("HTTPS route: %d handlers, want 2", len(handlers))
	}
	if metricsH := handlers[0].(map[string]any); metricsH["handler"] != "arenet_routemetrics" {
		t.Errorf("HTTPS handler[0]=%v, want arenet_routemetrics", metricsH["handler"])
	}
}

// TestSyncRegistry_CalledAfterSuccess validates the post-reload Sync
// pattern (§11.5 + D2): after a successful reload, the registry is
// populated with the canonical route IDs. Bypasses caddy.Load by
// calling syncRegistry directly with the route slice that
// applyLocked would have used.
func TestSyncRegistry_CalledAfterSuccess(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	registry := metrics.NewRegistry()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := New(store, logger, registry)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	routes := []storage.Route{
		{ID: "r1", Host: "a.local", UpstreamURL: "http://127.0.0.1:1"},
		{ID: "r2", Host: "b.local", UpstreamURL: "http://127.0.0.1:2"},
	}
	mgr.syncRegistry(routes)

	// The registry should now contain cells for r1 and r2. We can
	// observe this by taking a Snapshot: the keys we see are exactly
	// those Sync inserted.
	snap := registry.Snapshot()
	if _, ok := snap["r1"]; !ok {
		t.Error("r1 missing from registry after Sync")
	}
	if _, ok := snap["r2"]; !ok {
		t.Error("r2 missing from registry after Sync")
	}
	if _, ok := snap["unknown"]; ok {
		t.Error("unknown route appeared in registry; Sync must not add unrequested IDs")
	}
}

// TestSyncRegistry_NoOpOnNilRegistry validates that a CaddyManager
// constructed with a nil registry (typical for unit tests) does not
// panic and does not touch any global state when syncRegistry is
// called. Mirrors the pattern: Step E backward compat with Step D
// binaries that don't wire metrics.
func TestSyncRegistry_NoOpOnNilRegistry(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := New(store, logger, nil) // nil registry
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Must not panic on nil registry.
	mgr.syncRegistry([]storage.Route{
		{ID: "r1", Host: "a.local", UpstreamURL: "http://127.0.0.1:1"},
	})
}

// TestSyncRegistry_NotCalledOnReloadFailure validates the "no Sync
// on failure" invariant (spec §11.5 + Step D D2 pattern). When
// buildConfigJSON fails (invalid upstream URL), applyLocked returns
// the error BEFORE reaching syncRegistry. The registry stays empty.
//
// Uses ReloadFromStore as the public entry point. Since Caddy is
// never Start()ed in this test, the post-reload caddy.Load WILL
// fail too — but the assertion is on the registry's emptiness,
// which holds regardless of whether the failure came from
// buildConfigJSON or caddy.Load: in both cases, syncRegistry must
// not have run.
func TestSyncRegistry_NotCalledOnReloadFailure(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Insert a route with an INVALID upstream URL → buildConfigJSON
	// fails when upstreamDial rejects the empty URL. Note: we use
	// RestoreRoute (no validation) to bypass storage.CreateRoute's
	// own upstream_url presence check. This route would never enter
	// the system via the public API; we synthesize it here purely
	// to make buildConfigJSON fail downstream.
	if err := store.RestoreRoute(t.Context(), storage.Route{
		ID:          "bad-route-id",
		Host:        "bad.local",
		UpstreamURL: "", // upstreamDial rejects empty
	}); err != nil {
		t.Fatalf("seed route: %v", err)
	}

	registry := metrics.NewRegistry()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := New(store, logger, registry)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// ReloadFromStore MUST return an error and NOT have called Sync.
	if err := mgr.ReloadFromStore(t.Context()); err == nil {
		t.Fatal("expected ReloadFromStore to fail on invalid upstream; got nil")
	}

	snap := registry.Snapshot()
	if len(snap) != 0 {
		t.Errorf("registry has %d cells after failed reload; want 0 (Sync MUST NOT run on failure)", len(snap))
	}
}

func TestUpstreamDial(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{in: "http://127.0.0.1:9999", want: "127.0.0.1:9999"},
		{in: "http://example.com", want: "example.com:80"},
		{in: "https://example.com", want: "example.com:443"},
		{in: "https://example.com:8443", want: "example.com:8443"},
		{in: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := upstreamDial(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
