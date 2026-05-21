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

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
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

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
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
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
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

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
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
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
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
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
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
	mgr, err := New(store, logger, registry, true, "")
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
	mgr, err := New(store, logger, nil, true, "") // nil registry
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
	mgr, err := New(store, logger, registry, true, "")
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

// --- Step I.1 — ACME policies + listen ports ----------------------------

// readPolicies pulls apps.tls.automation.policies from a buildConfigJSON
// emission and returns them as a typed slice. Centralizes the deep-key
// traversal so individual tests assert on policy shape only.
func readPolicies(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}
	apps, _ := top["apps"].(map[string]any)
	tls, _ := apps["tls"].(map[string]any)
	autom, _ := tls["automation"].(map[string]any)
	raw2, ok := autom["policies"].([]any)
	if !ok {
		t.Fatalf("policies not an array: %v", autom["policies"])
	}
	out := make([]map[string]any, len(raw2))
	for i, p := range raw2 {
		out[i], _ = p.(map[string]any)
	}
	return out
}

func TestBuildConfigJSON_ACME_DevMode_StagingURL(t *testing.T) {
	routes := []storage.Route{
		{ID: "r1", Host: "test.example.com", UpstreamURL: "http://127.0.0.1:9000", TLSEnabled: true},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true, ACMEEmail: "ops@example.com"})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	if len(policies) != 2 {
		t.Fatalf("want 2 policies (ACME + internal), got %d: %v", len(policies), policies)
	}
	// First policy: ACME, bound to the TLS-enabled host.
	subjects, _ := policies[0]["subjects"].([]any)
	if len(subjects) != 1 || subjects[0] != "test.example.com" {
		t.Errorf("policies[0].subjects = %v; want [test.example.com]", subjects)
	}
	issuers, _ := policies[0]["issuers"].([]any)
	issuer, _ := issuers[0].(map[string]any)
	if issuer["module"] != "acme" {
		t.Errorf("policies[0].issuers[0].module = %v; want acme", issuer["module"])
	}
	if issuer["ca"] != acmeStagingURL {
		t.Errorf("policies[0].issuers[0].ca = %v; want staging URL", issuer["ca"])
	}
	if issuer["email"] != "ops@example.com" {
		t.Errorf("policies[0].issuers[0].email = %v; want ops@example.com", issuer["email"])
	}
	// Second policy: catch-all internal issuer.
	issuers2, _ := policies[1]["issuers"].([]any)
	internalIssuer, _ := issuers2[0].(map[string]any)
	if internalIssuer["module"] != "internal" {
		t.Errorf("policies[1].issuers[0].module = %v; want internal", internalIssuer["module"])
	}
	if _, hasSubjects := policies[1]["subjects"]; hasSubjects {
		t.Errorf("policies[1] should be catch-all (no subjects), got %v", policies[1])
	}
}

func TestBuildConfigJSON_ACME_ProdMode_ProdURL(t *testing.T) {
	routes := []storage.Route{
		{ID: "r1", Host: "prod.example.com", UpstreamURL: "http://127.0.0.1:9000", TLSEnabled: true},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: false, ACMEEmail: "ops@example.com"})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	issuers, _ := policies[0]["issuers"].([]any)
	issuer, _ := issuers[0].(map[string]any)
	if issuer["ca"] != acmeProdURL {
		t.Errorf("policies[0].issuers[0].ca = %v; want prod URL %q", issuer["ca"], acmeProdURL)
	}
}

func TestBuildConfigJSON_ACME_NoEmail_IssuerOmitsEmailKey(t *testing.T) {
	// Empty ACMEEmail must produce an issuer WITHOUT the "email"
	// key (Let's Encrypt accepts email-free accounts; main.go logs
	// a WARN separately at boot if a TLS route already exists).
	routes := []storage.Route{
		{ID: "r1", Host: "noemail.example.com", UpstreamURL: "http://127.0.0.1:9000", TLSEnabled: true},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true, ACMEEmail: ""})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	issuers, _ := policies[0]["issuers"].([]any)
	issuer, _ := issuers[0].(map[string]any)
	if _, has := issuer["email"]; has {
		t.Errorf("issuer should omit \"email\" key when ACMEEmail is empty, got %v", issuer)
	}
}

func TestBuildConfigJSON_NoTLS_InternalOnly(t *testing.T) {
	// No route has TLSEnabled=true → policies must be ONLY the
	// internal catch-all (preserves pre-Step-I.1 wire shape).
	routes := []storage.Route{
		{ID: "r1", Host: "plain.example.com", UpstreamURL: "http://127.0.0.1:9000"},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	if len(policies) != 1 {
		t.Fatalf("want 1 policy (internal only) when no TLS route, got %d", len(policies))
	}
	issuers, _ := policies[0]["issuers"].([]any)
	issuer, _ := issuers[0].(map[string]any)
	if issuer["module"] != "internal" {
		t.Errorf("policy[0].issuers[0].module = %v; want internal", issuer["module"])
	}
}

// --- Step I.2 — HTTP → HTTPS redirect -----------------------------------

// httpsServerRoutes extracts the arenet_https server's route slice. Mirrors
// httpRoutesFromConfig but for the HTTPS server, used by the redirect tests
// to assert the proxy chain stays intact on the HTTPS side.
func httpsServerRoutes(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	servers, _ := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	server, ok := servers["arenet_https"].(map[string]any)
	if !ok {
		t.Fatal("arenet_https server missing")
	}
	rawRoutes, _ := server["routes"].([]any)
	out := make([]map[string]any, len(rawRoutes))
	for i, r := range rawRoutes {
		out[i], _ = r.(map[string]any)
	}
	return out
}

func TestBuildConfigJSON_Redirect_TLSAndRedirectOn_EmitsStaticResponse301(t *testing.T) {
	routes := []storage.Route{
		{
			ID: "r1", Host: "redir.example.com", UpstreamURL: "http://127.0.0.1:9000",
			TLSEnabled: true, RedirectToHTTPS: true,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	// HTTP side: route 0 should be the 301 redirect (route 1 is the catch-all).
	httpRoutes := httpRoutesFromConfig(t, raw)
	if len(httpRoutes) < 1 {
		t.Fatalf("no HTTP routes emitted")
	}
	first := httpRoutes[0]
	handlers, _ := first["handle"].([]any)
	if len(handlers) != 1 {
		t.Fatalf("redirect route should have exactly 1 handler; got %d", len(handlers))
	}
	h, _ := handlers[0].(map[string]any)
	if h["handler"] != "static_response" {
		t.Errorf("HTTP route handler = %v; want static_response", h["handler"])
	}
	if status, _ := h["status_code"].(float64); int(status) != 301 {
		t.Errorf("status_code = %v; want 301", h["status_code"])
	}
	hdrs, _ := h["headers"].(map[string]any)
	loc, _ := hdrs["Location"].([]any)
	if len(loc) != 1 {
		t.Fatalf("Location header malformed: %v", hdrs)
	}
	locStr, _ := loc[0].(string)
	if !strings.HasPrefix(locStr, "https://") {
		t.Errorf("Location = %q; want https:// prefix", locStr)
	}
	if !strings.Contains(locStr, "{http.request.host}") || !strings.Contains(locStr, "{http.request.uri}") {
		t.Errorf("Location = %q; want both placeholders for host + uri", locStr)
	}

	// HTTPS side: the proxy chain must be untouched on this route.
	httpsRoutes := httpsServerRoutes(t, raw)
	if len(httpsRoutes) < 1 {
		t.Fatalf("no HTTPS routes emitted despite TLSEnabled=true")
	}
	httpsFirst := httpsRoutes[0]
	httpsHandlers, _ := httpsFirst["handle"].([]any)
	if len(httpsHandlers) != 2 {
		t.Fatalf("HTTPS route should keep [metrics, reverse_proxy]; got %d handlers", len(httpsHandlers))
	}
	rp, _ := httpsHandlers[1].(map[string]any)
	if rp["handler"] != "reverse_proxy" {
		t.Errorf("HTTPS handler[1] = %v; want reverse_proxy", rp["handler"])
	}
}

func TestBuildConfigJSON_Redirect_TLSOnlyNoRedirect_PreservesProxyOnHTTP(t *testing.T) {
	// User opted into TLS but disabled the auto-redirect: HTTP must
	// keep serving via the proxy chain (no 301), HTTPS must too.
	routes := []storage.Route{
		{
			ID: "r1", Host: "noredir.example.com", UpstreamURL: "http://127.0.0.1:9000",
			TLSEnabled: true, RedirectToHTTPS: false,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	httpRoutes := httpRoutesFromConfig(t, raw)
	first := httpRoutes[0]
	handlers, _ := first["handle"].([]any)
	if len(handlers) != 2 {
		t.Fatalf("HTTP route should keep [metrics, reverse_proxy]; got %d handlers", len(handlers))
	}
	rp, _ := handlers[1].(map[string]any)
	if rp["handler"] != "reverse_proxy" {
		t.Errorf("HTTP handler[1] = %v; want reverse_proxy (no 301)", rp["handler"])
	}

	// HTTPS side stays proxy.
	httpsRoutes := httpsServerRoutes(t, raw)
	httpsHandlers, _ := httpsRoutes[0]["handle"].([]any)
	httpsRP, _ := httpsHandlers[1].(map[string]any)
	if httpsRP["handler"] != "reverse_proxy" {
		t.Errorf("HTTPS handler[1] = %v; want reverse_proxy", httpsRP["handler"])
	}
}

func TestBuildConfigJSON_Redirect_NoTLSIgnoresRedirectFlag(t *testing.T) {
	// Absurd-but-possible UI state: RedirectToHTTPS=true with
	// TLSEnabled=false. Per L3, the redirect is a NO-OP when TLS is
	// off — the route serves plain HTTP normally, and no HTTPS
	// server is emitted.
	routes := []storage.Route{
		{
			ID: "r1", Host: "plain.example.com", UpstreamURL: "http://127.0.0.1:9000",
			TLSEnabled: false, RedirectToHTTPS: true,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers, _ := httpRoutes[0]["handle"].([]any)
	if len(handlers) != 2 {
		t.Fatalf("HTTP route should keep [metrics, reverse_proxy]; got %d handlers", len(handlers))
	}
	rp, _ := handlers[1].(map[string]any)
	if rp["handler"] != "reverse_proxy" {
		t.Errorf("HTTP handler[1] = %v; want reverse_proxy (NO-OP redirect)", rp["handler"])
	}

	// No HTTPS server when no TLS route exists.
	var cfg map[string]any
	_ = json.Unmarshal(raw, &cfg)
	servers, _ := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	if _, has := servers["arenet_https"]; has {
		t.Errorf("arenet_https should not be emitted when no route has TLSEnabled=true")
	}
}

func TestBuildConfigJSON_ListenPorts_DevVsProd(t *testing.T) {
	cases := []struct {
		name          string
		dev           bool
		wantHTTP      string
		wantHTTPS     string
		anyTLSEnabled bool
	}{
		{name: "dev_no_tls", dev: true, wantHTTP: ":8080", wantHTTPS: "", anyTLSEnabled: false},
		{name: "dev_with_tls", dev: true, wantHTTP: ":8080", wantHTTPS: ":8443", anyTLSEnabled: true},
		{name: "prod_no_tls", dev: false, wantHTTP: ":80", wantHTTPS: "", anyTLSEnabled: false},
		{name: "prod_with_tls", dev: false, wantHTTP: ":80", wantHTTPS: ":443", anyTLSEnabled: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			routes := []storage.Route{
				{ID: "r1", Host: "x.example.com", UpstreamURL: "http://127.0.0.1:9000", TLSEnabled: tc.anyTLSEnabled},
			}
			raw, err := buildConfigJSON(routes, buildOpts{DevMode: tc.dev})
			if err != nil {
				t.Fatalf("buildConfigJSON: %v", err)
			}
			var top map[string]any
			if err := json.Unmarshal(raw, &top); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			apps, _ := top["apps"].(map[string]any)
			httpApp, _ := apps["http"].(map[string]any)
			servers, _ := httpApp["servers"].(map[string]any)

			httpSrv, _ := servers["arenet_http"].(map[string]any)
			httpListens, _ := httpSrv["listen"].([]any)
			if len(httpListens) != 1 || httpListens[0] != tc.wantHTTP {
				t.Errorf("arenet_http.listen = %v; want [%q]", httpListens, tc.wantHTTP)
			}

			httpsSrv, hasHTTPS := servers["arenet_https"].(map[string]any)
			if tc.wantHTTPS == "" {
				if hasHTTPS {
					t.Errorf("expected no arenet_https server when no TLS route; got %v", httpsSrv)
				}
				return
			}
			httpsListens, _ := httpsSrv["listen"].([]any)
			if len(httpsListens) != 1 || httpsListens[0] != tc.wantHTTPS {
				t.Errorf("arenet_https.listen = %v; want [%q]", httpsListens, tc.wantHTTPS)
			}
		})
	}
}
