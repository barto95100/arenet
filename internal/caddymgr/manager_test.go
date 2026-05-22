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
	"reflect"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	// Step I.7 hotfix: side-effect import of coraza-caddy is needed so
	// caddy.GetModule("http.handlers.waf") in TestBuildConfigJSON_
	// HandlersAllResolvable returns a hit. cmd/arenet/main.go has the
	// same blank import at the binary level; the test binary needs its
	// own copy because Go's test binary doesn't link cmd/arenet.
	_ "github.com/corazawaf/coraza-caddy/v2"

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

// --- Step I.7 hotfix (Finding #6) — ACME private-host filtering -----------

// TestBuildConfigJSON_ACME_SkipsPrivateHosts verifies the fix:
// a TLS-enabled route on a .local hostname must NOT end up in an
// ACME policy subjects list (Let's Encrypt cannot validate .local).
// It should fall through to the internal catch-all policy and be
// served by Caddy's self-signed local CA.
//
// Pre-fix: this test would have produced policies[0].subjects =
// ["api.local"] routed to acme staging, the handshake would have
// failed with "internal error" at runtime (smoke I.7 Finding #6).
func TestBuildConfigJSON_ACME_SkipsPrivateHosts(t *testing.T) {
	routes := []storage.Route{
		{ID: "r1", Host: "api.local", UpstreamURL: "http://127.0.0.1:9000", TLSEnabled: true},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	// Only the catch-all internal policy must be emitted: api.local
	// is private, so acmeSubjects is empty, so the ACME policy is
	// not emitted at all.
	if len(policies) != 1 {
		t.Fatalf("want 1 policy (internal catch-all only), got %d:\n%v", len(policies), policies)
	}
	if _, hasSubjects := policies[0]["subjects"]; hasSubjects {
		t.Errorf("the only policy should be catch-all (no subjects key), got %v", policies[0])
	}
	issuers, _ := policies[0]["issuers"].([]any)
	if first, _ := issuers[0].(map[string]any); first["module"] != "internal" {
		t.Errorf("policy[0].issuer = %v; want internal", first["module"])
	}
}

// TestBuildConfigJSON_ACME_MixedPublicPrivate exercises the
// partitioning logic on a route set that mixes public and private
// hosts: only the public ones land in the ACME policy, the private
// ones fall through to the catch-all. Critical because the per-route
// AllHosts() loop walks both primary + aliases — a mistake on the
// per-host filter would leak a .local into ACME subjects.
func TestBuildConfigJSON_ACME_MixedPublicPrivate(t *testing.T) {
	routes := []storage.Route{
		{ID: "r1", Host: "api.example.com", UpstreamURL: "http://127.0.0.1:9000", TLSEnabled: true},
		{ID: "r2", Host: "api.local", UpstreamURL: "http://127.0.0.1:9001", TLSEnabled: true},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	if len(policies) != 2 {
		t.Fatalf("want 2 policies (ACME for public + internal catch-all), got %d:\n%v", len(policies), policies)
	}
	// policies[0] = ACME with ONLY the public host.
	subjects, _ := policies[0]["subjects"].([]any)
	if len(subjects) != 1 || subjects[0] != "api.example.com" {
		t.Errorf("policies[0].subjects = %v; want [api.example.com] (api.local must NOT leak into ACME)", subjects)
	}
	// policies[1] = catch-all internal, no subjects → handles api.local.
	if _, hasSubjects := policies[1]["subjects"]; hasSubjects {
		t.Errorf("policies[1] must be catch-all, got %v", policies[1])
	}
}

// TestBuildConfigJSON_ACME_IPLiteralSkipped — IP literals are
// another class of subjects Let's Encrypt does not issue for. The
// certmagic classifier rejects them; we just check the wire-shape
// outcome.
func TestBuildConfigJSON_ACME_IPLiteralSkipped(t *testing.T) {
	routes := []storage.Route{
		// 10.0.0.1 isn't a strictly valid HTTP "host" per Arenet's
		// validateHost (the regex rejects pure-digit labels in
		// some shapes), but storage.Route.validate doesn't run the
		// hostname regex — and routes can be seeded directly from
		// tests as we do here. The unit under test is the
		// public-cert filter; it must skip IP literals regardless.
		{ID: "r1", Host: "10.0.0.1", UpstreamURL: "http://127.0.0.1:9000", TLSEnabled: true},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	if len(policies) != 1 {
		t.Fatalf("want 1 policy (internal catch-all only), got %d:\n%v", len(policies), policies)
	}
	if _, hasSubjects := policies[0]["subjects"]; hasSubjects {
		t.Errorf("IP literal must fall through to the catch-all; got policy[0]=%v", policies[0])
	}
}

// TestBuildConfigJSON_ACME_AliasMixedPublicPrivate — a route's
// primary may be public while one of its aliases is private (or
// the inverse). The per-host filter must split them: only the
// public ones reach ACME, the private ones fall through to the
// internal catch-all. Anti-regression for any future refactor
// that switches back to a per-route (instead of per-host) decision.
func TestBuildConfigJSON_ACME_AliasMixedPublicPrivate(t *testing.T) {
	routes := []storage.Route{
		{
			ID: "r1", Host: "api.example.com", UpstreamURL: "http://127.0.0.1:9000",
			Aliases:    []string{"api.local", "alt.example.com"},
			TLSEnabled: true,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	if len(policies) != 2 {
		t.Fatalf("want 2 policies (ACME + catch-all), got %d:\n%v", len(policies), policies)
	}
	subjectsAny, _ := policies[0]["subjects"].([]any)
	got := make([]string, 0, len(subjectsAny))
	for _, s := range subjectsAny {
		got = append(got, s.(string))
	}
	// Order is the iteration order of AllHosts(): primary, then
	// aliases in the slice's order. The private alias is filtered
	// out; the rest keeps that order.
	want := []string{"api.example.com", "alt.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("acmeSubjects = %v; want %v (api.local must be filtered out)", got, want)
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

// --- Step I.3 — Alias hostnames -----------------------------------------

func TestBuildConfigJSON_Aliases_MatchHostContainsAll(t *testing.T) {
	routes := []storage.Route{
		{
			ID: "r1", Host: "primary.com", UpstreamURL: "http://127.0.0.1:9000",
			Aliases: []string{"alt1.com", "alt2.com"},
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	first := httpRoutes[0]
	matches, _ := first["match"].([]any)
	match0, _ := matches[0].(map[string]any)
	hosts, _ := match0["host"].([]any)
	got := make([]string, len(hosts))
	for i, h := range hosts {
		got[i], _ = h.(string)
	}
	want := []string{"primary.com", "alt1.com", "alt2.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("match.host = %v; want %v (primary first, then aliases in order)", got, want)
	}
}

func TestBuildConfigJSON_Aliases_ACMESubjectsExpanded(t *testing.T) {
	routes := []storage.Route{
		{
			ID: "r1", Host: "primary.com", UpstreamURL: "http://127.0.0.1:9000",
			Aliases: []string{"alt1.com", "alt2.com"}, TLSEnabled: true,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	subjects, _ := policies[0]["subjects"].([]any)
	got := make([]string, len(subjects))
	for i, s := range subjects {
		got[i], _ = s.(string)
	}
	want := []string{"primary.com", "alt1.com", "alt2.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("acmeSubjects = %v; want %v (primary first, then aliases in order)", got, want)
	}
}

func TestBuildConfigJSON_Aliases_RedirectHonorsAliases(t *testing.T) {
	routes := []storage.Route{
		{
			ID: "r1", Host: "primary.com", UpstreamURL: "http://127.0.0.1:9000",
			Aliases: []string{"alt1.com"}, TLSEnabled: true, RedirectToHTTPS: true,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	// Route[0] is the 301 redirect; its match.host must include the alias
	// so a hit on http://alt1.com/* is redirected to https://alt1.com/* via
	// the {http.request.host} placeholder.
	first := httpRoutes[0]
	handlers, _ := first["handle"].([]any)
	h, _ := handlers[0].(map[string]any)
	if h["handler"] != "static_response" {
		t.Fatalf("first HTTP route should be the 301 redirect; got handler=%v", h["handler"])
	}
	matches, _ := first["match"].([]any)
	match0, _ := matches[0].(map[string]any)
	hosts, _ := match0["host"].([]any)
	got := make([]string, len(hosts))
	for i, h := range hosts {
		got[i], _ = h.(string)
	}
	want := []string{"primary.com", "alt1.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("redirect match.host = %v; want %v", got, want)
	}
}

// --- Step I.5 — Basic Auth ------------------------------------------------

func TestBuildConfigJSON_BasicAuth_EmitsAuthHandler(t *testing.T) {
	routes := []storage.Route{
		{
			ID: "r1", Host: "auth.example.com", UpstreamURL: "http://127.0.0.1:9000",
			BasicAuthEnabled:      true,
			BasicAuthUsername:     "admin",
			BasicAuthPasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$SALT$KEY",
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	first := httpRoutes[0]
	handlers, _ := first["handle"].([]any)
	// Step I.5 chain: [metrics, authentication, reverse_proxy].
	if len(handlers) != 3 {
		t.Fatalf("handler chain length = %d; want 3 (metrics + auth + proxy)", len(handlers))
	}
	h0, _ := handlers[0].(map[string]any)
	if h0["handler"] != "arenet_routemetrics" {
		t.Errorf("handler[0] = %v; want arenet_routemetrics (metrics MUST stay first)", h0["handler"])
	}
	h1, _ := handlers[1].(map[string]any)
	if h1["handler"] != "authentication" {
		t.Errorf("handler[1] = %v; want authentication", h1["handler"])
	}
	providers, _ := h1["providers"].(map[string]any)
	httpBasic, _ := providers["http_basic"].(map[string]any)
	hash, _ := httpBasic["hash"].(map[string]any)
	if hash["algorithm"] != "argon2id" {
		t.Errorf("hash.algorithm = %v; want argon2id", hash["algorithm"])
	}
	accounts, _ := httpBasic["accounts"].([]any)
	if len(accounts) != 1 {
		t.Fatalf("accounts length = %d; want 1", len(accounts))
	}
	acc0, _ := accounts[0].(map[string]any)
	if acc0["username"] != "admin" {
		t.Errorf("accounts[0].username = %v; want admin", acc0["username"])
	}
	if acc0["password"] != "$argon2id$v=19$m=65536,t=3,p=4$SALT$KEY" {
		t.Errorf("accounts[0].password = %v; want PHC hash verbatim", acc0["password"])
	}
	h2, _ := handlers[2].(map[string]any)
	if h2["handler"] != "reverse_proxy" {
		t.Errorf("handler[2] = %v; want reverse_proxy", h2["handler"])
	}
}

func TestBuildConfigJSON_BasicAuth_OffSkipsHandler(t *testing.T) {
	// BasicAuthEnabled=false: chain stays [metrics, reverse_proxy].
	routes := []storage.Route{
		{ID: "r1", Host: "open.example.com", UpstreamURL: "http://127.0.0.1:9000"},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers, _ := httpRoutes[0]["handle"].([]any)
	if len(handlers) != 2 {
		t.Fatalf("handler chain length = %d; want 2 (no auth handler when disabled)", len(handlers))
	}
	for _, hh := range handlers {
		m, _ := hh.(map[string]any)
		if m["handler"] == "authentication" {
			t.Errorf("authentication handler present despite BasicAuthEnabled=false: %v", m)
		}
	}
}

// --- Step I.4 — WAF (Coraza) ----------------------------------------------

func TestBuildConfigJSON_WAF_DetectMode(t *testing.T) {
	routes := []storage.Route{
		{ID: "r1", Host: "waf.example.com", UpstreamURL: "http://127.0.0.1:9000", WAFMode: "detect"},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers, _ := httpRoutes[0]["handle"].([]any)
	// Chain: [metrics, waf, reverse_proxy] — the WAF handler value
	// is "waf" (last segment of http.handlers.waf), NOT "coraza";
	// the upstream coraza-caddy module registers itself under the
	// generic Caddy name "waf". Step I.7 hotfix.
	if len(handlers) != 3 {
		t.Fatalf("handler chain length = %d; want 3 (metrics + waf + proxy)", len(handlers))
	}
	h1, _ := handlers[1].(map[string]any)
	if h1["handler"] != "waf" {
		t.Fatalf("handler[1] = %v; want waf (Caddy module id http.handlers.waf)", h1["handler"])
	}
	// Finding #4 hotfix: the `load_owasp_crs` flag MUST be present
	// and true, otherwise coraza-caddy does not register the
	// embedded coreruleset.FS and the @owasp_crs/* alias resolves
	// to zero files at Include time.
	if v, ok := h1["load_owasp_crs"].(bool); !ok || !v {
		t.Errorf("load_owasp_crs missing or false: %v (WAF would run with zero rules)", h1["load_owasp_crs"])
	}
	dir, _ := h1["directives"].(string)
	if !strings.Contains(dir, "SecRuleEngine DetectionOnly") {
		t.Errorf("directives missing DetectionOnly toggle: %q", dir)
	}
	// Finding #4 hotfix: the canonical three-Include sequence is
	// required for CRS to function (Coraza defaults +
	// CRS-setup variables + the rule files themselves). Loading
	// only the third one runs rules against undefined tx.*
	// variables.
	for _, want := range []string{
		"Include @coraza.conf-recommended",
		"Include @crs-setup.conf.example",
		"Include @owasp_crs/*.conf",
	} {
		if !strings.Contains(dir, want) {
			t.Errorf("directives missing %q: %q", want, dir)
		}
	}
}

func TestBuildConfigJSON_WAF_BlockMode(t *testing.T) {
	routes := []storage.Route{
		{ID: "r1", Host: "block.example.com", UpstreamURL: "http://127.0.0.1:9000", WAFMode: "block"},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers, _ := httpRoutes[0]["handle"].([]any)
	h1, _ := handlers[1].(map[string]any)
	if h1["handler"] != "waf" {
		t.Fatalf("handler[1] = %v; want waf", h1["handler"])
	}
	if v, ok := h1["load_owasp_crs"].(bool); !ok || !v {
		t.Errorf("load_owasp_crs missing or false: %v", h1["load_owasp_crs"])
	}
	dir, _ := h1["directives"].(string)
	if !strings.Contains(dir, "SecRuleEngine On") {
		t.Errorf("directives missing block-mode toggle: %q", dir)
	}
	// Sanity: the engine setter is NOT "DetectionOnly" — guards
	// against a copy-paste where "On" could degrade to "DetectionOnly"
	// silently.
	if strings.Contains(dir, "DetectionOnly") {
		t.Errorf("block mode emitted DetectionOnly engine: %q", dir)
	}
	for _, want := range []string{
		"Include @coraza.conf-recommended",
		"Include @crs-setup.conf.example",
		"Include @owasp_crs/*.conf",
	} {
		if !strings.Contains(dir, want) {
			t.Errorf("directives missing %q: %q", want, dir)
		}
	}
}

func TestBuildConfigJSON_WAF_OffSkipsHandler(t *testing.T) {
	routes := []storage.Route{
		{ID: "r1", Host: "open.example.com", UpstreamURL: "http://127.0.0.1:9000", WAFMode: "off"},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers, _ := httpRoutes[0]["handle"].([]any)
	if len(handlers) != 2 {
		t.Fatalf("handler chain length = %d; want 2 (no waf handler when mode=off)", len(handlers))
	}
	for _, hh := range handlers {
		m, _ := hh.(map[string]any)
		if m["handler"] == "waf" {
			t.Errorf("waf handler present despite WAFMode=off: %v", m)
		}
	}
}

// --- Step I.7 hotfix — caddy.Validate e2e -------------------------------

// TestBuildConfigJSON_LoadsCleanly is the deeper anti-regression guard
// the I.4 audit + commit missed twice: it builds the Caddy config for
// a fixture route engaging every Step I feature and runs the real
// caddy.Validate on the emitted JSON. caddy.Validate provisions every
// module (including the coraza WAF) without starting the HTTP servers,
// so configuration mistakes that would have crashed caddy.Load at
// runtime are caught at unit-test time.
//
// This test would have caught:
//   - Finding #2 (handler ID "coraza" vs the actual "waf" registration)
//     — Provision returns "unknown module: http.handlers.coraza" as an
//     error and caddy.Validate fails.
//   - Finding #4 (zero CRS rules loaded) when load_owasp_crs is missing
//     — coraza Provision emits "empty glob result" Warn logs; even if
//     Validate itself returns nil (a missing-rule config is technically
//     valid), running the test verifies the rest of the chain stays
//     loadable AROUND the fix, ie. it locks the contract that the
//     emitted JSON is at least Caddy-parseable / provisionable.
//
// Capturing the Warn logs to fail the test when "empty glob result"
// fires would close the Finding-#4-style hole more strictly, but
// swapping Caddy's global logger requires modifying caddy package
// internals that aren't exposed. The shape assertions in
// TestBuildConfigJSON_WAF_DetectMode/_BlockMode already lock the
// presence of load_owasp_crs:true + the three Includes, so the
// missing-rule path is structurally prevented; this Validate test
// is the runtime safety net on top.
func TestBuildConfigJSON_LoadsCleanly(t *testing.T) {
	// Fixture route engaging every Step I feature so the emitted
	// chain contains [metrics, authentication, waf, headers,
	// reverse_proxy] + the redirect entry on the HTTP listener.
	// Use bcrypt-format-shaped password hash to satisfy Caddy's
	// basicauth Provision validation; coraza-caddy will Provision
	// against the real bundled OWASP CRS files.
	routes := []storage.Route{
		{
			ID:                    "r-all",
			Host:                  "everything.example.com",
			UpstreamURL:           "http://127.0.0.1:9000",
			TLSEnabled:            true,
			RedirectToHTTPS:       true,
			Aliases:               []string{"alt.example.com"},
			WAFMode:               "block",
			BasicAuthEnabled:      true,
			BasicAuthUsername:     "admin",
			BasicAuthPasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$U0FMVFNBTFRTQUxUU0FMVA$S0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0U",
			RequestHeaders:        map[string]string{"X-Real-Foo": "bar"},
			ResponseHeaders:       map[string]string{"X-Custom": "x"},
		},
	}
	// The arenet_routemetrics Caddy module's Provision asserts
	// metrics.GlobalRegistry() is non-nil (see internal/metrics).
	// cmd/arenet/main.go installs the registry at boot via
	// metrics.SetRegistry; the test harness must do the same before
	// caddy.Validate provisions the chain. Without this, Validate
	// would fail with "metrics: registry not installed", which has
	// nothing to do with the WAF config we're trying to exercise.
	metrics.SetRegistry(metrics.NewRegistry())

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	// Unmarshal to *caddy.Config, then run caddy.Validate which
	// Provisions every module (incl. coraza WAF rule loading).
	// Any unknown-module error, malformed directives, or
	// provisioning panic surfaces here as a non-nil err.
	var cfg caddy.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v\n%s", err, raw)
	}

	if err := caddy.Validate(&cfg); err != nil {
		t.Fatalf("caddy.Validate failed on emitted config: %v\nThis catches Finding #2-class bugs "+
			"(unknown handler ID) and any future module-ID drift. The config that failed:\n%s", err, raw)
	}
}

// --- Step I.7 hotfix — handler-ID resolvability anti-regression ----------

// TestBuildConfigJSON_HandlersAllResolvable is the deeper guard that the
// I.4 audit + commit missed: it builds the Caddy config for a fixture
// route that turns ON every Step I feature at once, walks every handler
// emitted in the chain, and verifies that the corresponding Caddy
// module is actually registered under `http.handlers.<value>`.
//
// The bug this catches: I.4 originally emitted "handler": "coraza"
// which Caddy resolved as `http.handlers.coraza` — and silently
// blew up at caddy.Load time with "unknown module" because the
// upstream coraza-caddy module registers itself as
// `http.handlers.waf`. Unit tests asserting on the JSON shape
// happily passed because they checked the (wrong) value we emitted
// against itself. The runtime check below would have caught the
// mismatch the moment the value was first set.
//
// Step E's TestBuildConfigJSON_HandlerJSONName guards the metrics
// handler the same way (spec §3.5); this test extends the same
// principle to every other handler we emit.
func TestBuildConfigJSON_HandlersAllResolvable(t *testing.T) {
	// Fixture route engaging every Step I feature so the emitted
	// chain contains [metrics, authentication, waf, headers, proxy]
	// + the redirect entry on the HTTP listener.
	routes := []storage.Route{
		{
			ID:                    "r-all",
			Host:                  "everything.example.com",
			UpstreamURL:           "http://127.0.0.1:9000",
			TLSEnabled:            true,
			RedirectToHTTPS:       true,
			Aliases:               []string{"alt.example.com"},
			WAFMode:               "block",
			BasicAuthEnabled:      true,
			BasicAuthUsername:     "admin",
			BasicAuthPasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$SALT$KEY",
			RequestHeaders:        map[string]string{"X-Real-Foo": "bar"},
			ResponseHeaders:       map[string]string{"X-Custom": "x"},
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	servers, _ := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)

	// Walk every server, every route, every handler entry; check
	// that caddy.GetModule("http.handlers.<value>") returns a known
	// module. A miss here means the value we emit doesn't match any
	// registered Caddy module — i.e., caddy.Load would crash with
	// "unknown module" at runtime.
	seen := make(map[string]struct{})
	for name, srvAny := range servers {
		srv, _ := srvAny.(map[string]any)
		routes, _ := srv["routes"].([]any)
		for ri, rt := range routes {
			route, _ := rt.(map[string]any)
			handlers, _ := route["handle"].([]any)
			for hi, hh := range handlers {
				m, _ := hh.(map[string]any)
				value, _ := m["handler"].(string)
				if value == "" {
					t.Errorf("server %s, route %d, handler %d: empty handler id (%v)", name, ri, hi, m)
					continue
				}
				moduleID := "http.handlers." + value
				if _, dup := seen[moduleID]; dup {
					continue
				}
				seen[moduleID] = struct{}{}
				if _, err := caddy.GetModule(moduleID); err != nil {
					t.Errorf("handler %q resolves to module %q but caddy.GetModule failed: %v (server %s, route %d, handler %d)",
						value, moduleID, err, name, ri, hi)
				}
			}
		}
	}

	// Belt-and-braces: confirm we actually exercised the modules
	// we care about (the test would silently pass if buildConfigJSON
	// stopped emitting one of them).
	wantModules := []string{
		"http.handlers.arenet_routemetrics",
		"http.handlers.authentication",
		"http.handlers.waf",
		"http.handlers.headers",
		"http.handlers.reverse_proxy",
		"http.handlers.static_response",
	}
	for _, m := range wantModules {
		if _, ok := seen[m]; !ok {
			t.Errorf("fixture did not exercise module %q (seen=%v)", m, seen)
		}
	}
}

// --- Step I.6 — Custom headers --------------------------------------------

func TestBuildConfigJSON_Headers_EmitsHandler(t *testing.T) {
	// Both request- and response-header maps populated: the chain
	// gains a `headers` handler between basicauth (absent here) and
	// reverse_proxy. Caddy's headers handler expects values wrapped
	// in []string — verify that conversion.
	routes := []storage.Route{
		{
			ID: "r1", Host: "hdr.example.com", UpstreamURL: "http://127.0.0.1:9000",
			RequestHeaders:  map[string]string{"X-Real-Foo": "bar"},
			ResponseHeaders: map[string]string{"X-Custom": "x"},
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers, _ := httpRoutes[0]["handle"].([]any)
	// Chain: [metrics, headers, reverse_proxy].
	if len(handlers) != 3 {
		t.Fatalf("handler chain length = %d; want 3 (metrics + headers + proxy)", len(handlers))
	}
	h1, _ := handlers[1].(map[string]any)
	if h1["handler"] != "headers" {
		t.Fatalf("handler[1] = %v; want headers", h1["handler"])
	}
	req, _ := h1["request"].(map[string]any)
	reqSet, _ := req["set"].(map[string]any)
	values, _ := reqSet["X-Real-Foo"].([]any)
	if len(values) != 1 || values[0] != "bar" {
		t.Errorf("request.set X-Real-Foo = %v; want [\"bar\"]", values)
	}
	resp, _ := h1["response"].(map[string]any)
	respSet, _ := resp["set"].(map[string]any)
	respValues, _ := respSet["X-Custom"].([]any)
	if len(respValues) != 1 || respValues[0] != "x" {
		t.Errorf("response.set X-Custom = %v; want [\"x\"]", respValues)
	}
	h2, _ := handlers[2].(map[string]any)
	if h2["handler"] != "reverse_proxy" {
		t.Errorf("handler[2] = %v; want reverse_proxy", h2["handler"])
	}
}

func TestBuildConfigJSON_Headers_EmptyMapsSkipHandler(t *testing.T) {
	// Both maps empty → no headers handler in the chain. Verifies
	// the legacy two-handler chain stays compact when the feature
	// is unused.
	routes := []storage.Route{
		{ID: "r1", Host: "nohdr.example.com", UpstreamURL: "http://127.0.0.1:9000"},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers, _ := httpRoutes[0]["handle"].([]any)
	if len(handlers) != 2 {
		t.Fatalf("handler chain length = %d; want 2 (no headers handler when both maps empty)", len(handlers))
	}
	for _, hh := range handlers {
		m, _ := hh.(map[string]any)
		if m["handler"] == "headers" {
			t.Errorf("headers handler present despite empty maps: %v", m)
		}
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

// --- Step I.7 hotfix (Finding #8) — http_port / https_port declared -----

// TestBuildConfigJSON_HTTPPort_DeclaredInAppConfig is the regression
// guard for Finding #8: pre-fix the emitted JSON did not declare
// apps.http.http_port / https_port at the app level. Caddy defaults
// to 80 / 443, so it considered our `:8080` listener a non-HTTP
// port and applied auto_https to arenet_http — silently injecting
// TLS connection policies at runtime, turning :8080 into a TLS
// listener. Clear HTTP requests then hit Go std's TLS handshake
// and got the canonical 400 "Client sent an HTTP request to an
// HTTPS server".
//
// Asserts dev mode → 8080/8443, prod mode → 80/443, and crucially
// that the values are emitted as JSON NUMBERS (int), not strings.
// A string value would silently fail Caddy's int parser at config
// load and reproduce the original Finding #8 bug.
func TestBuildConfigJSON_HTTPPort_DeclaredInAppConfig(t *testing.T) {
	cases := []struct {
		name      string
		dev       bool
		wantHTTP  float64 // JSON numbers decode as float64
		wantHTTPS float64
	}{
		{name: "dev", dev: true, wantHTTP: 8080, wantHTTPS: 8443},
		{name: "prod", dev: false, wantHTTP: 80, wantHTTPS: 443},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			routes := []storage.Route{
				{ID: "r1", Host: "x.example.com", UpstreamURL: "http://127.0.0.1:9000"},
			}
			raw, err := buildConfigJSON(routes, buildOpts{DevMode: tc.dev})
			if err != nil {
				t.Fatalf("buildConfigJSON: %v", err)
			}
			var top map[string]any
			if err := json.Unmarshal(raw, &top); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			httpApp, _ := top["apps"].(map[string]any)["http"].(map[string]any)

			// http_port MUST be present and a JSON number.
			gotHTTP, ok := httpApp["http_port"].(float64)
			if !ok {
				t.Fatalf("apps.http.http_port missing or not a JSON number; got %T: %v\n%s", httpApp["http_port"], httpApp["http_port"], raw)
			}
			if gotHTTP != tc.wantHTTP {
				t.Errorf("apps.http.http_port = %v; want %v", gotHTTP, tc.wantHTTP)
			}

			// https_port MUST be present and a JSON number.
			gotHTTPS, ok := httpApp["https_port"].(float64)
			if !ok {
				t.Fatalf("apps.http.https_port missing or not a JSON number; got %T: %v", httpApp["https_port"], httpApp["https_port"])
			}
			if gotHTTPS != tc.wantHTTPS {
				t.Errorf("apps.http.https_port = %v; want %v", gotHTTPS, tc.wantHTTPS)
			}

			// String values would silently break Caddy's int parser
			// → reproduce Finding #8. Explicit double-check.
			if _, isStr := httpApp["http_port"].(string); isStr {
				t.Errorf("apps.http.http_port emitted as string — Caddy needs int (Finding #8 regression)")
			}
			if _, isStr := httpApp["https_port"].(string); isStr {
				t.Errorf("apps.http.https_port emitted as string — Caddy needs int (Finding #8 regression)")
			}
		})
	}
}

// --- Step I.7 hotfix (Finding #7) — automatic_https flags --------------

// TestBuildConfigJSON_AutomaticHTTPS_KeepsCertManagementOn is the
// regression guard for Finding #7: pre-fix the builder emitted
// `automatic_https.disable: true` on both servers, which kills the
// AUTO CERT MANAGEMENT in addition to the redirects. The :8443
// listener was up but Caddy had no certs to present at Client
// Hello, so every TLS handshake failed with "internal error".
//
// The fix emits `disable_redirects: true` ALONE — keeping Caddy's
// automatic cert acquisition active (via the tls.automation.policies
// emitted separately), while preventing Caddy from synthesizing
// blanket HTTP→HTTPS 301 routes that would step on the per-route
// RedirectToHTTPS flag Arenet honors via buildRedirectRoute (I.2).
//
// This test asserts the three orthogonal flags
// (`disable`, `disable_certificates`, `disable_redirects`) on every
// emitted server. If any of them ever drifts back to `disable:true`,
// the test fails immediately at unit-test time instead of waiting
// for a smoke session to discover the broken TLS handshake.
func TestBuildConfigJSON_AutomaticHTTPS_KeepsCertManagementOn(t *testing.T) {
	// Need at least one TLS-enabled route so the arenet_https
	// server is emitted alongside arenet_http; otherwise the test
	// only covers the HTTP side.
	routes := []storage.Route{
		{
			ID: "r1", Host: "tls.example.com", UpstreamURL: "http://127.0.0.1:9000",
			TLSEnabled: true,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	servers, _ := top["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)

	for name, srvAny := range servers {
		srv, _ := srvAny.(map[string]any)
		ah, _ := srv["automatic_https"].(map[string]any)
		if ah == nil {
			t.Errorf("server %q: automatic_https block missing", name)
			continue
		}

		// `disable` MUST be false (or absent). Setting it true is
		// the Finding #7 bug — it would kill cert management
		// alongside the redirects.
		if v, ok := ah["disable"]; ok {
			if b, _ := v.(bool); b {
				t.Errorf("server %q: automatic_https.disable = true; this is the Finding #7 bug (would kill cert management — TLS handshake failures at runtime)", name)
			}
		}

		// `disable_certificates` MUST be false (or absent). Setting
		// it true would also kill cert management but spare the
		// redirect side — still wrong for Arenet's intent.
		if v, ok := ah["disable_certificates"]; ok {
			if b, _ := v.(bool); b {
				t.Errorf("server %q: automatic_https.disable_certificates = true; cert management is required", name)
			}
		}

		// `disable_redirects` MUST be true. This is what we want:
		// Arenet emits per-route 301s via buildRedirectRoute (I.2);
		// letting Caddy add its blanket auto-redirect on top would
		// double-redirect or step on routes where the user
		// explicitly disabled RedirectToHTTPS.
		dr, _ := ah["disable_redirects"].(bool)
		if !dr {
			t.Errorf("server %q: automatic_https.disable_redirects = %v; want true (Arenet handles redirects per-route)", name, ah["disable_redirects"])
		}
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
