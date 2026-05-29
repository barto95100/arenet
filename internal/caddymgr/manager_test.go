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

	// Step J.4: side-effect import of caddy-dns/ovh so the test
	// binary can Provision a DNS-01 policy in
	// TestBuildConfigJSON_LoadsCleanly_DNS01 (mirrors the
	// coraza-caddy import above and the production binary's blank
	// import in cmd/arenet/main.go). Without this, caddy.Validate
	// on a payload that references `dns.providers.ovh` fails with
	// `module not registered: dns.providers.ovh` even when the
	// production binary is correctly wired.
	_ "github.com/caddy-dns/ovh"

	"github.com/barto95100/arenet/internal/metrics"
	"github.com/barto95100/arenet/internal/storage"
)

func TestBuildConfigJSON_TestRoute(t *testing.T) {
	routes := []storage.Route{
		{ID: "fixture", Host: "test.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9999", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
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
		{ID: "a", Host: "a.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
		{ID: "b", Host: "b.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9002", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
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

	handlers := unwrapHandlers(catchAll)
	if len(handlers) != 1 {
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
		{ID: "a", Host: "secure.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin, TLSEnabled: true},
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
		{ID: "rid-1", Host: "a.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
		{ID: "rid-2", Host: "b.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9002", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
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
		handlers := unwrapHandlers(route)
		if len(handlers) == 0 {
			t.Fatalf("route %d: no handlers found", i)
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
		{ID: "rid-1", Host: "a.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers := unwrapHandlers(httpRoutes[0])
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
		{ID: "rid-tls", Host: "secure.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin, TLSEnabled: true},
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
	handlers := unwrapHandlers(first)
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
		{ID: "r1", Host: "a.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
		{ID: "r2", Host: "b.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:2", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
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
		{ID: "r1", Host: "a.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
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

	// Insert a route with an EMPTY upstream pool → buildConfigJSON
	// produces a reverse_proxy handler with no upstreams, and caddy.Load
	// rejects the config when the manager tries to apply it. Note: we
	// use RestoreRoute (no validation) to bypass storage.CreateRoute's
	// own pool-presence check. This route would never enter the system
	// via the public API; we synthesize it here purely to make
	// ReloadFromStore fail somewhere on the path so we can assert that
	// syncRegistry did not run.
	if err := store.RestoreRoute(t.Context(), storage.Route{
		ID:        "bad-route-id",
		Host:      "bad.local",
		Upstreams: nil, // empty pool → caddy.Load rejects on reload
		LBPolicy:  storage.LBPolicyRoundRobin,
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
		{ID: "r1", Host: "test.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin, TLSEnabled: true},
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
		{ID: "r1", Host: "prod.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin, TLSEnabled: true},
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
		{ID: "r1", Host: "noemail.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin, TLSEnabled: true},
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
		{ID: "r1", Host: "api.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin, TLSEnabled: true},
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
		{ID: "r1", Host: "api.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin, TLSEnabled: true},
		{ID: "r2", Host: "api.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin, TLSEnabled: true},
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
		{ID: "r1", Host: "10.0.0.1", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin, TLSEnabled: true},
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
			ID: "r1", Host: "api.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
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
		{ID: "r1", Host: "plain.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
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
			ID: "r1", Host: "primary.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
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
			ID: "r1", Host: "primary.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
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
			ID: "r1", Host: "primary.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
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
	handlers := unwrapHandlers(first)
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
			ID: "r1", Host: "auth.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
			AuthMode: storage.RouteAuthBasic,
			BasicAuth: storage.BasicAuthRouteConfig{
				Username:     "admin",
				PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$SALT$KEY",
			},
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	first := httpRoutes[0]
	handlers := unwrapHandlers(first)
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
		{ID: "r1", Host: "open.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers := unwrapHandlers(httpRoutes[0])
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
		{ID: "r1", Host: "waf.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin, WAFMode: "detect"},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers := unwrapHandlers(httpRoutes[0])
	// Chain: [metrics, arenet_waf, reverse_proxy]. Step M.1
	// swapped the legacy `waf` (coraza-caddy/v2) for the
	// new `arenet_waf` (custom coraza/v3 wrapper with
	// per-event capture). Spec §3.2.
	if len(handlers) != 3 {
		t.Fatalf("handler chain length = %d; want 3 (metrics + arenet_waf + proxy)", len(handlers))
	}
	h1, _ := handlers[1].(map[string]any)
	if h1["handler"] != "arenet_waf" {
		t.Fatalf("handler[1] = %v; want arenet_waf (Step M.1 swap from legacy waf)", h1["handler"])
	}
	if h1["route_id"] != "r1" {
		t.Errorf("route_id = %v; want r1 (required for per-route event attribution)", h1["route_id"])
	}
	if h1["mode"] != "detect" {
		t.Errorf("mode = %v; want detect", h1["mode"])
	}
	if v, ok := h1["load_owasp_crs"].(bool); !ok || !v {
		t.Errorf("load_owasp_crs missing or false: %v (WAF would run with zero rules)", h1["load_owasp_crs"])
	}
	dir, _ := h1["directives"].(string)
	// Step M.1: the directives string NO LONGER carries
	// SecRuleEngine — the arenet_waf module appends it based
	// on its Mode field so the module owns the policy.
	if strings.Contains(dir, "SecRuleEngine") {
		t.Errorf("Step M.1: directives must NOT include SecRuleEngine (module owns it via Mode): %q", dir)
	}
	// Finding #4 hotfix: the canonical three-Include sequence
	// is required for CRS to function (Coraza defaults +
	// CRS-setup variables + the rule files themselves).
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
		{ID: "r1", Host: "block.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin, WAFMode: "block"},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers := unwrapHandlers(httpRoutes[0])
	h1, _ := handlers[1].(map[string]any)
	if h1["handler"] != "arenet_waf" {
		t.Fatalf("handler[1] = %v; want arenet_waf", h1["handler"])
	}
	if h1["route_id"] != "r1" {
		t.Errorf("route_id = %v; want r1", h1["route_id"])
	}
	if h1["mode"] != "block" {
		t.Errorf("mode = %v; want block", h1["mode"])
	}
	if v, ok := h1["load_owasp_crs"].(bool); !ok || !v {
		t.Errorf("load_owasp_crs missing or false: %v", h1["load_owasp_crs"])
	}
	dir, _ := h1["directives"].(string)
	if strings.Contains(dir, "SecRuleEngine") {
		t.Errorf("Step M.1: directives must NOT include SecRuleEngine: %q", dir)
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
		{ID: "r1", Host: "open.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin, WAFMode: "off"},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers := unwrapHandlers(httpRoutes[0])
	if len(handlers) != 2 {
		t.Fatalf("handler chain length = %d; want 2 (no waf handler when mode=off)", len(handlers))
	}
	for _, hh := range handlers {
		m, _ := hh.(map[string]any)
		if m["handler"] == "arenet_waf" || m["handler"] == "waf" {
			t.Errorf("WAF handler present despite WAFMode=off: %v", m)
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
	// First fixture: route engaging every Step I feature so the
	// emitted chain contains [metrics, authentication, waf, headers,
	// reverse_proxy] + the redirect entry on the HTTP listener.
	// Use argon2id-format-shaped password hash to satisfy Caddy's
	// basicauth Provision validation; coraza-caddy will Provision
	// against the real bundled OWASP CRS files.
	//
	// Step J.1 extension: the fixture set also covers each of the
	// six LB policies on a multi-upstream pool, so caddy.Validate
	// has to provision every selection_policy module emitted by the
	// generator. Any future drift in the policy enum or in the
	// emitted JSON shape surfaces here as a "unknown module" /
	// provisioning panic — the same guard pattern that caught
	// Step I Finding #2.
	routes := []storage.Route{
		{
			ID:              "r-all",
			Host:            "everything.example.com",
			Upstreams:       []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:        storage.LBPolicyRoundRobin,
			TLSEnabled:      true,
			RedirectToHTTPS: true,
			Aliases:         []string{"alt.example.com"},
			WAFMode:         "block",
			AuthMode:        storage.RouteAuthBasic,
			BasicAuth: storage.BasicAuthRouteConfig{
				Username:     "admin",
				PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$U0FMVFNBTFRTQUxUU0FMVA$S0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0U",
			},
			RequestHeaders:  map[string]string{"X-Real-Foo": "bar"},
			ResponseHeaders: map[string]string{"X-Custom": "x"},
			// Step J.2 — empirical anchor for the active health check
			// block. Caddy v2.11.3 must Provision the emitted
			// `health_checks.active` shape (including the string form
			// "30s"/"5s" for caddy.Duration fields) without error.
			// A future drift in either Caddy's struct tags or our
			// generator surfaces here as a Validate failure, same
			// guard pattern as Finding #2.
			HealthCheck: storage.HealthCheck{
				Enabled:      true,
				URI:          "/healthz",
				Method:       "GET",
				Interval:     "30s",
				Timeout:      "5s",
				ExpectStatus: 200,
				ExpectBody:   "^OK$",
				Passes:       1,
				Fails:        1,
			},
		},
	}
	// One additional route per non-default LB policy. Each carries a
	// two-upstream pool so the selection_policy module has something
	// real to provision against. round_robin is already covered by
	// the r-all route above. Hosts are unique to avoid Caddy's
	// host-collision check.
	policyHosts := map[string]string{
		storage.LBPolicyWeightedRoundRobin: "weighted.example.com",
		storage.LBPolicyLeastConn:          "leastconn.example.com",
		storage.LBPolicyIPHash:             "iphash.example.com",
		storage.LBPolicyRandom:             "random.example.com",
		storage.LBPolicyFirst:              "first.example.com",
	}
	for policy, host := range policyHosts {
		routes = append(routes, storage.Route{
			ID:   "r-" + policy,
			Host: host,
			Upstreams: []storage.Upstream{
				{URL: "http://127.0.0.1:9001", Weight: 2},
				{URL: "http://127.0.0.1:9002", Weight: 1},
			},
			LBPolicy: policy,
			WAFMode:  "off",
		})
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

// TestBuildConfigJSON_LoadsCleanly_DNS01 is the J.4 §5.4 counterpart
// to TestBuildConfigJSON_LoadsCleanly: a route configured for
// DNS-01 ACME with a fixture DNSProviderConfig, fed through
// caddy.Validate to confirm the OVH module's `dns.providers.ovh`
// ID resolves at Provision time. The blank import on this test
// file is what makes the ID resolvable; if a future commit drops
// that import, this test fails before reaching the smoke (same
// guard pattern as Finding #2).
//
// The test also pins the two-policy shape: a route with
// acmeChallenge=dns-01 + a route with the default (http-01) on
// the same Arenet emits two distinct ACME policies plus the
// internal catch-all (§5.4 "up to three policies").
func TestBuildConfigJSON_LoadsCleanly_DNS01(t *testing.T) {
	routes := []storage.Route{
		{
			ID:            "r-wild",
			Host:          "wild.example.com",
			Upstreams:     []storage.Upstream{{URL: "http://127.0.0.1:9003", Weight: 1}},
			LBPolicy:      storage.LBPolicyRoundRobin,
			TLSEnabled:    true,
			ACMEChallenge: storage.ACMEChallengeDNS01,
			WAFMode:       "off",
		},
		{
			// HTTP-01 route on the same Arenet — exercises the
			// partition branch where both ACME policies are
			// emitted side by side.
			ID:            "r-plain",
			Host:          "plain.example.com",
			Upstreams:     []storage.Upstream{{URL: "http://127.0.0.1:9004", Weight: 1}},
			LBPolicy:      storage.LBPolicyRoundRobin,
			TLSEnabled:    true,
			ACMEChallenge: storage.ACMEChallengeHTTP01,
			WAFMode:       "off",
		},
	}
	metrics.SetRegistry(metrics.NewRegistry())

	opts := buildOpts{
		DevMode:   true,
		ACMEEmail: "ops@example.com",
		DNSProvider: storage.DNSProviderConfig{
			Endpoint:          "ovh-eu",
			ApplicationKey:    "fixture-app-key",
			ApplicationSecret: "fixture-app-secret",
			ConsumerKey:       "fixture-consumer-key",
		},
	}
	raw, err := buildConfigJSON(routes, opts)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	var cfg caddy.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v\n%s", err, raw)
	}
	if err := caddy.Validate(&cfg); err != nil {
		t.Fatalf("caddy.Validate failed on DNS-01 config: %v\nThis test pins that the OVH "+
			"module resolves under `dns.providers.ovh` and the emitted policy shape "+
			"survives Caddy v2.11.3's Provision. Config:\n%s", err, raw)
	}

	// Shape assertion: there must be exactly three TLS policies —
	// HTTP-01 ACME, DNS-01 ACME, internal catch-all — in that
	// order, and the DNS-01 issuer must carry `name:"ovh"`.
	var full map[string]any
	if err := json.Unmarshal(raw, &full); err != nil {
		t.Fatalf("unmarshal full: %v", err)
	}
	apps, _ := full["apps"].(map[string]any)
	tlsApp, _ := apps["tls"].(map[string]any)
	automation, _ := tlsApp["automation"].(map[string]any)
	policies, ok := automation["policies"].([]any)
	if !ok {
		t.Fatalf("policies missing or wrong type:\n%s", raw)
	}
	if got := len(policies); got != 3 {
		t.Fatalf("policy count: got %d, want 3 (HTTP-01 + DNS-01 + internal)\n%s", got, raw)
	}
	dnsPolicy, _ := policies[1].(map[string]any)
	issuers, _ := dnsPolicy["issuers"].([]any)
	if len(issuers) != 1 {
		t.Fatalf("DNS-01 policy must have exactly one issuer, got %d", len(issuers))
	}
	issuer, _ := issuers[0].(map[string]any)
	challenges, _ := issuer["challenges"].(map[string]any)
	dnsBlock, _ := challenges["dns"].(map[string]any)
	provider, _ := dnsBlock["provider"].(map[string]any)
	if provider["name"] != "ovh" {
		t.Fatalf("DNS-01 provider.name: got %v, want \"ovh\"\n%s", provider["name"], raw)
	}
	if provider["endpoint"] != "ovh-eu" {
		t.Fatalf("DNS-01 provider.endpoint: got %v, want \"ovh-eu\"", provider["endpoint"])
	}
}

// TestBuildConfigJSON_DNS01_NoProvider_FallsBackQuietly exercises
// the generator's defensive guard (§5.4): a DNS-01 route reaching
// buildConfigJSON without a complete DNSProvider config is the
// programming-error case (the API rejects this state at edit
// time). The generator MUST NOT emit a malformed DNS-01 policy
// that fails caddy.Validate; it skips the DNS-01 policy entirely
// and the affected route's host falls through to the internal CA
// (the same fallback any TLS host gets when there is no ACME
// policy covering it).
func TestBuildConfigJSON_DNS01_NoProvider_FallsBackQuietly(t *testing.T) {
	routes := []storage.Route{
		{
			ID:            "r-orphan",
			Host:          "orphan.example.com",
			Upstreams:     []storage.Upstream{{URL: "http://127.0.0.1:9005", Weight: 1}},
			LBPolicy:      storage.LBPolicyRoundRobin,
			TLSEnabled:    true,
			ACMEChallenge: storage.ACMEChallengeDNS01,
			WAFMode:       "off",
		},
	}
	metrics.SetRegistry(metrics.NewRegistry())
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	var full map[string]any
	if err := json.Unmarshal(raw, &full); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}
	apps := full["apps"].(map[string]any)
	tlsApp := apps["tls"].(map[string]any)
	automation := tlsApp["automation"].(map[string]any)
	policies := automation["policies"].([]any)
	if got := len(policies); got != 1 {
		t.Fatalf("policy count with orphan dns-01 route: got %d, want 1 (internal only)\n%s", got, raw)
	}

	var cfg caddy.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal cfg: %v", err)
	}
	if err := caddy.Validate(&cfg); err != nil {
		t.Fatalf("caddy.Validate must accept the fallback shape: %v\n%s", err, raw)
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
			ID:        "r-all",
			Host:      "everything.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
			TLSEnabled:      true,
			RedirectToHTTPS: true,
			Aliases:         []string{"alt.example.com"},
			WAFMode:         "block",
			AuthMode:        storage.RouteAuthBasic,
			BasicAuth: storage.BasicAuthRouteConfig{
				Username:     "admin",
				PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$SALT$KEY",
			},
			RequestHeaders:  map[string]string{"X-Real-Foo": "bar"},
			ResponseHeaders: map[string]string{"X-Custom": "x"},
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
			handlers := unwrapHandlers(route)
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
		"http.handlers.arenet_waf", // Step M.1: replaces legacy "http.handlers.waf" (coraza-caddy/v2)
		"http.handlers.authentication",
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
			ID: "r1", Host: "hdr.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
			RequestHeaders:  map[string]string{"X-Real-Foo": "bar"},
			ResponseHeaders: map[string]string{"X-Custom": "x"},
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers := unwrapHandlers(httpRoutes[0])
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
		{ID: "r1", Host: "nohdr.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers := unwrapHandlers(httpRoutes[0])
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
			ID: "r1", Host: "redir.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
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
	handlers := unwrapHandlers(first)
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
	httpsHandlers := unwrapHandlers(httpsFirst)
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
			ID: "r1", Host: "noredir.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
			TLSEnabled: true, RedirectToHTTPS: false,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	httpRoutes := httpRoutesFromConfig(t, raw)
	first := httpRoutes[0]
	handlers := unwrapHandlers(first)
	if len(handlers) != 2 {
		t.Fatalf("HTTP route should keep [metrics, reverse_proxy]; got %d handlers", len(handlers))
	}
	rp, _ := handlers[1].(map[string]any)
	if rp["handler"] != "reverse_proxy" {
		t.Errorf("HTTP handler[1] = %v; want reverse_proxy (no 301)", rp["handler"])
	}

	// HTTPS side stays proxy.
	httpsRoutes := httpsServerRoutes(t, raw)
	httpsHandlers := unwrapHandlers(httpsRoutes[0])
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
			ID: "r1", Host: "plain.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
			TLSEnabled: false, RedirectToHTTPS: true,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	httpRoutes := httpRoutesFromConfig(t, raw)
	handlers := unwrapHandlers(httpRoutes[0])
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
				{ID: "r1", Host: "x.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
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
			ID: "r1", Host: "tls.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
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
				{ID: "r1", Host: "x.example.com", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin, TLSEnabled: tc.anyTLSEnabled},
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

// --- Step J.1 — Upstream pool + LB policy emission -------------------------

// firstReverseProxyHandler walks the emitted Caddy config and returns
// the first reverse_proxy handler map it finds. The Step J.1 tests use
// this to inspect the upstreams / load_balancing block without having
// to navigate the full apps.http.servers.routes.handle tree by hand.
func firstReverseProxyHandler(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	apps, _ := got["apps"].(map[string]any)
	http, _ := apps["http"].(map[string]any)
	servers, _ := http["servers"].(map[string]any)
	for _, srvAny := range servers {
		srv, _ := srvAny.(map[string]any)
		routes, _ := srv["routes"].([]any)
		for _, routeAny := range routes {
			route, _ := routeAny.(map[string]any)
			handlers := unwrapHandlers(route)
			for _, hAny := range handlers {
				h, _ := hAny.(map[string]any)
				if h["handler"] == "reverse_proxy" {
					return h
				}
			}
		}
	}
	t.Fatalf("no reverse_proxy handler found in config:\n%s", raw)
	return nil
}

// TestBuildConfigJSON_LBPolicy_<X> — one test per LB policy. Every
// policy must reach the emitted JSON as the value of
// load_balancing.selection_policy.policy, verbatim. The constants
// from storage.LBPolicy* are the single source of truth (no string
// literals in test code or generator code) — drift would be caught
// by the package failing to compile.

func TestBuildConfigJSON_LBPolicy_RoundRobin(t *testing.T) {
	assertLBPolicyEmitted(t, storage.LBPolicyRoundRobin)
}

func TestBuildConfigJSON_LBPolicy_WeightedRoundRobin(t *testing.T) {
	assertLBPolicyEmitted(t, storage.LBPolicyWeightedRoundRobin)
}

func TestBuildConfigJSON_LBPolicy_LeastConn(t *testing.T) {
	assertLBPolicyEmitted(t, storage.LBPolicyLeastConn)
}

func TestBuildConfigJSON_LBPolicy_IPHash(t *testing.T) {
	assertLBPolicyEmitted(t, storage.LBPolicyIPHash)
}

func TestBuildConfigJSON_LBPolicy_Random(t *testing.T) {
	assertLBPolicyEmitted(t, storage.LBPolicyRandom)
}

func TestBuildConfigJSON_LBPolicy_First(t *testing.T) {
	assertLBPolicyEmitted(t, storage.LBPolicyFirst)
}

// assertLBPolicyEmitted is the per-policy assertion shared by the six
// TestBuildConfigJSON_LBPolicy_<X> tests above. It builds a two-
// upstream route with the given policy, parses the emitted JSON, and
// asserts that load_balancing.selection_policy.policy matches.
func assertLBPolicyEmitted(t *testing.T, policy string) {
	t.Helper()
	routes := []storage.Route{{
		ID:   "r-policy",
		Host: "policy.local",
		Upstreams: []storage.Upstream{
			{URL: "http://127.0.0.1:9001", Weight: 1},
			{URL: "http://127.0.0.1:9002", Weight: 1},
		},
		LBPolicy: policy,
	}}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	proxy := firstReverseProxyHandler(t, raw)
	lb, ok := proxy["load_balancing"].(map[string]any)
	if !ok {
		t.Fatalf("reverse_proxy.load_balancing missing or wrong type: %+v", proxy)
	}
	sel, ok := lb["selection_policy"].(map[string]any)
	if !ok {
		t.Fatalf("load_balancing.selection_policy missing or wrong type: %+v", lb)
	}
	if got := sel["policy"]; got != policy {
		t.Errorf("selection_policy.policy = %v; want %q", got, policy)
	}
}

// TestBuildConfigJSON_WeightedRoundRobin_EmitsWeights — only the
// weighted_round_robin policy must carry a `weights` array in pool
// order. Other policies must not.
func TestBuildConfigJSON_WeightedRoundRobin_EmitsWeights(t *testing.T) {
	routes := []storage.Route{{
		ID:   "r-weighted",
		Host: "weighted.local",
		Upstreams: []storage.Upstream{
			{URL: "http://127.0.0.1:9001", Weight: 3},
			{URL: "http://127.0.0.1:9002", Weight: 1},
			{URL: "http://127.0.0.1:9003", Weight: 2},
		},
		LBPolicy: storage.LBPolicyWeightedRoundRobin,
	}}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	proxy := firstReverseProxyHandler(t, raw)
	sel := proxy["load_balancing"].(map[string]any)["selection_policy"].(map[string]any)
	weights, ok := sel["weights"].([]any)
	if !ok {
		t.Fatalf("selection_policy.weights missing or wrong type for weighted_round_robin: %+v", sel)
	}
	// JSON numbers come back as float64.
	if len(weights) != 3 {
		t.Fatalf("weights len = %d; want 3", len(weights))
	}
	want := []float64{3, 1, 2}
	for i, w := range weights {
		gotF, ok := w.(float64)
		if !ok {
			t.Fatalf("weights[%d] type = %T; want float64", i, w)
		}
		if gotF != want[i] {
			t.Errorf("weights[%d] = %v; want %v (pool order matters)", i, gotF, want[i])
		}
	}
}

// TestBuildConfigJSON_OtherPolicies_DoNotEmitWeights — the five
// non-weighted policies must NOT emit a `weights` array, even if the
// Upstream entries have non-default Weight values (Weight is ignored
// outside weighted_round_robin per §1.3 decision 1).
func TestBuildConfigJSON_OtherPolicies_DoNotEmitWeights(t *testing.T) {
	for _, policy := range []string{
		storage.LBPolicyRoundRobin,
		storage.LBPolicyLeastConn,
		storage.LBPolicyIPHash,
		storage.LBPolicyRandom,
		storage.LBPolicyFirst,
	} {
		t.Run(policy, func(t *testing.T) {
			routes := []storage.Route{{
				ID:   "r-noweights",
				Host: "noweights.local",
				Upstreams: []storage.Upstream{
					// Deliberately set non-default weights to make sure
					// the generator IGNORES them when the policy is not
					// weighted_round_robin.
					{URL: "http://127.0.0.1:9001", Weight: 5},
					{URL: "http://127.0.0.1:9002", Weight: 7},
				},
				LBPolicy: policy,
			}}
			raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
			if err != nil {
				t.Fatalf("buildConfigJSON: %v", err)
			}
			proxy := firstReverseProxyHandler(t, raw)
			sel := proxy["load_balancing"].(map[string]any)["selection_policy"].(map[string]any)
			if _, present := sel["weights"]; present {
				t.Errorf("policy %q emitted a weights array; weights must be %s-only", policy, storage.LBPolicyWeightedRoundRobin)
			}
		})
	}
}

// TestBuildConfigJSON_MultiUpstreamPool_EmitsEveryDial — a pool with
// more than one Upstream produces one {"dial": ...} entry per pool
// element, in declaration order. This is the §3.2 "Loop over r.
// Upstreams" contract.
func TestBuildConfigJSON_MultiUpstreamPool_EmitsEveryDial(t *testing.T) {
	routes := []storage.Route{{
		ID:   "r-multi",
		Host: "multi.local",
		Upstreams: []storage.Upstream{
			{URL: "http://127.0.0.1:9001", Weight: 1},
			{URL: "http://127.0.0.1:9002", Weight: 1},
			{URL: "http://127.0.0.1:9003", Weight: 1},
		},
		LBPolicy: storage.LBPolicyRoundRobin,
	}}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	proxy := firstReverseProxyHandler(t, raw)
	upstreams, ok := proxy["upstreams"].([]any)
	if !ok {
		t.Fatalf("upstreams missing or wrong type: %+v", proxy)
	}
	if len(upstreams) != 3 {
		t.Fatalf("upstreams len = %d; want 3 (one entry per pool element)", len(upstreams))
	}
	want := []string{"127.0.0.1:9001", "127.0.0.1:9002", "127.0.0.1:9003"}
	for i, uAny := range upstreams {
		u, _ := uAny.(map[string]any)
		if got := u["dial"]; got != want[i] {
			t.Errorf("upstreams[%d].dial = %v; want %q (declaration order)", i, got, want[i])
		}
	}
}

// TestBuildConfigJSON_SingleUpstreamPool_EmitsLoadBalancing — a one-
// element pool still emits a load_balancing.selection_policy block,
// per §3.2 ("Emitting the policy for a one-upstream route is harmless
// — selection is moot but valid"). This is the AC #2 behavioural
// guarantee: a migrated Step I route, which becomes a one-element
// pool with round_robin, proxies identically — the addition of the
// load_balancing block is expected, the emitted JSON shape is
// validated against §3.2, NOT against the pre-J.1 byte-equal shape.
func TestBuildConfigJSON_SingleUpstreamPool_EmitsLoadBalancing(t *testing.T) {
	routes := []storage.Route{{
		ID:   "r-single",
		Host: "single.local",
		Upstreams: []storage.Upstream{
			{URL: "http://127.0.0.1:9000", Weight: 1},
		},
		LBPolicy: storage.LBPolicyRoundRobin,
	}}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	proxy := firstReverseProxyHandler(t, raw)
	upstreams, _ := proxy["upstreams"].([]any)
	if len(upstreams) != 1 {
		t.Fatalf("upstreams len = %d; want 1 (one-element pool)", len(upstreams))
	}
	lb, ok := proxy["load_balancing"].(map[string]any)
	if !ok {
		t.Fatalf("one-upstream pool did not emit load_balancing: %+v", proxy)
	}
	sel := lb["selection_policy"].(map[string]any)
	if got := sel["policy"]; got != storage.LBPolicyRoundRobin {
		t.Errorf("single-upstream selection_policy.policy = %v; want %q", got, storage.LBPolicyRoundRobin)
	}
}

// --- Step J.2 — Active health checks emission -----------------------------

// fixtureHealthCheckEnabled returns a minimal Route with Step J.2
// active health checks turned on. The five defaultable fields carry
// their §1.3 decision-4 default values (GET / 30s / 5s / 1 / 1),
// `uri` is the operator-supplied probe path. Used by the J.2 tests
// below to share one valid fixture; per-test variations override
// the field under test.
func fixtureHealthCheckEnabled() storage.Route {
	return storage.Route{
		ID:        "r-hc",
		Host:      "hc.local",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		HealthCheck: storage.HealthCheck{
			Enabled:  true,
			URI:      "/healthz",
			Method:   "GET",
			Interval: "30s",
			Timeout:  "5s",
			Passes:   1,
			Fails:    1,
		},
	}
}

// TestBuildConfigJSON_HealthCheck_DisabledOmitsBlock — Enabled=false
// must produce a reverse_proxy handler WITHOUT a health_checks key.
// Caddy treats the absence as "no probe runs" — which is what the
// spec calls for (§5.2 "When `Enabled` is false the entire
// health_checks key is omitted").
func TestBuildConfigJSON_HealthCheck_DisabledOmitsBlock(t *testing.T) {
	routes := []storage.Route{{
		ID:        "r-no-hc",
		Host:      "no-hc.local",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		// HealthCheck zero-value → Enabled is false.
	}}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	proxy := firstReverseProxyHandler(t, raw)
	if _, present := proxy["health_checks"]; present {
		t.Errorf("disabled health check leaked into config: %+v", proxy["health_checks"])
	}
}

// TestBuildConfigJSON_HealthCheck_EnabledEmitsActive — Enabled=true
// produces a `health_checks.active` block with the six mandatory
// fields. The values come back as their JSON-decoded form
// (`interval`/`timeout` as strings, `passes`/`fails` as float64).
func TestBuildConfigJSON_HealthCheck_EnabledEmitsActive(t *testing.T) {
	routes := []storage.Route{fixtureHealthCheckEnabled()}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	proxy := firstReverseProxyHandler(t, raw)
	hc, ok := proxy["health_checks"].(map[string]any)
	if !ok {
		t.Fatalf("health_checks missing or wrong type: %+v", proxy)
	}
	active, ok := hc["active"].(map[string]any)
	if !ok {
		t.Fatalf("health_checks.active missing or wrong type: %+v", hc)
	}
	// Six fields ALWAYS emitted when Enabled (§5.2). Each must be
	// present with the fixture value.
	wantStrings := map[string]string{
		"uri":      "/healthz",
		"method":   "GET",
		"interval": "30s",
		"timeout":  "5s",
	}
	for k, want := range wantStrings {
		if got := active[k]; got != want {
			t.Errorf("active.%s = %v; want %q", k, got, want)
		}
	}
	// JSON numbers come back as float64.
	wantInts := map[string]float64{
		"passes": 1,
		"fails":  1,
	}
	for k, want := range wantInts {
		got, ok := active[k].(float64)
		if !ok {
			t.Errorf("active.%s missing or wrong type: %v", k, active[k])
			continue
		}
		if got != want {
			t.Errorf("active.%s = %v; want %v", k, got, want)
		}
	}
}

// TestBuildConfigJSON_HealthCheck_ExpectStatusConditional —
// `expect_status` is emitted ONLY when non-zero. Zero means "any
// 2xx" per Caddy's documented behaviour (§5.2 generation rule),
// and emitting it would override that default.
func TestBuildConfigJSON_HealthCheck_ExpectStatusConditional(t *testing.T) {
	t.Run("zero is omitted", func(t *testing.T) {
		r := fixtureHealthCheckEnabled()
		r.HealthCheck.ExpectStatus = 0
		raw, err := buildConfigJSON([]storage.Route{r}, buildOpts{DevMode: true})
		if err != nil {
			t.Fatalf("buildConfigJSON: %v", err)
		}
		proxy := firstReverseProxyHandler(t, raw)
		active := proxy["health_checks"].(map[string]any)["active"].(map[string]any)
		if _, present := active["expect_status"]; present {
			t.Errorf("expect_status=0 leaked into config: %v", active["expect_status"])
		}
	})

	t.Run("non-zero is emitted", func(t *testing.T) {
		r := fixtureHealthCheckEnabled()
		r.HealthCheck.ExpectStatus = 204
		raw, err := buildConfigJSON([]storage.Route{r}, buildOpts{DevMode: true})
		if err != nil {
			t.Fatalf("buildConfigJSON: %v", err)
		}
		proxy := firstReverseProxyHandler(t, raw)
		active := proxy["health_checks"].(map[string]any)["active"].(map[string]any)
		got, ok := active["expect_status"].(float64)
		if !ok {
			t.Fatalf("expect_status missing or wrong type: %v", active["expect_status"])
		}
		if got != 204 {
			t.Errorf("expect_status = %v; want 204", got)
		}
	})
}

// TestBuildConfigJSON_HealthCheck_ExpectBodyConditional —
// `expect_body` is emitted ONLY when non-empty. An empty regex
// means "no body check"; emitting "" would compile-fail at Caddy's
// Provision (§5.2 generation rule).
func TestBuildConfigJSON_HealthCheck_ExpectBodyConditional(t *testing.T) {
	t.Run("empty is omitted", func(t *testing.T) {
		r := fixtureHealthCheckEnabled()
		r.HealthCheck.ExpectBody = ""
		raw, err := buildConfigJSON([]storage.Route{r}, buildOpts{DevMode: true})
		if err != nil {
			t.Fatalf("buildConfigJSON: %v", err)
		}
		proxy := firstReverseProxyHandler(t, raw)
		active := proxy["health_checks"].(map[string]any)["active"].(map[string]any)
		if _, present := active["expect_body"]; present {
			t.Errorf("empty expect_body leaked into config: %v", active["expect_body"])
		}
	})

	t.Run("non-empty is emitted verbatim", func(t *testing.T) {
		r := fixtureHealthCheckEnabled()
		r.HealthCheck.ExpectBody = "^OK$"
		raw, err := buildConfigJSON([]storage.Route{r}, buildOpts{DevMode: true})
		if err != nil {
			t.Fatalf("buildConfigJSON: %v", err)
		}
		proxy := firstReverseProxyHandler(t, raw)
		active := proxy["health_checks"].(map[string]any)["active"].(map[string]any)
		if got := active["expect_body"]; got != "^OK$" {
			t.Errorf("expect_body = %v; want %q", got, "^OK$")
		}
	})
}

// TestBuildConfigJSON_HealthCheck_FieldValuesFlowVerbatim — each
// of the six mandatory fields is passed through to the emitted
// JSON verbatim (not just the defaults). Catches a future
// regression where the generator hardcodes a value or applies a
// transformation.
func TestBuildConfigJSON_HealthCheck_FieldValuesFlowVerbatim(t *testing.T) {
	r := fixtureHealthCheckEnabled()
	r.HealthCheck.URI = "/custom/probe"
	r.HealthCheck.Method = "HEAD"
	r.HealthCheck.Interval = "45s"
	r.HealthCheck.Timeout = "7s"
	r.HealthCheck.Passes = 3
	r.HealthCheck.Fails = 5

	raw, err := buildConfigJSON([]storage.Route{r}, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	proxy := firstReverseProxyHandler(t, raw)
	active := proxy["health_checks"].(map[string]any)["active"].(map[string]any)
	if got := active["uri"]; got != "/custom/probe" {
		t.Errorf("uri = %v; want /custom/probe", got)
	}
	if got := active["method"]; got != "HEAD" {
		t.Errorf("method = %v; want HEAD", got)
	}
	if got := active["interval"]; got != "45s" {
		t.Errorf("interval = %v; want 45s", got)
	}
	if got := active["timeout"]; got != "7s" {
		t.Errorf("timeout = %v; want 7s", got)
	}
	if got, _ := active["passes"].(float64); got != 3 {
		t.Errorf("passes = %v; want 3", got)
	}
	if got, _ := active["fails"].(float64); got != 5 {
		t.Errorf("fails = %v; want 5", got)
	}
}

// TestBuildConfigJSON_LoadsCleanly_ForwardAuth is the Step K.1
// counterpart to TestBuildConfigJSON_LoadsCleanly and
// TestBuildConfigJSON_LoadsCleanly_DNS01: a route configured for
// forward_auth with a fixture provider, fed through caddy.Validate
// to confirm the emitted subroute / reverse_proxy / handle_response
// shape provisions cleanly. The forward_auth handler relies on
// modules from the Caddy standard set (reverse_proxy, headers,
// vars, handle_response) — all already imported via the
// modules/standard blank import, no new dependency.
func TestBuildConfigJSON_LoadsCleanly_ForwardAuth(t *testing.T) {
	routes := []storage.Route{
		{
			ID:        "r-fa",
			Host:      "protected.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
			AuthMode:  storage.RouteAuthForwardAuth,
			ForwardAuth: storage.ForwardAuthRouteConfig{
				ProviderName: "authelia-prod",
			},
		},
	}
	metrics.SetRegistry(metrics.NewRegistry())

	opts := buildOpts{
		DevMode: true,
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{
			"authelia-prod": {
				Name:           "authelia-prod",
				Kind:           "authelia",
				VerifyURL:      "http://127.0.0.1:9091",
				AuthRequestURI: "/api/authz/forward-auth",
				CopyHeaders:    []string{"Remote-User", "Remote-Email"},
			},
		},
	}
	raw, err := buildConfigJSON(routes, opts)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	var cfg caddy.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v\n%s", err, raw)
	}
	if err := caddy.Validate(&cfg); err != nil {
		t.Fatalf("caddy.Validate failed on forward_auth config: %v\n%s", err, raw)
	}

	// Shape assertion: the auth handler emitted must be the
	// reverse_proxy variant with handle_response, the IdP dial
	// must be the provider's VerifyURL, and the rewrite.uri must
	// be the provider's AuthRequestURI.
	var full map[string]any
	if err := json.Unmarshal(raw, &full); err != nil {
		t.Fatalf("unmarshal full: %v", err)
	}
	servers := full["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	httpSrv := servers["arenet_http"].(map[string]any)
	httpRoutes := httpSrv["routes"].([]any)
	target := findRouteByHost(t, httpRoutes, "protected.example.com")
	handlers := unwrapHandlers(target)
	// Chain: [metrics, forward_auth_proxy, ..., real_proxy]. The
	// forward_auth handler is at index 1 (right after metrics).
	if len(handlers) < 3 {
		t.Fatalf("handler chain too short: %v", handlers)
	}
	faHandler := handlers[1].(map[string]any)
	if faHandler["handler"] != "reverse_proxy" {
		t.Errorf("forward_auth handler is %v; want reverse_proxy", faHandler["handler"])
	}
	upstreams := faHandler["upstreams"].([]any)
	if dial := upstreams[0].(map[string]any)["dial"]; dial != "127.0.0.1:9091" {
		t.Errorf("forward_auth dial = %v; want 127.0.0.1:9091", dial)
	}
	rewrite := faHandler["rewrite"].(map[string]any)
	if uri := rewrite["uri"]; uri != "/api/authz/forward-auth" {
		t.Errorf("forward_auth rewrite.uri = %v; want /api/authz/forward-auth", uri)
	}
	// The handle_response block must contain two header-handling
	// routes per copied header (delete + conditional set), plus
	// the leading "vars" route.
	hr := faHandler["handle_response"].([]any)
	if len(hr) != 1 {
		t.Fatalf("handle_response: got %d blocks, want 1", len(hr))
	}
	hrRoutes := hr[0].(map[string]any)["routes"].([]any)
	// 1 vars + 2 per header * 2 headers = 5 routes.
	if len(hrRoutes) != 5 {
		t.Errorf("handle_response inner routes = %d; want 5 (vars + 2*2 headers)", len(hrRoutes))
	}
}

// TestBuildConfigJSON_ForwardAuth_UnknownProvider_FailsClosed
// pins the security-critical fail-closed contract: a route with
// AuthMode = "forward_auth" referencing a provider name that
// doesn't exist in opts.ForwardAuthProviders MUST NOT serve
// traffic to its upstream. The API rejects this state at edit
// time (and DELETE on a referenced provider is rejected with
// 409), so reaching this code path requires a corruption / a
// direct BoltDB edit / a bug class we haven't imagined — but
// for an auth control, the failure mode must be "route
// unavailable" (503, visible) rather than "route exposed
// without auth" (the catastrophic fail-OPEN that the original
// implementation produced; the previous test name
// "FallsBackQuietly" was itself the alarm bell).
//
// The emitted route MUST:
//   - Carry a static_response 503 handler instead of the IdP
//     forward_auth + reverse_proxy chain.
//   - NOT carry a `reverse_proxy` to the user's configured
//     upstream (that's the fail-open path we're guarding
//     against — a regression that re-introduced it would
//     silently expose the upstream as public).
//   - NOT carry an `authentication` (Basic Auth) handler — the
//     route's AuthMode was forward_auth, not basic; we don't
//     accidentally fall back to a different auth mode either.
//   - Pass caddy.Validate() so the reload doesn't fail when
//     the operator's last good config drifts into this edge.
func TestBuildConfigJSON_ForwardAuth_UnknownProvider_FailsClosed(t *testing.T) {
	routes := []storage.Route{
		{
			ID:        "r-orphan",
			Host:      "orphan.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
			AuthMode:  storage.RouteAuthForwardAuth,
			ForwardAuth: storage.ForwardAuthRouteConfig{
				ProviderName: "does-not-exist",
			},
		},
	}
	metrics.SetRegistry(metrics.NewRegistry())
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	var cfg caddy.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v\n%s", err, raw)
	}
	if err := caddy.Validate(&cfg); err != nil {
		t.Fatalf("caddy.Validate must accept the fail-closed shape: %v\n%s", err, raw)
	}

	var full map[string]any
	if err := json.Unmarshal(raw, &full); err != nil {
		t.Fatalf("unmarshal full: %v", err)
	}
	servers := full["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	httpSrv := servers["arenet_http"].(map[string]any)
	httpRoutes := httpSrv["routes"].([]any)
	target := findRouteByHost(t, httpRoutes, "orphan.example.com")
	handlers := unwrapHandlers(target)

	// Assertion 1: the static_response 503 deny handler IS present.
	var denyHandler map[string]any
	for _, h := range handlers {
		m := h.(map[string]any)
		if m["handler"] == "static_response" {
			denyHandler = m
			break
		}
	}
	if denyHandler == nil {
		t.Fatalf("expected static_response deny handler in fail-closed chain; got %v", handlers)
	}
	// status_code must be 503 (numeric in JSON).
	switch sc := denyHandler["status_code"].(type) {
	case float64:
		if sc != 503 {
			t.Errorf("deny handler status_code = %v; want 503", sc)
		}
	case int:
		if sc != 503 {
			t.Errorf("deny handler status_code = %v; want 503", sc)
		}
	default:
		t.Errorf("deny handler status_code is not numeric: %T %v", sc, sc)
	}
	// Body should name the missing provider for operator visibility.
	if body, _ := denyHandler["body"].(string); !strings.Contains(body, "does-not-exist") {
		t.Errorf("deny handler body should name the missing provider; got %q", body)
	}

	// Assertion 2 — the critical fail-CLOSED invariant: the
	// reverse_proxy to the user's upstream MUST NOT be in the
	// chain. A regression that re-introduces it is a
	// catastrophic auth bypass.
	for _, h := range handlers {
		m := h.(map[string]any)
		if m["handler"] != "reverse_proxy" {
			continue
		}
		// reverse_proxy is allowed ONLY if it dials the IdP
		// (forward_auth handler shape), not the user upstream.
		// In the fail-closed path the IdP itself is unknown, so
		// no reverse_proxy should appear at all.
		t.Errorf("FAIL-OPEN REGRESSION: reverse_proxy handler emitted in unknown-provider chain; "+
			"the route's upstream is exposed without authentication. Handler: %v", m)
	}

	// Assertion 3: no accidental fall-back to Basic Auth.
	for _, h := range handlers {
		m := h.(map[string]any)
		if m["handler"] == "authentication" {
			t.Errorf("unexpected authentication handler in fail-closed chain (auth mode was forward_auth): %v", m)
		}
	}
}

// TestBuildConfigJSON_ForwardAuth_PassthroughPrefix_BypassesGate
// pins the Step K.4 contract: a provider with a non-empty
// AuthPassthroughPrefix emits an ADDITIONAL httpRoute matching
// the path prefix on the same Host, whose handler chain has NO
// forward_auth gate (just a reverse_proxy to the verify URL
// host). Caddy dispatches routes in declaration order — the
// prefixed route MUST land before the catch-all main route so
// it claims its subtree first.
func TestBuildConfigJSON_ForwardAuth_PassthroughPrefix_BypassesGate(t *testing.T) {
	routes := []storage.Route{
		{
			ID:        "r-fa-pt",
			Host:      "protected.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
			AuthMode:  storage.RouteAuthForwardAuth,
			ForwardAuth: storage.ForwardAuthRouteConfig{
				ProviderName: "authentik-pt",
			},
		},
	}
	metrics.SetRegistry(metrics.NewRegistry())

	opts := buildOpts{
		DevMode: true,
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{
			"authentik-pt": {
				Name:                  "authentik-pt",
				Kind:                  "authentik",
				VerifyURL:             "https://auth.example.com/outpost.goauthentik.io/auth/caddy",
				AuthRequestURI:        "/outpost.goauthentik.io/auth/caddy",
				CopyHeaders:           []string{"X-Authentik-Username"},
				AuthPassthroughPrefix: "/outpost.goauthentik.io",
			},
		},
	}
	raw, err := buildConfigJSON(routes, opts)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var cfg caddy.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v\n%s", err, raw)
	}
	if err := caddy.Validate(&cfg); err != nil {
		t.Fatalf("caddy.Validate failed on passthrough config: %v\n%s", err, raw)
	}

	var full map[string]any
	if err := json.Unmarshal(raw, &full); err != nil {
		t.Fatalf("unmarshal full: %v", err)
	}
	servers := full["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	httpSrv := servers["arenet_http"].(map[string]any)
	httpRoutes := httpSrv["routes"].([]any)

	// Find the passthrough route: same host, has Path matcher
	// equal to "/outpost.goauthentik.io/*".
	passthroughIdx := -1
	mainIdx := -1
	for i, r := range httpRoutes {
		m := r.(map[string]any)
		matchSets, _ := m["match"].([]any)
		if len(matchSets) == 0 {
			continue
		}
		ms := matchSets[0].(map[string]any)
		hosts, _ := ms["host"].([]any)
		hostMatch := false
		for _, h := range hosts {
			if h == "protected.example.com" {
				hostMatch = true
				break
			}
		}
		if !hostMatch {
			continue
		}
		path, _ := ms["path"].([]any)
		if len(path) > 0 && path[0] == "/outpost.goauthentik.io/*" {
			passthroughIdx = i
		} else if len(path) == 0 {
			mainIdx = i
		}
	}
	if passthroughIdx < 0 {
		t.Fatalf("passthrough route not emitted; httpRoutes: %v", httpRoutes)
	}
	if mainIdx < 0 {
		t.Fatalf("main route not emitted")
	}
	// Order: passthrough MUST come before main, otherwise the
	// catch-all main route on the same Host would claim the
	// passthrough path first.
	if passthroughIdx >= mainIdx {
		t.Fatalf("PASSTHROUGH ORDERING REGRESSION: passthrough route idx=%d is at or after main route idx=%d; the main host route would claim the passthrough path before the passthrough route gets a chance", passthroughIdx, mainIdx)
	}

	// The passthrough route's handler chain MUST be just one
	// reverse_proxy to the verify URL's host. No forward_auth,
	// no static_response.
	ptRoute := httpRoutes[passthroughIdx].(map[string]any)
	ptHandlers := unwrapHandlers(ptRoute)
	if len(ptHandlers) != 1 {
		t.Fatalf("PASSTHROUGH SHAPE REGRESSION: passthrough chain length = %d; want 1 (single reverse_proxy)", len(ptHandlers))
	}
	rp := ptHandlers[0].(map[string]any)
	// Step K.4 parity — ALSO verify the canonical subroute
	// wrapper is in place and the route is terminal.
	if outer, _ := ptRoute["handle"].([]any); len(outer) != 1 || outer[0].(map[string]any)["handler"] != "subroute" {
		t.Errorf("PARITY REGRESSION: passthrough route is not wrapped in subroute (canonical Caddyfile shape)")
	}
	if ptRoute["terminal"] != true {
		t.Errorf("PARITY REGRESSION: passthrough route is not terminal (must short-circuit dispatch)")
	}
	if rp["handler"] != "reverse_proxy" {
		t.Errorf("passthrough handler = %v; want reverse_proxy", rp["handler"])
	}
	// No "rewrite" (forward_auth uses rewrite) — the
	// passthrough is a straight reverse-proxy.
	if _, hasRewrite := rp["rewrite"]; hasRewrite {
		t.Error("PASSTHROUGH BYPASS REGRESSION: passthrough route emitted a rewrite block (forward_auth shape leaked); the passthrough must be a straight reverse_proxy")
	}
	// No "handle_response" (forward_auth's copy-header block).
	if _, hasHR := rp["handle_response"]; hasHR {
		t.Error("PASSTHROUGH BYPASS REGRESSION: passthrough route emitted handle_response (forward_auth shape leaked)")
	}
	// Upstream dial must be the verify URL's host:port.
	dial := rp["upstreams"].([]any)[0].(map[string]any)["dial"]
	if dial != "auth.example.com:443" {
		t.Errorf("passthrough dial = %v; want auth.example.com:443", dial)
	}
}

// TestBuildConfigJSON_ForwardAuth_PassthroughEmpty_NoExtraRoute
// pins the regression boundary: AuthPassthroughPrefix="" keeps
// the legacy K.1 behaviour byte-identical (no extra route
// emitted, no Path matcher on the main route).
func TestBuildConfigJSON_ForwardAuth_PassthroughEmpty_NoExtraRoute(t *testing.T) {
	routes := []storage.Route{
		{
			ID:        "r-fa-legacy",
			Host:      "legacy.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
			AuthMode:  storage.RouteAuthForwardAuth,
			ForwardAuth: storage.ForwardAuthRouteConfig{
				ProviderName: "authelia-legacy",
			},
		},
	}
	metrics.SetRegistry(metrics.NewRegistry())

	opts := buildOpts{
		DevMode: true,
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{
			"authelia-legacy": {
				Name:           "authelia-legacy",
				Kind:           "authelia",
				VerifyURL:      "http://127.0.0.1:9091",
				AuthRequestURI: "/api/authz/forward-auth",
				CopyHeaders:    []string{"Remote-User"},
				// AuthPassthroughPrefix intentionally empty.
			},
		},
	}
	raw, err := buildConfigJSON(routes, opts)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var full map[string]any
	if err := json.Unmarshal(raw, &full); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	servers := full["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	httpSrv := servers["arenet_http"].(map[string]any)
	httpRoutes := httpSrv["routes"].([]any)

	hostMatches := 0
	for _, r := range httpRoutes {
		m := r.(map[string]any)
		matchSets, _ := m["match"].([]any)
		if len(matchSets) == 0 {
			continue
		}
		ms := matchSets[0].(map[string]any)
		hosts, _ := ms["host"].([]any)
		for _, h := range hosts {
			if h == "legacy.example.com" {
				hostMatches++
				// The main route MUST NOT carry a Path matcher
				// — legacy shape is host-only.
				if path, hasPath := ms["path"]; hasPath && path != nil {
					t.Errorf("LEGACY SHAPE REGRESSION: main route gained a Path matcher %v with empty AuthPassthroughPrefix", path)
				}
			}
		}
	}
	if hostMatches != 1 {
		t.Fatalf("LEGACY ADD-ONLY REGRESSION: expected exactly 1 httpRoute for legacy.example.com, got %d", hostMatches)
	}
}

// TestBuildConfigJSON_ForwardAuth_HTTPSVerifyURL_UsesTLSTransport
// pins the K.4 smoke-time fix: when the provider's VerifyURL is
// HTTPS the forward_auth sub-request MUST be sent over TLS. The
// previous K.1 generator omitted the transport block, so Caddy
// defaulted to plain HTTP — every IdP that exposes its verify
// endpoint on https (Authentik embedded outpost is the common
// case) returned 400 "Client sent HTTP to HTTPS server" on every
// sub-request, refusing every requester (same outcome as
// fail-closed, but for the wrong reason — operator can't tell
// "my IdP is rejecting" from "my Arenet config is bugged").
func TestBuildConfigJSON_ForwardAuth_HTTPSVerifyURL_UsesTLSTransport(t *testing.T) {
	routes := []storage.Route{
		{
			ID:        "r-fa-https",
			Host:      "tls-protected.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
			AuthMode:  storage.RouteAuthForwardAuth,
			ForwardAuth: storage.ForwardAuthRouteConfig{
				ProviderName: "authentik-tls",
			},
		},
	}
	metrics.SetRegistry(metrics.NewRegistry())

	opts := buildOpts{
		DevMode: true,
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{
			"authentik-tls": {
				Name:           "authentik-tls",
				Kind:           "authentik",
				VerifyURL:      "https://auth.example.com/outpost.goauthentik.io/auth/caddy",
				AuthRequestURI: "/outpost.goauthentik.io/auth/caddy",
				CopyHeaders:    []string{"X-Authentik-Username"},
			},
		},
	}
	raw, err := buildConfigJSON(routes, opts)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var full map[string]any
	if err := json.Unmarshal(raw, &full); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	servers := full["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	httpSrv := servers["arenet_http"].(map[string]any)
	httpRoutes := httpSrv["routes"].([]any)
	target := findRouteByHost(t, httpRoutes, "tls-protected.example.com")
	handlers := unwrapHandlers(target)
	// forward_auth handler is at index 1 (after metrics).
	fa := handlers[1].(map[string]any)
	transport, ok := fa["transport"].(map[string]any)
	if !ok {
		t.Fatalf("TLS TRANSPORT REGRESSION: forward_auth handler missing transport block for HTTPS VerifyURL; Caddy will default to plain HTTP and the IdP will reject every sub-request with 400. Handler: %v", fa)
	}
	if _, hasTLS := transport["tls"]; !hasTLS {
		t.Errorf("TLS TRANSPORT REGRESSION: transport block missing tls field: %v", transport)
	}
	if transport["protocol"] != "http" {
		t.Errorf("transport.protocol = %v; want \"http\" (the HTTP-over-TLS protocol)", transport["protocol"])
	}
}

func TestBuildConfigJSON_ForwardAuth_HTTPVerifyURL_NoTLSTransport(t *testing.T) {
	// Inverse: HTTP verify URL must NOT add a transport block —
	// staying byte-identical with the K.1 pre-fix shape so legacy
	// plain-HTTP providers (typical local Authelia setup) keep
	// working.
	routes := []storage.Route{
		{
			ID:        "r-fa-http-only",
			Host:      "plain-http.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
			AuthMode:  storage.RouteAuthForwardAuth,
			ForwardAuth: storage.ForwardAuthRouteConfig{
				ProviderName: "authelia-plain",
			},
		},
	}
	metrics.SetRegistry(metrics.NewRegistry())
	opts := buildOpts{
		DevMode: true,
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{
			"authelia-plain": {
				Name:           "authelia-plain",
				Kind:           "authelia",
				VerifyURL:      "http://127.0.0.1:9091",
				AuthRequestURI: "/api/authz/forward-auth",
				CopyHeaders:    []string{"Remote-User"},
			},
		},
	}
	raw, err := buildConfigJSON(routes, opts)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var full map[string]any
	_ = json.Unmarshal(raw, &full)
	servers := full["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	httpRoutes := servers["arenet_http"].(map[string]any)["routes"].([]any)
	target := findRouteByHost(t, httpRoutes, "plain-http.example.com")
	fa := unwrapHandlers(target)[1].(map[string]any)
	if _, hasTransport := fa["transport"]; hasTransport {
		t.Errorf("LEGACY SHAPE REGRESSION: HTTP-only verify URL gained a transport block: %v", fa["transport"])
	}
}

// TestBuildConfigJSON_ForwardAuth_PassthroughPrefix_FailsClosed_NoPassthroughEmitted
// pins the security-critical corner of the K.4 matrix: when the
// route's referenced forward-auth provider does NOT resolve (a
// state reachable only via storage corruption / migration drift
// / direct BoltDB edit per the K.1 invariants, NEVER through
// the API), the FAIL-CLOSED deny path MUST short-circuit
// completely — even when an AuthPassthroughPrefix was set on
// some OTHER provider that happens to share the name slot. The
// passthrough route must NOT be emitted: it would dial straight
// to the verify URL host bypassing every gate, leaking the
// IdP's UI to an unauthenticated request on a route the
// operator intended to protect.
//
// Mirror of TestBuildConfigJSON_ForwardAuth_UnknownProvider_
// FailsClosed but with the K.4 passthrough field involved:
// proves that the deny path's "STOP appending to the chain"
// also stops the passthrough emission.
func TestBuildConfigJSON_ForwardAuth_PassthroughPrefix_FailsClosed_NoPassthroughEmitted(t *testing.T) {
	routes := []storage.Route{
		{
			ID:        "r-fa-deny-pt",
			Host:      "orphan-with-pt.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
			AuthMode:  storage.RouteAuthForwardAuth,
			ForwardAuth: storage.ForwardAuthRouteConfig{
				ProviderName: "does-not-exist",
			},
		},
	}
	metrics.SetRegistry(metrics.NewRegistry())

	// The map carries a DIFFERENT provider name AND that provider
	// DOES declare a passthrough prefix. The route references
	// "does-not-exist" which is NOT this entry — the resolution
	// must fail, the deny chain must fire, and the passthrough
	// MUST NOT be emitted (the resolved-provider pointer never
	// gets set in the loop).
	opts := buildOpts{
		DevMode: true,
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{
			"some-other-provider": {
				Name:                  "some-other-provider",
				Kind:                  "authentik",
				VerifyURL:             "https://auth.example.com/outpost.goauthentik.io/auth/caddy",
				AuthRequestURI:        "/outpost.goauthentik.io/auth/caddy",
				CopyHeaders:           []string{"X-Authentik-Username"},
				AuthPassthroughPrefix: "/outpost.goauthentik.io",
			},
		},
	}
	raw, err := buildConfigJSON(routes, opts)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	var full map[string]any
	if err := json.Unmarshal(raw, &full); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	servers := full["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	httpSrv := servers["arenet_http"].(map[string]any)
	httpRoutes := httpSrv["routes"].([]any)

	// Enumerate every route claiming this host. Expect EXACTLY
	// ONE (the deny route) — zero passthroughs, zero reverse-
	// proxy chains to the user upstream.
	matchingHostRoutes := 0
	for _, r := range httpRoutes {
		m := r.(map[string]any)
		matchSets, _ := m["match"].([]any)
		for _, ms := range matchSets {
			hosts, _ := ms.(map[string]any)["host"].([]any)
			for _, h := range hosts {
				if h == "orphan-with-pt.example.com" {
					matchingHostRoutes++
					// If this is the passthrough route, it would
					// carry a Path matcher. Its mere presence here
					// is the regression.
					if path, hasPath := ms.(map[string]any)["path"]; hasPath && path != nil {
						t.Errorf("PASSTHROUGH FAIL-OPEN REGRESSION: passthrough route emitted on the deny path; an attacker can reach the IdP-side path %v without authentication. The deny chain MUST short-circuit BEFORE the passthrough emission.", path)
					}
				}
			}
		}
	}
	if matchingHostRoutes != 1 {
		t.Fatalf("DENY CHAIN BYPASS REGRESSION: expected exactly 1 httpRoute on the unresolved-provider host (the deny static_response), got %d. A second route on this host means the chain leaked past the FAIL-CLOSED short-circuit.", matchingHostRoutes)
	}

	// Pin the chain shape: single static_response 503 handler,
	// no reverse_proxy of any kind.
	target := findRouteByHost(t, httpRoutes, "orphan-with-pt.example.com")
	handlers := unwrapHandlers(target)
	for _, h := range handlers {
		m := h.(map[string]any)
		if m["handler"] == "reverse_proxy" {
			t.Errorf("PASSTHROUGH FAIL-OPEN REGRESSION: reverse_proxy emitted on the deny path; the K.4 passthrough leaked into the unresolved-provider chain. Handler: %v", m)
		}
	}
}

// TestBuildConfigJSON_ForwardAuth_RewriteVerifyHost_HostSetToUpstream
// pins the K.4 Host opt-in: when the provider has
// RewriteVerifyHost=true, the forward_auth handler emits a
// headers.request.set.Host pointing at the verify URL's
// hostport. Default false (legacy) does NOT set Host (canonical
// Caddy expansion propagates client Host).
func TestBuildConfigJSON_ForwardAuth_RewriteVerifyHost_HostSetToUpstream(t *testing.T) {
	routes := []storage.Route{
		{
			ID:        "r-fa-host-rw",
			Host:      "protected.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
			AuthMode:  storage.RouteAuthForwardAuth,
			ForwardAuth: storage.ForwardAuthRouteConfig{
				ProviderName: "authentik-embedded",
			},
		},
	}
	metrics.SetRegistry(metrics.NewRegistry())
	opts := buildOpts{
		DevMode: true,
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{
			"authentik-embedded": {
				Name:              "authentik-embedded",
				Kind:              "authentik",
				VerifyURL:         "https://auth.example.com/outpost.goauthentik.io/auth/caddy",
				AuthRequestURI:    "/outpost.goauthentik.io/auth/caddy",
				CopyHeaders:       []string{"X-Authentik-Username"},
				RewriteVerifyHost: true,
			},
		},
	}
	raw, err := buildConfigJSON(routes, opts)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var full map[string]any
	_ = json.Unmarshal(raw, &full)
	servers := full["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	httpRoutes := servers["arenet_http"].(map[string]any)["routes"].([]any)
	target := findRouteByHost(t, httpRoutes, "protected.example.com")
	// forward_auth handler is at index 1 (after metrics) inside
	// the unwrapped subroute chain.
	fa := unwrapHandlers(target)[1].(map[string]any)
	headers := fa["headers"].(map[string]any)["request"].(map[string]any)["set"].(map[string]any)
	hostVal, ok := headers["Host"]
	if !ok {
		t.Fatalf("HOST REWRITE REGRESSION: RewriteVerifyHost=true did not emit headers.request.set.Host on the forward_auth sub-request. headers: %v", headers)
	}
	hostList := hostVal.([]any)
	if len(hostList) != 1 || hostList[0] != "auth.example.com" {
		t.Errorf("Host set to %v; want [\"auth.example.com\"]", hostList)
	}
}

func TestBuildConfigJSON_ForwardAuth_RewriteVerifyHost_DefaultFalse_NoHostSet(t *testing.T) {
	// Inverse: default RewriteVerifyHost=false preserves the
	// canonical Caddyfile shape (no Host in headers.request.set).
	// Authelia + Keycloak + Authentik external outpost compat.
	routes := []storage.Route{
		{
			ID:        "r-fa-canon",
			Host:      "canon.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
			AuthMode:  storage.RouteAuthForwardAuth,
			ForwardAuth: storage.ForwardAuthRouteConfig{
				ProviderName: "authelia-canon",
			},
		},
	}
	metrics.SetRegistry(metrics.NewRegistry())
	opts := buildOpts{
		DevMode: true,
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{
			"authelia-canon": {
				Name:           "authelia-canon",
				Kind:           "authelia",
				VerifyURL:      "http://127.0.0.1:9091",
				AuthRequestURI: "/api/authz/forward-auth",
				CopyHeaders:    []string{"Remote-User"},
				// RewriteVerifyHost intentionally false.
			},
		},
	}
	raw, err := buildConfigJSON(routes, opts)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var full map[string]any
	_ = json.Unmarshal(raw, &full)
	servers := full["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	httpRoutes := servers["arenet_http"].(map[string]any)["routes"].([]any)
	target := findRouteByHost(t, httpRoutes, "canon.example.com")
	fa := unwrapHandlers(target)[1].(map[string]any)
	headers := fa["headers"].(map[string]any)["request"].(map[string]any)["set"].(map[string]any)
	if _, hasHost := headers["Host"]; hasHost {
		t.Errorf("CANONICAL SHAPE REGRESSION: Host header was set on the sub-request without RewriteVerifyHost opt-in. headers: %v", headers)
	}
}

// TestBuildConfigJSON_ForwardAuth_RouteIsTerminal pins the K.4
// parity defence-in-depth: every Step-K route (main,
// passthrough, deny) MUST carry terminal=true so the dispatcher
// does NOT match another route after this one. Without
// terminal, a future route addition on the same Host (e.g.
// catch-all, redirect) could accidentally also fire — a class
// of bug the canonical Caddyfile expansion eliminates by
// emitting terminal on every forward_auth route.
func TestBuildConfigJSON_ForwardAuth_RouteIsTerminal(t *testing.T) {
	routes := []storage.Route{
		{
			ID:        "r-term",
			Host:      "terminal.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
			AuthMode:  storage.RouteAuthForwardAuth,
			ForwardAuth: storage.ForwardAuthRouteConfig{
				ProviderName: "fa-term",
			},
		},
	}
	metrics.SetRegistry(metrics.NewRegistry())
	opts := buildOpts{
		DevMode: true,
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{
			"fa-term": {
				Name:                  "fa-term",
				Kind:                  "authentik",
				VerifyURL:             "https://auth.example.com/outpost.goauthentik.io/auth/caddy",
				AuthRequestURI:        "/outpost.goauthentik.io/auth/caddy",
				CopyHeaders:           []string{"X-Authentik-Username"},
				AuthPassthroughPrefix: "/outpost.goauthentik.io",
			},
		},
	}
	raw, _ := buildConfigJSON(routes, opts)
	var full map[string]any
	_ = json.Unmarshal(raw, &full)
	servers := full["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	httpRoutes := servers["arenet_http"].(map[string]any)["routes"].([]any)
	hostRoutes := 0
	for _, r := range httpRoutes {
		m := r.(map[string]any)
		matchSets, _ := m["match"].([]any)
		for _, ms := range matchSets {
			hosts, _ := ms.(map[string]any)["host"].([]any)
			for _, h := range hosts {
				if h == "terminal.example.com" {
					hostRoutes++
					if m["terminal"] != true {
						paths, _ := ms.(map[string]any)["path"].([]any)
						t.Errorf("TERMINAL REGRESSION: route on host=terminal.example.com path=%v is NOT terminal; canonical Caddyfile shape requires every forward_auth route to short-circuit", paths)
					}
					outer, _ := m["handle"].([]any)
					if len(outer) != 1 || outer[0].(map[string]any)["handler"] != "subroute" {
						t.Errorf("PARITY REGRESSION: route handle is not wrapped in canonical subroute")
					}
				}
			}
		}
	}
	if hostRoutes != 2 {
		t.Fatalf("expected 2 routes on terminal.example.com (passthrough + main), got %d", hostRoutes)
	}
}

// unwrapHandlers (Step K.4 parity fix) returns the flat handler
// chain inside a route, peeling off the canonical `subroute`
// wrapper that the K.4 generator emits. Routes that don't carry
// a single subroute (rare — legacy non-Step-K builds) are
// returned as-is. Tests that assert on handler shape use this
// instead of indexing route["handle"] directly so they stay
// agnostic of the wrapping layer.
func unwrapHandlers(route map[string]any) []any {
	raw, _ := route["handle"].([]any)
	if len(raw) != 1 {
		return raw
	}
	outer, ok := raw[0].(map[string]any)
	if !ok || outer["handler"] != "subroute" {
		return raw
	}
	subRoutes, ok := outer["routes"].([]any)
	if !ok {
		return raw
	}
	flat := make([]any, 0, len(subRoutes))
	for _, sr := range subRoutes {
		srMap, ok := sr.(map[string]any)
		if !ok {
			continue
		}
		inner, ok := srMap["handle"].([]any)
		if !ok {
			continue
		}
		flat = append(flat, inner...)
	}
	return flat
}

// findRouteByHost walks the httpRoutes array (Caddy JSON config
// shape) and returns the first entry whose match.host contains
func findRouteByHost(t *testing.T, routes []any, host string) map[string]any {
	t.Helper()
	for _, r := range routes {
		m := r.(map[string]any)
		matchSets, ok := m["match"].([]any)
		if !ok {
			continue
		}
		for _, ms := range matchSets {
			hosts := ms.(map[string]any)["host"]
			if hosts == nil {
				continue
			}
			for _, h := range hosts.([]any) {
				if h == host {
					return m
				}
			}
		}
	}
	t.Fatalf("route for host %q not found in config", host)
	return nil
}
