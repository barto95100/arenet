// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package caddymgr

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// TestBuildConfigJSON_DisabledRoute_NotEmitted pins that a disabled
// route contributes nothing to the emitted Caddy config: no HTTP/HTTPS
// route for its host, and no ACME subject (so Caddy never requests a
// cert for a disabled host — the rate-limit-safety invariant).
//
// NOTE: buildConfigJSON emits what it is given; the disabled FILTER
// lives in applyLocked (which reads storage then calls buildConfigJSON).
// So this test filters the slice the same way applyLocked will, and
// asserts the emitted JSON. A companion assertion (that the UNFILTERED
// slice WOULD have emitted the host) proves the host is otherwise valid.
func TestBuildConfigJSON_DisabledRoute_NotEmitted(t *testing.T) {
	routes := []storage.Route{
		{
			ID: "r-live", Host: "live.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin, TLSEnabled: true,
			ACMEChallenge: storage.ACMEChallengeHTTP01, WAFMode: "off",
		},
		{
			ID: "r-off", Host: "off.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin, TLSEnabled: true,
			ACMEChallenge: storage.ACMEChallengeHTTP01, WAFMode: "off",
			Disabled: true,
		},
	}
	// Sanity: unfiltered emission DOES include off.example.com.
	rawAll, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON(all): %v", err)
	}
	if !strings.Contains(string(rawAll), "off.example.com") {
		t.Fatal("precondition failed: off.example.com absent even before filtering")
	}

	// Apply the same filter applyLocked will apply.
	live := filterDisabledRoutes(routes)
	raw, err := buildConfigJSON(live, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON(live): %v", err)
	}
	got := string(raw)
	if strings.Contains(got, "off.example.com") {
		t.Errorf("disabled host off.example.com leaked into emitted config:\n%s", got)
	}
	if !strings.Contains(got, "live.example.com") {
		t.Errorf("live host missing from emitted config")
	}
	// Cert subjects: off.example.com must NOT be in apps.tls.
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if strings.Contains(mustDump(t, cfg["apps"]), "off.example.com") {
		t.Errorf("disabled host appears in apps (cert subject leak)")
	}
}

// TestFilterDisabledRoutes pins the helper directly.
func TestFilterDisabledRoutes(t *testing.T) {
	in := []storage.Route{
		{ID: "a"}, {ID: "b", Disabled: true}, {ID: "c"},
	}
	out := filterDisabledRoutes(in)
	if len(out) != 2 {
		t.Fatalf("want 2 live routes, got %d", len(out))
	}
	for _, r := range out {
		if r.Disabled {
			t.Errorf("disabled route %s survived filter", r.ID)
		}
	}
}

func mustDump(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// TestHasHTTPSServer_IgnoresDisabled pins that a disabled TLS route
// does not by itself make HasHTTPSServer report true (it would no
// longer be emitted, so no :443 server exists for it).
func TestHasHTTPSServer_IgnoresDisabled(t *testing.T) {
	// This is a documentation-level guard; the real predicate lives in
	// HasHTTPSServer which reads storage. We assert the pure predicate
	// used inside it via filterDisabledRoutes: a slice of only-disabled
	// TLS routes yields zero live TLS routes.
	routes := []storage.Route{
		{ID: "r", Host: "x.example.com", TLSEnabled: true, Disabled: true},
	}
	live := filterDisabledRoutes(routes)
	anyTLS := false
	for _, r := range live {
		if r.TLSEnabled {
			anyTLS = true
		}
	}
	if anyTLS {
		t.Error("a disabled TLS route should not count as a live HTTPS route")
	}
}
