// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package caddymgr

import (
	"encoding/json"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// TestBuildConfigJSON_EmitsPKIApp_WithInstallTrustFalse pins the
// #S-19v2 fix: every emitted config MUST carry an apps.pki block
// with install_trust:false on the local CA.
//
// Background (commit be4cbf0): v1.0.2 first attempted this via a
// typed cfg.Apps.PKI struct field on caddyConfig / appsConfig.
// That fix compiled and the resulting binary contained the new
// struct symbols, but it had no runtime effect — the JSON marshal
// path in buildConfigJSON builds the apps map directly as a
// map[string]any and only pulls cfg.Apps.HTTP.Servers from the
// typed struct. Every other field on cfg.Apps was silently
// dropped at marshal time. The fix shipped without effect; the
// 4 spam lines stayed in journalctl on every boot of v1.0.2-rc1.
//
// This test catches that exact regression at the JSON-emission
// layer where the original v1.0.2 implementation review missed
// it. If apps.pki is removed from the emitted JSON or the
// install_trust value flips back to true (or absent — Caddy
// treats *bool == nil as the default `true`), this test fails
// well before the live-smoke would catch it via journalctl.
func TestBuildConfigJSON_EmitsPKIApp_WithInstallTrustFalse(t *testing.T) {
	routes := []storage.Route{
		{ID: "fixture", Host: "test.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9999", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
	}

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	pki := pkiAppFromJSON(t, raw)
	if pki == nil {
		t.Fatalf("apps.pki missing from emitted config:\n%s", raw)
	}

	cas, ok := pki["certificate_authorities"].(map[string]any)
	if !ok {
		t.Fatalf("apps.pki.certificate_authorities missing or wrong type:\n%s", raw)
	}

	local, ok := cas["local"].(map[string]any)
	if !ok {
		t.Fatalf("apps.pki.certificate_authorities.local missing or wrong type:\n%s", raw)
	}

	installTrust, present := local["install_trust"]
	if !present {
		t.Fatalf("apps.pki.certificate_authorities.local.install_trust missing — Caddy treats absent *bool as default `true` and the local-CA install attempt resumes:\n%s", raw)
	}

	// Must be the literal boolean `false`, not nil and not absent —
	// the install attempt only stays suppressed when Caddy decodes
	// *bool == &false on its CA struct.
	if installTrust != false {
		t.Errorf("install_trust = %v (type %T), want literal bool false", installTrust, installTrust)
	}
}

// TestBuildConfigJSON_EmitsPKIApp_NoRoutes confirms the pki block
// is emitted unconditionally — not gated on the route list being
// non-empty. Cold-start scenario: Arenet boots with no user routes
// yet (fresh install), Caddy still spins up its catch-all internal
// CA policy at start time, so the install_trust suppression must
// already be active at first boot.
func TestBuildConfigJSON_EmitsPKIApp_NoRoutes(t *testing.T) {
	raw, err := buildConfigJSON([]storage.Route{}, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	if pki := pkiAppFromJSON(t, raw); pki == nil {
		t.Fatalf("apps.pki must be emitted even with no routes (cold-start scenario):\n%s", raw)
	}
}

// pkiAppFromJSON digs into the parsed JSON to extract the apps.pki
// block. Returns nil if absent (caller will t.Fatalf in that case).
// Mirror of crowdSecAppFromJSON in crowdsec_test.go.
func pkiAppFromJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	apps, ok := cfg["apps"].(map[string]any)
	if !ok {
		return nil
	}
	pki, ok := apps["pki"].(map[string]any)
	if !ok {
		return nil
	}
	return pki
}
