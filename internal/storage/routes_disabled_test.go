// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package storage

import (
	"encoding/json"
	"testing"
)

// TestRoute_Disabled_ZeroValueIsEnabled pins the backward-compat
// invariant: a route JSON with NO "disabled" key decodes to
// Disabled=false (= enabled). This is why the field is Disabled (not
// Enabled) — an old row / old backup must default to enabled, never
// silently go dark. Mirrors the WAFDisableCRS polarity precedent.
func TestRoute_Disabled_ZeroValueIsEnabled(t *testing.T) {
	// Legacy row shape: no "disabled" key at all.
	legacy := `{"id":"r1","host":"a.example.com","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lb_policy":"round_robin"}`
	var r Route
	if err := json.Unmarshal([]byte(legacy), &r); err != nil {
		t.Fatalf("unmarshal legacy route: %v", err)
	}
	if r.Disabled {
		t.Error("legacy route (no disabled key) decoded Disabled=true; want false (enabled)")
	}
}

// TestRoute_Disabled_RoundTrips pins that an explicitly disabled route
// survives a marshal→unmarshal cycle (backup export/import safety).
func TestRoute_Disabled_RoundTrips(t *testing.T) {
	in := Route{ID: "r2", Host: "b.example.com", Disabled: true}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Route
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.Disabled {
		t.Errorf("Disabled did not round-trip; got %+v", out)
	}
}

// TestRoute_Disabled_OmitemptyKeepsLegacyBytes pins that an ENABLED
// route (Disabled=false) marshals WITHOUT a "disabled" key, so the
// wire shape is byte-identical to pre-feature routes (omitempty).
func TestRoute_Disabled_OmitemptyKeepsLegacyBytes(t *testing.T) {
	raw, err := json.Marshal(Route{ID: "r3", Host: "c.example.com"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(raw); contains(got, `"disabled"`) {
		t.Errorf("enabled route emitted a disabled key: %s", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
