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

package storage

import (
	"context"
	"reflect"
	"testing"
)

// Step X Option (e) — tag-based WAF exclusion storage tests.
// Mirror of routes_waf_exclude_rules_test.go shape ; the
// validation lives at the API boundary (normalizeExcludeTags),
// so the storage tests pin the BoltDB roundtrip + the zero-
// value byte-equivalence for pre-X(e) stored routes.

func TestRoute_WAFExcludeTags_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	r := Route{
		Host: "fp.local",
		Upstreams: []Upstream{
			{URL: "http://192.168.1.50:8080", Weight: 1},
		},
		LBPolicy: LBPolicyRoundRobin,
		AuthMode: "none",
		WAFMode:  "detect",
		WAFExcludeTags: []string{
			"attack-protocol",
			"paranoia-level/3",
		},
	}
	created, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	got, err := s.GetRoute(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRoute: %v", err)
	}
	want := []string{"attack-protocol", "paranoia-level/3"}
	if !reflect.DeepEqual(got.WAFExcludeTags, want) {
		t.Errorf("WAFExcludeTags round-trip mismatch: got=%v want=%v",
			got.WAFExcludeTags, want)
	}
}

func TestRoute_WAFExcludeTags_DefaultsNilOrEmpty(t *testing.T) {
	// Pre-X(e) byte-equivalence : a route created without
	// WAFExcludeTags decodes as nil-or-empty. The zero-value
	// slice is the runtime equivalent of "no tag exclusions",
	// matching the pre-X(e) handler behaviour, so the caddymgr
	// emit produces the same directives string as before
	// for routes that don't touch this field.
	s := newTestStore(t)
	ctx := context.Background()

	r := Route{
		Host: "no-tags.local",
		Upstreams: []Upstream{
			{URL: "http://127.0.0.1:9000", Weight: 1},
		},
		LBPolicy: LBPolicyRoundRobin,
		AuthMode: "none",
		WAFMode:  "detect",
		// WAFExcludeTags intentionally unset.
	}
	created, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	got, err := s.GetRoute(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRoute: %v", err)
	}
	if len(got.WAFExcludeTags) != 0 {
		t.Errorf("expected nil/empty WAFExcludeTags ; got %v", got.WAFExcludeTags)
	}
}

func TestRoute_WAFExcludeTags_CoExistsWithExcludeRulesAndDisableCRS(t *testing.T) {
	// The three Step X options (a) DisableCRS, (c) ExcludeRules,
	// (e) ExcludeTags are orthogonal at storage. The route can
	// carry all three simultaneously ; the caddymgr emit
	// resolves the runtime semantics (DisableCRS=true makes
	// rule/tag exclusions become no-ops, but the SecAction
	// itself stays for pool-key stability — same pattern Step
	// X (c) established).
	s := newTestStore(t)
	ctx := context.Background()

	r := Route{
		Host: "combined.local",
		Upstreams: []Upstream{
			{URL: "http://127.0.0.1:9000", Weight: 1},
		},
		LBPolicy:        LBPolicyRoundRobin,
		AuthMode:        "none",
		WAFMode:         "detect",
		WAFDisableCRS:   true,
		WAFExcludeRules: []int{942100},
		WAFExcludeTags:  []string{"attack-sqli"},
	}
	created, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	got, err := s.GetRoute(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRoute: %v", err)
	}
	if !got.WAFDisableCRS {
		t.Errorf("WAFDisableCRS lost on round-trip")
	}
	if !reflect.DeepEqual(got.WAFExcludeRules, []int{942100}) {
		t.Errorf("WAFExcludeRules mismatch: %v", got.WAFExcludeRules)
	}
	if !reflect.DeepEqual(got.WAFExcludeTags, []string{"attack-sqli"}) {
		t.Errorf("WAFExcludeTags mismatch: %v", got.WAFExcludeTags)
	}
}
