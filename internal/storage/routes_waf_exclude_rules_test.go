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

// Step X Option (c) (2026-06-18) storage tests —
// Route.WAFExcludeRules field.
//
// Pins the BoltDB roundtrip + the zero-value byte-equivalence
// for pre-Y stored routes. ADR D5 captures the no-migration
// rationale ; this case re-uses the same path for the slice
// shape (nil slice = empty exclusion list = current behaviour).

func TestRoute_WAFExcludeRules_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	r := Route{
		Host: "fp.local",
		Upstreams: []Upstream{
			{URL: "http://192.168.1.50:8080", Weight: 1},
		},
		LBPolicy:        LBPolicyRoundRobin,
		AuthMode:        "none",
		WAFMode:         "detect",
		WAFExcludeRules: []int{942100, 941390, 920280},
	}
	created, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	got, err := s.GetRoute(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRoute: %v", err)
	}
	want := []int{942100, 941390, 920280}
	if !reflect.DeepEqual(got.WAFExcludeRules, want) {
		t.Errorf("WAFExcludeRules round-trip mismatch: got=%v want=%v",
			got.WAFExcludeRules, want)
	}
}

func TestRoute_WAFExcludeRules_DefaultsNilOrEmpty(t *testing.T) {
	// Pre-Y byte-equivalence : a route created without
	// WAFExcludeRules decodes as nil-or-empty. The zero-value
	// slice is the runtime equivalent of "no exclusions",
	// matching the pre-Y handler behaviour, so the caddymgr
	// emit produces the same directives string as before.
	s := newTestStore(t)
	ctx := context.Background()

	r := Route{
		Host: "default.local",
		Upstreams: []Upstream{
			{URL: "http://192.168.1.20:8080", Weight: 1},
		},
		LBPolicy: LBPolicyRoundRobin,
		AuthMode: "none",
		WAFMode:  "detect",
	}
	created, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	got, _ := s.GetRoute(ctx, created.ID)
	if len(got.WAFExcludeRules) != 0 {
		t.Errorf("WAFExcludeRules len = %d on default Route ; want 0 (pre-Y byte-equivalent)",
			len(got.WAFExcludeRules))
	}
}

func TestRoute_WAFExcludeRules_CoExistsWithDisableCRS(t *testing.T) {
	// WAFDisableCRS and WAFExcludeRules are independent. The
	// combo (disable CRS + a populated exclusion list) is
	// operator-valid (the operator may toggle CRS back on
	// later and expect the list to still be there). Pin the
	// orthogonality so a future change doesn't accidentally
	// clear one when the other is set.
	s := newTestStore(t)
	ctx := context.Background()

	r := Route{
		Host: "combo.local",
		Upstreams: []Upstream{
			{URL: "http://192.168.1.50:5000", Weight: 1},
		},
		LBPolicy:        LBPolicyRoundRobin,
		AuthMode:        "none",
		WAFMode:         "detect",
		WAFDisableCRS:   true,
		WAFExcludeRules: []int{942100},
	}
	created, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	got, _ := s.GetRoute(ctx, created.ID)
	if !got.WAFDisableCRS || len(got.WAFExcludeRules) != 1 || got.WAFExcludeRules[0] != 942100 {
		t.Errorf("orthogonal flags clobbered: disableCRS=%v excludes=%v",
			got.WAFDisableCRS, got.WAFExcludeRules)
	}
}
