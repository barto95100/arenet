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
	"testing"
)

// Step Q (2026-06-18) storage tests — Route.RateLimit field.
//
// Pins the BoltDB roundtrip + the pre-Q-byte-equivalent default
// (nil pointer = no rate limit). No migration : the additive
// nil-pointer shape decodes pre-Q rows cleanly.

func TestRoute_RateLimit_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	r := Route{
		Host: "limited.local",
		Upstreams: []Upstream{
			{URL: "http://192.168.1.50:8080", Weight: 1},
		},
		LBPolicy: LBPolicyRoundRobin,
		AuthMode: "none",
		RateLimit: &RouteRateLimit{
			Events: 60,
			Window: "1m",
			Key:    "{http.request.remote.host}",
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
	if got.RateLimit == nil {
		t.Fatalf("RateLimit roundtrip = nil ; want non-nil")
	}
	if got.RateLimit.Events != 60 {
		t.Errorf("Events = %d ; want 60", got.RateLimit.Events)
	}
	if got.RateLimit.Window != "1m" {
		t.Errorf("Window = %q ; want %q", got.RateLimit.Window, "1m")
	}
	if got.RateLimit.Key != "{http.request.remote.host}" {
		t.Errorf("Key = %q ; want default placeholder", got.RateLimit.Key)
	}
}

func TestRoute_RateLimit_NilByDefault_PreQByteEquivalent(t *testing.T) {
	// Pre-Q byte-equivalence : a route created without
	// RateLimit persists with a nil pointer. The runtime
	// caddymgr emit skips the rate_limit handler entirely
	// for nil RateLimit, so the handler chain is byte-equal
	// to the pre-Q one (no extra entry).
	s := newTestStore(t)
	ctx := context.Background()

	r := Route{
		Host: "noLimit.local",
		Upstreams: []Upstream{
			{URL: "http://192.168.1.20:8080", Weight: 1},
		},
		LBPolicy: LBPolicyRoundRobin,
		AuthMode: "none",
	}
	created, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	got, _ := s.GetRoute(ctx, created.ID)
	if got.RateLimit != nil {
		t.Errorf("RateLimit = %+v on default Route ; want nil", got.RateLimit)
	}
}

func TestRoute_RateLimit_CoExistsWithOtherWAFFields(t *testing.T) {
	// RateLimit, WAFMode, WAFExcludeRules, WAFDisableCRS are
	// independent. The combo (rate limit + WAF detect +
	// excluded rules) is operator-valid (e.g. public API
	// behind WAF observe-mode with a hard 100 req/min cap).
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
		WAFExcludeRules: []int{942100},
		RateLimit:       &RouteRateLimit{Events: 100, Window: "1m"},
	}
	created, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	got, _ := s.GetRoute(ctx, created.ID)
	if got.RateLimit == nil || got.RateLimit.Events != 100 ||
		len(got.WAFExcludeRules) != 1 || got.WAFMode != "detect" {
		t.Errorf("orthogonal fields clobbered : rateLimit=%+v wafMode=%q excludes=%v",
			got.RateLimit, got.WAFMode, got.WAFExcludeRules)
	}
}
