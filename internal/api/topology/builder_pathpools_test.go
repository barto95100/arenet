// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package topology

import (
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

func TestBuildRoute_PathPools_OnlyRulesWithOwnPool(t *testing.T) {
	// A route with two path rules: /v1 has its own pool, /docs is
	// protection-only (no pool). Only /v1 becomes a PathPool (B2).
	r := storage.Route{
		ID:        "r1",
		Host:      "api.example.com",
		Upstreams: []storage.Upstream{{URL: "http://route:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		PathRules: []storage.PathRule{
			{
				PathPrefix: "/v1",
				Upstreams:  []storage.Upstream{{URL: "http://v1a:8080", Weight: 1}, {URL: "http://v1b:8080", Weight: 1}},
				LBPolicy:   storage.LBPolicyRoundRobin,
			},
			{
				PathPrefix: "/docs",
				BasicAuth:  &storage.BasicAuthRouteConfig{Username: "u", PasswordHash: "$h"},
			},
		},
	}
	out := buildRoute(&r, nil, nil)
	if len(out.PathPools) != 1 {
		t.Fatalf("expected 1 path pool (only /v1), got %d: %+v", len(out.PathPools), out.PathPools)
	}
	pp := out.PathPools[0]
	if pp.PathPrefix != "/v1" {
		t.Fatalf("path pool prefix = %q, want /v1", pp.PathPrefix)
	}
	if len(pp.Upstreams) != 2 {
		t.Fatalf("path pool upstream count = %d, want 2", len(pp.Upstreams))
	}
	if pp.LBPolicy != storage.LBPolicyRoundRobin {
		t.Fatalf("path pool lb = %q", pp.LBPolicy)
	}
}

func TestBuildRoute_PathPools_CarriesSkipVerify(t *testing.T) {
	r := storage.Route{
		ID:        "r2",
		Host:      "api.example.com",
		Upstreams: []storage.Upstream{{URL: "http://route:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		PathRules: []storage.PathRule{{
			PathPrefix:         "/legacy",
			Upstreams:          []storage.Upstream{{URL: "https://old:8443", Weight: 1}},
			LBPolicy:           storage.LBPolicyRoundRobin,
			InsecureSkipVerify: true,
		}},
	}
	out := buildRoute(&r, nil, nil)
	if len(out.PathPools) != 1 || !out.PathPools[0].InsecureSkipVerify {
		t.Fatalf("path pool should carry InsecureSkipVerify=true: %+v", out.PathPools)
	}
}

func TestBuildRoute_NoPathRules_PathPoolsNil(t *testing.T) {
	// Non-regression: a route with no path rules emits no PathPools
	// (nil → omitempty → absent from JSON, byte-identical to before).
	r := storage.Route{
		ID:        "r3",
		Host:      "plain.example.com",
		Upstreams: []storage.Upstream{{URL: "http://a:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}
	out := buildRoute(&r, nil, nil)
	if out.PathPools != nil {
		t.Fatalf("route without path rules must have nil PathPools, got: %+v", out.PathPools)
	}
}
