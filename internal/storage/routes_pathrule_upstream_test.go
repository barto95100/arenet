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

import "testing"

func upstreamPool(urls ...string) []Upstream {
	out := make([]Upstream, len(urls))
	for i, u := range urls {
		out[i] = Upstream{URL: u, Weight: 1}
	}
	return out
}

func TestPathRule_Validate_UpstreamOnlyIsValid(t *testing.T) {
	// Pure routing: an upstream pool with NO protection is valid (Q3).
	pr := PathRule{
		PathPrefix: "/v1",
		Upstreams:  upstreamPool("http://api-a:8080"),
		LBPolicy:   LBPolicyRoundRobin,
	}
	if err := pr.Validate(); err != nil {
		t.Fatalf("upstream-only rule should be valid, got: %v", err)
	}
}

func TestPathRule_Validate_FullyEmptyIsRejected(t *testing.T) {
	// No basic-auth, no active IP filter, no upstream → still rejected.
	pr := PathRule{PathPrefix: "/x"}
	if err := pr.Validate(); err == nil {
		t.Fatal("fully-empty rule must be rejected")
	}
}

func TestPathRule_Validate_MultiSchemePoolRejected(t *testing.T) {
	pr := PathRule{
		PathPrefix: "/v1",
		Upstreams:  []Upstream{{URL: "http://a:8080", Weight: 1}, {URL: "https://b:8443", Weight: 1}},
		LBPolicy:   LBPolicyRoundRobin,
	}
	if err := pr.Validate(); err == nil {
		t.Fatal("mixed-scheme path pool must be rejected")
	}
}

func TestPathRule_Validate_HTTPSPoolDifferentFromRouteIsValid(t *testing.T) {
	// A path pool may be https even if (elsewhere) the route is http — the
	// PathRule itself only enforces same-scheme WITHIN its own pool (Q2).
	pr := PathRule{
		PathPrefix: "/legacy",
		Upstreams:  upstreamPool("https://old:8443"),
		LBPolicy:   LBPolicyRoundRobin,
	}
	if err := pr.Validate(); err != nil {
		t.Fatalf("https path pool should be valid on its own, got: %v", err)
	}
}

func TestPathRule_Validate_EmptyUpstreamURLRejected(t *testing.T) {
	// Mirrors the route-level validate() check (routes.go ~815-821): an
	// upstream with an empty URL must be rejected, not silently accepted.
	pr := PathRule{
		PathPrefix: "/v1",
		Upstreams:  []Upstream{{URL: "", Weight: 1}},
		LBPolicy:   LBPolicyRoundRobin,
	}
	if err := pr.Validate(); err == nil {
		t.Fatal("empty upstream URL must be rejected")
	}
}

func TestPathRule_Validate_InvalidLBPolicyRejected(t *testing.T) {
	// Mirrors the route-level validate() check (routes.go ~843-859): an
	// LBPolicy outside storage.LBPolicies must be rejected when a pool is
	// present.
	pr := PathRule{
		PathPrefix: "/v1",
		Upstreams:  upstreamPool("http://api-a:8080"),
		LBPolicy:   "banana",
	}
	if err := pr.Validate(); err == nil {
		t.Fatal("invalid lb_policy must be rejected")
	}
}
