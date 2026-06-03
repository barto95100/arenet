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

package topology

import (
	"math"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

// stubMetrics returns a fixed Aggregate for a single route id;
// every other id returns zero. Tiny test double — no map needed
// because builder tests only query the route they care about.
type stubMetrics struct {
	id  string
	agg Aggregate
}

func (s stubMetrics) Aggregate(id string) Aggregate {
	if id == s.id {
		return s.agg
	}
	return Aggregate{}
}

// stubStatus returns the same canned status for any URL it
// recognises; unknown URLs get StatusUnknown.
type stubStatus struct {
	statuses map[string]string
}

func (s stubStatus) Status(url string) string {
	if v, ok := s.statuses[url]; ok {
		return v
	}
	return StatusUnknown
}

func TestBuildSnapshot_EmptyRoutes(t *testing.T) {
	resp := BuildSnapshot(nil, nil, nil, time.Unix(0, 0).UTC())
	if len(resp.Routes) != 0 {
		t.Errorf("Routes: got %d, want 0", len(resp.Routes))
	}
	// GeneratedAt MUST be UTC even if the caller passed local;
	// builder normalises so the JSON encoder emits the 'Z' suffix.
	if resp.GeneratedAt.Location() != time.UTC {
		t.Errorf("GeneratedAt location: got %v, want UTC", resp.GeneratedAt.Location())
	}
}

func TestBuildSnapshot_NilDependenciesSafe(t *testing.T) {
	// nil MetricsView + nil StatusLookup must not panic; every
	// upstream comes back idle/unknown.
	routes := []storage.Route{{
		ID:        "r1",
		Host:      "api.example",
		LBPolicy:  "round_robin",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.1:80", Weight: 1}},
	}}
	resp := BuildSnapshot(routes, nil, nil, time.Now())
	if len(resp.Routes) != 1 {
		t.Fatalf("len Routes: got %d, want 1", len(resp.Routes))
	}
	r := resp.Routes[0]
	if r.ReqPerSec != 0 || r.ErrorRate5xx != 0 || r.P99LatencyMs != 0 {
		t.Errorf("metrics: want zero with nil view, got %+v", r)
	}
	if r.Upstreams[0].Status != StatusUnknown {
		t.Errorf("status: got %q, want %q", r.Upstreams[0].Status, StatusUnknown)
	}
}

func TestBuildSnapshot_SingleUpstreamGetsAllTraffic(t *testing.T) {
	routes := []storage.Route{{
		ID:         "r1",
		Host:       "api.example",
		LBPolicy:   "round_robin",
		TLSEnabled: true,
		WAFMode:    "block",
		Aliases:    []string{"alt.example"},
		Upstreams: []storage.Upstream{
			{URL: "http://10.0.0.1:8080", Weight: 1},
		},
	}}
	m := stubMetrics{id: "r1", agg: Aggregate{ReqPerSec: 400, ErrorRate5xx: 0, P95LatencyMs: 42}}
	s := stubStatus{statuses: map[string]string{"http://10.0.0.1:8080": StatusHealthy}}
	resp := BuildSnapshot(routes, m, s, time.Unix(1_700_000_000, 0).UTC())

	if len(resp.Routes) != 1 {
		t.Fatalf("len Routes: got %d, want 1", len(resp.Routes))
	}
	r := resp.Routes[0]
	if r.ID != "r1" || r.Host != "api.example" || r.LBPolicy != "round_robin" {
		t.Errorf("identity: got %+v", r)
	}
	if !r.TLSEnabled || r.WAFLevel != "block" {
		t.Errorf("tls/waf: got tls=%v waf=%q", r.TLSEnabled, r.WAFLevel)
	}
	if len(r.Aliases) != 1 || r.Aliases[0] != "alt.example" {
		t.Errorf("aliases: got %v", r.Aliases)
	}
	if r.ReqPerSec != 400 || r.P99LatencyMs != 42 {
		t.Errorf("route metrics: got reqPerSec=%v p99=%d", r.ReqPerSec, r.P99LatencyMs)
	}
	if len(r.Upstreams) != 1 {
		t.Fatalf("len Upstreams: got %d, want 1", len(r.Upstreams))
	}
	u := r.Upstreams[0]
	if u.ID != "r1-0" {
		t.Errorf("upstream id: got %q, want r1-0", u.ID)
	}
	if u.ReqPerSec != 400 || math.Abs(u.FairnessRatio-1.0) > 1e-9 {
		t.Errorf("single upstream split: got reqPerSec=%v fairness=%v, want 400 and 1.0",
			u.ReqPerSec, u.FairnessRatio)
	}
	// v1.1.0 status policy (#R-TOPO-health-coherence): the prober
	// is still consulted (and the stub here returns StatusHealthy)
	// but the result is intentionally dropped — every upstream
	// reports StatusUnknown until Stage B real-probe ingestion.
	// The test fixture used to assert StatusHealthy here; the
	// stub's canned value is now expected to be ignored.
	if u.Status != StatusUnknown {
		t.Errorf("status: got %q, want %q (v1.1.0 always-unknown)", u.Status, StatusUnknown)
	}
	if u.P99LatencyMs != 42 {
		t.Errorf("upstream p99 echo: got %d, want 42", u.P99LatencyMs)
	}
}

func TestBuildSnapshot_WeightedSplitAcrossUpstreams(t *testing.T) {
	// Three upstreams with weights 3 / 1 / 1 → shares 0.6 / 0.2 / 0.2.
	// Route reqPerSec = 1000 → 600 / 200 / 200 split.
	routes := []storage.Route{{
		ID:       "r1",
		Host:     "api.example",
		LBPolicy: "weighted_round_robin",
		Upstreams: []storage.Upstream{
			{URL: "http://10.0.0.1:80", Weight: 3},
			{URL: "http://10.0.0.2:80", Weight: 1},
			{URL: "http://10.0.0.3:80", Weight: 1},
		},
	}}
	m := stubMetrics{id: "r1", agg: Aggregate{ReqPerSec: 1000, P95LatencyMs: 25}}
	resp := BuildSnapshot(routes, m, nil, time.Now())
	r := resp.Routes[0]
	if len(r.Upstreams) != 3 {
		t.Fatalf("len Upstreams: got %d, want 3", len(r.Upstreams))
	}

	wantShares := []float64{0.6, 0.2, 0.2}
	wantRPS := []float64{600, 200, 200}
	for i, u := range r.Upstreams {
		if math.Abs(u.FairnessRatio-wantShares[i]) > 1e-9 {
			t.Errorf("upstream %d fairness: got %v, want %v", i, u.FairnessRatio, wantShares[i])
		}
		if math.Abs(u.ReqPerSec-wantRPS[i]) > 1e-9 {
			t.Errorf("upstream %d reqPerSec: got %v, want %v", i, u.ReqPerSec, wantRPS[i])
		}
		if u.ID != map[int]string{0: "r1-0", 1: "r1-1", 2: "r1-2"}[i] {
			t.Errorf("upstream %d id: got %q", i, u.ID)
		}
	}

	// Sum of fairness ratios MUST be 1.0 — that's the contract
	// the frontend's fairness bars rely on.
	var sum float64
	for _, u := range r.Upstreams {
		sum += u.FairnessRatio
	}
	if math.Abs(sum-1.0) > 1e-9 {
		t.Errorf("sum(fairnessRatio): got %v, want 1.0", sum)
	}
}

func TestBuildSnapshot_ZeroWeightDefendsAgainstDivByZero(t *testing.T) {
	// storage validation guarantees Weight >= 1 but the builder
	// should still produce a well-formed response if a corrupt
	// row sneaks through.
	routes := []storage.Route{{
		ID:       "r1",
		Host:     "api.example",
		LBPolicy: "round_robin",
		Upstreams: []storage.Upstream{
			{URL: "http://10.0.0.1:80", Weight: 0},
			{URL: "http://10.0.0.2:80", Weight: 0},
		},
	}}
	m := stubMetrics{id: "r1", agg: Aggregate{ReqPerSec: 200}}
	resp := BuildSnapshot(routes, m, nil, time.Now())
	if len(resp.Routes) != 1 {
		t.Fatalf("len Routes: got %d, want 1", len(resp.Routes))
	}
	r := resp.Routes[0]
	if len(r.Upstreams) != 2 {
		t.Fatalf("len Upstreams: got %d, want 2 (zero weights fall back to 1)", len(r.Upstreams))
	}
	// Two upstreams with effective weight 1 each → 0.5 / 0.5.
	for i, u := range r.Upstreams {
		if math.Abs(u.FairnessRatio-0.5) > 1e-9 {
			t.Errorf("upstream %d fairness: got %v, want 0.5", i, u.FairnessRatio)
		}
	}
}

func TestBuildSnapshot_AliasesIsClonedNotAliased(t *testing.T) {
	routes := []storage.Route{{
		ID:        "r1",
		Host:      "api.example",
		LBPolicy:  "round_robin",
		Aliases:   []string{"a.example"},
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.1:80", Weight: 1}},
	}}
	resp := BuildSnapshot(routes, nil, nil, time.Now())
	// Mutating the source after build MUST NOT change the
	// response — proof the slice was cloned, not aliased.
	routes[0].Aliases[0] = "MUTATED"
	if resp.Routes[0].Aliases[0] == "MUTATED" {
		t.Errorf("Aliases is aliased to storage slice; want clone")
	}
}

// TestBuildSnapshot_HealthCheckConfiguredPropagates verifies the
// v1.1.0 #R-TOPO-health-coherence contract: HasHealthCheck on the
// route and HealthCheckConfigured on every upstream both mirror
// storage.Route.HealthCheck.Enabled. Status remains StatusUnknown
// regardless, even when the prober would have returned StatusHealthy
// — the prober result is intentionally dropped (see builder.go).
func TestBuildSnapshot_HealthCheckConfiguredPropagates(t *testing.T) {
	hcRoute := storage.Route{
		ID:        "r-hc",
		Host:      "monitored.example",
		LBPolicy:  "round_robin",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.1:80", Weight: 1}},
		HealthCheck: storage.HealthCheck{
			Enabled:  true,
			URI:      "/healthz",
			Interval: "10s",
			Timeout:  "2s",
			Method:   "GET",
		},
	}
	noHCRoute := storage.Route{
		ID:        "r-nohc",
		Host:      "unmonitored.example",
		LBPolicy:  "round_robin",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.2:80", Weight: 1}},
		// HealthCheck: zero-value (Enabled=false)
	}
	// Prober claims both upstreams healthy — the v1.1.0 policy must
	// ignore it and surface StatusUnknown for both.
	s := stubStatus{statuses: map[string]string{
		"http://10.0.0.1:80": StatusHealthy,
		"http://10.0.0.2:80": StatusHealthy,
	}}
	resp := BuildSnapshot(
		[]storage.Route{hcRoute, noHCRoute},
		stubMetrics{id: "r-hc", agg: Aggregate{ReqPerSec: 10}},
		s,
		time.Now(),
	)
	if len(resp.Routes) != 2 {
		t.Fatalf("len Routes: got %d, want 2", len(resp.Routes))
	}
	hc := resp.Routes[0]
	nohc := resp.Routes[1]
	if !hc.HasHealthCheck {
		t.Errorf("hc route HasHealthCheck = false; want true")
	}
	if nohc.HasHealthCheck {
		t.Errorf("nohc route HasHealthCheck = true; want false")
	}
	if !hc.Upstreams[0].HealthCheckConfigured {
		t.Errorf("hc upstream HealthCheckConfigured = false; want true")
	}
	if nohc.Upstreams[0].HealthCheckConfigured {
		t.Errorf("nohc upstream HealthCheckConfigured = true; want false")
	}
	// Both upstreams must report unknown despite the prober saying
	// healthy — the operator-flagged misleading-green case.
	if hc.Upstreams[0].Status != StatusUnknown {
		t.Errorf("hc status: got %q, want %q", hc.Upstreams[0].Status, StatusUnknown)
	}
	if nohc.Upstreams[0].Status != StatusUnknown {
		t.Errorf("nohc status: got %q, want %q", nohc.Upstreams[0].Status, StatusUnknown)
	}
}

// TestBuildSnapshot_HTTPRedirectPropagates verifies Critique 18
// wire-shape extension: Route.HTTPRedirect mirrors
// storage.Route.RedirectToHTTPS so the frontend can render the
// "HTTP → HTTPS" protocols variant on the FQDN node. Default-zero
// path covered alongside the explicit-true case.
func TestBuildSnapshot_HTTPRedirectPropagates(t *testing.T) {
	redirectRoute := storage.Route{
		ID:               "r-redirect",
		Host:             "redirect.example",
		LBPolicy:         "round_robin",
		TLSEnabled:       true,
		RedirectToHTTPS:  true,
		Upstreams:        []storage.Upstream{{URL: "http://10.0.0.1:80", Weight: 1}},
	}
	plainRoute := storage.Route{
		ID:        "r-plain",
		Host:      "plain.example",
		LBPolicy:  "round_robin",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.2:80", Weight: 1}},
		// TLSEnabled, RedirectToHTTPS both zero-value
	}
	resp := BuildSnapshot(
		[]storage.Route{redirectRoute, plainRoute},
		nil, nil, time.Now(),
	)
	if len(resp.Routes) != 2 {
		t.Fatalf("len Routes: got %d, want 2", len(resp.Routes))
	}
	if !resp.Routes[0].HTTPRedirect {
		t.Errorf("redirect route HTTPRedirect = false; want true")
	}
	if resp.Routes[1].HTTPRedirect {
		t.Errorf("plain route HTTPRedirect = true; want false (zero-value)")
	}
}

func TestHostBasename(t *testing.T) {
	cases := map[string]string{
		"api.arenet.fr":   "api",
		"app":             "app",
		"":                "",
		".leading":        "",
		"singletoken.com": "singletoken",
	}
	for in, want := range cases {
		if got := HostBasename(in); got != want {
			t.Errorf("HostBasename(%q) = %q, want %q", in, got, want)
		}
	}
}
