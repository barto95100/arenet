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
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

// Topology Plan B Phase 2.2 — builder AliasMetrics tests.

func routeWithAliases(id, primary string, aliases []string) storage.Route {
	return storage.Route{
		ID:        id,
		Host:      primary,
		Aliases:   aliases,
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  "round_robin",
	}
}

func TestBuildRoute_AliasMetrics_SortedByReqPerSecDesc(t *testing.T) {
	// Three aliases with distinct traffic. The slice must come
	// back sorted descending by ReqPerSec so the frontend can
	// render the "top consumers" at the top of the column.
	m := stubMetrics{
		id:  "r1",
		agg: Aggregate{ReqPerSec: 99}, // route-level, separate from alias slice
		hosts: map[string]Aggregate{
			"r1|low.example.com":  {ReqPerSec: 0.5, ErrorRate5xx: 0, P95LatencyMs: 10},
			"r1|busy.example.com": {ReqPerSec: 50, ErrorRate5xx: 1, P95LatencyMs: 25},
			"r1|mid.example.com":  {ReqPerSec: 5, ErrorRate5xx: 0, P95LatencyMs: 15},
		},
	}
	resp := BuildSnapshot(
		[]storage.Route{routeWithAliases("r1", "primary.example.com",
			[]string{"low.example.com", "busy.example.com", "mid.example.com"})},
		m,
		nil,
		time.Now(),
	)

	if len(resp.Routes) != 1 {
		t.Fatalf("routes len=%d want 1", len(resp.Routes))
	}
	got := resp.Routes[0].AliasMetrics
	if len(got) != 3 {
		t.Fatalf("AliasMetrics len=%d want 3", len(got))
	}
	if got[0].Host != "busy.example.com" || got[0].ReqPerSec != 50 {
		t.Errorf("AliasMetrics[0]=%+v; want busy.example.com @ 50 req/s (top consumer)", got[0])
	}
	if got[1].Host != "mid.example.com" || got[1].ReqPerSec != 5 {
		t.Errorf("AliasMetrics[1]=%+v; want mid.example.com @ 5 req/s", got[1])
	}
	if got[2].Host != "low.example.com" || got[2].ReqPerSec != 0.5 {
		t.Errorf("AliasMetrics[2]=%+v; want low.example.com @ 0.5 req/s", got[2])
	}
}

func TestBuildRoute_AliasMetrics_IdleAliasZero(t *testing.T) {
	// An alias the operator declared but no traffic has hit yet
	// MUST still appear (with ReqPerSec=0) so the frontend
	// renders the node — operator-visible "configured but idle"
	// is meaningful.
	m := stubMetrics{
		id:    "r1",
		agg:   Aggregate{ReqPerSec: 5},
		hosts: nil, // no per-host entries → every alias idle
	}
	resp := BuildSnapshot(
		[]storage.Route{routeWithAliases("r1", "primary.example.com",
			[]string{"alias1.example.com", "alias2.example.com"})},
		m,
		nil,
		time.Now(),
	)
	got := resp.Routes[0].AliasMetrics
	if len(got) != 2 {
		t.Fatalf("AliasMetrics len=%d want 2", len(got))
	}
	for _, a := range got {
		if a.ReqPerSec != 0 {
			t.Errorf("idle alias %q got ReqPerSec=%v; want 0", a.Host, a.ReqPerSec)
		}
	}
}

func TestBuildRoute_AliasMetrics_EmptyWhenNoAliases(t *testing.T) {
	// Route without aliases → AliasMetrics is the empty (non-nil)
	// slice. The omitempty-absence on the field means JSON
	// emits "aliasMetrics": [] (not null, not absent).
	m := stubMetrics{id: "r1", agg: Aggregate{ReqPerSec: 5}}
	resp := BuildSnapshot(
		[]storage.Route{routeWithAliases("r1", "primary.example.com", nil)},
		m, nil, time.Now(),
	)
	got := resp.Routes[0].AliasMetrics
	if got == nil {
		t.Errorf("AliasMetrics = nil; want non-nil empty slice for stable wire shape")
	}
	if len(got) != 0 {
		t.Errorf("AliasMetrics len=%d want 0", len(got))
	}
}

func TestBuildRoute_AliasMetrics_LowercaseLookup(t *testing.T) {
	// storage.Route.Aliases may carry mixed-case operator input.
	// The window key is the lowercased canonical (Phase 1
	// middleware + Phase 2.1 caddymgr emit both lowercase).
	// The builder MUST lowercase at lookup time so the metrics
	// match. The wire shape preserves the operator's original
	// casing on the Alias.Host field.
	m := stubMetrics{
		id:  "r1",
		agg: Aggregate{},
		hosts: map[string]Aggregate{
			"r1|api.example.com": {ReqPerSec: 7, ErrorRate5xx: 0, P95LatencyMs: 12},
		},
	}
	resp := BuildSnapshot(
		[]storage.Route{routeWithAliases("r1", "primary.example.com",
			[]string{"API.Example.com"})}, // mixed case in storage
		m, nil, time.Now(),
	)
	got := resp.Routes[0].AliasMetrics
	if len(got) != 1 {
		t.Fatalf("AliasMetrics len=%d want 1", len(got))
	}
	// Wire shape preserves the original casing.
	if got[0].Host != "API.Example.com" {
		t.Errorf("Alias.Host=%q; want operator's original casing API.Example.com", got[0].Host)
	}
	// Metrics surfaced from the lowercased lookup.
	if got[0].ReqPerSec != 7 {
		t.Errorf("Alias.ReqPerSec=%v; want 7 (lowercase lookup hit)", got[0].ReqPerSec)
	}
}

func TestBuildRoute_AliasMetrics_TieBreakAlphabetical(t *testing.T) {
	// Aliases with identical ReqPerSec (e.g., 0 — every alias
	// idle) MUST sort alphabetically as the stable secondary
	// key. Without this the sort order varies tick-to-tick and
	// the frontend re-renders every node every tick.
	m := stubMetrics{id: "r1", agg: Aggregate{}, hosts: nil}
	resp := BuildSnapshot(
		[]storage.Route{routeWithAliases("r1", "primary.example.com",
			[]string{"zeta.example.com", "alpha.example.com", "mu.example.com"})},
		m, nil, time.Now(),
	)
	got := resp.Routes[0].AliasMetrics
	if len(got) != 3 {
		t.Fatalf("AliasMetrics len=%d want 3", len(got))
	}
	for i, want := range []string{"alpha.example.com", "mu.example.com", "zeta.example.com"} {
		if got[i].Host != want {
			t.Errorf("AliasMetrics[%d].Host=%q want %q", i, got[i].Host, want)
		}
	}
}

func TestBuildRoute_AliasMetrics_NoopMetricsView(t *testing.T) {
	// noopMetricsView (no window wired) must satisfy
	// AggregateByHost (return zero) so the builder doesn't crash
	// on a degraded boot. Verifies the interface contract pinned
	// at compile time + the runtime degradation path.
	resp := BuildSnapshot(
		[]storage.Route{routeWithAliases("r1", "primary.example.com",
			[]string{"alias.example.com"})},
		nil, // MetricsView nil → noopMetricsView fallback
		nil,
		time.Now(),
	)
	got := resp.Routes[0].AliasMetrics
	if len(got) != 1 {
		t.Fatalf("AliasMetrics len=%d want 1 (alias still listed under noop window)", len(got))
	}
	if got[0].Host != "alias.example.com" || got[0].ReqPerSec != 0 {
		t.Errorf("noop AliasMetrics[0]=%+v; want alias.example.com @ 0", got[0])
	}
}
