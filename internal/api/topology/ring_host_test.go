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
	"sync"
	"testing"
)

// Topology Plan B Phase 2.2 — SlidingWindow per-host tests.

func TestSlidingWindow_PushHost_AggregatePerHost(t *testing.T) {
	w := NewSlidingWindow()
	// Two aliases of the same route, distinct traffic profiles.
	w.PushHost("r1", "primary.example.com", 100, 5, 42)
	w.PushHost("r1", "alt.example.com", 50, 0, 30)

	primary := w.AggregateByHost("r1", "primary.example.com")
	alt := w.AggregateByHost("r1", "alt.example.com")

	if primary.ReqPerSec != 100 {
		t.Errorf("primary.ReqPerSec=%v want 100", primary.ReqPerSec)
	}
	if primary.ErrorRate5xx != 5.0 {
		t.Errorf("primary.ErrorRate5xx=%v want 5.0", primary.ErrorRate5xx)
	}
	if alt.ReqPerSec != 50 {
		t.Errorf("alt.ReqPerSec=%v want 50", alt.ReqPerSec)
	}
	if alt.ErrorRate5xx != 0 {
		t.Errorf("alt.ErrorRate5xx=%v want 0", alt.ErrorRate5xx)
	}
}

func TestSlidingWindow_AggregateByHost_UnknownReturnsZero(t *testing.T) {
	w := NewSlidingWindow()
	w.PushHost("r1", "primary.example.com", 100, 0, 0)

	// Unknown host on a known route → zero.
	if got := w.AggregateByHost("r1", "ghost.example.com"); got != (Aggregate{}) {
		t.Errorf("unknown host AggregateByHost = %+v; want zero", got)
	}
	// Unknown route → zero.
	if got := w.AggregateByHost("r-ghost", "primary.example.com"); got != (Aggregate{}) {
		t.Errorf("unknown route AggregateByHost = %+v; want zero", got)
	}
}

func TestSlidingWindow_PushHost_SlidingMean(t *testing.T) {
	// 3 ticks pushed → mean over populated slots, not divided
	// by WindowSlots. Mirrors the route-level test in
	// TestSlidingWindow_Aggregate_MeanOverPopulatedSlots.
	w := NewSlidingWindow()
	w.PushHost("r1", "h1", 100, 0, 10)
	w.PushHost("r1", "h1", 200, 0, 20)
	w.PushHost("r1", "h1", 300, 0, 30)

	agg := w.AggregateByHost("r1", "h1")
	wantReqPerSec := (100.0 + 200.0 + 300.0) / 3.0
	if agg.ReqPerSec != wantReqPerSec {
		t.Errorf("ReqPerSec=%v want %v", agg.ReqPerSec, wantReqPerSec)
	}
	// Latest-slot p95.
	if agg.P95LatencyMs != 30 {
		t.Errorf("P95LatencyMs=%d want 30 (latest slot)", agg.P95LatencyMs)
	}
}

func TestSlidingWindow_PushHost_EmptyHostNoOp(t *testing.T) {
	// Defensive: producer should never call with host="" but if
	// it does we must not create a phantom inner-map entry that
	// Prune would never clear.
	w := NewSlidingWindow()
	w.PushHost("r1", "", 100, 0, 0)
	w.mu.RLock()
	_, has := w.hosts["r1"]
	w.mu.RUnlock()
	if has {
		t.Errorf("PushHost with empty host created outer-map entry; want absent")
	}
}

func TestSlidingWindow_Prune_DropsHostEntries(t *testing.T) {
	w := NewSlidingWindow()
	w.PushHost("r1", "h1", 100, 0, 0)
	w.PushHost("r2", "h2", 100, 0, 0)
	// Push a per-route entry too so Prune has both layers to clean.
	w.Push("r1", 100, 0, 0)
	w.Push("r2", 100, 0, 0)

	// Prune drops r1 (keep r2 only).
	w.Prune(map[string]struct{}{"r2": {}})

	if got := w.AggregateByHost("r1", "h1"); got != (Aggregate{}) {
		t.Errorf("AggregateByHost r1/h1 after Prune = %+v; want zero", got)
	}
	if got := w.AggregateByHost("r2", "h2").ReqPerSec; got != 100 {
		t.Errorf("AggregateByHost r2/h2 after Prune = %v; want 100", got)
	}

	w.mu.RLock()
	_, hasR1 := w.hosts["r1"]
	_, hasR2 := w.hosts["r2"]
	w.mu.RUnlock()
	if hasR1 {
		t.Errorf("hosts[r1] still present after Prune dropped r1")
	}
	if !hasR2 {
		t.Errorf("hosts[r2] missing after Prune preserved r2")
	}
}

func TestSlidingWindow_PushHost_ConcurrentSafe(t *testing.T) {
	// Mirror of the metrics.IncByHost race test — concurrent
	// first-hits on the same (routeID, host) must not race on
	// the lazy outer/inner map insertion paths.
	w := NewSlidingWindow()
	const goroutines = 16
	const perGoroutine = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				host := "h1"
				if i%2 == 1 {
					host = "h2"
				}
				w.PushHost("r1", host, 1, 0, 0)
			}
		}()
	}
	wg.Wait()

	// Each host got exactly half the bumps. The aggregator
	// returns the mean per slot, NOT the total — but since each
	// push wrote a slot, the slot count = bump count and the
	// mean = 1 (Reqs=1 per slot).
	got1 := w.AggregateByHost("r1", "h1")
	got2 := w.AggregateByHost("r1", "h2")
	if got1.ReqPerSec != 1 {
		t.Errorf("h1.ReqPerSec=%v want 1 (slot mean)", got1.ReqPerSec)
	}
	if got2.ReqPerSec != 1 {
		t.Errorf("h2.ReqPerSec=%v want 1 (slot mean)", got2.ReqPerSec)
	}
}
