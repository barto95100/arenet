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
	"sync"
	"testing"
)

func TestSlidingWindow_EmptyRouteReturnsZero(t *testing.T) {
	w := NewSlidingWindow()
	agg := w.Aggregate("nope")
	if agg.ReqPerSec != 0 || agg.ErrorRate5xx != 0 || agg.P95LatencyMs != 0 {
		t.Errorf("empty route: want zero aggregate, got %+v", agg)
	}
}

func TestSlidingWindow_SingleTick(t *testing.T) {
	w := NewSlidingWindow()
	w.Push("r1", 100, 5, 42)
	agg := w.Aggregate("r1")
	if agg.ReqPerSec != 100 {
		t.Errorf("ReqPerSec: got %v, want 100", agg.ReqPerSec)
	}
	if agg.P95LatencyMs != 42 {
		t.Errorf("P95LatencyMs: got %d, want 42", agg.P95LatencyMs)
	}
	wantRate := 5.0
	if agg.ErrorRate5xx != wantRate {
		t.Errorf("ErrorRate5xx: got %v, want %v", agg.ErrorRate5xx, wantRate)
	}
}

func TestSlidingWindow_MeanAcrossMultipleTicks(t *testing.T) {
	w := NewSlidingWindow()
	// 3 ticks at 100 / 200 / 300 req → mean 200.
	w.Push("r1", 100, 0, 10)
	w.Push("r1", 200, 0, 20)
	w.Push("r1", 300, 0, 30)
	agg := w.Aggregate("r1")
	if agg.ReqPerSec != 200 {
		t.Errorf("ReqPerSec mean: got %v, want 200", agg.ReqPerSec)
	}
	if agg.P95LatencyMs != 30 {
		t.Errorf("P95LatencyMs (latest): got %d, want 30", agg.P95LatencyMs)
	}
}

func TestSlidingWindow_CountWeightedErrorRate(t *testing.T) {
	w := NewSlidingWindow()
	// Slot 1: 1000 reqs, 0 errs (busy clean slot).
	// Slot 2:    1 req,  1 err (one outlier 500).
	// Count-weighted rate = 1 / 1001 ≈ 0.0999 % — NOT 50 %
	// (which a naive mean of slot rates would yield).
	w.Push("r1", 1000, 0, 0)
	w.Push("r1", 1, 1, 0)
	agg := w.Aggregate("r1")
	want := 100.0 / 1001.0 // already a percentage (1 / 1001 * 100)
	if math.Abs(agg.ErrorRate5xx-want) > 1e-9 {
		t.Errorf("count-weighted ErrorRate5xx: got %v, want %v", agg.ErrorRate5xx, want)
	}
}

func TestSlidingWindow_FillsUpToWindowSlots(t *testing.T) {
	w := NewSlidingWindow()
	for i := 0; i < WindowSlots+5; i++ {
		w.Push("r1", uint64(i+1), 0, int32(i))
	}
	if got := w.SlotCount("r1"); got != WindowSlots {
		t.Errorf("SlotCount: got %d, want %d (ring should cap at WindowSlots)", got, WindowSlots)
	}
	// After the ring fills + 5 extra pushes, the oldest 5 slots
	// have been evicted. Slot values pushed: 1..65; remaining
	// should be 6..65; mean = (6+7+...+65) / 60 = 35.5.
	agg := w.Aggregate("r1")
	// Sum of 6..65 = (6+65)*60/2 = 2130; mean = 2130 / 60 = 35.5.
	want := 35.5
	if math.Abs(agg.ReqPerSec-want) > 1e-9 {
		t.Errorf("ReqPerSec mean after eviction: got %v, want %v", agg.ReqPerSec, want)
	}
	// Latest slot value pushed was i=64 (last iteration), so
	// P95 latest = int32(64) = 64.
	if agg.P95LatencyMs != 64 {
		t.Errorf("P95LatencyMs latest after eviction: got %d, want 64", agg.P95LatencyMs)
	}
}

func TestSlidingWindow_PruneDropsAbsentRoutes(t *testing.T) {
	w := NewSlidingWindow()
	w.Push("r1", 1, 0, 0)
	w.Push("r2", 1, 0, 0)
	w.Push("r3", 1, 0, 0)
	if w.Size() != 3 {
		t.Fatalf("Size before prune: got %d, want 3", w.Size())
	}
	w.Prune(map[string]struct{}{"r1": {}, "r3": {}})
	if w.Size() != 2 {
		t.Errorf("Size after prune: got %d, want 2", w.Size())
	}
	if w.SlotCount("r2") != 0 {
		t.Errorf("r2 should have been pruned, still has %d slots", w.SlotCount("r2"))
	}
}

func TestSlidingWindow_ConcurrentPushAggregate(t *testing.T) {
	// Smoke for race detector: 100 pushers + 100 readers in
	// parallel should never panic or trip -race. We don't assert
	// values (the order is non-deterministic) — the test passes
	// as long as -race stays quiet.
	w := NewSlidingWindow()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				w.Push("r1", uint64(i), 0, int32(j))
			}
		}(i)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = w.Aggregate("r1")
			}
		}()
	}
	wg.Wait()
}
