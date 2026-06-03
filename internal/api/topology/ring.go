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

import "sync"

// WindowSlots is the depth of the per-route sliding window. The
// underlying metrics package ticks at 1 Hz (metrics.TickInterval),
// so 60 slots == 60 seconds of history. The UI's legend
// ("moyenne glissante des 60 dernières secondes") is matched
// exactly by this choice.
//
// A future change to metrics.TickInterval would NOT silently break
// the window size — both the slot count and the contract are tied
// to the 1 Hz tick. If either changes, both update.
const WindowSlots = 60

// SlidingWindow tracks the last WindowSlots ticks of per-route
// metrics. Push records one tick's metrics for a route; Aggregate
// returns the windowed view ready for the SnapshotResponse builder.
//
// Stage A aggregation rules:
//
//   - reqPerSec is the arithmetic mean across the populated slots
//     (sum / count, not sum / WindowSlots). A freshly-created route
//     reports its real rate immediately rather than a divided-by-60
//     underestimate; once the ring is full the two denominators
//     converge.
//   - errorRate5xx is a count-weighted average:
//     sum(errs) / max(sum(reqs), 1) × 100. Each slot's contribution
//     is proportional to its traffic — a quiet slot with one 500
//     doesn't dominate a busy slot with zero errors.
//   - p95LatencyMs is the LATEST slot's p95 (not aggregated). A
//     true window p95 requires keeping the underlying bucket counts
//     per tick (Stage B). Aggregating per-tick p95s ourselves
//     would be statistically dubious — the mean of 60 percentiles
//     is not the window percentile. We document the limitation and
//     defer.
//
// SlidingWindow is goroutine-safe.
type SlidingWindow struct {
	mu     sync.RWMutex
	routes map[string]*ringState
}

// ringState is one route's per-tick history. Slots are stored in
// append order — the oldest slot is at index 0, the most recent
// at len(slots)-1. The ring "rotates" via a copy-and-overwrite in
// Push when len == WindowSlots, which is O(N) per push (N=60) but
// trivial at any homelab route cardinality.
type ringState struct {
	slots []metricSlot
}

// metricSlot is one tick's worth of post-aggregation route metrics.
type metricSlot struct {
	Reqs         uint64
	Errs         uint64
	LatencyP95Ms int32
}

// NewSlidingWindow returns an empty window with no route history.
func NewSlidingWindow() *SlidingWindow {
	return &SlidingWindow{
		routes: make(map[string]*ringState),
	}
}

// Push records one tick's metrics for routeID. reqs is the count
// of requests in this tick; errs is the count of 5xx responses;
// p95Ms is the per-tick p95 already computed by the metrics
// histogram drain (or 0 if no samples in this tick).
//
// Pushes for absent route ids implicitly create the ring on first
// touch; routes are NOT pruned here, see Prune.
func (w *SlidingWindow) Push(routeID string, reqs, errs uint64, p95Ms int32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	rs, ok := w.routes[routeID]
	if !ok {
		// Preallocate cap WindowSlots so the first WindowSlots
		// appends don't grow the backing array.
		rs = &ringState{slots: make([]metricSlot, 0, WindowSlots)}
		w.routes[routeID] = rs
	}
	slot := metricSlot{
		Reqs:         reqs,
		Errs:         errs,
		LatencyP95Ms: p95Ms,
	}
	if len(rs.slots) < WindowSlots {
		rs.slots = append(rs.slots, slot)
	} else {
		copy(rs.slots, rs.slots[1:])
		rs.slots[WindowSlots-1] = slot
	}
}

// Aggregate is the windowed view of one route, ready for the
// builder to splice into the SnapshotResponse.
type Aggregate struct {
	ReqPerSec    float64
	ErrorRate5xx float64 // percentage 0..100
	P95LatencyMs int32   // latest-slot value (see SlidingWindow doc)
}

// Aggregate computes the windowed metrics for one route. An
// empty/unknown route returns zero values, which the builder
// renders as an idle entry on the canvas — correct for a route
// that's been declared but has not yet seen traffic.
func (w *SlidingWindow) Aggregate(routeID string) Aggregate {
	w.mu.RLock()
	defer w.mu.RUnlock()
	rs, ok := w.routes[routeID]
	if !ok || len(rs.slots) == 0 {
		return Aggregate{}
	}
	var (
		totalReqs uint64
		totalErrs uint64
	)
	for _, s := range rs.slots {
		totalReqs += s.Reqs
		totalErrs += s.Errs
	}
	out := Aggregate{
		// Per-tick is per-second (metrics.TickInterval == 1s), so
		// mean of slot Reqs IS the mean req/s — no extra division
		// by tick width.
		ReqPerSec:    float64(totalReqs) / float64(len(rs.slots)),
		P95LatencyMs: rs.slots[len(rs.slots)-1].LatencyP95Ms,
	}
	if totalReqs > 0 {
		// Count-weighted error rate, expressed as a percentage to
		// match the frontend TopologyRoute.errorRate5xx contract
		// (0..100, not 0..1).
		out.ErrorRate5xx = (float64(totalErrs) / float64(totalReqs)) * 100.0
	}
	return out
}

// Prune drops every route from the window that is NOT in keep.
// Called by the stream handler whenever the storage route list
// changes (route deletion) to avoid an unbounded map for routes
// that no longer exist.
func (w *SlidingWindow) Prune(keep map[string]struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for id := range w.routes {
		if _, ok := keep[id]; !ok {
			delete(w.routes, id)
		}
	}
}

// Size returns the count of routes currently tracked. Test helper.
func (w *SlidingWindow) Size() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.routes)
}

// SlotCount returns the number of slots populated for routeID.
// Test helper.
func (w *SlidingWindow) SlotCount(routeID string) int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	rs, ok := w.routes[routeID]
	if !ok {
		return 0
	}
	return len(rs.slots)
}
