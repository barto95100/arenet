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
	// hosts is the per-(routeID, host) state introduced by
	// Topology Plan B Phase 2.2. Outer key = routeID, inner
	// key = lowercased host. Independent of the route-level
	// state above (per-host bumps come from the parallel
	// Snapshot.Hosts slice the ticker produces).
	//
	// Memory budget (worst case): 50 routes × 30 aliases ×
	// (60 slots × ~32 bytes/slot + ~48 bytes/map-entry) ≈
	// ~100 KB total. Negligible at homelab cardinality.
	hosts map[string]map[string]*ringState
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
		hosts:  make(map[string]map[string]*ringState),
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
	appendSlot(rs, reqs, errs, p95Ms)
}

// appendSlot is the shared slot-rotate helper used by both Push
// (per-route) and PushHost (per-host). Splitting it out keeps the
// rotation semantics in one place — if the WindowSlots / append
// model changes, both call sites move together.
func appendSlot(rs *ringState, reqs, errs uint64, p95Ms int32) {
	slot := metricSlot{
		Reqs:         reqs,
		Errs:         errs,
		LatencyP95Ms: p95Ms,
	}
	if len(rs.slots) < WindowSlots {
		rs.slots = append(rs.slots, slot)
		return
	}
	copy(rs.slots, rs.slots[1:])
	rs.slots[WindowSlots-1] = slot
}

// PushHost records one tick's metrics for a (routeID, host)
// pair. Mirror of Push but for the per-host ring buffers.
// Topology Plan B Phase 2.2 addition.
//
// Pushes for absent (routeID, host) pairs implicitly create the
// outer + inner maps on first touch. The host string must
// already be the canonical (lowercased + port-stripped) form —
// the producer (Ticker.makeSnapshot consuming Registry.
// SnapshotHosts()) preserves the canonical form chosen by the
// Phase 1 middleware's resolveHost.
//
// Routes are NOT pruned here. See Prune.
func (w *SlidingWindow) PushHost(routeID, host string, reqs, errs uint64, p95Ms int32) {
	if host == "" {
		// Empty host is not a valid key — defensive guard against a
		// future producer that forgets to validate. Without this the
		// inner map would acquire an "" entry that AggregateByHost
		// would never query but Prune would never clear.
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	inner, ok := w.hosts[routeID]
	if !ok {
		inner = make(map[string]*ringState)
		w.hosts[routeID] = inner
	}
	rs, ok := inner[host]
	if !ok {
		rs = &ringState{slots: make([]metricSlot, 0, WindowSlots)}
		inner[host] = rs
	}
	appendSlot(rs, reqs, errs, p95Ms)
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
	return aggregateRing(w.routes[routeID])
}

// AggregateByHost is the per-(routeID, host) windowed view.
// Topology Plan B Phase 2.2 addition. Same semantics as
// Aggregate but indexed on the (routeID, host) pair instead of
// routeID alone. Unknown pairs (route exists but no traffic
// yet on this alias) return zero — the topology builder
// renders this as an idle alias entry sorted to the bottom of
// the per-route alias list.
//
// Phase 3.d (2026-06-17) denominator-parity fix. The per-route
// ring (Push) accumulates a slot every source tick because
// pushSnap iterates snap.Routes which always carries every
// route from ListRoutesForMetrics. The per-host ring (PushHost)
// only accumulates slots on ticks where the host actually
// emitted a HostDelta — which only happens AFTER the lazy
// host cell exists in the Registry (created on first hit).
// As a result, a long-running route with an alias whose first
// traffic arrived recently produces:
//
//   route ring: 60 slots (most pre-traffic zeros + recent 1s)
//   host ring: K slots (only the post-first-hit ones)
//
// aggregateRing divides by `len(slots)` so the host ring
// reports rate / K while the route ring reports rate / 60.
// Same underlying traffic, wildly different denominators —
// host appears (60/K)× higher than reality. The operator's
// screenshot (sonarr 3.33 r/s, radarr 1.67 r/s, logs 0.16 r/s
// for a route reporting 1 r/s aggregate) was this inflation
// at K ≈ 18 / 36 / 6 respectively.
//
// Fix: align the host ring's denominator to the route ring's
// slot count. Slots missing from the host ring (because no
// cell existed yet) are equivalent to zero-Reqs slots — the
// host received no traffic during those ticks, by
// construction. Computing host's rate as
// host.totalReqs / route.slotCount gives the SAME number of
// requests over the SAME window as the route's denominator.
func (w *SlidingWindow) AggregateByHost(routeID, host string) Aggregate {
	w.mu.RLock()
	defer w.mu.RUnlock()
	inner, ok := w.hosts[routeID]
	if !ok {
		return Aggregate{}
	}
	hostRing := inner[host]
	if hostRing == nil || len(hostRing.slots) == 0 {
		return Aggregate{}
	}
	// Use the route ring's slot count as the denominator —
	// see the docstring above for the parity rationale. If
	// the route ring doesn't exist (e.g., the host ring has
	// been pushed before the route ring, which can happen
	// at startup before the first storage.ListRoutes
	// resolves) fall back to the host ring's own length —
	// preserves the pre-Phase-3.d behaviour for that
	// degenerate transient.
	denom := len(hostRing.slots)
	if routeRing := w.routes[routeID]; routeRing != nil && len(routeRing.slots) > denom {
		denom = len(routeRing.slots)
	}
	return aggregateRingWithDenom(hostRing, denom)
}

// aggregateRing is the shared aggregation kernel used by
// Aggregate. The denominator IS the ring's own slot count —
// freshly-created routes report their real rate immediately
// rather than a divided-by-WindowSlots underestimate.
//
// AggregateByHost uses aggregateRingWithDenom instead so it
// can pin the denominator to the route ring's slot count
// (see AggregateByHost docstring on the Phase 3.d parity fix).
//
// Returns the zero Aggregate when rs is nil or empty — the
// "idle entry" case the builder relies on.
func aggregateRing(rs *ringState) Aggregate {
	if rs == nil || len(rs.slots) == 0 {
		return Aggregate{}
	}
	return aggregateRingWithDenom(rs, len(rs.slots))
}

// aggregateRingWithDenom is the parametrised aggregation
// kernel. Denominator MUST be ≥ 1 and SHOULD be ≥ len(rs.slots);
// callers wanting the legacy "divide by own length" semantics
// should use aggregateRing.
//
// Pure on its input; safe to call under either RLock or no
// lock as long as the ring isn't mutated concurrently.
func aggregateRingWithDenom(rs *ringState, denom int) Aggregate {
	if rs == nil || len(rs.slots) == 0 || denom <= 0 {
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
		// Per-tick is per-second (metrics.TickInterval == 1s),
		// so the mean of slot Reqs IS the mean req/s — no
		// extra division by tick width.
		ReqPerSec:    float64(totalReqs) / float64(denom),
		P95LatencyMs: rs.slots[len(rs.slots)-1].LatencyP95Ms,
	}
	if totalReqs > 0 {
		// Count-weighted error rate, expressed as a percentage
		// to match the frontend TopologyRoute.errorRate5xx
		// contract (0..100, not 0..1).
		out.ErrorRate5xx = (float64(totalErrs) / float64(totalReqs)) * 100.0
	}
	return out
}

// Prune drops every route from the window that is NOT in keep.
// Called by the stream handler whenever the storage route list
// changes (route deletion) to avoid an unbounded map for routes
// that no longer exist.
//
// Phase 2.2 — also drops the corresponding per-host entries.
// Inner maps are released wholesale so a renamed / deleted
// route doesn't leak per-alias ring state.
func (w *SlidingWindow) Prune(keep map[string]struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for id := range w.routes {
		if _, ok := keep[id]; !ok {
			delete(w.routes, id)
		}
	}
	for id := range w.hosts {
		if _, ok := keep[id]; !ok {
			delete(w.hosts, id)
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
