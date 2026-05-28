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

package metrics

import (
	"sync"
	"sync/atomic"
)

// Registry holds per-route request and 5xx-error counters with
// concurrency semantics specified in §4 of the Step E spec:
//
//   - Inc is the hot path: RLock + atomic add. Called once per
//     proxied HTTP request, must not allocate (bench < 200 ns
//     per op, allocs/op == 0).
//   - Snapshot runs at 1 Hz from the Ticker goroutine: RLock +
//     atomic.SwapUint64 per cell, returns a fresh map of Deltas
//     (count since previous tick, NOT cumulative — spec §11.9).
//   - Sync runs on each Caddy reload (rare): Lock, then inserts
//     new cells and deletes stale ones in a single critical
//     section regardless of the diff size (spec §4.1).
//
// The Read/Write mutex pattern lets Inc and Snapshot proceed in
// parallel; Sync is the only writer. Inc and Snapshot are correct
// concurrently because each cell field is mutated with atomic
// operations independently of the lock. The lock only protects the
// map's structure (key add/remove), not the cell contents.
//
// The pair (reqs, errs) is NOT atomic together; spec §11.8 documents
// the rare race and the client-side mitigation (errRate clamp).
type Registry struct {
	mu    sync.RWMutex
	cells map[string]*counterCell
}

// counterCell holds the atomic counters for a single route. Counter
// fields are accessed exclusively via the sync/atomic package; bare
// reads/writes are forbidden by go vet's copylocks/atomic checks
// (and would race under -race).
//
// counterCell is heap-allocated via NewRegistry and Sync; the map
// stores pointers so Inc can update fields without re-inserting.
//
// Step L additions (additive, no Step E regression):
//   - errs4xx tracks 4xx responses separately from errs (5xx).
//   - latency is a fixed-bucket histogram populated by Inc on the
//     hot path. Snapshot drains it into a per-tick p95 value;
//     hot-path cost stays atomic-only (no allocation, no lock).
type counterCell struct {
	reqs    uint64 // total requests since last Snapshot
	errs    uint64 // 5xx responses since last Snapshot (Step E name preserved)
	errs4xx uint64 // 4xx responses since last Snapshot (Step L)
	latency latencyHist
}

// latencyHist is the metrics-package-internal copy of the
// observability.LatencyHistogram contract. Duplicated rather than
// imported to keep internal/metrics independent of
// internal/observability — preserves the spec's clean dependency
// direction (metrics → nothing; observability → metrics indirectly,
// via main.go wiring, never via import).
//
// 17 log-spaced buckets covering [0.5 ms, 65536 ms). See
// internal/observability/histogram.go for the design rationale —
// the bucket layout is identical so a future refactor (if we ever
// move the histogram into a shared internal/histogram package)
// is a rename, not a semantic change.
type latencyHist struct {
	counts [17]uint64
}

func (h *latencyHist) observe(durMs float64) {
	const baseMs = 0.5
	idx := 0
	switch {
	case durMs < baseMs:
		idx = 0
	default:
		// log2(durMs / baseMs) clamped to [0, 16].
		x := durMs / baseMs
		// Fast log2-of-float via repeated halving; avoids math.Log2
		// to keep the hot path free of any FP transcendental cost.
		// For our range (0.5 ms .. 65536 ms = factor 131072 = 2^17),
		// 17 iterations is the worst case.
		for x >= 2 && idx < 16 {
			x /= 2
			idx++
		}
	}
	atomic.AddUint64(&h.counts[idx], 1)
}

// drainP95 returns the p95 in ms over the buckets and resets all
// counts to zero in one go. Goroutine-local read pattern (called
// only by Snapshot, which already holds the RLock that protects
// the map structure); within each cell we atomic.Swap each bucket
// so a concurrent observe() either lands in this drain (counted)
// or in the next tick (counted next time).
func (h *latencyHist) drainP95() int32 {
	const baseMs = 0.5
	var total uint64
	var drained [17]uint64
	for i := range h.counts {
		c := atomic.SwapUint64(&h.counts[i], 0)
		drained[i] = c
		total += c
	}
	if total == 0 {
		return 0
	}
	// p95 = upper edge of bucket where cumulative count first
	// reaches 95 % of total. Compute threshold with integer ceil:
	// ceil(total * 95 / 100).
	threshold := (total*95 + 99) / 100
	var cum uint64
	for i, c := range drained {
		cum += c
		if cum >= threshold {
			// Upper edge of bucket i = baseMs * 2^(i+1).
			edge := baseMs * float64(int(1)<<(i+1))
			if edge > float64(int32(^uint32(0)>>1)) {
				return int32(^uint32(0) >> 1)
			}
			return int32(edge)
		}
	}
	// Shouldn't happen — if total > 0 some bucket was non-zero.
	return int32(baseMs * float64(int(1)<<17))
}

// NewRegistry returns an empty Registry. The Caddy module's
// Provision call (Chunk 2) is expected to obtain a *Registry via
// the package-level singleton (global.go), not by calling
// NewRegistry directly except in tests and in cmd/arenet's main.
func NewRegistry() *Registry {
	return &Registry{
		cells: make(map[string]*counterCell),
	}
}

// Inc records a single request against routeID with the given HTTP
// status code and duration. Increments reqs unconditionally;
// classifies 5xx into errs and 4xx into errs4xx separately (Step L
// AC #3: 4xx and 5xx must NEVER share a counter). Records the
// duration into the cell's latency histogram for p95 computation
// at the next Snapshot.
//
// If routeID is unknown to the Registry, the call is a SILENT
// no-op (spec §11.1: the brief race window between route deletion
// and Caddy reload completion is intentionally tolerated rather
// than erroring).
//
// Hot path. Must not allocate, must not perform I/O. AC #13: a
// metrics-DB failure later in the pipeline must not propagate
// here — Inc only mutates in-memory atomic state.
func (r *Registry) Inc(routeID string, status int, durMs float64) {
	r.mu.RLock()
	cell, ok := r.cells[routeID]
	r.mu.RUnlock()
	if !ok {
		return
	}
	atomic.AddUint64(&cell.reqs, 1)
	switch {
	case status >= 500:
		atomic.AddUint64(&cell.errs, 1)
	case status >= 400:
		atomic.AddUint64(&cell.errs4xx, 1)
	}
	cell.latency.observe(durMs)
}

// Sync reconciles the Registry's cells with the canonical list of
// current route IDs. Called by caddymgr after each successful Caddy
// reload (spec §4.1). One write-lock acquisition per reload,
// regardless of how many routes were added or removed.
//
// Cells preserved across the call (same routeID in both old and new
// set) retain their current counter values — a route updated
// in-place (same UUID, new upstream) keeps accumulating per §11.2.
//
// The function tolerates an empty routeIDs slice (drains all cells)
// and a nil slice (treated as empty).
func (r *Registry) Sync(routeIDs []string) {
	wanted := make(map[string]struct{}, len(routeIDs))
	for _, id := range routeIDs {
		wanted[id] = struct{}{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Insert cells for IDs in wanted but absent from r.cells.
	for id := range wanted {
		if _, exists := r.cells[id]; !exists {
			r.cells[id] = &counterCell{}
		}
	}
	// Delete cells for IDs in r.cells but absent from wanted.
	// Safe per Go spec: range over a map allows delete of current key.
	for id := range r.cells {
		if _, keep := wanted[id]; !keep {
			delete(r.cells, id)
		}
	}
}

// Snapshot atomically swaps each cell's counters to zero and
// returns the deltas observed for this tick. Called by the Ticker
// at 1 Hz (spec §4.3).
//
// The RWMutex is read-locked so concurrent Inc calls proceed in
// parallel. The serialization point per cell is the
// atomic.SwapUint64 — the value returned is the count that
// accumulated since the previous Snapshot.
//
// NOT atomic across the (reqs, errs) pair within a single cell:
// spec §11.8 documents the symptom (a tick may show errs > reqs)
// and the client-side clamp that masks it. This implementation
// keeps the simple two-swap form because the next tick auto-corrects
// and the rare cosmetic spike is preferable to a per-cell mutex
// on the hot path.
//
// Returns a fresh, non-nil map; callers may retain it freely. An
// empty Registry returns an empty (non-nil) map.
//
// Step L addition: also drains errs4xx and the per-tick p95 from
// the latency histogram. The drain pattern is the same atomic
// swap-and-zero — consistent with Step E's existing semantics.
func (r *Registry) Snapshot() map[string]Delta {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make(map[string]Delta, len(r.cells))
	for id, cell := range r.cells {
		reqs := atomic.SwapUint64(&cell.reqs, 0)
		errs := atomic.SwapUint64(&cell.errs, 0)
		errs4xx := atomic.SwapUint64(&cell.errs4xx, 0)
		p95 := cell.latency.drainP95()
		out[id] = Delta{Reqs: reqs, Errs: errs, Errs4xx: errs4xx, LatencyP95Ms: p95}
	}
	return out
}
