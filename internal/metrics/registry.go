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

// counterCell holds the atomic counters for a single route. Both
// fields are accessed exclusively via the sync/atomic package; bare
// reads/writes are forbidden by go vet's copylocks/atomic checks
// (and would race under -race).
//
// counterCell is heap-allocated via NewRegistry and Sync; the map
// stores pointers so Inc can update fields without re-inserting.
type counterCell struct {
	reqs uint64 // total requests since last Snapshot
	errs uint64 // 5xx responses since last Snapshot
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
// status code. Increments reqs unconditionally; increments errs only
// when status >= 500. If routeID is unknown to the Registry, the
// call is a SILENT no-op (spec §11.1: the brief race window between
// route deletion and Caddy reload completion is intentionally
// tolerated rather than erroring).
//
// Hot path. Must not allocate.
func (r *Registry) Inc(routeID string, status int) {
	r.mu.RLock()
	cell, ok := r.cells[routeID]
	r.mu.RUnlock()
	if !ok {
		return
	}
	atomic.AddUint64(&cell.reqs, 1)
	if status >= 500 {
		atomic.AddUint64(&cell.errs, 1)
	}
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
func (r *Registry) Snapshot() map[string]Delta {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make(map[string]Delta, len(r.cells))
	for id, cell := range r.cells {
		reqs := atomic.SwapUint64(&cell.reqs, 0)
		errs := atomic.SwapUint64(&cell.errs, 0)
		out[id] = Delta{Reqs: reqs, Errs: errs}
	}
	return out
}
