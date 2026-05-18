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
	"context"
	"time"
)

// RouteLister returns the canonical list of routes for the current
// configuration. The Ticker calls it once per tick to join the
// Registry's deltas with route metadata (host, upstream) for the
// Snapshot wire shape (spec §5.2).
//
// The concrete implementation in production is a thin adapter over
// storage.Store.ListRoutes; an interface keeps this package
// decoupled from internal/storage and trivially mockable in tests.
type RouteLister interface {
	// ListRoutesForMetrics returns one entry per persisted route,
	// in the canonical order produced by storage. The ID, Host, and
	// Upstream fields are the only ones consumed.
	ListRoutesForMetrics(ctx context.Context) ([]RouteMetadata, error)
}

// RouteMetadata is the subset of storage.Route consumed by Ticker.
// Defined here so internal/metrics does not import internal/storage.
type RouteMetadata struct {
	ID       string
	Host     string
	Upstream string
}

// Ticker drives the per-tick snapshot loop (spec §4.3). On each tick
// it calls Registry.Snapshot, joins the deltas with the current
// route list, and publishes the resulting Snapshot to the broadcaster.
//
// Cancellation: Run honors ctx.Done() and returns promptly. Caller
// typically uses the cmd/arenet process context.
type Ticker struct {
	registry    *Registry
	broadcaster *Broadcaster
	lister      RouteLister
}

// NewTicker constructs a Ticker bound to the given registry,
// broadcaster, and route lister. All three are required; nil
// arguments panic at construction (programmer error, not a runtime
// condition).
func NewTicker(registry *Registry, broadcaster *Broadcaster, lister RouteLister) *Ticker {
	if registry == nil {
		panic("metrics.NewTicker: registry is nil")
	}
	if broadcaster == nil {
		panic("metrics.NewTicker: broadcaster is nil")
	}
	if lister == nil {
		panic("metrics.NewTicker: lister is nil")
	}
	return &Ticker{
		registry:    registry,
		broadcaster: broadcaster,
		lister:      lister,
	}
}

// Run drives the snapshot loop until ctx is cancelled. Blocking;
// caller invokes it in a goroutine. Returns when ctx is done.
func (t *Ticker) Run(ctx context.Context) {
	tick := time.NewTicker(TickInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			snap := t.makeSnapshot(ctx, now)
			t.broadcaster.Publish(snap)
		}
	}
}

// makeSnapshot reads the Registry's deltas, joins them with the
// route list from the lister, and assembles the wire-shape Snapshot
// (spec §5.2). Idle routes — those present in the route list but
// absent from the Registry's snapshot, or present with zero counters
// — are still included with zero counters.
//
// On lister error, the snapshot still goes out but with an empty
// Routes slice. The client sees a tick with zero routes for one
// second; the next tick (when storage is healthy again) restores
// the normal listing. The error is not logged here — the lister
// implementation owns its own error logging.
func (t *Ticker) makeSnapshot(ctx context.Context, now time.Time) Snapshot {
	deltas := t.registry.Snapshot()

	routes, err := t.lister.ListRoutesForMetrics(ctx)
	if err != nil {
		return Snapshot{T: now.UTC(), Routes: []RouteSnapshot{}}
	}

	out := make([]RouteSnapshot, 0, len(routes))
	for _, rt := range routes {
		d := deltas[rt.ID] // zero Delta if absent
		var errRate float64
		if d.Reqs > 0 {
			errRate = float64(d.Errs) / float64(d.Reqs)
			if errRate > 1.0 {
				errRate = 1.0 // §5.2 clamp guarantee
			}
		}
		out = append(out, RouteSnapshot{
			ID:         rt.ID,
			Host:       rt.Host,
			Upstream:   rt.Upstream,
			Reqs:       d.Reqs,
			Errs:       d.Errs,
			ReqPerSec:  d.Reqs, // == reqs since TickInterval == 1s (§5.2)
			ErrRate5xx: errRate,
		})
	}
	return Snapshot{T: now.UTC(), Routes: out}
}
