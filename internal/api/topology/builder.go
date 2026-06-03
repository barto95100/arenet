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
	"fmt"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

// StatusLookup is the interface the snapshot builder uses to
// resolve per-upstream health. CaddyStatusProber satisfies this
// directly; tests pass a stub.
type StatusLookup interface {
	Status(upstreamURL string) string
}

// noopStatusLookup is the fallback when no prober is supplied —
// every upstream reports "unknown", which matches the spec's
// graceful-degradation contract (the field is still present and
// well-typed, just informationless).
type noopStatusLookup struct{}

func (noopStatusLookup) Status(string) string { return StatusUnknown }

// MetricsView is the read-only view of the SlidingWindow that
// BuildSnapshot needs. Defined as an interface so callers can stub
// in tests without standing up a full window.
type MetricsView interface {
	Aggregate(routeID string) Aggregate
}

// BuildSnapshot joins the storage route list with the windowed
// metrics and per-upstream Caddy status into the wire-shape
// SnapshotResponse. Stage A behaviour for synthesised per-upstream
// fields is locked here:
//
//   - The route-level reqPerSec is split across upstreams
//     proportional to configured Weight (storage.Upstream.Weight).
//     When every weight is the same (round_robin default
//     post-J.1 = Weight 1 per backend), the split is even.
//   - p99LatencyMs on every upstream mirrors the route-level p95
//     (Stage A substitute — see types.go docstring).
//   - fairnessRatio is the same weight share, sums to ≈ 1.0 across
//     the cluster by construction.
//   - status comes from the Caddy admin probe; "unknown" when the
//     probe is unavailable or the upstream hasn't seen traffic yet.
//   - runtime is omitted (no source today).
//   - mtlsRequired stays false (no source today).
//
// The function never returns an error — degraded inputs (empty
// route list, nil metrics view, nil status lookup) all yield a
// well-formed, possibly-empty SnapshotResponse. The caller (HTTP
// handler / WS frame writer) does the I/O.
//
// now is the wall-clock for GeneratedAt. Passing it in rather
// than calling time.Now lets tests pin a deterministic value
// without ambient state.
func BuildSnapshot(
	routes []storage.Route,
	metrics MetricsView,
	status StatusLookup,
	now time.Time,
) SnapshotResponse {
	if metrics == nil {
		metrics = noopMetricsView{}
	}
	if status == nil {
		status = noopStatusLookup{}
	}

	out := SnapshotResponse{
		GeneratedAt: now.UTC(),
		Routes:      make([]Route, 0, len(routes)),
	}
	for i := range routes {
		out.Routes = append(out.Routes, buildRoute(&routes[i], metrics, status))
	}
	return out
}

// buildRoute is the per-route projection. Split out so the
// (route, metrics, status) ternary is testable independently of
// the storage list iteration.
func buildRoute(r *storage.Route, metrics MetricsView, status StatusLookup) Route {
	agg := metrics.Aggregate(r.ID)
	out := Route{
		ID:           r.ID,
		Host:         r.Host,
		Aliases:      cloneStrings(r.Aliases),
		LBPolicy:     r.LBPolicy,
		ReqPerSec:    agg.ReqPerSec,
		P99LatencyMs: agg.P95LatencyMs, // p95 substitute, see types doc
		ErrorRate5xx: agg.ErrorRate5xx,
		TLSEnabled:   r.TLSEnabled,
		WAFLevel:     r.WAFMode,
		// rateLimited and mtlsRequired: see Stage A docstring on
		// types.Route. rateLimited derivation will land when
		// storage.Route exposes a per-route rate-limit flag;
		// today the rate-limit handler is global (Step Q.4 +
		// S.4 lift to /api/v1) so there is no per-route bit to
		// map. We surface false rather than fabricate.
		RateLimited:  false,
		MTLSRequired: false,
		ClusterLabel: r.Host,
	}

	// Build the upstream list. weight-split first; status second
	// (status is independent of the split math).
	totalWeight := 0
	for _, u := range r.Upstreams {
		w := u.Weight
		if w <= 0 {
			w = 1 // storage validation guarantees >=1 but be defensive
		}
		totalWeight += w
	}
	if totalWeight == 0 {
		// Zero upstreams is forbidden by storage validation, but be
		// defensive — return the route with an empty upstream slice
		// rather than divide-by-zero.
		out.Upstreams = []Upstream{}
		return out
	}
	out.Upstreams = make([]Upstream, 0, len(r.Upstreams))
	for i, u := range r.Upstreams {
		w := u.Weight
		if w <= 0 {
			w = 1
		}
		share := float64(w) / float64(totalWeight)
		out.Upstreams = append(out.Upstreams, Upstream{
			ID:            fmt.Sprintf("%s-%d", r.ID, i),
			URL:           u.URL,
			Status:        status.Status(u.URL),
			ReqPerSec:     agg.ReqPerSec * share,
			P99LatencyMs:  agg.P95LatencyMs,
			FairnessRatio: share,
		})
	}
	return out
}

// cloneStrings deep-copies a []string so the response doesn't
// alias the storage layer's slice. Cheap (single allocation per
// route per emit) and keeps the contract clean.
func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// noopMetricsView is the fallback when no window is supplied.
// Every route looks idle.
type noopMetricsView struct{}

func (noopMetricsView) Aggregate(string) Aggregate { return Aggregate{} }

// HostBasename returns the part of host before the first dot.
// Used by callers that want a short cluster label (e.g.
// "api.arenet.fr" -> "api"). Currently the builder doesn't
// strip — frontend can decide. Exported for the (eventual)
// place that wants the short form without re-implementing the
// strip; kept here so the contract has a single owner.
func HostBasename(host string) string {
	if i := strings.IndexByte(host, '.'); i >= 0 {
		return host[:i]
	}
	return host
}
