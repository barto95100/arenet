// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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

package routehealth

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/barto95100/arenet/internal/caddyhc"
	"github.com/barto95100/arenet/internal/storage"
)

// upstreamVerdicts maps a route's normalized upstream address to its
// per-route caddyhc status (healthy / unhealthy).
type upstreamVerdicts = map[string]string

// Evaluator holds per-route health for routes whose upstream is SHARED
// with other routes. Routes on a unique upstream are never evaluated here
// — their address-keyed tracker status is already correct, and the badge
// and notifier keep reading it unchanged. Shared routes are probed
// individually (probe.go) so a Traefik-style multiplexing upstream can be
// disambiguated per route. Safe for concurrent use.
//
// The evaluator is the single source of per-route truth consumed by both
// the route-list badge and the notifier, so the two can never again
// disagree with reality for a shared upstream.
type Evaluator struct {
	// probe is the seam tests replace; production calls probeRouteUpstreams.
	probe   func(ctx context.Context, r storage.Route) map[string]string
	timeout time.Duration
	clk     clock
	logger  *slog.Logger

	mu           sync.RWMutex
	shared       map[string]int              // normalized addr -> count of enabled routes using it
	sharedRoutes map[string]storage.Route    // routeID -> route, only routes on a shared upstream
	perRoute     map[string]upstreamVerdicts // routeID -> (addr -> status)
}

// NewEvaluator builds an evaluator. timeout bounds one upstream probe
// (DefaultProbeTimeout if <= 0). The index is empty until the first
// Refresh; RouteUpstreamStatus reports ok=false until then, so callers
// fall back to the tracker.
func NewEvaluator(timeout time.Duration, logger *slog.Logger) *Evaluator {
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	if logger == nil {
		logger = slog.Default()
	}
	e := &Evaluator{
		timeout:      timeout,
		clk:          realClock{},
		logger:       logger,
		shared:       make(map[string]int),
		sharedRoutes: make(map[string]storage.Route),
		perRoute:     make(map[string]upstreamVerdicts),
	}
	e.probe = func(ctx context.Context, r storage.Route) map[string]string {
		return probeRouteUpstreams(ctx, r, e.timeout)
	}
	return e
}

// Refresh recomputes which upstreams are shared and the set of shared
// routes from the applied config, dropping cached verdicts for routes
// that are no longer shared (deleted, disabled, or their upstream became
// unique). Call it at each Caddy reload — the same seam the notifier and
// tracker use.
func (e *Evaluator) Refresh(routes []storage.Route) {
	counts := SharedUpstreams(routes)
	sharedRoutes := make(map[string]storage.Route)
	for _, r := range routes {
		if IsRouteShared(r, counts) {
			sharedRoutes[r.ID] = r
		}
	}
	e.mu.Lock()
	e.shared = counts
	e.sharedRoutes = sharedRoutes
	for id := range e.perRoute {
		if _, ok := sharedRoutes[id]; !ok {
			delete(e.perRoute, id)
		}
	}
	e.mu.Unlock()
}

// IsShared reports whether a route's health must be read per-route rather
// than from the address-keyed tracker.
func (e *Evaluator) IsShared(r storage.Route) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return IsRouteShared(r, e.shared)
}

// IsSharedAddr reports whether a normalized upstream address is used by
// two or more enabled routes.
func (e *Evaluator) IsSharedAddr(addr string) bool {
	key := caddyhc.NormalizeAddr(addr)
	if key == "" {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.shared[key] >= 2
}

// RouteUpstreamStatus returns the per-route verdict for one upstream of a
// shared route. ok is false when the route is not evaluated here (unique
// upstream) or no verdict has been computed yet — the caller then falls
// back to the address-keyed tracker, preserving today's behaviour.
func (e *Evaluator) RouteUpstreamStatus(routeID, upstreamURL string) (string, bool) {
	key := caddyhc.NormalizeAddr(upstreamURL)
	if key == "" {
		return "", false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	m, ok := e.perRoute[routeID]
	if !ok {
		return "", false
	}
	s, ok := m[key]
	return s, ok
}

// evaluateRoute probes one shared route now and stores its per-upstream
// verdicts, returning the stored map. An empty probe result (HC disabled,
// nothing readable) clears the route's cache so RouteUpstreamStatus falls
// back to the tracker rather than serve a stale verdict.
func (e *Evaluator) evaluateRoute(ctx context.Context, r storage.Route) upstreamVerdicts {
	res := e.probe(ctx, r)
	e.mu.Lock()
	if len(res) == 0 {
		delete(e.perRoute, r.ID)
	} else {
		e.perRoute[r.ID] = res
	}
	e.mu.Unlock()
	return res
}

// sharedRoutesSnapshot copies the current shared-route set so a probe loop
// does not hold the lock across network I/O.
func (e *Evaluator) sharedRoutesSnapshot() []storage.Route {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]storage.Route, 0, len(e.sharedRoutes))
	for _, r := range e.sharedRoutes {
		out = append(out, r)
	}
	return out
}
