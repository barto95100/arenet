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

package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/barto95100/arenet/internal/api/topology"
	"github.com/barto95100/arenet/internal/storage"
)

// SnapshotRouteLister is the minimal storage interface
// SnapshotHandler needs. Defined here rather than reused from
// metrics.RouteLister because metrics.RouteLister returns a slim
// RouteMetadata projection (Step E) — the snapshot endpoint needs
// the full storage.Route (aliases, lb policy, tls, waf mode, etc.)
// so it queries storage directly.
type SnapshotRouteLister interface {
	ListRoutes(ctx context.Context) ([]storage.Route, error)
}

// SnapshotHandler serves GET /api/v1/topology/snapshot — the
// one-shot read used on initial page mount and as a fallback
// after a WebSocket reconnect.
//
// Hard-auth (viewer + admin both accepted) is applied upstream by
// the router middleware; by the time ServeHTTP runs, the session
// is already resolved. No additional role gate here — Phase 2 is
// read-only (Phase 2.1 will add admin-only mutations on
// sibling routes).
type SnapshotHandler struct {
	store   SnapshotRouteLister
	metrics topology.MetricsView
	status  topology.StatusLookup
	logger  *slog.Logger

	// now is the wall-clock source. Defaults to time.Now; tests
	// override to pin a deterministic GeneratedAt.
	now func() time.Time
}

// NewSnapshotHandler constructs the handler. Only store + logger
// are required; metrics and status are tolerated as nil and
// degrade gracefully to "no traffic yet" / "status unknown",
// matching the BuildSnapshot contract.
//
// This nil-tolerance lets tests build a SnapshotHandler against a
// fake store without standing up the full metrics + Caddy probe
// pipeline. Production wiring in cmd/arenet always passes both.
func NewSnapshotHandler(
	store SnapshotRouteLister,
	metrics topology.MetricsView,
	status topology.StatusLookup,
	logger *slog.Logger,
) *SnapshotHandler {
	if store == nil {
		panic("api.NewSnapshotHandler: store is nil")
	}
	if logger == nil {
		panic("api.NewSnapshotHandler: logger is nil")
	}
	return &SnapshotHandler{
		store:   store,
		metrics: metrics,
		status:  status,
		logger:  logger,
		now:     time.Now,
	}
}

// ServeHTTP responds with the wire-shape SnapshotResponse. The
// payload is exactly what topology.BuildSnapshot returns — no
// re-wrapping, no envelope around the response. This is the
// frontend's direct-assignable contract per docs/api/topology.md.
//
// Status codes:
//   - 200 with JSON body on success (including empty routes).
//   - 500 if the storage list fails; the handler does NOT fall
//     back to a partial response. A failed list means we can't
//     produce a faithful snapshot, and returning empty routes
//     would silently misrepresent the system state.
//   - 405 on non-GET methods (chi already filters via r.Get
//     mount, but we double-check for defence-in-depth).
//
// Auth: hard-auth middleware upstream gates this; viewer + admin
// both accepted (see SnapshotHandler doc).
func (h *SnapshotHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	routes, err := h.store.ListRoutes(r.Context())
	if err != nil {
		h.logger.Error("topology snapshot: list routes failed",
			slog.String("err", err.Error()))
		http.Error(w, "failed to list routes", http.StatusInternalServerError)
		return
	}

	resp := topology.BuildSnapshot(routes, h.metrics, h.status, h.now())

	w.Header().Set("Content-Type", "application/json")
	// Disable caching — the snapshot is point-in-time and the
	// client is expected to refresh either by re-fetching or by
	// switching to the /stream WS. A cached response would
	// silently show stale data after a reconnect.
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// Headers already sent at this point — we can only log.
		h.logger.Error("topology snapshot: encode failed",
			slog.String("err", err.Error()))
	}
}

// Compile-time check: SnapshotHandler satisfies http.Handler.
var _ http.Handler = (*SnapshotHandler)(nil)
