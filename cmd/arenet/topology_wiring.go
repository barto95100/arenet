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

// Topology wiring helpers — the cmd/arenet glue between the
// internal/api/topology package (shared shape + builder) and the
// internal/api HTTP layer.
//
// Pre-Stage B this file owned a background goroutine that polled
// Caddy's /reverse_proxy/upstreams admin endpoint every second
// and cached results into a CaddyStatusProber. With Stage B
// (#R-TOPO-real-health-probe, 2026-06-04) the source-of-truth
// for status moved to Caddy's events App: the caddymgr emits a
// subscription pointing at the internal/caddyhc EventHandler
// module, which records "healthy"/"unhealthy" events as they
// transition. No polling, no goroutine, no warm-up call needed
// at boot — the tracker simply returns StatusUnknown for any
// upstream it hasn't received an event for yet.

package main

import (
	"log/slog"

	"github.com/barto95100/arenet/internal/api"
	"github.com/barto95100/arenet/internal/api/topology"
	"github.com/barto95100/arenet/internal/caddyhc"
	"github.com/barto95100/arenet/internal/storage"
)

// newTopologySnapshotHandler wires the api.SnapshotHandler with
// the shared sliding window and the process-wide HC status
// tracker. The tracker reference is also held by the caddyhc
// package singleton (installed via SetTracker before the caddymgr
// emits the events-subscription config), so reads here and writes
// from Caddy's event-dispatch goroutine share the same map.
func newTopologySnapshotHandler(
	store *storage.Store,
	window *topology.SlidingWindow,
	tracker *caddyhc.HCStatusTracker,
	logger *slog.Logger,
) *api.SnapshotHandler {
	return api.NewSnapshotHandler(store, window, tracker, logger)
}
