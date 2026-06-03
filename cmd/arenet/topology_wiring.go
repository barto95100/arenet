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
// This file owns construction-time wiring: it builds the snapshot
// handler with a CaddyStatusProber that is refreshed on a 1-second
// background ticker. The cached statuses are then served to every
// HTTP request without re-probing inline — keeps the snapshot
// endpoint cheap (no 200 ms probe penalty per request) and the
// per-upstream Status() lookup at memory-read speed.

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/barto95100/arenet/internal/api"
	"github.com/barto95100/arenet/internal/api/topology"
	"github.com/barto95100/arenet/internal/storage"
)

// topologyProbeInterval is the cadence at which the background
// goroutine refreshes the Caddy admin status cache. 1 second is
// chosen to match the metrics sampler tick (a status that
// changed within the last second is "fresh enough" for the
// topology canvas's slower 2-second emit cadence in C3, AND for
// the on-demand snapshot endpoint).
const topologyProbeInterval = 1 * time.Second

// newTopologySnapshotHandler builds the api.SnapshotHandler and
// starts a background goroutine that refreshes the Caddy admin
// status cache every topologyProbeInterval. The goroutine
// terminates when ctx is cancelled (typically the cmd/arenet
// process context).
//
// The prober reference is shared between the background refresher
// and the api.SnapshotHandler — the CaddyStatusProber type is
// goroutine-safe (Refresh and Status hold the same mutex), so
// concurrent reads from the HTTP handler and writes from the
// refresher are safe.
//
// For the C3 stream handler, the SAME prober + window will be
// shared: a single background refresher serves both endpoints,
// no extra goroutine per WS subscriber.
func newTopologySnapshotHandler(
	ctx context.Context,
	store *storage.Store,
	window *topology.SlidingWindow,
	prober *topology.CaddyStatusProber,
	logger *slog.Logger,
) *api.SnapshotHandler {
	// Prime the cache once at boot so the first snapshot request
	// doesn't return all-unknown statuses before the first tick.
	// 200 ms blocking call at startup is fine — it runs once,
	// during the cmd/arenet main() init sequence.
	prober.Refresh(ctx)

	// Background refresher. The goroutine respects ctx so a
	// clean shutdown (SIGTERM) stops the probing without leaking.
	go func() {
		ticker := time.NewTicker(topologyProbeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				logger.Debug("topology probe refresher stopped")
				return
			case <-ticker.C:
				prober.Refresh(ctx)
			}
		}
	}()

	return api.NewSnapshotHandler(store, window, prober, logger)
}
