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

import "time"

// Step E configuration constants per spec §8 (single source of truth).
// Frontend constants (particle density cap, color thresholds, etc.) live
// in web/frontend/src/lib/stores/topology-constants.ts; both files must
// stay in sync. CI does not yet enforce this.
const (
	// TickInterval is the cadence at which Ticker calls Registry.Snapshot
	// and Broadcaster.Publish. 1 s balances UI smoothness against
	// bandwidth (spec §8).
	TickInterval = 1 * time.Second

	// SubscriberChanCap is the size of each subscriber's pending-snapshot
	// channel. Capacity 1 implements the "latest wins, slow clients drop"
	// backpressure semantics of spec §5.6.
	SubscriberChanCap = 1

	// DropLogInterval throttles the per-subscriber debug log emitted when
	// Publish cannot enqueue (channel full). A persistently slow client
	// produces at most 60 log lines/hour (spec §5.6).
	DropLogInterval = 1 * time.Minute

	// WSWriteDeadline bounds each WebSocket write. A slow client that
	// cannot drain its socket within this deadline gets disconnected
	// (spec §5.4 + §8 wsWriteDeadlineMs). 1 s is generous enough for a
	// healthy LAN client but short enough to surface real backpressure.
	WSWriteDeadline = 1 * time.Second
)
