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

// Package ratelimit captures rate-limit-exceeded events
// emitted by the mholt/caddy-ratelimit handler (Step Q,
// commit 98015f6) and persists them through Arenet's
// observability layer.
//
// Step Z (2026-06-18). Closes the observability gap from
// Step Q : pre-Z, 429 events lived only in Caddy's zap log
// stream — not visible on /dashboard, /logs, or
// /security/[routeId]. The package subscribes to Caddy's
// event bus via a Caddy events.handler module
// (events.handlers.arenet_ratelimit_sink), receives
// "rate_limit_exceeded" events emitted by upstream
// caddy-ratelimit at handler.go:232, and forwards them to
// the global sink for SQLite persistence.
//
// Event flow :
//   caddy-ratelimit Handler.ServeHTTP (429 path)
//     → caddy.Event{name:"rate_limit_exceeded",
//                   data:{zone, wait, remote_ip}}
//     → caddyevents.App propagation
//     → events.handlers.arenet_ratelimit_sink (this pkg)
//     → ratelimit.Sink (this pkg)
//     → observability.Store.InsertRateLimitEventBatch
//
// The zone field carries the operator-facing route
// identifier ("route-<routeID>") emitted by Arenet's
// caddymgr.buildRateLimitHandler (Step Q manager.go).
// We extract the routeID by stripping the "route-" prefix.
//
// See docs/superpowers/specs (TBD if a Step Z spec lands)
// for the architectural details. The closest pre-existing
// reference is internal/throttle (Step Q for auth-failure
// throttle — semantically distinct, naming collision is
// historical).
package ratelimit

import "time"

// Event is one rate-limit-exceeded decision captured from
// the caddy-ratelimit handler's event emit.
//
// RouteID is extracted from the zone name at sink time.
// The zone format is the "route-<routeID>" convention
// established by Step Q's caddymgr.buildRateLimitHandler.
// A zone that doesn't match this prefix (e.g. operator
// hand-crafted a custom Caddy config bypassing Arenet's
// emit path) lands with RouteID == "" and the original
// Zone string preserved for forensic value.
//
// RemoteIP is the {http.request.remote.host} placeholder
// value the upstream caddy-ratelimit handler resolved at
// 429 time — already the raw socket peer (no X-Forwarded-
// For trust by default, per Step Q's defaultRateLimitKey
// choice). If the operator overrode the key to a header
// placeholder, the captured value reflects that placeholder
// resolution.
//
// WaitMs is the milliseconds the upstream handler told the
// client to wait before retrying (the Retry-After value
// computed from the sliding-window state). 0 when the
// emit didn't include the wait field (defensive parse).
type Event struct {
	Ts       time.Time
	RouteID  string
	Zone     string
	RemoteIP string
	WaitMs   int64
}

// EventSink is the package-level abstraction the Caddy
// events.handler emits events into. The production type is
// *Sink (sink.go) ; tests substitute their own
// implementation without going through the channel-
// buffered batching.
type EventSink interface {
	Emit(Event)
}
