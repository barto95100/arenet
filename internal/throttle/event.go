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

// Package throttle implements the Step Q rate-limit event
// capture layer. The auth handler's rate limiter
// (internal/auth/ratelimit.go) emits one Event per BLOCK
// decision (Tier 1 OR Tier 2 — see spec §1.3 D1); the events
// flow through an EventSink mirroring internal/waf/sink.go.
//
// See docs/superpowers/specs/2026-05-29-step-q-rate-limit-auth-events.md
// §3.2 for the rate-limiter integration and §1.6.5 for the
// LRU rate-limit invariant (10k cap, 60s TTL per (srcIP, tier)
// triple).
package throttle

import "time"

// Event is one rate-limit block decision. Persisted into the
// throttle_event table by the EventSink; surfaced to the
// operator via /api/v1/security/throttle-events.
//
// AttemptedUsername is captured verbatim per spec §1.3 D8.A:
// parity with the audit log's existing exposure. The
// "someone is spraying 'admin'" signal is the value of the
// field; the audit log already records it, so Step Q does
// not introduce a new disclosure.
//
// SrcIP is captured verbatim from the request's effective
// remote address (after the trusted-proxy chain resolution
// shared with the audit log). Same operator note as the WAF
// event: behind an internal LAN, expect RFC1918 addresses.
type Event struct {
	Ts                   time.Time
	Tier                 int // 1 (5 fails / 5 min) or 2 (10 fails / 1 h)
	SrcIP                string
	AttemptedUsername    string
	BlockedUntil         time.Time
	BlockDurationSeconds int
}

// EventSink is the package-level abstraction the rate limiter
// emits events into. The production type is *Sink (see
// sink.go); tests can substitute their own implementation
// without going through the channel-buffered batching.
//
// Defined here (alongside Event) so the global singleton in
// global.go has the type available even when sink.go is
// being scaffolded — keeps the package's API surface in one
// readable file pair.
type EventSink interface {
	Emit(Event)
}
