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

// Package crowdsec implements the Step N rate-limit-IP-reputation
// event capture layer. CrowdSec LAPI is the source of truth; the
// Caddy bouncer (caddy-crowdsec-bouncer) enforces decisions at
// the proxy edge; this package runs an INDEPENDENT, parallel
// go-cs-bouncer.StreamBouncer consumer that mirrors LAPI's
// {new, deleted} deltas into Arenet's own decision_event SQLite
// table for the admin dashboard.
//
// See docs/superpowers/specs/2026-05-29-step-n-crowdsec.md
// §3.1 for the two-consumer architecture and §3.2 for the
// dedupe-before-bump structural inversion vs M/Q.
package crowdsec

import "time"

// Decision is one CrowdSec LAPI ban/captcha/throttle decision
// persisted into the decision_event table by the EventSink;
// surfaced to the operator via /api/v1/security/decisions.
//
// Per Step N spec D5.B: operator-facing subset of the LAPI
// row. Dropped vs full upstream:
//   - id      (LAPI server-local autoincrement; uuid is the
//     stable cross-instance identifier).
//   - origin  (operational CrowdSec metadata; no admin-UI use).
//
// UUID is the LRU key (dedupe-before-bump per D4.A — see
// sink.go absorb()).
//
// SrcIP and Scope are the bouncer-observed values (D6.A:
// trusted-proxy IP discrepancy is a cross-cutting backlog item
// from Q.5-2 inherited as-is by N).
type Decision struct {
	UUID            string
	Ts              time.Time
	Scope           string // "ip" | "range" | "country" | "as" — free-form, validate at write-time
	Value           string // IP, CIDR, country code, AS — interpretation depends on Scope
	Type            string // "ban" | "captcha" | "throttle" — see N spec §3.3
	Scenario        string // e.g. "crowdsecurity/http-probing"
	ExpiresAt       time.Time
	DurationSeconds int
}

// EventSink is the package-level abstraction the StreamBouncer
// consumer emits decisions into. The production type is *Sink
// (see sink.go); tests can substitute their own implementation
// without going through the channel-buffered batching.
//
// Defined here (alongside Decision) so the global singleton in
// global.go has the type available even when sink.go is being
// scaffolded — same convention as internal/throttle/event.go.
type EventSink interface {
	// Emit registers a NEW decision arriving from LAPI (the
	// `new[]` slice of /v1/decisions/stream). The sink dedupes
	// on UUID and bumps the BlockCounter only on first sight.
	Emit(Decision)

	// Tombstone registers a REVOKED decision (the `deleted[]`
	// slice of the same stream response). The sink may use
	// this to expire its LRU entry early, freeing a slot for
	// a future re-grant of the same IP. No bucket counter
	// effect — tombstones do not count as "new attack
	// activity".
	Tombstone(uuid string)
}
