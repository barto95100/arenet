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

// Package metrics implements the Step E per-route metrics pipeline:
// a Caddy middleware module increments atomic counters per matched
// route, a ticker snapshots them at 1 Hz, and a broadcaster fans out
// the snapshot to subscribed WebSocket clients.
//
// All public types in this file are pure data; behavior lives in
// registry.go, broadcaster.go, ticker.go.
//
// See docs/superpowers/specs/2026-05-18-step-e-topology-design.md
// (§4 and §5 in particular).
package metrics

import "time"

// Delta is the per-route counter difference produced by one Snapshot
// call. Reqs and Errs are counts SINCE THE PREVIOUS TICK, not
// cumulative totals (spec §11.9). Errs counts 5xx responses
// (kept under that name for Step E wire-shape backward compat —
// the WebSocket clients read .Errs as the 5xx counter).
//
// Step L additions (additive, no Step E regression):
//   - Errs4xx tracks 4xx separately from 5xx (Step L spec §1.3 D1:
//     internet-exposed proxies need 4xx as a security/exposure
//     signal, not folded into "errors").
//   - LatencyP95Ms is the p95 over the per-route latency
//     histogram during the tick window. Zero when no samples
//     landed in this tick — the L.2 API projection layer maps
//     that to JSON null per AC #5 (a "0 ms p95" would render as
//     a fake latency dip on the timeline chart).
//
// Errs may transiently exceed Reqs for a single tick due to the
// non-paired-atomic swap in Registry.Snapshot (spec §11.8). The
// WebSocket wire layer is responsible for clamping errRate5xx to
// [0, 1] before sending; consumers of Delta directly must apply the
// same clamp if they compute a rate.
type Delta struct {
	Reqs         uint64 `json:"reqs"`
	Errs         uint64 `json:"errs"` // 5xx (Step E wire-shape name)
	Errs4xx      uint64 `json:"errs4xx,omitempty"`
	LatencyP95Ms int32  `json:"latencyP95Ms,omitempty"`
}

// RouteSnapshot is one route's entry in the per-tick Snapshot. It
// joins the Registry's per-route Delta with the route's metadata
// from storage (host, upstream) so the WebSocket frame is
// self-contained (spec §5.2 — denormalized into every tick to
// save the client a GET /routes).
//
// The frontend interprets reqPerSec == reqs because the tick is
// exactly tickInterval (1 s, spec §8); the dedicated field exists
// so a future tick variation does not break the wire contract.
type RouteSnapshot struct {
	ID         string  `json:"id"`
	Host       string  `json:"host"`
	Upstream   string  `json:"upstream"`
	Reqs       uint64  `json:"reqs"`
	Errs       uint64  `json:"errs"`
	ReqPerSec  uint64  `json:"reqPerSec"`
	ErrRate5xx float64 `json:"errRate5xx"`
}

// Snapshot is what the Ticker produces every tickInterval and what
// the Broadcaster fans out to subscribers. Each Snapshot lists EVERY
// persisted route (spec §5.2), including idle routes at zero
// counters; the frontend uses the full listing for its idle-state
// detection.
//
// T is the wall-clock UTC timestamp of the tick (spec §5.2 "t" field).
// Producers MUST populate T in UTC (time.Now().UTC()) for the default
// JSON marshaler to emit RFC 3339 with the 'Z' suffix the wire
// contract expects; a non-UTC value would render as "+02:00" etc.
// and break clients that parse the suffix strictly. time.Time is
// preserved here rather than a pre-formatted string so downstream
// layers retain full control over encoding.
type Snapshot struct {
	T      time.Time       `json:"t"`
	Routes []RouteSnapshot `json:"routes"`
}
