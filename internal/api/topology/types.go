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

// Package topology implements the Phase 2 live data feed for the
// /topology canvas. The wire shape mirrors the frontend domain types
// declared at web/frontend/src/routes/topology/_types.ts so the
// JSON payload is directly assignable to TopologyRoute /
// TopologyUpstream on the client side — no adapter layer.
//
// Spec: docs/api/topology.md.
package topology

import "time"

// SnapshotResponse is the envelope returned by both
// GET /api/v1/topology/snapshot and each tick of the
// /api/v1/topology/stream WebSocket. The generatedAt field is the
// wall-clock UTC timestamp of the emit (NOT of the underlying
// metrics sample window — the window is implicit, see WindowSeconds
// below if a future iteration surfaces it).
type SnapshotResponse struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Routes      []Route   `json:"routes"`
}

// Route is one entry in the snapshot. Field-by-field mirror of the
// frontend TopologyRoute interface. Numeric scalars use the JSON
// number type; the frontend interprets them as plain numbers
// (TypeScript `number`).
//
// Stage A (this iteration) limitations carried in the per-field
// docstrings:
//   - p99LatencyMs is the p95 from the existing metrics histogram
//     (Step L); the spec permits p95 as a substitute when p99 is
//     expensive. Sliding-window p95 across 60 source ticks is the
//     value emitted here.
//   - errorRate5xx is the percentage form (0..100) of the per-tick
//     ErrRate5xx (0..1) provided by the metrics package, averaged
//     over the 60s sliding window.
//   - mtlsRequired is absent (zero-value bool) until storage models
//     the per-route mTLS gate.
type Route struct {
	ID      string   `json:"id"`
	Host    string   `json:"host"`
	Aliases []string `json:"aliases,omitempty"`

	Upstreams []Upstream `json:"upstreams"`
	LBPolicy  string     `json:"lbPolicy"`

	ReqPerSec    float64 `json:"reqPerSec"`
	P99LatencyMs int32   `json:"p99LatencyMs"`
	ErrorRate5xx float64 `json:"errorRate5xx"`

	TLSEnabled   bool   `json:"tlsEnabled"`
	WAFLevel     string `json:"wafLevel,omitempty"`
	RateLimited  bool   `json:"rateLimited,omitempty"`
	MTLSRequired bool   `json:"mtlsRequired,omitempty"`

	// HTTPRedirect mirrors storage.Route.RedirectToHTTPS. When true,
	// Arenet emits a Caddy redirect from :80 → :443 for the route's
	// host. The frontend uses this to render "HTTP → HTTPS" instead
	// of plain "HTTPS" on the FQDN node so the operator can tell
	// at a glance whether plain-HTTP requests get bounced (Critique
	// 18, 2026-06-04). TLSEnabled = false implies HTTPRedirect = false
	// (you can't redirect to a non-existent HTTPS endpoint); the
	// frontend treats the combination consistently.
	HTTPRedirect bool `json:"httpRedirect"`

	// HasHealthCheck mirrors storage.Route.HealthCheck.Enabled. The
	// frontend uses this to drive the per-upstream "monitored"
	// shield indicator (#R-TOPO-health-coherence v1.1.0 compromise,
	// 2026-06-03). When false, no health-check block is in the
	// route's Caddy config and the upstreams are not being probed —
	// the UI must NOT show green/red status for these.
	HasHealthCheck bool `json:"hasHealthCheck"`

	ClusterLabel string `json:"clusterLabel,omitempty"`
}

// Upstream is the per-backend entry. Stage A fields that are NOT
// directly measured but synthesised from the route-level values are
// documented inline.
//
// Stage A synthesised fields:
//   - reqPerSec, p99LatencyMs, fairnessRatio are split from the
//     route-level totals by configured upstream weight. The frontend
//     renders these as fairness bars; the values reflect the
//     operator's INTENT (configured weight share), not measured
//     reality. Stage B (#R-TOPO-upstream-metrics) replaces these
//     with real per-upstream counters.
//   - status v1.1.0 compromise (#R-TOPO-health-coherence): ALWAYS
//     "unknown" right now. The Caddy /reverse_proxy/upstreams admin
//     endpoint surfaces only num_requests + fails (proxy-error
//     counter), neither of which is the health-probe outcome. Mapping
//     "fails=0" to "healthy" was lying — a route with no health
//     check OR with a failing health check (Caddy stops routing →
//     fails stays 0) both reported green. We now surface the
//     unambiguous truth: "we don't know yet". The shield indicator
//     (HealthCheckConfigured) tells the operator at least whether
//     a probe is configured. Real probe ingestion lands in Stage B
//     (#R-TOPO-real-health-probe).
//   - healthCheckConfigured mirrors the parent route's
//     HasHealthCheck (denormalised onto each upstream so the
//     frontend doesn't have to thread the route into the upstream
//     component). When true, the frontend renders a small shield
//     glyph next to the URL — "this upstream is being watched" —
//     even though we can't surface the probe result yet.
//   - runtime is absent until storage models operator-supplied
//     runtime metadata.
type Upstream struct {
	ID                    string  `json:"id"`
	URL                   string  `json:"url"`
	Runtime               string  `json:"runtime,omitempty"`
	Status                string  `json:"status"`
	HealthCheckConfigured bool    `json:"healthCheckConfigured"`
	ReqPerSec             float64 `json:"reqPerSec"`
	P99LatencyMs          int32   `json:"p99LatencyMs"`
	FairnessRatio         float64 `json:"fairnessRatio"`
}

// HealthStatus enum values mirroring the frontend `HealthStatus`
// union. Defined as exported string constants so the builder uses
// them by name rather than scattering raw literals.
const (
	StatusHealthy   = "healthy"
	StatusUnhealthy = "unhealthy"
	StatusDraining  = "draining" // reserved for Phase 2.1
	StatusUnknown   = "unknown"
)
