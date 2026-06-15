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

// Package systemhealth ships the GET /system/health endpoint:
// 5 independent component probes (Caddy admin, BoltDB,
// observability SQLite, CrowdSec LAPI, certmagic in-memory
// tracker) with a uniform Status report.
//
// Step AL.3a (Phase 6 alerting prerequisite). The endpoint
// is intentionally mounted OUTSIDE any auth middleware so an
// external monitoring stack (Uptime Kuma, Prometheus
// blackbox_exporter, k8s readiness probe analog) can scrape
// it without bouncer credentials. The response carries
// component status + counts + latency only — no secrets,
// no PII, no internal IDs.
//
// See docs/superpowers/decisions/2026-06-15-step-al-decisions.md
// (D3) for the eight-decision context that bounds V1 scope.
package systemhealth

import (
	"context"
	"time"
)

// Status is the per-component classification surfaced in the
// HTTP response. Vocabulary aligned with the K8s readiness
// probe convention (healthy → 200, unhealthy → 503).
type Status string

const (
	// StatusHealthy: component fully operational.
	StatusHealthy Status = "healthy"
	// StatusDegraded: component partially operational —
	// arenet's core data plane still works but a peripheral
	// feature is impaired. Examples: observability SQLite
	// slow (latency > 500ms), CrowdSec LAPI unreachable
	// (bouncer fails open), certmagic with ≥1 cert
	// expiring < 14d.
	StatusDegraded Status = "degraded"
	// StatusUnhealthy: component broken in a way that
	// prevents traffic. Examples: Caddy admin endpoint
	// down (no reload possible, but already-loaded routes
	// keep working — so arenet is still partially serving),
	// BoltDB read failure (config broken, can't load any
	// route on next reload).
	StatusUnhealthy Status = "unhealthy"
)

// ComponentStatus is the per-component report. JSON-tagged so
// the HTTP handler can marshal it directly (no separate wire
// shape needed). LatencyMs is omitted on checks that have no
// natural latency signal (e.g. certmagic reads in-memory
// state; no wall-clock delay to report).
type ComponentStatus struct {
	Status    Status `json:"status"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
	Message   string `json:"message"`
}

// ComponentCheck is the seam every probe implements. Name
// determines the JSON key in the final response (kept stable
// via the fixed slice order in HealthChecker.checks — map
// iteration order would diverge across calls and break
// monitoring stacks that rely on stable shape).
//
// Check honours its context: the wrapper enforces a 2s
// per-check timeout via context.WithTimeout. A check that
// blocks past that ceiling MUST observe ctx.Done() and
// return StatusDegraded with a "check timed out" message —
// the wrapper does not preempt; it's the check's
// responsibility to exit promptly.
type ComponentCheck interface {
	Name() string
	Check(ctx context.Context) ComponentStatus
}

// Report is the JSON shape returned by GET /system/health.
// Components is ordered (not a map) so the wire output stays
// stable across calls — monitoring tools can rely on key
// order if they parse incrementally.
type Report struct {
	Status     Status         `json:"status"`
	Timestamp  string         `json:"timestamp"`
	Version    string         `json:"version,omitempty"`
	Components []NamedReport  `json:"components"`
}

// NamedReport is a (name, status) tuple emitted as a JSON
// object with a "name" field — the slice serialises to an
// array of {name, status, ...} objects rather than a map.
// V1 chose this over map[string]ComponentStatus because
// JSON object key order is not guaranteed in older parsers
// (jq is fine, some k8s probe parsers are not). An array
// of objects is the safest stable wire shape.
type NamedReport struct {
	Name string `json:"name"`
	ComponentStatus
}

// timestampFormat is the wire shape of the report's
// timestamp field. RFC 3339 UTC is the convention every
// other Arenet endpoint uses.
const timestampFormat = "2006-01-02T15:04:05Z07:00"

// HealthChecker owns the configured ComponentCheck slice and
// runs them with the V1 timeout discipline:
//   - Per-check: 2s ceiling via context.WithTimeout
//   - Total: 5s wall-clock budget (overall context.Done())
//
// All checks run in parallel goroutines. The order in
// .checks is the order in the response's Components array.
type HealthChecker struct {
	checks  []ComponentCheck
	version string
}

// New constructs a HealthChecker from the provided checks.
// version is the build version string (vDEV in dev, semver
// in releases) surfaced in the Report.Version field. The
// caller wires the checks in the desired output order:
// [caddy, db, metrics, crowdsec, certmagic] per the V1
// ADR.
func New(version string, checks ...ComponentCheck) *HealthChecker {
	return &HealthChecker{
		checks:  checks,
		version: version,
	}
}

// PerCheckTimeout is the V1 per-component deadline. Exposed
// as a const so tests can reference it for boundary
// assertions ("did the slow check actually time out at the
// documented budget?").
const PerCheckTimeout = 2 * time.Second

// TotalTimeout is the wall-clock ceiling for the whole
// endpoint. With 5 parallel checks at 2s each plus the
// fan-out / fan-in overhead, 5s gives a generous margin —
// in practice the slowest check (CrowdSec LAPI over WAN)
// dominates and the rest finish in <100ms.
const TotalTimeout = 5 * time.Second
