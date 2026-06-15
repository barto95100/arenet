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

package systemhealth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// MetricsProber is the minimal surface MetricsCheck needs.
// SchemaVersion is the cheapest read against the
// observability SQLite (single-row SELECT against the
// schema_migrations table). *observability.Store satisfies
// it; the wiring file adapts via a thin wrapper.
type MetricsProber interface {
	SchemaVersion(ctx context.Context) (int, error)
}

// MetricsCheck probes the observability SQLite store via
// SchemaVersion. Health classification per the ADR D2:
//   - healthy: SchemaVersion returned a positive int in
//     under DegradedLatencyThreshold ms
//   - degraded: SchemaVersion returned OK but slowly
//     (latency > DegradedLatencyThreshold) OR the prober
//     is nil (AC #13 boot-degraded — observability boot
//     failed, the rest of arenet keeps running)
//   - unhealthy: NOT used by this check. Observability is
//     advisory-only (Caddy data plane is unaffected by
//     metrics-store failure), so a broken SQLite is
//     degraded, never unhealthy.
type MetricsCheck struct {
	Prober MetricsProber
}

// DegradedLatencyThreshold is the wall-clock ceiling above
// which a successful SchemaVersion read still flags the
// store as degraded. 500ms reflects "the SQLite file is
// on disk but I/O is slow enough to risk pile-up under
// even moderate ingest" — observed empirically when the
// host's disk is saturated by another workload.
const DegradedLatencyThresholdMs int64 = 500

// Name implements ComponentCheck.
func (c *MetricsCheck) Name() string { return "metrics" }

// Check implements ComponentCheck. The LatencyMs of the
// SchemaVersion read is the discriminator between healthy
// and slow-but-OK. A returned schema version of 0 (no
// migrations applied) is treated as degraded — a
// production binary always runs at the head schema
// version.
func (c *MetricsCheck) Check(ctx context.Context) ComponentStatus {
	if c.Prober == nil {
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "observability store not configured (degraded mode)",
		}
	}

	start := time.Now()
	v, err := c.Prober.SchemaVersion(ctx)
	latencyMs := time.Since(start).Milliseconds()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return ComponentStatus{
				Status:    StatusDegraded,
				LatencyMs: latencyMs,
				Message:   "observability check timed out",
			}
		}
		return ComponentStatus{
			Status:    StatusDegraded,
			LatencyMs: latencyMs,
			Message:   "observability read failed",
		}
	}

	if v <= 0 {
		return ComponentStatus{
			Status:    StatusDegraded,
			LatencyMs: latencyMs,
			Message:   "observability schema not initialised",
		}
	}

	if latencyMs > DegradedLatencyThresholdMs {
		return ComponentStatus{
			Status:    StatusDegraded,
			LatencyMs: latencyMs,
			Message:   fmt.Sprintf("sqlite slow (%dms > %dms)", latencyMs, DegradedLatencyThresholdMs),
		}
	}

	return ComponentStatus{
		Status:    StatusHealthy,
		LatencyMs: latencyMs,
		Message:   fmt.Sprintf("sqlite OK, schema v%d", v),
	}
}
