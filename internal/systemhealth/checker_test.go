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
	"testing"
	"time"
)

// stubCheck is a hand-rolled ComponentCheck for the wrapper
// tests. The check function is called by Check; the name is
// returned verbatim by Name. Both fields are read-only after
// construction.
type stubCheck struct {
	name string
	fn   func(ctx context.Context) ComponentStatus
}

func (s *stubCheck) Name() string                                 { return s.name }
func (s *stubCheck) Check(ctx context.Context) ComponentStatus    { return s.fn(ctx) }

func TestRun_HealthyAggregation(t *testing.T) {
	hc := New("v1.2.3",
		&stubCheck{name: "a", fn: func(_ context.Context) ComponentStatus {
			return ComponentStatus{Status: StatusHealthy, Message: "ok"}
		}},
		&stubCheck{name: "b", fn: func(_ context.Context) ComponentStatus {
			return ComponentStatus{Status: StatusHealthy, Message: "ok"}
		}},
	)
	report := hc.Run(context.Background())

	if report.Status != StatusHealthy {
		t.Errorf("global status = %q; want healthy", report.Status)
	}
	if report.Version != "v1.2.3" {
		t.Errorf("version = %q; want v1.2.3", report.Version)
	}
	if len(report.Components) != 2 {
		t.Fatalf("components len = %d; want 2", len(report.Components))
	}
	if report.Components[0].Name != "a" || report.Components[1].Name != "b" {
		t.Errorf("component order broken: got %s, %s; want a, b",
			report.Components[0].Name, report.Components[1].Name)
	}
}

func TestRun_DegradedAggregation(t *testing.T) {
	hc := New("",
		&stubCheck{name: "a", fn: func(_ context.Context) ComponentStatus {
			return ComponentStatus{Status: StatusHealthy}
		}},
		&stubCheck{name: "b", fn: func(_ context.Context) ComponentStatus {
			return ComponentStatus{Status: StatusDegraded, Message: "slow"}
		}},
	)
	report := hc.Run(context.Background())

	if report.Status != StatusDegraded {
		t.Errorf("global status = %q; want degraded", report.Status)
	}
}

func TestRun_UnhealthyDominatesDegraded(t *testing.T) {
	hc := New("",
		&stubCheck{name: "a", fn: func(_ context.Context) ComponentStatus {
			return ComponentStatus{Status: StatusDegraded}
		}},
		&stubCheck{name: "b", fn: func(_ context.Context) ComponentStatus {
			return ComponentStatus{Status: StatusUnhealthy, Message: "down"}
		}},
		&stubCheck{name: "c", fn: func(_ context.Context) ComponentStatus {
			return ComponentStatus{Status: StatusHealthy}
		}},
	)
	report := hc.Run(context.Background())

	if report.Status != StatusUnhealthy {
		t.Errorf("global status = %q; want unhealthy (the unhealthy 'b' must dominate degraded 'a' and healthy 'c')", report.Status)
	}
}

func TestRun_PanickingCheck_TranslatesToUnhealthy(t *testing.T) {
	hc := New("",
		&stubCheck{name: "panic-check", fn: func(_ context.Context) ComponentStatus {
			panic("synthetic panic")
		}},
	)
	report := hc.Run(context.Background())

	if report.Status != StatusUnhealthy {
		t.Errorf("global status = %q; want unhealthy on panic", report.Status)
	}
	if len(report.Components) != 1 || report.Components[0].Message != "check panicked" {
		t.Errorf("expected panic translation in component message; got %+v", report.Components)
	}
}

func TestRun_PerCheckTimeout(t *testing.T) {
	// One check sleeps past PerCheckTimeout; the ctx
	// passed in MUST fire .Done() before the sleep
	// completes, and the check is expected to honour that
	// signal. Use a faster ctx via the parent to keep the
	// suite snappy (parent ctx fires before the per-check
	// 2s ceiling would).
	hc := New("",
		&stubCheck{name: "slow", fn: func(ctx context.Context) ComponentStatus {
			select {
			case <-ctx.Done():
				return ComponentStatus{Status: StatusDegraded, Message: "check timed out"}
			case <-time.After(2 * time.Second):
				return ComponentStatus{Status: StatusHealthy}
			}
		}},
	)
	// Pass a 100ms parent ctx; the per-check 2s budget
	// won't fire because the parent is tighter.
	parent, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	report := hc.Run(parent)
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Errorf("Run took %s; expected ≈100ms (parent ctx timeout)", elapsed)
	}
	if report.Components[0].Status != StatusDegraded {
		t.Errorf("expected slow check to surface degraded; got %q", report.Components[0].Status)
	}
}

func TestRun_LatencyPopulated(t *testing.T) {
	// A check that leaves LatencyMs at 0 — the wrapper
	// must compute and inject the wall-clock duration so
	// every component row in the report carries a
	// latency signal.
	hc := New("",
		&stubCheck{name: "untimed", fn: func(_ context.Context) ComponentStatus {
			time.Sleep(20 * time.Millisecond)
			return ComponentStatus{Status: StatusHealthy, Message: "ok"}
		}},
	)
	report := hc.Run(context.Background())

	if report.Components[0].LatencyMs < 15 {
		t.Errorf("LatencyMs = %d; expected at least ~15ms (sleep was 20ms)",
			report.Components[0].LatencyMs)
	}
}

func TestRun_LatencyOverrideRespected(t *testing.T) {
	// A check that returns its own LatencyMs (e.g. a
	// component that exposes a phase-specific timing —
	// TLS handshake vs full HTTP round-trip) — the
	// wrapper must NOT overwrite it.
	hc := New("",
		&stubCheck{name: "self-timed", fn: func(_ context.Context) ComponentStatus {
			return ComponentStatus{
				Status:    StatusHealthy,
				LatencyMs: 42,
				Message:   "ok",
			}
		}},
	)
	report := hc.Run(context.Background())

	if report.Components[0].LatencyMs != 42 {
		t.Errorf("LatencyMs = %d; want 42 (check-supplied value preserved)",
			report.Components[0].LatencyMs)
	}
}
