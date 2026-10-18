// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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

package caddyhc

import (
	"sync"
	"testing"
	"time"
)

type transition struct {
	addr, old, new string
	at             time.Time
}

// recorder is a concurrency-safe OnTransition sink for the tests.
type recorder struct {
	mu   sync.Mutex
	hits []transition
}

func (r *recorder) fn(addr, old, newStatus string, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits = append(r.hits, transition{addr, old, newStatus, at})
}

func (r *recorder) snapshot() []transition {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]transition(nil), r.hits...)
}

// fakeClock hands out a fixed instant, settable between calls.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func TestTracker_OnTransition_FiresOncePerChange(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0).UTC()}
	tr := NewTracker()
	tr.now = clk.now
	rec := &recorder{}
	tr.SetOnTransition(rec.fn)

	const addr = "10.0.4.12:8080"

	// First unhealthy event: unknown -> unhealthy, one transition.
	tr.RecordUnhealthy(addr)
	downAt := clk.t

	// A SECOND unhealthy event at a LATER instant must NOT fire again,
	// and must NOT move the since (it is still the same outage).
	clk.t = clk.t.Add(5 * time.Minute)
	tr.RecordUnhealthy(addr)

	// Recovery: unhealthy -> healthy, one transition.
	clk.t = clk.t.Add(1 * time.Minute)
	tr.RecordHealthy(addr)
	upAt := clk.t

	hits := rec.snapshot()
	if len(hits) != 2 {
		t.Fatalf("got %d transitions, want 2 (down, recovered); repeated same-status must not fire: %+v", len(hits), hits)
	}
	if hits[0] != (transition{addr, StatusUnknown, StatusUnhealthy, downAt}) {
		t.Errorf("down transition = %+v; want unknown->unhealthy at %v", hits[0], downAt)
	}
	if hits[1] != (transition{addr, StatusUnhealthy, StatusHealthy, upAt}) {
		t.Errorf("recovery transition = %+v; want unhealthy->healthy at %v", hits[1], upAt)
	}

	// Since now reflects the recovery edge (current status = healthy).
	if got := tr.Since(addr); !got.Equal(upAt) {
		t.Errorf("Since = %v; want the current-status edge %v", got, upAt)
	}
}

func TestTracker_Since_IsTheFirstEdge_NotLatestEvent(t *testing.T) {
	clk := &fakeClock{t: time.Unix(2000, 0).UTC()}
	tr := NewTracker()
	tr.now = clk.now

	const addr = "db.internal:5432"
	tr.RecordUnhealthy(addr)
	downAt := clk.t

	// Three more unhealthy events over the next 20 minutes: the outage
	// start must stay the first edge, not creep forward.
	for i := 0; i < 3; i++ {
		clk.t = clk.t.Add(7 * time.Minute)
		tr.RecordUnhealthy(addr)
	}
	if got := tr.Since(addr); !got.Equal(downAt) {
		t.Errorf("Since = %v; want the first down edge %v (an ongoing outage must not reset its start)", got, downAt)
	}
}

func TestTracker_Reset_ClearsSince_NoCallback(t *testing.T) {
	tr := NewTracker()
	rec := &recorder{}
	tr.SetOnTransition(rec.fn)

	const addr = "10.0.4.12:8080"
	tr.RecordUnhealthy(addr)
	if tr.Since(addr).IsZero() {
		t.Fatal("precondition: Since should be set after a transition")
	}

	tr.Reset()
	if !tr.Since(addr).IsZero() {
		t.Error("Reset must clear the since map")
	}
	if tr.Status(addr) != StatusUnknown {
		t.Error("Reset must clear the status map")
	}
	// Reset is a reload, not an upstream transition: it must not page.
	if got := len(rec.snapshot()); got != 1 {
		t.Errorf("callback fired %d times; want 1 (the RecordUnhealthy only) — Reset must not invoke it", got)
	}
}
