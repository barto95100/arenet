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

package caddymgr

import (
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// TestSetReloadHook_ReplaysLastAppliedRoutes guards the boot-ordering fix
// (v2.75.4). mgr.Start runs the first applyLocked BEFORE the route-health
// notifier wires its hook (cmd/arenet/main.go), so a hook installed after
// an apply must be seeded immediately with the already-applied route set —
// otherwise the notifier's index stays empty until the next config change
// and a restart-then-outage notifies no one (the reported 2026-10-19 bug).
//
// White-box so it never drives the global Caddy (caddy.Load): it sets the
// retained route set directly and asserts SetReloadHook replays it.
// Remove the replay in SetReloadHook and this fails.
func TestSetReloadHook_ReplaysLastAppliedRoutes(t *testing.T) {
	m := &CaddyManager{}
	m.lastAppliedRoutes = []storage.Route{{ID: "r1", Host: "a.example"}}

	var got []storage.Route
	calls := 0
	m.SetReloadHook(func(rs []storage.Route) {
		calls++
		got = rs
	})

	if calls != 1 {
		t.Fatalf("hook called %d times; want exactly 1 replay at wiring time", calls)
	}
	if len(got) != 1 || got[0].ID != "r1" {
		t.Fatalf("hook seeded with %+v; want the last applied route r1", got)
	}
}

// TestSetReloadHook_NoReplayBeforeFirstApply confirms the replay is gated
// on an apply having happened: a hook wired before any applyLocked (unit
// tests, boot orderings without a prior apply) must not fire spuriously.
func TestSetReloadHook_NoReplayBeforeFirstApply(t *testing.T) {
	m := &CaddyManager{}
	called := false
	m.SetReloadHook(func([]storage.Route) { called = true })
	if called {
		t.Fatal("hook replayed although no apply has happened yet")
	}
}

// TestSetReloadHook_NilClearDoesNotReplay confirms clearing the hook with
// nil never invokes anything, even with a retained route set.
func TestSetReloadHook_NilClearDoesNotReplay(t *testing.T) {
	m := &CaddyManager{}
	m.lastAppliedRoutes = []storage.Route{{ID: "r1"}}
	// Clearing must be inert (no panic, no call).
	m.SetReloadHook(nil)
}
