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

package caddyhc

import (
	"context"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// makeEvent constructs a caddy.Event for testing. caddy.NewEvent
// requires a caddy.Context which we don't have in isolation; we
// use caddy.Context's zero value here. The Event fields we read
// (Name, Data) are settable indirectly via the helper or, when
// the helper rejects the construction, via the caddy.NewEvent
// path with a background context (the API accepts a context.TODO-
// backed caddy.Context).
//
// The test treats Event as an opaque value: we only assert the
// observable effect (tracker state change), not the Event's
// internals.
func makeEvent(t *testing.T, name string, data map[string]any) caddy.Event {
	t.Helper()
	ev, err := caddy.NewEvent(caddy.Context{Context: context.Background()}, name, data)
	if err != nil {
		t.Fatalf("caddy.NewEvent(%q): %v", name, err)
	}
	return ev
}

// withFreshTracker installs a clean tracker for the duration of
// the test and restores the previous singleton afterward. The
// singleton is package-global state; tests must not leak.
func withFreshTracker(t *testing.T) *HCStatusTracker {
	t.Helper()
	prev := getTracker()
	tr := NewTracker()
	SetTracker(tr)
	t.Cleanup(func() {
		SetTracker(prev)
	})
	return tr
}

func TestEventHandler_HealthyEventRecordsHealthy(t *testing.T) {
	tr := withFreshTracker(t)
	h := &EventHandler{}
	ev := makeEvent(t, "healthy", map[string]any{"host": "10.0.0.1:80"})

	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := tr.Status("10.0.0.1:80"); got != StatusHealthy {
		t.Errorf("after healthy event: got %q, want %q", got, StatusHealthy)
	}
}

func TestEventHandler_UnhealthyEventRecordsUnhealthy(t *testing.T) {
	tr := withFreshTracker(t)
	h := &EventHandler{}
	ev := makeEvent(t, "unhealthy", map[string]any{"host": "10.0.0.2:80"})

	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := tr.Status("10.0.0.2:80"); got != StatusUnhealthy {
		t.Errorf("after unhealthy event: got %q, want %q", got, StatusUnhealthy)
	}
}

func TestEventHandler_UnknownEventNameIsNoOp(t *testing.T) {
	tr := withFreshTracker(t)
	h := &EventHandler{}
	// A future Caddy version might add new events on the same
	// source. The handler must ignore them gracefully — no panic,
	// no spurious state change.
	ev := makeEvent(t, "draining", map[string]any{"host": "10.0.0.3:80"})

	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := tr.Status("10.0.0.3:80"); got != StatusUnknown {
		t.Errorf("after unknown event: got %q, want %q", got, StatusUnknown)
	}
}

func TestEventHandler_MissingHostFieldIsNoOp(t *testing.T) {
	tr := withFreshTracker(t)
	h := &EventHandler{}
	ev := makeEvent(t, "healthy", map[string]any{"not-host": "x"})

	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	// No host extracted → nothing recorded. Verifying the tracker
	// is still empty for any address.
	if got := tr.Status("10.0.0.1:80"); got != StatusUnknown {
		t.Errorf("after host-less event: got %q, want %q", got, StatusUnknown)
	}
}

func TestEventHandler_HostFieldNotStringIsNoOp(t *testing.T) {
	tr := withFreshTracker(t)
	h := &EventHandler{}
	// Defensive: a payload-shape regression where "host" arrives
	// as a non-string (int, struct, whatever) must not panic.
	ev := makeEvent(t, "healthy", map[string]any{"host": 42})

	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := tr.Status("10.0.0.1:80"); got != StatusUnknown {
		t.Errorf("after non-string-host event: got %q, want %q", got, StatusUnknown)
	}
}

func TestEventHandler_NilTrackerIsSafe(t *testing.T) {
	prev := getTracker()
	SetTracker(nil)
	t.Cleanup(func() { SetTracker(prev) })

	h := &EventHandler{}
	ev := makeEvent(t, "healthy", map[string]any{"host": "10.0.0.1:80"})
	// Missing tracker singleton should be treated as "no consumer
	// installed" — no error, no panic, just drop the event.
	if err := h.Handle(context.Background(), ev); err != nil {
		t.Errorf("Handle with nil tracker: got error %v, want nil", err)
	}
}

func TestEventHandler_ProvisionIsNoOp(t *testing.T) {
	// Provision captures the Caddy-context logger and emits a
	// "provisioned" debug line. The test pins the no-error
	// contract — future changes that introduce a failure mode
	// must update both the test and the docstring intentionally.
	h := &EventHandler{}
	if err := h.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Errorf("Provision: got error %v, want nil", err)
	}
	// Logger should have been set (to a real or Nop zap.Logger);
	// never nil after Provision so Handle can safely call it.
	if h.logger == nil {
		t.Error("Provision did not capture a logger (h.logger is nil)")
	}
}

func TestEventHandler_CaddyModuleIDMatches(t *testing.T) {
	// Brittle on purpose: the module ID is what the emitted Caddy
	// JSON references in apps.events.subscriptions[].handlers[].
	// A rename here without a matching caddymgr update would
	// silently break event delivery in production.
	info := EventHandler{}.CaddyModule()
	if got := string(info.ID); got != "events.handlers.arenet_topology_hc" {
		t.Errorf("CaddyModule().ID = %q, want %q", got, "events.handlers.arenet_topology_hc")
	}
}
