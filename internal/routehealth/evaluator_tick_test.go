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

package routehealth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/caddyhc"
	"github.com/barto95100/arenet/internal/storage"
)

// TestEvaluator_OnSharedEvent_ReprobesAffectedRoutes confirms a tracker
// event on a shared address re-probes the routes on that address and
// updates the cache, without notifying (the composed callback notifies).
func TestEvaluator_OnSharedEvent_ReprobesAffectedRoutes(t *testing.T) {
	e := NewEvaluator(0, nil)
	var probed []string
	var mu sync.Mutex
	e.probe = func(_ context.Context, r storage.Route) map[string]string {
		mu.Lock()
		probed = append(probed, r.ID)
		mu.Unlock()
		if r.ID == "meet" {
			return map[string]string{"10.0.0.2:80": caddyhc.StatusUnhealthy}
		}
		return map[string]string{"10.0.0.2:80": caddyhc.StatusHealthy}
	}
	notified := 0
	e.SetNotify(func(string, time.Time) { notified++ })
	e.Refresh(sharedPair("http://10.0.0.2:80", "http://10.0.0.9:3000"))

	e.OnSharedEvent(context.Background(), "10.0.0.2:80")

	if s, ok := e.RouteUpstreamStatus("meet", "http://10.0.0.2:80"); !ok || s != caddyhc.StatusUnhealthy {
		t.Errorf("meet = %q ok=%v; want unhealthy after event re-probe", s, ok)
	}
	if notified != 0 {
		t.Errorf("OnSharedEvent notified %d times; want 0 (the composed callback notifies, not this)", notified)
	}
	// A non-shared address is a no-op (no probe).
	mu.Lock()
	probed = nil
	mu.Unlock()
	e.OnSharedEvent(context.Background(), "10.0.0.9:3000")
	mu.Lock()
	n := len(probed)
	mu.Unlock()
	if n != 0 {
		t.Errorf("OnSharedEvent on a unique address probed %d routes; want 0", n)
	}
}

// TestEvaluator_Tick_NotifiesOnlyChangedAddresses is the recovery gate
// (spec §7.4): a periodic tick re-probes shared routes and notifies for an
// address only when a verdict changed — so a recovery the flapping shared
// host never announced still converges, and a steady state is quiet.
func TestEvaluator_Tick_NotifiesOnlyChangedAddresses(t *testing.T) {
	e := NewEvaluator(0, nil)
	var meetStatus = caddyhc.StatusUnhealthy
	var mu sync.Mutex
	e.probe = func(_ context.Context, r storage.Route) map[string]string {
		mu.Lock()
		defer mu.Unlock()
		if r.ID == "meet" {
			return map[string]string{"10.0.0.2:80": meetStatus}
		}
		return map[string]string{"10.0.0.2:80": caddyhc.StatusHealthy}
	}
	var notifiedAddrs []string
	e.SetNotify(func(addr string, _ time.Time) { notifiedAddrs = append(notifiedAddrs, addr) })
	e.Refresh(sharedPair("http://10.0.0.2:80", "http://10.0.0.9:3000"))

	// First tick: meet down, www up → both are first-seen changes → notify.
	e.Tick(context.Background())
	if len(notifiedAddrs) == 0 {
		t.Fatal("first tick: expected a notify for the newly-observed verdicts")
	}

	// Second tick, nothing changed → quiet.
	notifiedAddrs = nil
	e.Tick(context.Background())
	if len(notifiedAddrs) != 0 {
		t.Errorf("steady tick notified %v; want silence (no verdict changed)", notifiedAddrs)
	}

	// meet's backend recovers; next tick must notify even though no
	// distinct Caddy event fired for meet.
	mu.Lock()
	meetStatus = caddyhc.StatusHealthy
	mu.Unlock()
	notifiedAddrs = nil
	e.Tick(context.Background())
	if len(notifiedAddrs) != 1 || notifiedAddrs[0] != "10.0.0.2:80" {
		t.Errorf("recovery tick notified %v; want exactly [10.0.0.2:80]", notifiedAddrs)
	}
	if s, _ := e.RouteUpstreamStatus("meet", "http://10.0.0.2:80"); s != caddyhc.StatusHealthy {
		t.Errorf("meet after recovery = %q; want healthy", s)
	}
}

// TestEvaluator_Start_StopsOnContextCancel confirms the periodic goroutine
// exits cleanly when the context is cancelled.
func TestEvaluator_Start_StopsOnContextCancel(t *testing.T) {
	e := NewEvaluator(0, nil)
	e.probe = func(context.Context, storage.Route) map[string]string { return nil }
	e.Refresh(sharedPair("http://10.0.0.2:80", "http://10.0.0.9:3000"))

	ctx, cancel := context.WithCancel(context.Background())
	e.Start(ctx, time.Hour) // floored, but we cancel before any tick
	cancel()
	// No assertion beyond -race catching a leak/panic; the goroutine must
	// return on ctx.Done.
	time.Sleep(10 * time.Millisecond)
}
