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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barto95100/arenet/internal/caddyhc"
	"github.com/barto95100/arenet/internal/storage"
)

// sharedPair builds two routes on the same upstream + one unique route.
func sharedPair(upstream, unique string) []storage.Route {
	hc := storage.HealthCheck{Enabled: true, URI: "/api/health", Method: "GET", ExpectStatus: 200}
	return []storage.Route{
		{ID: "meet", Host: "meet.example", Upstreams: []storage.Upstream{{URL: upstream}}, HealthCheck: hc},
		{ID: "www", Host: "www.example", Upstreams: []storage.Upstream{{URL: upstream}}, HealthCheck: hc},
		{ID: "solo", Host: "solo.example", Upstreams: []storage.Upstream{{URL: unique}}, HealthCheck: hc},
	}
}

func TestEvaluator_RefreshTracksOnlySharedRoutes(t *testing.T) {
	e := NewEvaluator(0, nil)
	e.Refresh(sharedPair("http://10.0.0.2:80", "http://10.0.0.9:3000"))

	if !e.IsSharedAddr("http://10.0.0.2:80") {
		t.Error("10.0.0.2:80 is used by meet+www — should be shared")
	}
	if e.IsSharedAddr("http://10.0.0.9:3000") {
		t.Error("10.0.0.9:3000 is unique — should not be shared")
	}
	snap := e.sharedRoutesSnapshot()
	if len(snap) != 2 {
		t.Fatalf("shared routes = %d; want 2 (meet, www)", len(snap))
	}
}

func TestEvaluator_PerRouteVerdictsAreIndependentForSharedUpstream(t *testing.T) {
	e := NewEvaluator(0, nil)
	// Fake probe: meet's backend is down, www's is up, SAME upstream addr.
	e.probe = func(_ context.Context, r storage.Route) map[string]string {
		switch r.ID {
		case "meet":
			return map[string]string{"10.0.0.2:80": caddyhc.StatusUnhealthy}
		case "www":
			return map[string]string{"10.0.0.2:80": caddyhc.StatusHealthy}
		}
		return nil
	}
	e.Refresh(sharedPair("http://10.0.0.2:80", "http://10.0.0.9:3000"))

	for _, r := range e.sharedRoutesSnapshot() {
		e.evaluateRoute(context.Background(), r)
	}

	if s, ok := e.RouteUpstreamStatus("meet", "http://10.0.0.2:80"); !ok || s != caddyhc.StatusUnhealthy {
		t.Errorf("meet verdict = %q ok=%v; want unhealthy", s, ok)
	}
	if s, ok := e.RouteUpstreamStatus("www", "http://10.0.0.2:80"); !ok || s != caddyhc.StatusHealthy {
		t.Errorf("www verdict = %q ok=%v; want healthy — same upstream, opposite verdict", s, ok)
	}
	// A unique route is never evaluated here → ok=false → caller uses the tracker.
	if _, ok := e.RouteUpstreamStatus("solo", "http://10.0.0.9:3000"); ok {
		t.Error("solo is unique; RouteUpstreamStatus must report ok=false so the tracker is used")
	}
}

func TestEvaluator_RefreshEvictsRoutesNoLongerShared(t *testing.T) {
	e := NewEvaluator(0, nil)
	e.probe = func(_ context.Context, r storage.Route) map[string]string {
		return map[string]string{"10.0.0.2:80": caddyhc.StatusUnhealthy}
	}
	e.Refresh(sharedPair("http://10.0.0.2:80", "http://10.0.0.9:3000"))
	for _, r := range e.sharedRoutesSnapshot() {
		e.evaluateRoute(context.Background(), r)
	}
	if _, ok := e.RouteUpstreamStatus("meet", "http://10.0.0.2:80"); !ok {
		t.Fatal("precondition: meet should have a verdict before eviction")
	}

	// Now www is gone → meet's upstream is unique → meet must be evicted.
	e.Refresh([]storage.Route{
		{ID: "meet", Host: "meet.example", Upstreams: []storage.Upstream{{URL: "http://10.0.0.2:80"}},
			HealthCheck: storage.HealthCheck{Enabled: true, URI: "/api/health", ExpectStatus: 200}},
	})
	if _, ok := e.RouteUpstreamStatus("meet", "http://10.0.0.2:80"); ok {
		t.Error("meet is no longer shared; its cached verdict must be evicted so the tracker is used")
	}
}

// TestProbeRouteUpstreams_HostRoutedBackend exercises the real probe
// against an httptest server that mimics a Host-multiplexing proxy: it
// answers 200 for Host meet.example and 404 for anything else. With
// expect_status 200, the meet probe is healthy and a www-Host probe is
// unhealthy — proving the probe judges by the route's HC criteria, not a
// lenient "any non-5xx is up".
func TestProbeRouteUpstreams_HostRoutedBackendAndExpectStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "meet.example" && r.URL.Path == "/api/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String() // 127.0.0.1:port

	hc := storage.HealthCheck{Enabled: true, URI: "/api/health", Method: "GET", ExpectStatus: 200, ExpectBody: `"status":"ok"`}

	up := storage.Route{ID: "meet", Host: "meet.example",
		Upstreams: []storage.Upstream{{URL: "http://" + addr}}, HealthCheck: hc}
	down := storage.Route{ID: "www", Host: "www.example",
		Upstreams: []storage.Upstream{{URL: "http://" + addr}}, HealthCheck: hc}

	key := caddyhc.NormalizeAddr("http://" + addr)

	if got := probeRouteUpstreams(context.Background(), up, DefaultProbeTimeout); got[key] != caddyhc.StatusHealthy {
		t.Errorf("meet (Host-routed 200 + body match) = %q; want healthy", got[key])
	}
	if got := probeRouteUpstreams(context.Background(), down, DefaultProbeTimeout); got[key] != caddyhc.StatusUnhealthy {
		t.Errorf("www (Host gets 404, expect 200) = %q; want unhealthy — a 404 is NOT healthy", got[key])
	}
}
