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

package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Topology Plan B Phase 1 — middleware host-resolution tests.

// newTestHostHandler returns a provisioned RouteMetricsHandler
// with a KnownHosts set, bypassing the SetRegistry singleton
// dance so each test can use a fresh local Registry.
func newTestHostHandler(t *testing.T, registry *Registry, routeID string, knownHosts []string) *RouteMetricsHandler {
	t.Helper()
	t.Cleanup(ResetForTest)
	ResetForTest()
	SetRegistry(registry)
	h := &RouteMetricsHandler{
		RouteID:    routeID,
		KnownHosts: knownHosts,
	}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return h
}

func TestRouteMetrics_HostBump_OnKnownHostMatch(t *testing.T) {
	reg := NewRegistry()
	reg.Sync([]string{"r1"})
	h := newTestHostHandler(t, reg, "r1", []string{"api.example.com", "alt.example.com"})

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "api.example.com"
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	// Route counter bumped.
	if got := reg.Snapshot()["r1"].Reqs; got != 1 {
		t.Errorf("route reqs=%d want 1", got)
	}
	// Host counter bumped.
	hosts := reg.SnapshotHosts()
	if len(hosts) != 1 || hosts[0].Host != "api.example.com" || hosts[0].Reqs != 1 {
		t.Errorf("host deltas = %+v; want [{r1, api.example.com, 1}]", hosts)
	}
}

func TestRouteMetrics_HostBump_DroppedOnUnknownHost(t *testing.T) {
	// r.Host that ISN'T in KnownHosts must drop the host bump
	// silently. Route counter still ticks.
	reg := NewRegistry()
	reg.Sync([]string{"r1"})
	h := newTestHostHandler(t, reg, "r1", []string{"api.example.com"})

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "evil.attacker.com" // not in KnownHosts
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	// Route counter must still bump (route authoritative).
	if got := reg.Snapshot()["r1"].Reqs; got != 1 {
		t.Errorf("route reqs=%d want 1 (route counter must tick on unknown host)", got)
	}
	// No host cell created.
	hosts := reg.SnapshotHosts()
	if len(hosts) != 0 {
		t.Errorf("host deltas len=%d want 0 (unknown host must not create cell)", len(hosts))
	}
}

func TestRouteMetrics_HostBump_LowercaseNormalization(t *testing.T) {
	// r.Host with uppercase letters must lookup in lowercase
	// against the cached knownHostSet (which Provision
	// lowercased at install time).
	reg := NewRegistry()
	reg.Sync([]string{"r1"})
	h := newTestHostHandler(t, reg, "r1", []string{"api.example.com"})

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	for _, hostHeader := range []string{"API.Example.com", "api.EXAMPLE.com", "API.EXAMPLE.COM"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = hostHeader
		rec := httptest.NewRecorder()
		if err := h.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
	}

	hosts := reg.SnapshotHosts()
	if len(hosts) != 1 || hosts[0].Host != "api.example.com" || hosts[0].Reqs != 3 {
		t.Errorf("host deltas = %+v; want one cell at api.example.com with reqs=3", hosts)
	}
}

func TestRouteMetrics_HostBump_PortStripped(t *testing.T) {
	// r.Host with a :port suffix is normalised before the
	// KnownHosts lookup. Both bare IPv4 and IPv6 (bracketed)
	// host:port forms must work.
	reg := NewRegistry()
	reg.Sync([]string{"r1"})
	h := newTestHostHandler(t, reg, "r1", []string{"api.example.com"})

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	for _, hostHeader := range []string{"api.example.com:443", "api.example.com:8080", "api.example.com"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = hostHeader
		rec := httptest.NewRecorder()
		if err := h.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
	}

	hosts := reg.SnapshotHosts()
	if len(hosts) != 1 || hosts[0].Host != "api.example.com" || hosts[0].Reqs != 3 {
		t.Errorf("host deltas = %+v; want one cell at api.example.com with reqs=3", hosts)
	}
}

func TestRouteMetrics_HostBump_LegacyKnownHostsEmpty(t *testing.T) {
	// Pre-Phase-1 Caddy configs emit no KnownHosts → the
	// middleware MUST behave identically to the legacy Inc
	// path: route counter ticks, no host counter created
	// for any value of r.Host.
	reg := NewRegistry()
	reg.Sync([]string{"r1"})
	h := newTestHostHandler(t, reg, "r1", nil)

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "anything.example.com"
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if got := reg.Snapshot()["r1"].Reqs; got != 1 {
		t.Errorf("route reqs=%d want 1 (legacy path still increments)", got)
	}
	if hosts := reg.SnapshotHosts(); len(hosts) != 0 {
		t.Errorf("host deltas len=%d want 0 (no KnownHosts → no host cells)", len(hosts))
	}
}

func TestRouteMetrics_HostBump_EmptyHostHeader(t *testing.T) {
	// Defensive: a request with r.Host == "" (HTTP/0.9 or
	// hand-crafted curl) must not crash and must not create a
	// host cell.
	reg := NewRegistry()
	reg.Sync([]string{"r1"})
	h := newTestHostHandler(t, reg, "r1", []string{"api.example.com"})

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = ""
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	// Route counter still ticks (defence in depth).
	if got := reg.Snapshot()["r1"].Reqs; got != 1 {
		t.Errorf("route reqs=%d want 1", got)
	}
	if hosts := reg.SnapshotHosts(); len(hosts) != 0 {
		t.Errorf("host deltas len=%d want 0 on empty Host header", len(hosts))
	}
}
