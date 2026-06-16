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

package caddymgr

import (
	"reflect"
	"testing"

	"github.com/barto95100/arenet/internal/metrics"
	"github.com/barto95100/arenet/internal/storage"
)

// Topology Plan B Phase 2.1 — buildKnownHosts + emit integration
// tests. The Phase 1 middleware (commit af48ad6) consumes the
// emitted known_hosts list via RouteMetricsHandler.KnownHosts;
// these tests pin the producer side.

func TestBuildKnownHosts_PrimaryOnly(t *testing.T) {
	// No aliases → single-entry slice with the primary host.
	got := buildKnownHosts(storage.Route{Host: "api.example.com"})
	want := []string{"api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildKnownHosts = %v; want %v", got, want)
	}
}

func TestBuildKnownHosts_PrimaryPlusAliases_LowercasedOrdered(t *testing.T) {
	// Primary + aliases, mixed case → all lowercased, primary
	// first, aliases in declared order.
	got := buildKnownHosts(storage.Route{
		Host:    "API.Example.com",
		Aliases: []string{"Alt.example.com", "WWW.example.com"},
	})
	want := []string{"api.example.com", "alt.example.com", "www.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildKnownHosts = %v; want %v", got, want)
	}
}

func TestBuildKnownHosts_StripPort(t *testing.T) {
	// Defensive: an operator who typed "example.com:443" must
	// be normalised to "example.com" so the middleware's
	// SplitHostPort path matches.
	got := buildKnownHosts(storage.Route{
		Host:    "example.com:443",
		Aliases: []string{"alt.example.com:8080"},
	})
	want := []string{"example.com", "alt.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildKnownHosts = %v; want %v", got, want)
	}
}

func TestBuildKnownHosts_DedupCaseInsensitive(t *testing.T) {
	// "Example.COM" + "example.com" reduce to a single entry
	// (first-seen wins; subsequent dupes dropped).
	got := buildKnownHosts(storage.Route{
		Host:    "Example.COM",
		Aliases: []string{"example.com", "ALIAS.example.com", "alias.example.com"},
	})
	want := []string{"example.com", "alias.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildKnownHosts = %v; want %v", got, want)
	}
}

func TestBuildKnownHosts_EmptyAliasEntriesDropped(t *testing.T) {
	// Defensive: storage shouldn't produce an alias slice with
	// empty strings, but a degraded row (manually edited bolt
	// file, future migration bug) must not crash the emit. The
	// helper drops blanks silently and still ships the primary.
	got := buildKnownHosts(storage.Route{
		Host:    "api.example.com",
		Aliases: []string{"", "  ", "alt.example.com"},
	})
	want := []string{"api.example.com", "alt.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildKnownHosts = %v; want %v", got, want)
	}
}

func TestBuildKnownHosts_EmptyRouteReturnsNil(t *testing.T) {
	// Degraded Host == "" (storage.validate() rejects this in
	// practice, but the helper must not panic on a bypass).
	got := buildKnownHosts(storage.Route{Host: ""})
	if got != nil {
		t.Errorf("buildKnownHosts on empty route = %v; want nil", got)
	}
}

// TestBuildConfigJSON_EmitsKnownHosts is the integration pin: the
// emitted Caddy JSON for arenet_routemetrics must carry the
// known_hosts field as a string slice equal to buildKnownHosts.
// Without this, the Phase 1 middleware silently runs the legacy
// route-only path (KnownHosts == nil).
func TestBuildConfigJSON_EmitsKnownHosts(t *testing.T) {
	routes := []storage.Route{
		{
			ID:   "rid-1",
			Host: "api.example.com",
			Aliases: []string{
				"Alt.example.com", // case + dedup angle
				"www.example.com:443", // port-strip angle
			},
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
		},
	}

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	httpRoutes := httpRoutesFromConfig(t, raw)
	if len(httpRoutes) < 1 {
		t.Fatalf("expected ≥1 user route, got %d", len(httpRoutes))
	}
	handlers := unwrapHandlers(httpRoutes[0])
	if len(handlers) == 0 {
		t.Fatalf("route 0: no handlers")
	}
	metricsH, ok := handlers[0].(map[string]any)
	if !ok {
		t.Fatalf("route 0 handler[0] is not a map: %T", handlers[0])
	}
	if metricsH["handler"] != metrics.HandlerName {
		t.Fatalf("handler[0]=%v, want metrics handler first per §11.5", metricsH["handler"])
	}

	rawKnown, present := metricsH["known_hosts"]
	if !present {
		t.Fatalf("known_hosts absent from metricsHandler emit; want present")
	}
	// JSON round-trip yields []any; cast each.
	asSlice, ok := rawKnown.([]any)
	if !ok {
		// In-memory map (pre-marshal) carries the []string
		// literal — accept both shapes since this test runs on
		// the in-memory config object.
		if direct, ok2 := rawKnown.([]string); ok2 {
			want := []string{"api.example.com", "alt.example.com", "www.example.com"}
			if !reflect.DeepEqual(direct, want) {
				t.Errorf("known_hosts = %v; want %v", direct, want)
			}
			return
		}
		t.Fatalf("known_hosts wrong shape: %T", rawKnown)
	}
	got := make([]string, len(asSlice))
	for i, v := range asSlice {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("known_hosts[%d] not a string: %T", i, v)
		}
		got[i] = s
	}
	want := []string{"api.example.com", "alt.example.com", "www.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("known_hosts = %v; want %v", got, want)
	}
}
