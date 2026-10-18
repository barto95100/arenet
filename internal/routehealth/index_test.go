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
	"sort"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

func notifyRoute(id, host string, upstreams ...string) storage.Route {
	ups := make([]storage.Upstream, len(upstreams))
	for i, u := range upstreams {
		ups[i] = storage.Upstream{URL: u, Weight: 1}
	}
	return storage.Route{
		ID:           id,
		Host:         host,
		Upstreams:    ups,
		HealthNotify: storage.HealthNotifyConfig{Enabled: true, ChannelID: "ch1"},
	}
}

func routeIDs(refs []routeRef) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.routeID
	}
	sort.Strings(out)
	return out
}

func TestIndex_SharedUpstreamMapsToAllRoutes(t *testing.T) {
	ix := newIndex()
	ix.Refresh([]storage.Route{
		notifyRoute("r1", "a.example.com", "http://10.0.0.5:8080"),
		notifyRoute("r2", "b.example.com", "http://10.0.0.5:8080"),
		notifyRoute("r3", "c.example.com", "https://10.0.0.5:8080"), // same host:port, different scheme
	})
	got := routeIDs(ix.routesFor("10.0.0.5:8080"))
	want := []string{"r1", "r2", "r3"}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("routesFor shared upstream = %v; want %v (scheme is normalized away)", got, want)
	}
}

func TestIndex_DisabledRouteAbsent(t *testing.T) {
	ix := newIndex()
	on := notifyRoute("on", "on.example.com", "http://10.0.0.9:80")
	off := notifyRoute("off", "off.example.com", "http://10.0.0.9:80")
	off.HealthNotify.Enabled = false
	ix.Refresh([]storage.Route{on, off})

	got := routeIDs(ix.routesFor("10.0.0.9:80"))
	if len(got) != 1 || got[0] != "on" {
		t.Errorf("routesFor = %v; a notify-disabled route must not be indexed", got)
	}
}

func TestIndex_RefreshReplaces(t *testing.T) {
	ix := newIndex()
	ix.Refresh([]storage.Route{notifyRoute("r1", "a", "http://10.0.0.1:80")})
	if len(ix.routesFor("10.0.0.1:80")) != 1 {
		t.Fatal("precondition: r1 indexed")
	}
	// A reload that drops r1 and adds r2 must leave no trace of r1.
	ix.Refresh([]storage.Route{notifyRoute("r2", "b", "http://10.0.0.2:80")})
	if len(ix.routesFor("10.0.0.1:80")) != 0 {
		t.Error("stale upstream from the previous route set survived a Refresh")
	}
	if len(ix.routesFor("10.0.0.2:80")) != 1 {
		t.Error("the new route set was not indexed")
	}
}

func TestIndex_MultiUpstreamRouteIndexedUnderEach(t *testing.T) {
	ix := newIndex()
	ix.Refresh([]storage.Route{
		notifyRoute("r1", "a", "http://10.0.0.1:80", "http://10.0.0.2:80"),
	})
	for _, addr := range []string{"10.0.0.1:80", "10.0.0.2:80"} {
		refs := ix.routesFor(addr)
		if len(refs) != 1 || refs[0].routeID != "r1" {
			t.Errorf("routesFor(%s) = %v; a multi-upstream route is indexed under each upstream", addr, routeIDs(refs))
		}
		if len(refs[0].upstream) != 2 {
			t.Errorf("routeRef should carry both upstreams for aggregate-state computation, got %v", refs[0].upstream)
		}
	}
}
