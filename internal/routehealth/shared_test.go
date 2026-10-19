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
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

func TestSharedUpstreams_CountsEnabledRoutesPerAddress(t *testing.T) {
	routes := []storage.Route{
		{ID: "meet", Upstreams: []storage.Upstream{{URL: "http://10.66.0.2:80"}}},
		{ID: "sso", Upstreams: []storage.Upstream{{URL: "http://10.66.0.2:80"}}},
		{ID: "www", Upstreams: []storage.Upstream{{URL: "http://10.66.0.2"}}}, // port-less, same host
		{ID: "solo", Upstreams: []storage.Upstream{{URL: "http://10.0.0.9:3000"}}},
		{ID: "off", Disabled: true, Upstreams: []storage.Upstream{{URL: "http://10.66.0.2:80"}}},
	}

	counts := SharedUpstreams(routes)

	// http://10.66.0.2 and http://10.66.0.2:80 both normalize to
	// 10.66.0.2:80 (NormalizeAddr adds the scheme default port), so meet +
	// sso + www = 3; the disabled "off" route does not count.
	if counts["10.66.0.2:80"] != 3 {
		t.Fatalf("10.66.0.2:80 count = %d; want 3 (meet+sso+www, disabled excluded)", counts["10.66.0.2:80"])
	}
	if counts["10.0.0.9:3000"] != 1 {
		t.Fatalf("10.0.0.9:3000 count = %d; want 1 (solo)", counts["10.0.0.9:3000"])
	}
}

func TestSharedUpstreams_SameAddressTwiceInOneRouteCountsOnce(t *testing.T) {
	routes := []storage.Route{
		{ID: "dup", Upstreams: []storage.Upstream{
			{URL: "http://10.0.0.5:80"}, {URL: "http://10.0.0.5:80"},
		}},
	}
	if got := SharedUpstreams(routes)["10.0.0.5:80"]; got != 1 {
		t.Fatalf("count = %d; want 1 — the same address twice in ONE route is not shared across routes", got)
	}
}

func TestIsRouteShared(t *testing.T) {
	routes := []storage.Route{
		{ID: "meet", Upstreams: []storage.Upstream{{URL: "http://10.66.0.2:80"}}},
		{ID: "sso", Upstreams: []storage.Upstream{{URL: "http://10.66.0.2:80"}}},
		{ID: "solo", Upstreams: []storage.Upstream{{URL: "http://10.0.0.9:3000"}}},
	}
	counts := SharedUpstreams(routes)

	if !IsRouteShared(routes[0], counts) {
		t.Error("meet should be shared (10.66.0.2:80 used by meet+sso)")
	}
	if IsRouteShared(routes[2], counts) {
		t.Error("solo should NOT be shared (unique upstream)")
	}

	disabled := storage.Route{ID: "meet", Disabled: true, Upstreams: routes[0].Upstreams}
	if IsRouteShared(disabled, counts) {
		t.Error("a disabled route is never shared")
	}
}
