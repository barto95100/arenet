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
	"github.com/barto95100/arenet/internal/caddyhc"
	"github.com/barto95100/arenet/internal/storage"
)

// SharedUpstreams returns, for the given route set, how many ENABLED
// routes dial each normalized upstream address. An address used by two or
// more routes is "shared": Caddy keeps per-upstream health in one global
// pool keyed by dial address (reverseproxy/hosts.go:130,:308), so routes
// sharing an address share one health verdict — and when the upstream is
// a multiplexing proxy (a Traefik fanning out by Host) that verdict
// cannot distinguish one route's backend from another's. The per-route
// evaluator uses this to decide which routes need an individual probe.
//
// Disabled routes are excluded: they emit no config and run no probe, so
// they neither share nor are shared.
func SharedUpstreams(routes []storage.Route) map[string]int {
	counts := make(map[string]int)
	for _, r := range routes {
		if r.Disabled {
			continue
		}
		// A route can list the same address twice; count it once per
		// route so "shared" means shared ACROSS routes, not within one.
		seen := make(map[string]struct{}, len(r.Upstreams))
		for _, u := range r.Upstreams {
			key := caddyhc.NormalizeAddr(u.URL)
			if key == "" {
				continue
			}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			counts[key]++
		}
	}
	return counts
}

// IsRouteShared reports whether any of the route's upstreams is shared
// with at least one other route, per a counts map from SharedUpstreams.
// A shared route's health must be determined per-route (an individual
// probe), not read from the address-keyed tracker.
func IsRouteShared(r storage.Route, counts map[string]int) bool {
	if r.Disabled {
		return false
	}
	for _, u := range r.Upstreams {
		if key := caddyhc.NormalizeAddr(u.URL); key != "" && counts[key] >= 2 {
			return true
		}
	}
	return false
}
