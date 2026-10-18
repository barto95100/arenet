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

// Package routehealth turns the per-upstream health transitions the
// caddyhc tracker observes into per-route notifications on a chosen
// alert channel (v2.75). It sits above three subsystems without any of
// them depending on it: caddyhc (the transitions), storage (which routes
// an upstream belongs to, and their notify config), and alerting (the
// channels and the dispatcher).
package routehealth

import (
	"sync"

	"github.com/barto95100/arenet/internal/caddyhc"
	"github.com/barto95100/arenet/internal/storage"
)

// routeRef is a route the index knows about: enough to decide its
// aggregate health and to address a notification, with no back-reference
// to storage so a lookup on the hot path copies a small value.
type routeRef struct {
	routeID  string
	host     string
	upstream []string // normalized upstream addresses (caddyhc keys)
	notify   storage.HealthNotifyConfig
}

// index maps a normalized upstream address to the routes that use it,
// refreshed from the emitted route set at each Caddy reload. Only routes
// with notification enabled are indexed — a flip on an upstream no route
// watches is ignored cheaply.
type index struct {
	mu     sync.RWMutex
	byAddr map[string][]routeRef
}

func newIndex() *index {
	return &index{byAddr: make(map[string][]routeRef)}
}

// Refresh rebuilds the index from the current route set. Routes with
// HealthNotify disabled are skipped, so the hot-path lookup only ever
// returns routes that actually want a message. Upstream URLs are
// normalized with the same function the tracker keys on, so a lookup by
// the tracker's address matches.
func (ix *index) Refresh(routes []storage.Route) {
	next := make(map[string][]routeRef)
	for _, r := range routes {
		if !r.HealthNotify.Enabled {
			continue
		}
		addrs := make([]string, 0, len(r.Upstreams))
		for _, u := range r.Upstreams {
			if key := caddyhc.NormalizeAddr(u.URL); key != "" {
				addrs = append(addrs, key)
			}
		}
		if len(addrs) == 0 {
			continue
		}
		ref := routeRef{
			routeID:  r.ID,
			host:     r.Host,
			upstream: addrs,
			notify:   r.HealthNotify,
		}
		for _, a := range addrs {
			next[a] = append(next[a], ref)
		}
	}
	ix.mu.Lock()
	ix.byAddr = next
	ix.mu.Unlock()
}

// routesFor returns the routes (notification-enabled) that use the given
// normalized upstream address. The slice is the index's own; callers
// must not mutate it.
func (ix *index) routesFor(addr string) []routeRef {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return ix.byAddr[addr]
}
