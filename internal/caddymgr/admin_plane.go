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
	"net"
	"net/url"
	"strings"

	"github.com/barto95100/arenet/internal/storage"
)

// Which route is the management plane (v2.73).
//
// The CRS false-positive guard for Arenet's own admin API used to be
// prepended to EVERY route's WAF engine, and it keys on
// REQUEST_FILENAME — the path the client picks. So any unauthenticated
// request under /api/v1/ had CRS families 911*, 930*, 931* and the
// 949* anomaly-score evaluator stripped from its transaction, on any
// route in block mode. The guard's own comment claimed user routes
// were unaffected because the pattern was path-based; that is the
// reason they WERE affected.
//
// The guard is only needed where admin API traffic actually reaches a
// WAF. That is not the admin listener itself — cmd/arenet serves it
// from a plain http.Server, outside Caddy, so no WAF handler is in
// that path at all. It is the documented topology where the operator
// publishes the admin UI as an Arenet route pointing at the admin
// listener on loopback. That route, and only that route, gets the
// exemption.

// routeTargetsAdminListener reports whether any of the route's
// upstreams points at this instance's own admin listener.
//
// Both halves are required: the port must be the admin port, and the
// host must be loopback. The admin listener only ever binds locally
// (or, in the container, to the container's interfaces reachable as
// loopback from the same process), so a route aimed at some other
// host's :8001 is a route to someone else's machine and gets no
// exemption.
func routeTargetsAdminListener(r storage.Route, adminListen string) bool {
	adminPort := adminPortFrom(adminListen)
	if adminPort == "" {
		// No admin address recorded: no route can be identified as the
		// management plane, so none gets the exemption. Failing closed
		// here costs a false positive on an admin route; failing open
		// would cost the CRS blocking evaluator on every route, which
		// is the defect being fixed.
		return false
	}
	for _, u := range r.Upstreams {
		if upstreamIsLoopbackPort(u.URL, adminPort) {
			return true
		}
	}
	return false
}

// adminPortFrom extracts the port from a bind address like
// "127.0.0.1:8001", ":8001" or "[::]:8001". Empty when it cannot be
// read.
func adminPortFrom(listen string) string {
	if strings.TrimSpace(listen) == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil {
		return ""
	}
	return port
}

// upstreamIsLoopbackPort reports whether rawURL names a loopback host
// on the given port.
func upstreamIsLoopbackPort(rawURL, port string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" {
		return false
	}
	host, hostPort, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		// No explicit port. The admin listener never runs on 80 or
		// 443, so an upstream without a port cannot be it.
		return false
	}
	if hostPort != port {
		return false
	}
	return hostIsLoopback(host)
}

// hostIsLoopback covers the three spellings an operator writes for
// "this machine": the literal addresses and the name.
func hostIsLoopback(host string) bool {
	h := strings.ToLower(strings.Trim(host, "[]"))
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
