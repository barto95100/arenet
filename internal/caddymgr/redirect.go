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
	"strings"

	"github.com/barto95100/arenet/internal/storage"
)

// v2.44 — the route-level redirect state.
//
// Shape and reasoning:
// docs/superpowers/specs/2026-09-24-route-redirects-design.md.
//
// A redirecting route does not proxy at all, so this replaces the
// whole proxy chain exactly the way maintenance does — same subroute
// wrapper, same metrics handler in front, so a redirect still shows up
// in the route's counters. An operator who moved a domain wants to see
// how much traffic still arrives at the old name; that is the number
// that tells them when they can retire it.
//
// The one placeholder used is {http.request.uri}, which Caddy expands
// to the path AND the query string — not {http.request.uri.path},
// which would silently drop ?utm_source=… and every other parameter.

// buildRedirectStateHandler returns the subroute that answers the
// redirect, in place of the proxy handler.
func buildRedirectStateHandler(metricsHandler map[string]any, rc *storage.RedirectConfig) map[string]any {
	location := strings.TrimSpace(rc.Target)
	if rc.PreservePath {
		// The visitor's own path is appended, so the target must not
		// end in a slash or the result carries a doubled one.
		// Validate already refuses a target with a real path; this
		// only normalises the harmless trailing "/".
		location = strings.TrimSuffix(location, "/") + "{http.request.uri}"
	}

	static := map[string]any{
		"handler":     "static_response",
		"status_code": rc.Code(),
		"headers":     map[string]any{"Location": []string{location}},
	}

	return map[string]any{
		"handler": "subroute",
		"routes": []map[string]any{
			{"handle": []map[string]any{metricsHandler, static}},
		},
	}
}
