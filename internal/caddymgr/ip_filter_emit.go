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

import "github.com/barto95100/arenet/internal/storage"

// buildIPFilterRoute emits a Caddy route that blocks the traffic an
// IPFilter forbids, using the native client_ip matcher (which honours
// ARENET_TRUSTED_PROXIES — NOT remote_ip). Returns nil when inactive.
//
// allow mode → block everything NOT in the list: match {not:{client_ip}}.
//
//	This is the FAIL-CLOSED shape: an unknown client hits the 403.
//
// deny mode → block the listed: match {client_ip}.
// Caddy has no ResponseMatcher `not` but MatchNot (http.matchers.not,
// matchers.go:1366) IS a request matcher — valid here.
func buildIPFilterRoute(f storage.IPFilter) map[string]any {
	if !f.IsActive() {
		return nil
	}
	status := f.StatusCode
	if status == 0 {
		status = 403
	}
	clientIP := map[string]any{"ranges": f.NormalizedCIDRs()}
	var match map[string]any
	if f.Mode == storage.IPFilterModeAllow {
		match = map[string]any{"not": []map[string]any{{"client_ip": clientIP}}}
	} else { // deny
		match = map[string]any{"client_ip": clientIP}
	}
	return map[string]any{
		"match": []map[string]any{match},
		"handle": []map[string]any{
			{"handler": "static_response", "status_code": status},
		},
	}
}
