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

// pathMatchers returns Caddy path matchers for a prefix: the prefix
// itself + everything under it. "/docs" → ["/docs","/docs/*"].
func pathMatchers(prefix string) []string {
	return []string{prefix, prefix + "/*"}
}

// buildPathRulesSubroute wraps the proxy in a subroute whose inner
// routes are the path-rules (sorted longest-prefix first, Q4) each
// applying its override handlers (path IP filter block, then basic
// auth) before proxying, followed by a match-less catch-all proxy.
//
// Ordering inside a matched path route is IP filter BEFORE basic
// auth BEFORE proxy: a blocked client gets its 403 without ever
// reaching the auth prompt (avoids leaking that the path exists /
// wasting a credential round-trip on traffic that would be denied
// anyway).
//
// The catch-all (no `match`) is REQUIRED: without it, a request
// whose path doesn't fall under any PathRule prefix would have no
// route to fall through to inside this subroute and would be
// dropped instead of reaching the plain proxy.
func buildPathRulesSubroute(
	rules []storage.PathRule,
	proxyHandler map[string]any,
	basicAuthBuilder func(storage.BasicAuthRouteConfig) map[string]any,
) map[string]any {
	sorted := storage.SortPathRulesByPrefixLenDesc(rules)
	inner := make([]map[string]any, 0, len(sorted)+1)
	for _, pr := range sorted {
		handle := make([]map[string]any, 0, 3)
		if pr.IPFilter != nil && pr.IPFilter.IsActive() {
			// A path IP block inside the matched route: emit the block
			// route's matcher+handler as a nested subroute so a blocked
			// client gets the 403 before the proxy (and before auth).
			if ipRoute := buildIPFilterRoute(*pr.IPFilter); ipRoute != nil {
				handle = append(handle, map[string]any{
					"handler": "subroute",
					"routes":  []map[string]any{ipRoute},
				})
			}
		}
		if pr.BasicAuth != nil {
			handle = append(handle, basicAuthBuilder(*pr.BasicAuth))
		}
		handle = append(handle, proxyHandler)
		inner = append(inner, map[string]any{
			"match":  []map[string]any{{"path": pathMatchers(pr.PathPrefix)}},
			"handle": handle,
		})
	}
	// catch-all: no path match → plain proxy (paths with no rule).
	inner = append(inner, map[string]any{
		"handle": []map[string]any{proxyHandler},
	})
	return map[string]any{"handler": "subroute", "routes": inner}
}
