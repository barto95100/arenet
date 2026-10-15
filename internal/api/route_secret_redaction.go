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

package api

import (
	"context"

	"github.com/barto95100/arenet/internal/auth"
)

// A viewer does not read the operator's upstream credentials (v2.73).
//
// GET /routes and GET /routes/{id} are mounted in the hard-auth group
// WITHOUT RequireAdminMiddleware, so a viewer — a human invited to
// watch dashboards, an OIDC identity auto-created with the default
// viewer role, or a viewer-scoped service-account token handed to a
// monitoring script — read every route's custom request and response
// headers and its health-check probe headers in cleartext.
//
// Those values are credentials for the backend, and the project treats
// them as such everywhere else: storage.IsSensitiveHeader seals them
// at rest with the v2.30 keyring, redactSensitiveHeaders strips them
// from the audit log, and the backup exporter replaces them with
// sentinels. The route read was the one surface that handed them over.
//
// Redacting by ROLE rather than for everyone is deliberate. The admin
// route form round-trips these values on edit; blanking them for the
// admin too would need a preserve-on-edit sentinel on every header
// map, and a sentinel the operator can type is a new way to write the
// literal string into a backend header. An admin can already read
// every secret in the instance, so there is nothing to protect from
// them here.

// redactRouteForRole blanks the credential-bearing values of a route
// response unless the caller is an admin.
//
// The route's own identity, its upstreams, its policy — everything an
// operator needs a read-only account for — is untouched. Only the
// values of headers storage.IsSensitiveHeader recognises are replaced,
// and the header NAMES stay, so a viewer can still see that the route
// injects an Authorization toward its upstream.
func redactRouteForRole(resp routeResponse, ctx context.Context) routeResponse {
	if auth.RoleFromContext(ctx) == auth.UserRoleAdmin {
		return resp
	}
	return redactRouteSecrets(resp)
}

// redactRouteSecrets is the role-free half, so a test can assert on
// the shape without building a context.
func redactRouteSecrets(resp routeResponse) routeResponse {
	resp.RequestHeaders = redactSensitiveHeaders(resp.RequestHeaders)
	resp.ResponseHeaders = redactSensitiveHeaders(resp.ResponseHeaders)
	resp.HealthCheck.Headers = redactSensitiveHeaders(resp.HealthCheck.Headers)

	// Path rules carry their own health check, with their own probe
	// headers. handler.go maps them separately, so they need the same
	// treatment separately — the leak was reported on the route and
	// lives here too.
	if len(resp.PathRules) > 0 {
		rules := make([]pathRuleReq, len(resp.PathRules))
		copy(rules, resp.PathRules)
		for i := range rules {
			if rules[i].HealthCheck != nil {
				hc := *rules[i].HealthCheck
				hc.Headers = redactSensitiveHeaders(hc.Headers)
				rules[i].HealthCheck = &hc
			}
		}
		resp.PathRules = rules
	}
	return resp
}
