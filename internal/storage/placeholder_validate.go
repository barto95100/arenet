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

package storage

import (
	"strings"

	"github.com/barto95100/arenet/internal/apierr"
)

// Operator-supplied header values and redirect targets reach Caddy
// handlers that run them through the request replacer:
//
//   - the headers handler, for request and response header values
//     (caddy v2.11.4 modules/caddyhttp/headers/headers.go: ApplyTo →
//     repl.ReplaceKnown on every Add/Set value);
//   - static_response, for the Location of a redirect
//     (modules/caddyhttp/staticresp.go: repl.ReplaceAll on each header
//     value).
//
// Two replacer families read host state: {env.NAME} expands to a process
// environment variable, {file./path} to the contents of a host file. In
// a response or a request forwarded upstream, either is a disclosure of
// exactly the material the proxy process can see — process secrets and
// arbitrary files — chosen by whoever can write a route, which on the
// restore path is whoever can get an operator to import a snapshot.
//
// They are refused here, at storage, because this is the one gate every
// write path shares (API create/update AND backup restore), the same
// posture as the WAF fields (waf_validate.go) and the glob path prefix.
//
// Scope is deliberately narrow. Request-derived placeholders —
// {http.request.host}, {http.request.remote.host} and the rest — are
// safe and common (X-Real-IP, X-Forwarded-*), so only the two
// host-state families are refused. The match is the literal Caddy
// expands: a leading "{env." or "{file.", case-sensitive, because the
// replacer itself is (a " {env." with a leading space is not a
// placeholder and is left alone, so it is no risk and not refused).
var dangerousPlaceholderFamilies = []string{"{env.", "{file."}

// placeholderUnsafe returns the first dangerous placeholder family found
// in value, or "" when there is none.
func placeholderUnsafe(value string) string {
	for _, fam := range dangerousPlaceholderFamilies {
		if strings.Contains(value, fam) {
			return fam
		}
	}
	return ""
}

// refusePlaceholder builds the operator-facing refusal.
func refusePlaceholder(code, field, value, family string) error {
	return apierr.New(code,
		map[string]string{"field": field, "value": value, "placeholder": family},
		"%s: %q contains the %s…} placeholder, which Caddy expands into the "+
			"response from host state (environment variables or file contents)",
		field, value, family)
}

// validatePlaceholderSafety refuses the Caddy host-state placeholders in
// every operator value that reaches a replacer-expanded Caddy handler:
// the route's request and response header values, the route-level
// redirect target, and each path rule's redirect target.
func (r *Route) validatePlaceholderSafety() error {
	for name, value := range r.RequestHeaders {
		if fam := placeholderUnsafe(value); fam != "" {
			return refusePlaceholder("route_request_header_placeholder",
				"request_headers["+name+"]", value, fam)
		}
	}
	for name, value := range r.ResponseHeaders {
		if fam := placeholderUnsafe(value); fam != "" {
			return refusePlaceholder("route_response_header_placeholder",
				"response_headers["+name+"]", value, fam)
		}
	}
	if r.RedirectConfig != nil {
		if fam := placeholderUnsafe(r.RedirectConfig.Target); fam != "" {
			return refusePlaceholder("route_redirect_target_placeholder",
				"redirect_config.target", r.RedirectConfig.Target, fam)
		}
	}
	for _, pr := range r.PathRules {
		if pr.Redirect == nil {
			continue
		}
		if fam := placeholderUnsafe(pr.Redirect.Target); fam != "" {
			return refusePlaceholder("path_redirect_target_placeholder",
				"path_rules[].redirect.target", pr.Redirect.Target, fam)
		}
	}
	return nil
}
