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
	"mime"
	"net/http"
)

// csrfGuard is the CSRF defence for the admin API (F37). Before it, the
// only protection on a state-changing request was the session cookie's
// SameSite=Strict, which isolates the registrable domain, not a sibling
// origin of the admin host — so a stored XSS in any app Arenet proxies on
// a neighbouring subdomain could auto-submit a form to the admin host and
// perform a fully privileged write (create an admin account, rewrite a
// provider, delete routes) with the admin's cookie attached.
//
// The guard applies ONLY to a cookie-authenticated unsafe request:
//
//   - A bearer-token request is not CSRF-exposed — the token is never
//     attached automatically by a browser — and programmatic clients do
//     not send Origin or Sec-Fetch-Site, so gating them would break
//     automation. A request without the session cookie is passed through
//     (bearer, or unauthenticated, which the auth middleware then 401s).
//   - A safe method (GET/HEAD/OPTIONS/TRACE) changes nothing.
//
// For a cookie-authenticated unsafe request it enforces two things:
//
//   - A non-empty body must be application/json. The classic
//     cross-origin CSRF write is an auto-submitted HTML form, which can
//     only produce the CORS "simple" content types (text/plain,
//     application/x-www-form-urlencoded, multipart/form-data) and never
//     triggers a preflight; a cross-origin fetch with application/json
//     WOULD trigger a preflight, which this no-CORS API never answers, so
//     the browser blocks it. Requiring application/json therefore rejects
//     exactly the no-preflight cross-origin shape. A bodyless request
//     (ContentLength 0 — e.g. a plain DELETE) carries no payload to forge
//     and is not form-reachable, so the content-type rule does not apply.
//   - When the browser labels the request's origin relationship via
//     Sec-Fetch-Site, it must be same-origin. This is browser-set and
//     unaffected by any Host rewriting between Arenet's proxy and the
//     admin listener, so it is reliable where an Origin/Referer host
//     comparison would not be. Absent (a non-fetch client, or a browser
//     too old to send it), the content-type rule already covers the
//     realistic attack, so the request is allowed.
func csrfGuard() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isCSRFSafeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			if _, err := r.Cookie(sessionCookieName); err != nil {
				// No session cookie: not cookie-authenticated, so not
				// CSRF-exposed. Bearer and anonymous requests pass here.
				next.ServeHTTP(w, r)
				return
			}
			if r.ContentLength != 0 && !isJSONContentType(r.Header.Get("Content-Type")) {
				writeError(w, http.StatusUnsupportedMediaType,
					"this endpoint requires Content-Type: application/json")
				return
			}
			if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" {
				writeError(w, http.StatusForbidden,
					"cross-site request refused")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isCSRFSafeMethod reports whether the HTTP method is side-effect-free
// per RFC 7231 §4.2.1 and so needs no CSRF defence.
func isCSRFSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// isJSONContentType reports whether the Content-Type's media type is
// application/json, ignoring any charset or other parameter.
func isJSONContentType(ct string) bool {
	if ct == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && mt == "application/json"
}
