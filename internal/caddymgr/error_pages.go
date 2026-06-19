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

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/microcosm-cc/bluemonday"

	"github.com/barto95100/arenet/internal/storage"
)

// Step R — caddymgr-side emit of per-route custom error pages.
//
// Wire shape verified against caddy v2.11.3 :
//   - modules/caddyhttp/server.go:745 (HTTPErrorConfig { Routes RouteList })
//   - modules/caddyhttp/staticresp.go:127 (static_response handler)
//   - modules/caddyhttp/celmatcher.go:82 (http.matchers.expression module)
//
// Resolution order at emit time, in this priority :
//   1. Route.ErrorPageOverrides[code]      (per-route override)
//   2. Template.Pages[code]                (template the route opted into)
//   3. arenetDefaultErrorPages[code]       (built-in default)
//
// First non-empty hit wins. Empty body at any layer falls through.
//
// HTML sanitization : every emitted body passes through the
// bluemonday policy below. Defense-in-depth against a compromised-
// admin reflected-XSS scenario even though the CRUD endpoint is
// RequireAdmin-gated. See Phase R.0 audit.

// errorPageSanitizer is the process-global bluemonday policy
// applied to every emitted body. Allocated once via UGCPolicy()
// then loosened to permit branded error pages (inline + external
// CSS, common <meta> tags) while keeping <script> / <iframe> /
// <object> / event handlers blocked.
//
// bluemonday.Policy is documented as goroutine-safe after the
// AllowXxx wiring completes ; we call those wirings only here.
var errorPageSanitizer = func() *bluemonday.Policy {
	p := bluemonday.UGCPolicy()
	p.AllowStyling()
	p.AllowElements("style", "head", "html", "body", "meta", "title", "link")
	p.AllowAttrs("rel", "href", "media", "type", "crossorigin").OnElements("link")
	p.AllowAttrs("name", "content", "charset", "http-equiv").OnElements("meta")
	p.AllowAttrs("lang").OnElements("html")
	return p
}()

// arenetDefaultErrorPages is the built-in fallback used when no
// template / override matches. Slate dark theme matching the
// Arenet brand. Operators get a recognisable Arenet-branded page
// for free without configuring anything ; opt-in for custom
// branding starts here.
//
// Body strings carry Caddy runtime placeholders
// ({http.error.status_code}, {http.request.uri}, ...) which the
// static_response handler expands at serve time.
var arenetDefaultErrorPages = map[int]string{
	401: arenetDefaultPage(401, "Unauthorized", "Authentication is required to access this resource."),
	403: arenetDefaultPage(403, "Forbidden", "Access to this resource has been denied."),
	404: arenetDefaultPage(404, "Not Found", "The requested resource could not be located on this server."),
	429: arenetDefaultPage(429, "Too Many Requests", "Rate limit exceeded. Please retry after a short wait."),
	500: arenetDefaultPage(500, "Internal Server Error", "An unexpected condition was encountered."),
	502: arenetDefaultPage(502, "Bad Gateway", "The upstream service returned an invalid response."),
	503: arenetDefaultPage(503, "Service Unavailable", "The service is temporarily unable to handle the request."),
	504: arenetDefaultPage(504, "Gateway Timeout", "The upstream service did not respond in time."),
}

// arenetDefaultPage produces a minimal, brand-aligned HTML body
// for one status code. ~1.5 KiB per body — well under the 1 MiB
// cap. The duplicate %d/%s vs format args is intentional ; the
// status code appears twice in the rendered HTML (large hero +
// the <title> tag).
func arenetDefaultPage(code int, title, msg string) string {
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%d %s</title>
<style>
  body { background:#0d1117; color:#c9d1d9; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px; }
  .card { max-width:520px; text-align:center; }
  .code { font-family:"SF Mono",Menlo,Consolas,monospace; font-size:96px; font-weight:600; color:#58a6ff; margin:0; line-height:1; letter-spacing:-2px; }
  h1 { font-size:24px; font-weight:500; margin:16px 0 8px; color:#f0f6fc; }
  p { color:#8b949e; line-height:1.5; margin:8px 0; }
  .meta { margin-top:32px; padding-top:16px; border-top:1px solid #21262d; color:#6e7681; font-size:12px; font-family:"SF Mono",Menlo,Consolas,monospace; }
  a { color:#58a6ff; text-decoration:none; }
</style>
</head>
<body>
<div class="card">
  <p class="code">%d</p>
  <h1>%s</h1>
  <p>%s</p>
  <div class="meta">
    {http.request.method} {http.request.uri} · request id: {http.request.uuid}<br>
    <a href="https://github.com/barto95100/arenet">powered by Arenet</a>
  </div>
</div>
</body>
</html>`, code, title, code, title, msg)
}

// postSanitize re-prepends the `<!doctype html>` declaration
// that bluemonday strips by design (sanitize.go:241 — "DocType
// is not handled as there is no safe parsing mechanism"). The
// DOCTYPE is a static, parameter-less string ; re-adding it
// is safe because it doesn't carry user content. Without it,
// browsers fall into quirks mode and rendering of the
// operator's CSS becomes unpredictable.
//
// The check skips bodies that don't look like a full HTML
// document (operator wrote just `<h1>403</h1>`) — those don't
// benefit from a DOCTYPE prefix and browsers will quirks-render
// the fragment anyway.
func postSanitize(s string) string {
	trimmed := strings.TrimLeft(s, " \t\n\r")
	// Only re-prepend if the output starts with <html ...> — that's
	// the marker that the operator intended a full document.
	if strings.HasPrefix(strings.ToLower(trimmed), "<html") {
		return "<!doctype html>\n" + s
	}
	return s
}

// resolveErrorPage returns the HTML body to emit for the given
// (route, statusCode) tuple after applying the 3-layer resolution
// order. Empty result means no body is configured — caller skips
// the error route for this code (Caddy falls back to its bare
// status-line response with no body).
//
// templates is the lookup map keyed by template ID, built from
// store.ListErrorPageTemplates(). A dangling
// Route.ErrorPageTemplateID (template deleted) is treated as if
// the route had no template ref : layer 2 falls through to
// layer 3 (built-in default).
func resolveErrorPage(route storage.Route, code int, templates map[string]storage.ErrorPageTemplate) string {
	if body, ok := route.ErrorPageOverrides[code]; ok && body != "" {
		return body
	}
	if route.ErrorPageTemplateID != "" {
		if tmpl, ok := templates[route.ErrorPageTemplateID]; ok {
			if body, ok := tmpl.Pages[code]; ok && body != "" {
				return body
			}
		}
	}
	if body, ok := arenetDefaultErrorPages[code]; ok && body != "" {
		return body
	}
	return ""
}

// buildErrorRoutesForRoute returns the httpRoute entries that
// should appear under apps.http.servers.<srv>.errors.routes for
// ONE upstream route's host set. One httpRoute per supported
// status code that has a resolvable body.
//
// Each emitted entry carries a matcher set with :
//   - Host : the route's primary host + aliases (scopes the
//     error page to THIS route's traffic ; api.example.com 403
//     doesn't fire the admin.example.com 403 template)
//   - Expression : CEL `{http.error.status_code} == <code>`
//     (dispatches by the in-flight error's status)
//
// The two fields AND-combine inside one matcherSet per Caddy
// docs. One code per route = trivial expressions + the operator
// can disable a single code without affecting the others.
func buildErrorRoutesForRoute(route storage.Route, templates map[string]storage.ErrorPageTemplate, logger *slog.Logger) []httpRoute {
	// AllHosts always returns at least [Host] (possibly "") so we
	// check Host explicitly. A route without a Host shouldn't have
	// made it past storage validation, but defence-in-depth keeps
	// the error route emission tight when an obscure code path
	// calls in with a half-initialised Route.
	if route.Host == "" {
		return nil
	}
	hosts := route.AllHosts()

	if route.ErrorPageTemplateID != "" {
		if _, ok := templates[route.ErrorPageTemplateID]; !ok && logger != nil {
			logger.Warn("error_pages: template ref dangling ; route falls back to built-in defaults",
				"route_id", route.ID,
				"host", route.Host,
				"missing_template_id", route.ErrorPageTemplateID,
			)
		}
	}

	out := make([]httpRoute, 0, len(storage.SupportedErrorStatusCodes))
	for _, code := range storage.SupportedErrorStatusCodes {
		body := resolveErrorPage(route, code, templates)
		if body == "" {
			continue
		}
		clean := postSanitize(errorPageSanitizer.Sanitize(body))
		out = append(out, httpRoute{
			Match: []matcherSet{{
				Host:       hosts,
				Expression: fmt.Sprintf("{http.error.status_code} == %d", code),
			}},
			Handle: []map[string]any{
				{
					"handler":     "static_response",
					"status_code": fmt.Sprintf("%d", code),
					"headers": map[string]any{
						"Content-Type": []string{"text/html; charset=utf-8"},
					},
					"body": clean,
				},
			},
		})
	}
	return out
}

// buildErrorRoutesForServer aggregates the per-route error routes
// for every route in `routes` whose hosts belong on this server
// (HTTP vs HTTPS — TLS-enabled routes land on the HTTPS server).
// Returns the slice ready to plug into httpServer.Errors.Routes,
// or nil if no route has any error config (the caller omits the
// Errors field entirely to keep the emitted JSON tight for the
// no-feature case).
//
// tlsScope picks which routes contribute :
//   - true  → only routes with TLSEnabled (HTTPS server)
//   - false → only routes WITHOUT TLSEnabled (plain-HTTP server)
//
// The split mirrors how the primary routes are dispatched between
// servers (httpRoutes vs httpsRoutes) in buildConfigJSON.
func buildErrorRoutesForServer(routes []storage.Route, templates map[string]storage.ErrorPageTemplate, tlsScope bool, logger *slog.Logger) []httpRoute {
	var out []httpRoute
	for _, r := range routes {
		if r.TLSEnabled != tlsScope {
			continue
		}
		out = append(out, buildErrorRoutesForRoute(r, templates, logger)...)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
