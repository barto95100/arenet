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
	"html"
	"strconv"
	"strings"
)

// maintenanceRetryAfterSentinel is replaced at emission time with the
// route's Retry-After value inside the maintenance page body. Kept as
// a distinct placeholder (rather than reusing an error-page runtime
// placeholder) because the retry-after value is a per-route STATIC
// int baked in at config-build time, not a Caddy runtime expression —
// there is no {http....} equivalent for "this route's configured
// Retry-After seconds".
const maintenanceRetryAfterSentinel = "{arenet.maintenance.retry_after}"

// maintenanceMessageSentinel is replaced at emission time with the
// global operator-authored maintenance message
// (storage.MaintenancePageConfig.Message, v2.18.0). Unlike the
// retry_after value (a trusted int), the message is untrusted free
// text, so buildMaintenanceBody HTML-escapes it before substitution
// and renders its newlines as <br>. Empty message → substituted with
// the empty string, so the built-in default's generic sentence stands
// alone and a custom page referencing the placeholder renders nothing
// there.
const maintenanceMessageSentinel = "{arenet.maintenance.message}"

// buildMaintenanceBody returns the maintenance HTML with the per-route
// Retry-After and the global message substituted in. `pageHTML` is the
// operator's stored page (already sanitized via SanitizeErrorPageBody
// upstream) or the branded default (arenetDefaultMaintenancePage).
// retryAfter is seconds, rendered as a plain integer (e.g. "300").
//
// message is untrusted operator free text. It is HTML-escaped (so it
// cannot inject markup into every 503 body) and its newlines rendered
// as <br> (so a multi-line message from the Settings textarea displays
// across lines instead of collapsing). Escape-then-<br> ordering is
// deliberate: any <br> typed into the message is escaped to &lt;br&gt;
// first, so only the newline-derived <br> tags are real markup. An
// empty message substitutes to the empty string.
func buildMaintenanceBody(pageHTML string, retryAfter int, message string) string {
	renderedMsg := strings.ReplaceAll(html.EscapeString(message), "\n", "<br>")
	out := strings.ReplaceAll(pageHTML, maintenanceRetryAfterSentinel, strconv.Itoa(retryAfter))
	return strings.ReplaceAll(out, maintenanceMessageSentinel, renderedMsg)
}

// resolveMaintenancePage returns the HTML body to use for a
// maintenance route: the operator's stored global page (Task 2,
// MaintenancePageConfig singleton) if non-empty, sanitized through
// the same pipeline as error-page bodies, else the branded default.
// Mirrors resolveErrorPage's override-then-default precedence
// (error_pages.go:404), collapsed to two tiers since there is only
// one global maintenance page (no per-route override, no template
// catalogue) per the Task 2 storage shape.
func resolveMaintenancePage(storedHTML string) string {
	if storedHTML != "" {
		return SanitizeErrorPageBody(storedHTML)
	}
	return arenetDefaultMaintenancePage
}

// buildMaintenanceRoute builds the terminal subroute handler for a
// route in maintenance mode: an OPTIONAL first inner route matching
// the operator's client_ip bypass allow-list (terminal, dispatches to
// the normal proxy handler chain), followed by a catch-all inner
// route serving a static_response 503 (with Retry-After + the
// maintenance body). metricsHandler is placed first in the 503 inner
// route so the 503 is counted in the per-route metrics (mirrors the
// invariant that metrics stays first in every emitted chain,
// manager.go handlers := []map[string]any{metricsHandler}).
//
// When bypassIPs is empty, the bypass inner route is omitted
// entirely rather than emitted with an empty ranges list: Caddy's
// client_ip matcher with a zero-length ranges slice is documented as
// "matches nothing meaningfully" territory we don't want to rely on
// — omitting the route entirely is the unambiguous "all traffic hits
// the 503" shape.
//
// message is the global operator maintenance message (v2.18.0),
// substituted (escaped, newlines→<br>) into the body via
// buildMaintenanceBody. Empty message renders nothing.
func buildMaintenanceRoute(metricsHandler, proxyHandler map[string]any, bypassIPs []string, retryAfterSeconds int, maintenanceHTML, message string) map[string]any {
	innerRoutes := make([]map[string]any, 0, 2)

	if len(bypassIPs) > 0 {
		innerRoutes = append(innerRoutes, map[string]any{
			"match": []map[string]any{
				{"client_ip": map[string]any{"ranges": bypassIPs}},
			},
			"handle":   []map[string]any{metricsHandler, proxyHandler},
			"terminal": true,
		})
	}

	body := buildMaintenanceBody(maintenanceHTML, retryAfterSeconds, message)
	headers := map[string]any{
		"Content-Type": []string{"text/html; charset=utf-8"},
	}
	if retryAfterSeconds > 0 {
		headers["Retry-After"] = []string{strconv.Itoa(retryAfterSeconds)}
	}
	staticResp := map[string]any{
		"handler":     "static_response",
		"status_code": 503,
		"body":        body,
		"headers":     headers,
	}
	innerRoutes = append(innerRoutes, map[string]any{
		"handle": []map[string]any{metricsHandler, staticResp},
	})

	return map[string]any{
		"handler": "subroute",
		"routes":  innerRoutes,
	}
}

// arenetDefaultMaintenancePage is the branded default served when the
// operator has not customized the global maintenance page (Task 2,
// MaintenancePageConfig.HTML empty). Mirrors the structure/branding
// of arenetDefaultPage (error_pages.go:259) — same dark theme, same
// card layout, same "powered by Arenet" footer — with a blue "Back
// soon" framing appropriate for a planned outage rather than an
// error, plus the Retry-After sentinel rendered as a human-readable
// line.
var arenetDefaultMaintenancePage = fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>503 Maintenance</title>
<style>
  body { background:#0d1117; color:#c9d1d9; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px; }
  .card { max-width:520px; text-align:center; }
  .code { font-family:"SF Mono",Menlo,Consolas,monospace; font-size:96px; font-weight:600; color:#58a6ff; margin:0; line-height:1; letter-spacing:-2px; }
  h1 { font-size:24px; font-weight:500; margin:16px 0 8px; color:#f0f6fc; }
  p { color:#8b949e; line-height:1.5; margin:8px 0; }
  .retry { color:#58a6ff; font-family:"SF Mono",Menlo,Consolas,monospace; font-size:13px; }
  /* .msg holds the operator's global message ({arenet.maintenance.message}).
     :empty collapses it to zero height so an unset message leaves no gap. */
  .msg { color:#c9d1d9; line-height:1.6; margin:16px 0 0; }
  .msg:empty { display:none; }
  .meta { margin-top:32px; padding-top:16px; border-top:1px solid #21262d; color:#6e7681; font-size:12px; font-family:"SF Mono",Menlo,Consolas,monospace; }
  a { color:#58a6ff; text-decoration:none; }
</style>
</head>
<body>
<div class="card">
  <p class="code">503</p>
  <h1>Back soon</h1>
  <p>This service is undergoing scheduled maintenance. Please check back shortly.</p>
  <p class="msg">%s</p>
  <p class="retry">Retry in %ss</p>
  <div class="meta">
    {http.request.method} {http.request.uri_escaped} · request id: {http.request.uuid}<br>
    <a href="https://github.com/barto95100/arenet">powered by Arenet</a>
  </div>
</div>
</body>
</html>`, maintenanceMessageSentinel, maintenanceRetryAfterSentinel)

// DefaultMaintenancePageHTML returns the branded default maintenance
// page HTML served when the operator has not customized the global
// maintenance page (storage.MaintenancePageConfig.HTML empty). It is
// the exported accessor for arenetDefaultMaintenancePage, added
// (v2.17.1 Item E) so internal/api's GET /settings/maintenance-page
// handler can surface the built-in default to the frontend — mirrors
// how the error-templates surface exposes its own built-in default
// (Step R Phase 2.1's virtual "arenet-default" template entry).
func DefaultMaintenancePageHTML() string {
	return arenetDefaultMaintenancePage
}
