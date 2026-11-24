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

// Package errorvars provides the arenet_error_vars Caddy middleware
// handler (#367). It injects HTML-escaped request fields into the
// per-request Replacer under the {arenet.request.*} namespace so an
// operator's error-page template can display the host and path
// SAFELY — without the reflected-XSS exposure that gates the raw
// {http.request.*} placeholders behind the F42 defang
// (internal/caddymgr/error_pages.go:neutralizeDangerousPlaceholders).
//
// Deliberately NOT the Caddy templates handler
// (modules/caddyhttp/templates): that handler executes the response
// body as a Go template whose FuncMap exposes env / readFile /
// httpInclude / listFiles + the full sprig map (verified against
// Caddy v2.11.9, tplcontext.go:80-93 + :599). Running
// operator-authored error-page bodies through it would trade an
// XSS-defang for secret-exfil + LFI + SSRF. This module adds ONLY a
// tiny, fixed set of pre-escaped placeholder values and runs no
// template engine at all. See
// docs/superpowers/decisions + the #367 reframe.
package errorvars

import (
	"html"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	// ModuleID is the Caddy module identifier emitted by caddymgr
	// in the error-route handler chain.
	ModuleID = "http.handlers.arenet_error_vars"

	// HandlerName is the short handler name used in the emitted
	// Caddy JSON ("handler": HandlerName). Referenced from
	// internal/caddymgr so this package is pulled in for its
	// init()-time RegisterModule (mirror of countryblock).
	HandlerName = "arenet_error_vars"

	// PlaceholderHost / PlaceholderPath are the Replacer keys set
	// by this handler. Operators reference them as
	// {arenet.request.host} / {arenet.request.path} in a template.
	PlaceholderHost = "arenet.request.host"
	PlaceholderPath = "arenet.request.path"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is the arenet_error_vars middleware. It carries no config
// (no FuncMap, no fields): its sole job is to set the escaped
// {arenet.request.*} keys on the request Replacer and pass control
// to the next handler (the static_response that renders the page).
type Handler struct{}

// CaddyModule returns the module info. Value receiver: Caddy calls
// this on a zero value to discover the type (mirror of
// countryblock.Handler.CaddyModule).
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  ModuleID,
		New: func() caddy.Module { return new(Handler) },
	}
}

// ServeHTTP sets the HTML-escaped {arenet.request.host} and
// {arenet.request.path} values on the per-request Replacer, then
// calls next (the static_response that renders the error body and
// expands the placeholders via ReplaceKnown).
//
// html.EscapeString escapes < > & ' " and leaves every other byte
// untouched, so UTF-8 hosts/paths (IDN, non-ASCII) survive intact
// while attacker-controlled HTML metacharacters cannot break out of
// the surrounding markup — the whole point vs the raw, F42-defanged
// {http.request.*} placeholders.
//
// Defensive: if no Replacer is in context (should never happen on a
// real Caddy request, but keeps the handler panic-free in isolation)
// the handler is a transparent pass-through.
func (h *Handler) ServeHTTP(
	w http.ResponseWriter, r *http.Request, next caddyhttp.Handler,
) error {
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok && repl != nil {
		repl.Set(PlaceholderHost, html.EscapeString(r.Host))
		repl.Set(PlaceholderPath, html.EscapeString(r.URL.Path))
	}
	return next.ServeHTTP(w, r)
}

// Interface guard: Handler is a Caddy HTTP middleware.
var _ caddyhttp.MiddlewareHandler = (*Handler)(nil)
