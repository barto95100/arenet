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

package metrics

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Per spec §3.1 and §3.5: dotted module ID for Caddy's internal
// module system, plain handler name for the JSON config.
const (
	// ModuleID is the full dotted module identifier registered with
	// Caddy. Spec §3.1.
	ModuleID = "http.handlers.arenet_routemetrics"

	// HandlerName is the last segment of ModuleID, used as the
	// "handler" string in Caddy JSON config (spec §3.5). Mixing forms
	// (passing ModuleID instead of HandlerName in JSON) silently
	// fails Caddy config load with an "unknown handler" error.
	HandlerName = "arenet_routemetrics"
)

// ErrRegistryNotInstalled is returned by Provision when no Registry
// has been installed via SetRegistry. Indicates a programmer error
// in main(): the wiring order must be NewRegistry → SetRegistry →
// caddymgr.Start. Exported so tests can match with errors.Is.
var ErrRegistryNotInstalled = errors.New(
	"metrics: registry not installed; call SetRegistry before caddymgr.Start",
)

func init() {
	caddy.RegisterModule(RouteMetricsHandler{})
}

// RouteMetricsHandler is the Caddy middleware module that counts
// requests per route (spec §3). Caddy provisions one instance per
// route from the JSON config produced by internal/caddymgr; each
// instance carries its own RouteID. Provision fetches the
// process-wide *Registry via the package-level singleton (spec §3.4).
type RouteMetricsHandler struct {
	// RouteID is the storage UUID of the route this handler is
	// attached to. Set from JSON config. Required (Validate rejects
	// empty).
	RouteID string `json:"route_id,omitempty"`

	// registry is resolved at Provision time. Not serialized: Caddy
	// instantiates modules from JSON and cannot inject Go pointers
	// (spec §3.4).
	registry *Registry
}

// CaddyModule returns the module info. Required by the Caddy module
// interface. Value receiver because Caddy calls this on a zero
// value to discover the type.
func (RouteMetricsHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  ModuleID,
		New: func() caddy.Module { return new(RouteMetricsHandler) },
	}
}

// Provision is called once per handler instance after the JSON
// config is loaded and before Validate. Resolves the process-wide
// Registry or returns ErrRegistryNotInstalled.
func (h *RouteMetricsHandler) Provision(_ caddy.Context) error {
	r := GlobalRegistry()
	if r == nil {
		return ErrRegistryNotInstalled
	}
	h.registry = r
	return nil
}

// Validate checks the resolved configuration. Rejects empty RouteID
// (spec §3.1): a handler with no RouteID would silently miscount
// every request as belonging to "" in the registry map.
func (h *RouteMetricsHandler) Validate() error {
	if h.RouteID == "" {
		return errors.New(
			"metrics: route_id is required on arenet_routemetrics handler",
		)
	}
	return nil
}

// ServeHTTP wraps the response writer in a statusRecorder, defers
// the counter increment so it observes the final status code, then
// dispatches to the next handler in the chain (typically
// reverse_proxy). Spec §3.3.
//
// The defer uses a closure rather than a direct call so the status
// code is read AFTER next.ServeHTTP has returned. A direct
// `defer h.registry.Inc(h.RouteID, rec.status)` would capture the
// default 200 at defer time, losing every non-200 status.
//
// Status code 0 (handler returned an error before any WriteHeader
// or Write call) is recorded as 200 per spec §11.6 — matches
// Caddy's implicit-OK semantics for empty responses.
func (h *RouteMetricsHandler) ServeHTTP(
	w http.ResponseWriter, r *http.Request, next caddyhttp.Handler,
) error {
	rec := newStatusRecorder(w)
	start := time.Now()
	defer func() {
		durMs := float64(time.Since(start).Microseconds()) / 1000.0
		h.registry.Inc(h.RouteID, rec.status, durMs)
	}()
	return next.ServeHTTP(rec, r)
}

// Interface guards: compile-time assertions of the Caddy interfaces
// we implement. If Caddy's API changes incompatibly, this breaks at
// compile time rather than at first request.
var (
	_ caddy.Provisioner           = (*RouteMetricsHandler)(nil)
	_ caddy.Validator             = (*RouteMetricsHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*RouteMetricsHandler)(nil)
)

// --- statusRecorder --------------------------------------------------------

// statusRecorder wraps an http.ResponseWriter to remember the status
// code written by an inner handler. Forwards Hijacker / Flusher /
// Pusher to the wrapped writer when supported; degrades gracefully
// (ErrNotSupported / no-op) otherwise — spec §3.3.
//
// Default status is http.StatusOK to match Caddy's implicit-OK
// behavior when the inner handler returns without explicitly setting
// a status code (spec §11.6).
type statusRecorder struct {
	http.ResponseWriter
	status        int
	headerWritten bool
}

func newStatusRecorder(w http.ResponseWriter) *statusRecorder {
	return &statusRecorder{
		ResponseWriter: w,
		status:         http.StatusOK,
	}
}

// WriteHeader captures the status code on the first call. Subsequent
// calls follow the http.ResponseWriter contract (Go stdlib emits a
// "superfluous WriteHeader" log on double calls); we mirror that by
// keeping the first status and forwarding only the first call.
func (s *statusRecorder) WriteHeader(code int) {
	if s.headerWritten {
		// Per Go contract, subsequent WriteHeader calls are no-ops on
		// the wire. Forward anyway so the underlying writer can log
		// "superfluous" if it wishes.
		s.ResponseWriter.WriteHeader(code)
		return
	}
	s.status = code
	s.headerWritten = true
	s.ResponseWriter.WriteHeader(code)
}

// Write implies WriteHeader(200) if WriteHeader has not been called
// (per net/http contract). We mark headerWritten so a later explicit
// WriteHeader is treated as superfluous, matching stdlib behavior.
func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.headerWritten {
		s.headerWritten = true
		// status already 200 from newStatusRecorder.
	}
	return s.ResponseWriter.Write(b)
}

// Hijack forwards to the wrapped writer if it supports Hijacker, else
// returns http.ErrNotSupported. WebSocket upgrades through proxied
// routes need this path; without it, gorilla/websocket Upgrade
// would error out at our handler.
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Flush forwards if supported, else no-op. SSE handlers under a
// proxied route would call Flush; we must not panic on a writer that
// does not support it.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Push forwards if supported (HTTP/2 server push), else returns
// http.ErrNotSupported. Caddy passes through writers that may or may
// not implement Pusher depending on the request's protocol.
func (s *statusRecorder) Push(target string, opts *http.PushOptions) error {
	if p, ok := s.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

// Status returns the recorded status code. After ServeHTTP returns,
// this is the final status the client will see (or http.StatusOK if
// the handler emitted no explicit code).
func (s *statusRecorder) Status() int {
	return s.status
}
