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

package ratelimit

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// HandlerModuleID is the Caddy module ID for the events
// handler that captures rate_limit_exceeded emits.
const HandlerModuleID = "events.handlers.arenet_ratelimit_sink"

// EventName is the upstream caddy-ratelimit event the
// handler subscribes to. Verified empirically against
// mholt/caddy-ratelimit@v0.1.0 handler.go:232.
const EventName = "rate_limit_exceeded"

// zoneNamePrefix matches Step Q's caddymgr emit
// convention (manager.go:buildRateLimitHandler). The
// handler strips this prefix to recover the route UUID
// for the captured Event.RouteID. A zone whose name
// doesn't start with this prefix lands with RouteID == ""
// and the zone string preserved verbatim — forensic
// fallback for operator-hand-crafted Caddy configs that
// bypass Arenet's emit path.
const zoneNamePrefix = "route-"

// EventsHandler is the Caddy events.handler module that
// subscribes to the upstream caddy-ratelimit
// rate_limit_exceeded events and forwards each one to
// Arenet's package-level sink for SQLite persistence.
//
// Caddy instantiates this module via the events app's
// JSON subscription (caddymgr emits the wiring at
// manager.go's app section ; see emitEventsAppConfig).
// The Handle method runs synchronously on Caddy's event-
// dispatch goroutine — must be quick. Sink.Emit is a
// channel send so the synchronous path stays sub-µs.
type EventsHandler struct {
	logger *slog.Logger
}

// CaddyModule satisfies caddy.Module.
func (EventsHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  HandlerModuleID,
		New: func() caddy.Module { return new(EventsHandler) },
	}
}

// Provision is called once per handler instance after JSON
// config decode.
func (h *EventsHandler) Provision(_ caddy.Context) error {
	h.logger = slog.Default()
	return nil
}

// Handle is invoked by Caddy's events app on every
// matching event. The events app applies our subscription's
// Events / Modules filter BEFORE calling here, so we trust
// the event name is rate_limit_exceeded — defensive check
// kept anyway in case a future subscription change widens
// the scope.
func (h *EventsHandler) Handle(ctx context.Context, evt caddy.Event) error {
	if evt.Name() != EventName {
		return nil
	}
	sink := GetGlobalSink()
	if sink == nil {
		// AC #13 degraded-mode case : observability didn't
		// boot. The event is dropped at the sink boundary,
		// not at the handler — operator still sees the 429
		// in Caddy's zap log.
		return nil
	}

	data := evt.Data
	zone, _ := data["zone"].(string)
	remoteIP, _ := data["remote_ip"].(string)
	// Wait is emitted as time.Duration by upstream
	// (caddy-ratelimit handler.go:217 uses zap.Duration).
	// Caddy's events app marshals Data through JSON for
	// the CloudEvent wire shape ; in-process the Handle
	// receives the original interface{} values though so
	// we get a real time.Duration here.
	var waitMs int64
	if d, ok := data["wait"].(time.Duration); ok {
		waitMs = d.Milliseconds()
	}

	sink.Emit(Event{
		Ts:       evt.Timestamp(),
		RouteID:  routeIDFromZone(zone),
		Zone:     zone,
		RemoteIP: remoteIP,
		WaitMs:   waitMs,
	})
	return nil
}

// routeIDFromZone extracts the route UUID from the zone
// name when it matches Step Q's "route-<UUID>" convention.
// Returns "" for zone strings that don't match (operator-
// hand-crafted Caddy config) — the Event still persists
// with RouteID == "" so the per-route counter wiring
// skips it cleanly and the /logs Activity log row
// renders without a route attribution.
func routeIDFromZone(zone string) string {
	if !strings.HasPrefix(zone, zoneNamePrefix) {
		return ""
	}
	return zone[len(zoneNamePrefix):]
}

func init() {
	caddy.RegisterModule(EventsHandler{})
}
