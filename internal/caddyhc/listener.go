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

package caddyhc

import (
	"context"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// CaddyModuleID is the identifier the Caddy registry uses for the
// arenet_topology_hc handler. The "events.handlers." namespace is
// the one the events App looks in when resolving Subscription
// `handlers` array entries (see caddyevents/app.go and the inline
// `caddy:"namespace=events.handlers"` struct tag).
const CaddyModuleID = "events.handlers.arenet_topology_hc"

// init registers the handler module with the Caddy registry. Caddy
// only sees module IDs that have been registered by import-time;
// the caddymgr package side-effect-imports this package so the
// registration happens before any caddy.Load call.
func init() {
	caddy.RegisterModule(EventHandler{})
}

// trackerSingleton is the package-level pointer the handler
// module's Handle method delegates into. Set once at process start
// by main via SetTracker. The singleton is necessary because the
// handler is instantiated by Caddy (via JSON unmarshal during
// Provision) and there is no JSON-config path to inject a Go
// reference — the module body is empty JSON.
//
// Concurrency: SetTracker may race with Handle in theory if main
// were to swap the tracker mid-run. We don't do that today (one
// tracker per process lifetime), but the mutex keeps the read
// safe regardless.
var (
	trackerMu        sync.RWMutex
	trackerSingleton *HCStatusTracker
)

// SetTracker installs the process-wide tracker the event handler
// module delegates into. Called from cmd/arenet during init,
// BEFORE the caddymgr emits a config that references the
// arenet_topology_hc handler.
//
// Passing nil clears the singleton — useful for tests that want
// to assert isolation between cases. The handler treats a nil
// singleton as "no tracker available, drop event silently" rather
// than returning an error: a missing tracker should not break
// Caddy's event dispatch.
func SetTracker(t *HCStatusTracker) {
	trackerMu.Lock()
	trackerSingleton = t
	trackerMu.Unlock()
}

// getTracker returns the current singleton (may be nil).
func getTracker() *HCStatusTracker {
	trackerMu.RLock()
	defer trackerMu.RUnlock()
	return trackerSingleton
}

// EventHandler is the caddyevents.Handler module that translates
// "healthy"/"unhealthy" events into tracker state changes.
//
// Carries no JSON-configurable state. The tracker reference comes
// from the package-level singleton; the logger is captured during
// Provision (Nop fallback if Caddy hands us nil) so future debug
// emission can be re-enabled without restructuring the module.
// Keeping the logger field even when we don't emit at runtime
// pays the cost once (single field, set in Provision) and avoids
// re-dipping into Caddy's global logger any time we DO want to
// log — operator-runnable diagnostics are one line away.
type EventHandler struct {
	logger *zap.Logger
}

// CaddyModule satisfies caddy.Module so RegisterModule accepts us.
func (EventHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  CaddyModuleID,
		New: func() caddy.Module { return new(EventHandler) },
	}
}

// Provision captures the Caddy-context logger for future
// diagnostics. The tracker singleton is installed by main before
// caddy.Load runs, so it's reliably non-nil by the time Provision
// fires; we don't surface that here, but a future debug pass can
// log it without taking new dependencies.
//
// Returns nil unconditionally — Provision has no failure path the
// caller can act on, and a failing Provision would tear down the
// whole subscription.
func (h *EventHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.logger == nil {
		h.logger = zap.NewNop()
	}
	return nil
}

// Handle is invoked once per matching event. The caddyevents App
// calls Handle synchronously from its dispatch goroutine — we
// must NOT block. The current implementation only acquires the
// tracker's RWMutex briefly to record the new state, which is
// well within "don't block" tolerances.
//
// Returning an error from Handle causes the events App to log it
// but does not stop subsequent handlers. We return nil even on
// missing/malformed payload because event-source contracts can
// shift with Caddy versions and we'd rather degrade silently
// than spam Caddy's error log on every probe.
func (h *EventHandler) Handle(_ context.Context, e caddy.Event) error {
	t := getTracker()
	if t == nil {
		return nil
	}
	host, ok := extractHost(e.Data)
	if !ok {
		return nil
	}
	switch e.Name() {
	case "healthy":
		t.RecordHealthy(host)
	case "unhealthy":
		t.RecordUnhealthy(host)
	default:
		// Subscription filters on these two names, but be defensive:
		// an unexpected event name is a no-op, not an error.
	}
	return nil
}

// extractHost reads the "host" key from a Caddy event payload.
// Returns ("", false) when the field is missing or not a string —
// future-proof against payload-shape changes.
func extractHost(data map[string]any) (string, bool) {
	if data == nil {
		return "", false
	}
	raw, ok := data["host"]
	if !ok {
		return "", false
	}
	host, ok := raw.(string)
	if !ok {
		return "", false
	}
	return host, true
}

// Compile-time interface guards. caddyevents.Handler is the
// public type the Caddy events App expects; caddy.Provisioner is
// optionally honored during Provision. We duplicate the
// single-method Handler interface here to avoid taking an import
// dependency on modules/caddyevents just for the guard.
//
// Both interfaces are satisfied by *EventHandler (pointer
// receivers) since Provision mutates the struct (stores the
// logger). Caddy's CaddyModule.New returns a *EventHandler, so
// the runtime instance is always addressable.
type handlerLike interface {
	Handle(context.Context, caddy.Event) error
}

var (
	_ handlerLike       = (*EventHandler)(nil)
	_ caddy.Provisioner = (*EventHandler)(nil)
)
