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

// Package caddyhc bridges Caddy's active-health-checker events into
// AreNET's topology snapshot. Caddy v2's reverse proxy emits two
// state-transition events through its events App (modules/caddyhttp/
// reverseproxy/healthchecks.go:479, :502):
//
//	source module: http.handlers.reverse_proxy.health_checker
//	events:        "healthy", "unhealthy"
//	payload:       map[string]any{"host": "10.0.4.12:8080"}
//
// We subscribe to those via a Caddy event-handler module
// (events.handlers.arenet_topology_hc) registered into the emitted
// Caddy JSON config. The handler delegates to a package-level
// HCStatusTracker singleton, which the topology snapshot builder
// reads from per upstream.
//
// The Caddy events API rejects subscriptions after the events App
// has started, so the handler module MUST be wired into the JSON
// the caddymgr emits — it can't be attached programmatically
// post-Load.
//
// Closes #R-TOPO-real-health-probe (the Stage B follow-up flagged
// during the v1.1.0 C6a turn).
package caddyhc

import (
	"strings"
	"sync"
)

// Status mirrors the three states the topology layer cares about.
// Defined here as untyped strings so this package depends on
// nothing topology-internal — the topology builder maps these to
// its own typed HealthStatus when projecting the snapshot.
//
// The choice of "" as the zero value for unknown matters: it lets
// callers do `if t.Status(addr) == "" { ... }` without needing a
// sentinel, and Status() returns "" by default for any address
// the tracker hasn't seen an event for yet (warm-up case).
const (
	StatusHealthy   = "healthy"
	StatusUnhealthy = "unhealthy"
	StatusUnknown   = "" // zero value — no event observed yet
)

// HCStatusTracker is the in-memory source of truth for per-upstream
// health status, populated by the Caddy events handler module.
//
// Concurrency: every method is safe for concurrent use. Status()
// is in the hot path of the topology snapshot builder (called once
// per upstream per emit tick), so the lock is an RWMutex with the
// reads taking the read lock. Writes from Caddy event handlers are
// in-process and never block reads beyond the brief map mutation.
type HCStatusTracker struct {
	mu       sync.RWMutex
	statuses map[string]string // normalized addr -> Status*
}

// NewTracker returns an empty tracker. The tracker carries no
// configuration — every address starts in StatusUnknown until the
// first event for it arrives. Caller is expected to register the
// tracker with the package-level singleton (SetTracker) so the
// Caddy event-handler module can find it during Provision.
func NewTracker() *HCStatusTracker {
	return &HCStatusTracker{
		statuses: make(map[string]string),
	}
}

// RecordHealthy marks an upstream healthy. Called by the Caddy
// event handler when a `"healthy"` event arrives. addr is the
// raw "host" field from the event payload — RecordHealthy calls
// NormalizeAddr on it to match the storage representation the
// topology builder will query with.
func (t *HCStatusTracker) RecordHealthy(addr string) {
	t.set(addr, StatusHealthy)
}

// RecordUnhealthy is the failure-side counterpart of RecordHealthy.
func (t *HCStatusTracker) RecordUnhealthy(addr string) {
	t.set(addr, StatusUnhealthy)
}

func (t *HCStatusTracker) set(addr, status string) {
	key := NormalizeAddr(addr)
	if key == "" {
		return // refuse to record garbage — protects the map from "" keys
	}
	t.mu.Lock()
	t.statuses[key] = status
	t.mu.Unlock()
}

// Reset clears every recorded per-upstream status, restoring the
// tracker to the same observable state as a freshly-built one
// (every address returns StatusUnknown until the next event).
//
// Called by the Caddy config manager BEFORE each caddy.Load.
//
// Why this exists — empirical Caddy v2.11.3
// reverseproxy/healthchecks.go:478,498 + hosts.go:251-264:
// "healthy"/"unhealthy" events fire only on state TRANSITIONS via
// the Upstream.setHealthy atomic CompareAndSwap. New Upstream Go
// objects created at reload default to healthy (unhealthy = 0).
// The first probe success therefore CASes 0→0, returns false, and
// no event is emitted. Without this Reset, the tracker keeps its
// pre-reload value (often "unhealthy" from a failed-probe history)
// forever — UI badge stuck DOWN even when the upstream is now
// answering 2xx. After Reset, the badge falls back to the gray
// warm-up state (routeStatusUnknown) and converges on the next
// real transition.
//
// Concurrency: acquires the write lock briefly. Topology readers
// see either the pre-reset map or an empty map — both are safe
// interpretations; the next probe event repopulates whichever
// addresses Caddy now cares about.
func (t *HCStatusTracker) Reset() {
	t.mu.Lock()
	t.statuses = make(map[string]string)
	t.mu.Unlock()
}

// Status returns the last-known state for an upstream, or
// StatusUnknown ("") if no event has been observed for it yet.
// Called by the topology snapshot builder per upstream per emit.
func (t *HCStatusTracker) Status(addr string) string {
	key := NormalizeAddr(addr)
	if key == "" {
		return StatusUnknown
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.statuses[key]
}

// NormalizeAddr strips scheme + path/query/fragment from an
// upstream URL so the lookup key matches Caddy's event payload
// format (Caddy emits "host:port", e.g. "10.0.4.12:8080", via
// addr.JoinHostPort(0) at healthchecks.go:347).
//
// Mirrors the strip rules previously used by the deprecated
// CaddyStatusProber: http://, https://, h2://, h2c://.
// Exported because both the events handler (which receives raw
// payload strings from Caddy) and the topology builder (which
// receives storage-shaped strings like "http://10.0.4.12:8080")
// need to produce the same key.
func NormalizeAddr(raw string) string {
	s := raw
	// Strip scheme.
	for _, prefix := range []string{"http://", "https://", "h2c://", "h2://"} {
		if strings.HasPrefix(s, prefix) {
			s = s[len(prefix):]
			break
		}
	}
	// Strip path/query/fragment — anything past the authority.
	for _, sep := range []byte{'/', '?', '#'} {
		if i := strings.IndexByte(s, sep); i >= 0 {
			s = s[:i]
		}
	}
	return s
}
