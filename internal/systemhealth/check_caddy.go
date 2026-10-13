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

package systemhealth

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ReloadStater reports the health of Caddy config reloads.
// Satisfied by *caddymgr.CaddyManager.
type ReloadStater interface {
	ReloadHealth() (started bool, inFlight time.Duration, timedOut bool)
	// LastReloadFailure reports the most recent reload Caddy rejected,
	// and when. Empty message = the last completed reload was accepted.
	LastReloadFailure() (msg string, at time.Time)
}

// maxReloadErrorChars caps the Caddy error quoted in the health
// message. Provisioning errors can run to several lines, and this
// string is rendered in a status card.
const maxReloadErrorChars = 200

// truncateReloadError keeps the head of msg, which is where Caddy puts
// the failing module and reason.
func truncateReloadError(msg string) string {
	msg = strings.TrimSpace(strings.ReplaceAll(msg, "\n", " "))
	if len(msg) <= maxReloadErrorChars {
		return msg
	}
	return msg[:maxReloadErrorChars] + "…"
}

// stuckReloadThreshold is how long a config reload may run before the
// check reports it as stuck. Normal reloads take milliseconds to a few
// seconds (ACME / DNS provisioning included).
const stuckReloadThreshold = 15 * time.Second

// CaddyCheck reports whether the embedded Caddy accepts config reloads.
//
// v2.26: it used to GET Caddy's admin API /config/ on 127.0.0.1:2019
// to detect a deadlocked config mutex (#R-CADDY-ADMIN-DEADLOCK).
// That API is now disabled (it exposed every secret, unauthenticated),
// so the same condition is read from the reload state Arenet keeps:
// a caddy.Load stuck on that mutex shows up as a reload in flight for
// too long, or as the last reload having timed out.
type CaddyCheck struct {
	// Reloads is the reload-state source. nil → unhealthy
	// ("not wired").
	Reloads ReloadStater
}

// Name implements ComponentCheck.
func (c *CaddyCheck) Name() string { return "caddy" }

// Check implements ComponentCheck.
func (c *CaddyCheck) Check(_ context.Context) ComponentStatus {
	if c.Reloads == nil {
		return ComponentStatus{Status: StatusUnhealthy, Message: "caddy manager not wired"}
	}
	started, inFlight, timedOut := c.Reloads.ReloadHealth()
	switch {
	case !started:
		return ComponentStatus{Status: StatusUnhealthy, Message: "caddy not started"}
	case inFlight > stuckReloadThreshold:
		return ComponentStatus{
			Status:  StatusUnhealthy,
			Message: fmt.Sprintf("config reload stuck for %s", inFlight.Round(time.Second)),
		}
	case timedOut:
		return ComponentStatus{Status: StatusDegraded, Message: "last config reload timed out"}
	}
	// v2.72 — a reload Caddy REJECTED used to land here and be reported
	// as healthy. The goroutine that runs the apply clears timedOut
	// whatever the apply returned, so a rejection was indistinguishable
	// from a clean run, and several handlers answer 200 on a failed
	// reload by design (the store write is committed; undoing it would
	// be worse). The operator got a success toast, a UI reading back the
	// new value, and an edge still running the old config — with this
	// check affirming health on top.
	//
	// Degraded, not unhealthy: the previous config is still being
	// served, so Arenet is up. What is wrong is that it is not serving
	// what the store says.
	if msg, _ := c.Reloads.LastReloadFailure(); msg != "" {
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "last config reload failed: " + truncateReloadError(msg),
		}
	}
	return ComponentStatus{Status: StatusHealthy, Message: "config reloads healthy"}
}
