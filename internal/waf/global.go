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

package waf

import "sync/atomic"

// Caddy provisions modules from JSON config; there is no
// constructor injection path. The module needs the EventSink
// at Provision time (to set up the per-instance error
// callback), so we mirror the Step E metrics.GlobalRegistry
// pattern: cmd/arenet/main.go sets the sink at boot via
// SetGlobalSink, the Caddy module reads it via getGlobalSink
// at Provision.
//
// Stored as atomic.Pointer for race-clean access (the boot
// sequence in main.go is single-threaded but the read happens
// from arbitrary goroutines once Caddy starts).
var globalSink atomic.Pointer[EventSink]

// SetGlobalSink installs the process-wide WAF event sink.
// Called once during boot (cmd/arenet/main.go) BEFORE
// caddymgr.Start so the first Provision call on the
// arenet_waf module sees a non-nil sink. Subsequent calls
// override the value — useful for tests, but never used in
// production.
//
// Passing nil is the AC #13 degraded-mode case (boot-failed
// observability subsystem); the Caddy module tolerates it
// and skips event emission while still enforcing the WAF
// block decision on the data plane.
func SetGlobalSink(s EventSink) {
	if s == nil {
		globalSink.Store(nil)
		return
	}
	globalSink.Store(&s)
}

// getGlobalSink returns the installed sink, or nil if none
// (degraded mode or test that did not call SetGlobalSink).
func getGlobalSink() EventSink {
	p := globalSink.Load()
	if p == nil {
		return nil
	}
	return *p
}
