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

package throttle

import "sync/atomic"

// Same pattern as internal/waf/global.go + metrics.Global
// Registry: the rate limiter (in internal/auth) is constructed
// at boot before any sink exists. Constructor injection isn't
// viable — the auth package would have to take a sink
// dependency it doesn't otherwise need, and the rate limiter
// already exists outside the sink's lifecycle (it predates
// Step Q).
//
// The exported name (vs the waf package's lowercase getter)
// is the small carve-out: internal/auth lives in a different
// package, needs a public accessor. internal/waf only reads
// its own global from its own package, so the lowercase
// helper sufficed.
var globalSink atomic.Pointer[EventSink]

// SetGlobalSink installs the process-wide throttle event sink.
// Called once during boot (cmd/arenet/main.go) BEFORE the
// rate limiter starts taking traffic. Subsequent calls
// override — useful for tests, never used in production.
//
// Passing nil is the AC #13 degraded-mode case (boot-failed
// observability subsystem); the rate limiter tolerates a nil
// sink (no event emission, slog.Warn line still fires on
// Tier 2 for operator-log retention).
func SetGlobalSink(s EventSink) {
	if s == nil {
		globalSink.Store(nil)
		return
	}
	globalSink.Store(&s)
}

// GetGlobalSink returns the installed sink, or nil if none.
// Called by internal/auth/ratelimit.go on every block
// decision. The nil check is the caller's responsibility:
//
//	if sink := throttle.GetGlobalSink(); sink != nil {
//	    sink.Emit(throttle.Event{...})
//	}
func GetGlobalSink() EventSink {
	p := globalSink.Load()
	if p == nil {
		return nil
	}
	return *p
}
