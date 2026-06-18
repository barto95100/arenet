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

import "sync/atomic"

// Same pattern as internal/throttle/global.go and
// internal/waf/global.go : the Caddy events.handler module
// is instantiated by Caddy at config-load time, BEFORE
// any sink could be passed via constructor. The handler
// reads the global sink on every Handle() call.
//
// Lifecycle :
//   1. cmd/arenet/main.go boots observability + creates *Sink.
//   2. SetGlobalSink(*Sink) installed.
//   3. caddymgr applies Caddy config including the events
//      app subscription pointing at events.handlers.
//      arenet_ratelimit_sink.
//   4. Caddy provisions the handler module, which reads the
//      global sink on every event Handle.
//   5. mholt/caddy-ratelimit emits rate_limit_exceeded →
//      handler.Handle → sink.Emit → batch insert.
//
// Setting nil = AC #13 degraded-mode (boot-failed
// observability) ; the handler module tolerates nil and
// skips persistence without erroring.

var globalSink atomic.Pointer[EventSink]

// SetGlobalSink installs the process-wide rate-limit event
// sink. Called once during boot (cmd/arenet/main.go) BEFORE
// Caddy starts taking traffic.
func SetGlobalSink(s EventSink) {
	if s == nil {
		globalSink.Store(nil)
		return
	}
	globalSink.Store(&s)
}

// GetGlobalSink returns the installed sink, or nil if none.
func GetGlobalSink() EventSink {
	p := globalSink.Load()
	if p == nil {
		return nil
	}
	return *p
}
