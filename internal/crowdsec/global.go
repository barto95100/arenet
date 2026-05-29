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

package crowdsec

import "sync/atomic"

// Same pattern as internal/waf/global.go + internal/throttle/
// global.go + metrics.Global Registry: the StreamBouncer
// consumer (in stream.go) is constructed at boot before the
// sink exists in all test scaffolds, AND main.go installs the
// sink via an atomic pointer so a future hot-reload of the
// observability subsystem could swap it without rebuilding
// the consumer. Constructor injection would couple the two
// lifecycles in a way that prevents that future flexibility.
//
// The exported name (vs the waf package's lowercase getter)
// is consistent with Q's throttle package: the consumer in
// stream.go reads it from the same package, but tests in
// other packages (e.g. integration tests) need a public
// accessor to install a fake.
var globalSink atomic.Pointer[EventSink]

// SetGlobalSink installs the process-wide CrowdSec decision
// sink. Called once during boot (cmd/arenet/main.go) BEFORE
// the StreamBouncer consumer starts polling. Subsequent calls
// override — useful for tests, never used in production.
//
// Passing nil is the AC #13 degraded-mode case (LAPI key not
// configured OR boot-failed observability subsystem). The
// StreamBouncer consumer tolerates a nil sink and runs as a
// no-op drain.
func SetGlobalSink(s EventSink) {
	if s == nil {
		globalSink.Store(nil)
		return
	}
	globalSink.Store(&s)
}

// GetGlobalSink returns the installed sink, or nil if none.
// Called by stream.go's poll loop on every {new, deleted}
// delta. The nil check is the caller's responsibility:
//
//	if sink := crowdsec.GetGlobalSink(); sink != nil {
//	    for _, d := range deltas.New {
//	        sink.Emit(...)
//	    }
//	}
func GetGlobalSink() EventSink {
	p := globalSink.Load()
	if p == nil {
		return nil
	}
	return *p
}
