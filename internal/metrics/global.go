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
	"sync"
	"sync/atomic"
)

// Process-wide Registry singleton (spec §3.4).
//
// Rationale: the Caddy middleware module (Chunk 2) is instantiated by
// Caddy from a JSON config and cannot receive arbitrary Go pointers
// through its struct fields. The module's Provision call reads
// GlobalRegistry() to obtain the *Registry installed by main() at
// startup.
//
// SetRegistry is guarded by sync.Once: the first successful call wins,
// subsequent calls are silent no-ops. This keeps startup robust if
// main() is refactored or a test mistakenly re-initializes.
var (
	globalOnce     sync.Once
	globalRegistry *Registry
)

// Step V.1.2 — process-wide NormalSubmitter + ClientIPFn
// singletons. Defaults are nil / fallback so the V.1
// branch in the middleware no-ops when V.1 is disabled
// (operator never set ARENET_NORMAL_TRAFFIC_SAMPLE_PCT,
// or set it to 0).
//
// V.1.3 install-order constraint: the geoBus + geoEnricher
// + DefaultNormalSink are constructed in cmd/arenet/main.go
// AFTER mgr.Start (the Caddy reload path needs an
// observability store, MMDB lookup, etc. that all live
// later in the boot sequence). So the Caddy module's
// Provision (which runs DURING mgr.Start) cannot cache
// the sink on the handler — at Provision time the global
// is still nil. To make late installation visible to
// already-provisioned handlers, the middleware re-reads
// the global on EVERY request via atomic.Pointer (the
// only sync primitive that gives lock-free reads on the
// hot path). SetNormalSubmitter writes through the same
// atomic; per-request reads are nanoseconds and the
// branch is short-circuited anyway when the value is nil.
//
// ClientIPFn follows the same pattern. main() can call
// SetClientIPFn at any point during boot; the next
// request reads the live value.
var (
	globalNormalSubmitter atomic.Pointer[NormalSubmitter]
	globalClientIPFn      atomic.Pointer[ClientIPFunc]
)

// SetRegistry installs the process-wide registry. Safe to call from
// any goroutine. Only the first call has effect; subsequent calls
// are silent no-ops.
//
// Called from cmd/arenet/main.go before caddymgr.Start, so that the
// Caddy module's Provision (which runs during Start's config apply)
// observes a non-nil registry.
func SetRegistry(r *Registry) {
	globalOnce.Do(func() {
		globalRegistry = r
	})
}

// GlobalRegistry returns the installed registry, or nil if SetRegistry
// was never called. Caddy module Provision callers check for nil and
// return a provisioning error in that case.
func GlobalRegistry() *Registry {
	return globalRegistry
}

// ResetForTest clears the singleton and the once. Tests that need a
// fresh registry per case call this in t.Cleanup. Tests-only by
// convention (no build tag — keeping the helper on the package's main
// build avoids a parallel test-only file just for one function).
func ResetForTest() {
	globalOnce = sync.Once{}
	globalRegistry = nil
	globalNormalSubmitter.Store(nil)
	globalClientIPFn.Store(nil)
}

// SetNormalSubmitter installs the V.1 normal-traffic sink.
// Safe to call from any goroutine. Re-callable (V.1.3 may
// swap the sink after mgr.Start has provisioned the Caddy
// modules — atomic.Pointer makes the swap immediately
// visible to all already-provisioned handlers).
//
// Pass nil to disable the V.1 branch in the middleware's
// defer.
func SetNormalSubmitter(s NormalSubmitter) {
	if s == nil {
		globalNormalSubmitter.Store(nil)
		return
	}
	globalNormalSubmitter.Store(&s)
}

// GlobalNormalSubmitter returns the currently-installed
// sink, or nil when V.1 is disabled / unset. Lock-free
// atomic load; safe on the per-request hot path.
func GlobalNormalSubmitter() NormalSubmitter {
	p := globalNormalSubmitter.Load()
	if p == nil {
		return nil
	}
	return *p
}

// SetClientIPFn installs the process-wide client-IP
// resolver. cmd/arenet wires this at boot using the
// auth.IPExtractor-backed function (trusted-proxy aware
// per ARENET_TRUSTED_PROXIES). When unset, GlobalClientIPFn
// falls back to RemoteAddrClientIPFn (port-stripped
// r.RemoteAddr) — degraded but safe; an operator on a
// homelab without reverse proxies sees correct IPs.
//
// Re-callable (same atomic.Pointer pattern as
// SetNormalSubmitter); installations after mgr.Start
// take effect on the next request.
func SetClientIPFn(fn ClientIPFunc) {
	if fn == nil {
		globalClientIPFn.Store(nil)
		return
	}
	globalClientIPFn.Store(&fn)
}

// GlobalClientIPFn returns the installed resolver, or the
// RemoteAddr fallback if SetClientIPFn was never called.
// Never returns nil — callers can invoke without a guard.
func GlobalClientIPFn() ClientIPFunc {
	p := globalClientIPFn.Load()
	if p == nil {
		return RemoteAddrClientIPFn
	}
	return *p
}
