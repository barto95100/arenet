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

import "sync"

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
// singletons. Same rationale as globalRegistry: the Caddy
// module is provisioned from JSON config and cannot
// receive Go pointers through its struct fields. main()
// installs both before caddymgr.Start so the module's
// Provision (which runs during Start's config apply)
// observes non-nil values.
//
// Both default to safe no-op behavior when unset:
//   - GlobalNormalSubmitter()   → nil → middleware's defer
//     sees normalSink==nil and
//     skips the V.1 branch.
//   - GlobalClientIPFn()        → fallback closure that
//     strips r.RemoteAddr's
//     port (no trusted-proxy
//     awareness; degraded but
//     safe).
//
// V.1.3 installs the real values from cmd/arenet/main.go.
var (
	globalNormalSubmitter NormalSubmitter
	globalNormalMu        sync.RWMutex

	globalClientIPFn   ClientIPFunc
	globalClientIPOnce sync.Once
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
	globalNormalMu.Lock()
	globalNormalSubmitter = nil
	globalNormalMu.Unlock()
	globalClientIPOnce = sync.Once{}
	globalClientIPFn = nil
}

// SetNormalSubmitter installs the V.1 normal-traffic sink.
// Safe to call from any goroutine. Re-callable (unlike
// SetRegistry) — V.1.3's wiring may swap the sink on a
// runtime config reload in a future increment, so the
// once-only guard isn't appropriate.
//
// Pass nil to disable the V.1 branch in the middleware's
// defer (the resolver below returns nil → the middleware
// short-circuits).
func SetNormalSubmitter(s NormalSubmitter) {
	globalNormalMu.Lock()
	globalNormalSubmitter = s
	globalNormalMu.Unlock()
}

// GlobalNormalSubmitter returns the installed sink, or nil
// when V.1 is disabled / unset. The Caddy module's
// Provision call reads this once and stores the result on
// the handler; per-request reads from a non-mutable field
// avoid the lock on the hot path.
func GlobalNormalSubmitter() NormalSubmitter {
	globalNormalMu.RLock()
	defer globalNormalMu.RUnlock()
	return globalNormalSubmitter
}

// SetClientIPFn installs the process-wide client-IP
// resolver. cmd/arenet wires this once at boot using the
// auth.IPExtractor-backed function (trusted-proxy aware
// per ARENET_TRUSTED_PROXIES). When unset, the middleware
// falls back to RemoteAddrClientIPFn (port-stripped
// r.RemoteAddr) — degraded but safe; an operator on a
// homelab without reverse proxies sees correct IPs.
//
// sync.Once: same single-shot guard as SetRegistry, for
// the same reason (boot wiring is single-shot;
// re-installing would be a programmer error).
func SetClientIPFn(fn ClientIPFunc) {
	globalClientIPOnce.Do(func() {
		globalClientIPFn = fn
	})
}

// GlobalClientIPFn returns the installed resolver, or the
// RemoteAddr fallback if SetClientIPFn was never called.
// Never returns nil — callers can invoke without a guard.
func GlobalClientIPFn() ClientIPFunc {
	if fn := globalClientIPFn; fn != nil {
		return fn
	}
	return RemoteAddrClientIPFn
}
