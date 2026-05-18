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
}
