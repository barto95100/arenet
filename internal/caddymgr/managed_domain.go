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

package caddymgr

import (
	"strings"

	"github.com/barto95100/arenet/internal/storage"
)

// IsHostCoveredByManagedDomain reports whether the given host is
// covered by any managed domain in mds. Returns the covering
// ManagedDomain on the first match, and a bool for the call-site
// readability ("if md, ok := ...; ok { ... }").
//
// Coverage rules (Step O spec §3.2, RFC 6125 §6.4.3):
//
//   - host `app.example.com` is covered by managed domain
//     `example.com` iff host has exactly ONE more label than the
//     apex (the single-label wildcard rule).
//   - host `deep.app.example.com` is NOT covered by
//     `example.com` — wildcards cover one label, not many.
//   - host `example.com` (bare apex) is covered by managed
//     domain `example.com` iff md.IncludeApex == true
//     (spec D2.C operator toggle).
//   - host `*.example.com` (the wildcard itself, as a route
//     host) is NOT covered — the wildcard form is what the
//     managed domain emits, not what it consumes. A route that
//     wants to serve `*.example.com` directly is opting out of
//     the managed-domain model and should declare its own
//     dns-01 issuance (per-route).
//
// Case + trailing-dot normalisation (DNS is case-insensitive,
// trailing dot is RFC 1035 canonical form): both the host and
// the apex are lowercased + trailing-dot-stripped before the
// suffix compare. The host `App.Example.Com.` therefore matches
// a stored apex `example.com`.
//
// Empty mds → returns (zero, false) for every host. This is the
// spec D5.A short-circuit invariant the byte-equality test pins:
// when no managed domains are declared, this function is a no-op
// and caddymgr's build path emits Step-J-equivalent JSON.
//
// Pure function. Called from FOUR sites per spec §3.2:
//  1. caddymgr at config-build time (wildcard vs per-route TLS).
//  2. api/routes.go for the effectiveCertSource response field.
//  3. api/routes.go validation (rejecting bad ACMEChallenge values).
//  4. api/managed_domain_handlers.go for the on-create migration.
func IsHostCoveredByManagedDomain(host string, mds []storage.ManagedDomain) (storage.ManagedDomain, bool) {
	if len(mds) == 0 || host == "" {
		return storage.ManagedDomain{}, false
	}
	h := normalizeHost(host)
	if h == "" {
		return storage.ManagedDomain{}, false
	}
	// Wildcard route-host is not covered (see doc comment). Bail
	// before the suffix loop so we don't match `*.example.com`
	// against managed `example.com` — that direction is wrong.
	if strings.HasPrefix(h, "*.") {
		return storage.ManagedDomain{}, false
	}
	for _, md := range mds {
		apex := storage.NormalizeApex(md.Apex)
		if apex == "" {
			continue
		}
		// Bare apex case (spec D2.C).
		if h == apex {
			if md.IncludeApex {
				return md, true
			}
			continue
		}
		// Single-label wildcard case: h must end in "."+apex,
		// AND the prefix (everything before that suffix) must
		// be exactly ONE DNS label (no dots).
		suffix := "." + apex
		if !strings.HasSuffix(h, suffix) {
			continue
		}
		prefix := strings.TrimSuffix(h, suffix)
		if prefix == "" {
			// Impossible at this point (h != apex was checked
			// above), but defensive.
			continue
		}
		if strings.Contains(prefix, ".") {
			// Multi-label depth — `deep.app.example.com` vs
			// apex `example.com` yields prefix `deep.app`,
			// which contains a dot. Not covered per RFC 6125.
			continue
		}
		// Single-label prefix matches a single-label wildcard.
		return md, true
	}
	return storage.ManagedDomain{}, false
}

// normalizeHost canonicalises a route host for comparison: strip
// the trailing dot (RFC 1035), lowercase. Same shape as
// storage.NormalizeApex but kept private to caddymgr because the
// host-side normalisation is a different concern (route hosts
// can be wildcards; apexes can't) and the symmetry is
// non-obvious.
func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}
