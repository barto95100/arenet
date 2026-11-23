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

package allowlist

import (
	"context"
	"net/netip"
	"strings"
	"sync/atomic"
)

// Category is the allowlist scope bucket. It mirrors automation.Category
// but is defined here independently so the automation package takes no
// dependency on this one (the cmd adapter maps between them).
type Category string

const (
	CategoryBlock    Category = "block"
	CategoryThrottle Category = "throttle"
	CategoryAudit    Category = "audit"
)

// resolvedSet is an immutable snapshot of the active allowlist prefixes,
// bucketed by category. Swapped atomically on Rebuild so the hot-path
// Lookup is lock-free.
type resolvedSet struct {
	byCat map[Category][]netip.Prefix
}

// Resolver answers the hot-path question "is this IP exempt for this
// category?" for the trigger. It holds an atomic snapshot rebuilt from the
// store on every mutation (and at boot).
type Resolver struct {
	store *Store
	set   atomic.Pointer[resolvedSet]
}

// NewResolver returns a resolver backed by store (which may be nil in the
// degraded path, #364 spec D-DEGRADED). The initial set is empty, so
// Lookup returns false for everything until Rebuild runs.
func NewResolver(store *Store) *Resolver {
	r := &Resolver{store: store}
	r.set.Store(&resolvedSet{byCat: map[Category][]netip.Prefix{}})
	return r
}

// Rebuild reloads the active-allowlist snapshot from the store and swaps
// it in atomically. A nil store (#364 spec D-DEGRADED) yields an empty
// set: fail-closed, exempt nobody.
func (r *Resolver) Rebuild(ctx context.Context) error {
	byCat := map[Category][]netip.Prefix{}
	if r.store == nil {
		r.set.Store(&resolvedSet{byCat: byCat})
		return nil
	}
	lists, err := r.store.List(ctx)
	if err != nil {
		return err
	}
	for _, a := range lists {
		if !a.Enabled {
			continue
		}
		var prefixes []netip.Prefix
		for _, e := range a.Entries {
			p, err := netip.ParsePrefix(e.CIDR)
			if err != nil {
				continue // defensive: entries are normalised on write
			}
			prefixes = append(prefixes, p)
		}
		if len(prefixes) == 0 {
			continue
		}
		if a.ScopeBlock {
			byCat[CategoryBlock] = append(byCat[CategoryBlock], prefixes...)
		}
		if a.ScopeThrottle {
			byCat[CategoryThrottle] = append(byCat[CategoryThrottle], prefixes...)
		}
		if a.ScopeAudit {
			byCat[CategoryAudit] = append(byCat[CategoryAudit], prefixes...)
		}
	}
	r.set.Store(&resolvedSet{byCat: byCat})
	return nil
}

// Lookup reports whether ip is covered by an active allowlist whose scope
// includes cat. Lock-free: reads the current atomic snapshot.
func (r *Resolver) Lookup(ip netip.Addr, cat Category) bool {
	set := r.set.Load()
	if set == nil {
		return false
	}
	for _, p := range set.byCat[cat] {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// slugify turns a display name into a URL/log-safe slug ([a-z0-9-]).
func slugify(name string) string {
	var b strings.Builder
	lastDash := true // avoid leading dash
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}
