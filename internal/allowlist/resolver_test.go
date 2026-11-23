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
	"testing"
)

func openMem(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// G_allowlist_cidr_match: an IP inside an allowlisted CIDR (not an exact
// IP match) is covered. RED before the resolver loads the store.
func TestAllowlistCIDRMatch_G(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	if _, err := s.Create(ctx, Input{
		Name: "office", Enabled: true, ScopeBlock: true, ScopeThrottle: true, ScopeAudit: true,
		Entries: []Entry{{CIDR: "10.0.0.0/24"}},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	r := NewResolver(s)
	if err := r.Rebuild(ctx); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if !r.Lookup(netip.MustParseAddr("10.0.0.5"), CategoryBlock) {
		t.Error("10.0.0.5 should be covered by allowlisted CIDR 10.0.0.0/24 (block)")
	}
}

// G_allowlist_rebuild_on_mutation: after a Create + Rebuild the resolver
// reflects the new entry. RED before Rebuild loads the store.
func TestAllowlistRebuildOnMutation_G(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	r := NewResolver(s)
	if err := r.Rebuild(ctx); err != nil {
		t.Fatalf("Rebuild (empty): %v", err)
	}
	ip := netip.MustParseAddr("192.168.1.1")
	if r.Lookup(ip, CategoryBlock) {
		t.Fatal("precondition: nothing allowlisted yet")
	}
	if _, err := s.Create(ctx, Input{
		Name: "host", Enabled: true, ScopeBlock: true,
		Entries: []Entry{{CIDR: "192.168.1.1"}},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := r.Rebuild(ctx); err != nil {
		t.Fatalf("Rebuild (after create): %v", err)
	}
	if !r.Lookup(ip, CategoryBlock) {
		t.Error("192.168.1.1 should be covered after Create + Rebuild (block)")
	}
}

// G_allowlist_inactive: a disabled allowlist contributes nothing to the
// resolved set. Sibling guard — stays green; bites if Rebuild loads
// disabled allowlists.
func TestAllowlistInactive_IgnoredByResolver_G(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	if _, err := s.Create(ctx, Input{
		Name: "paused", Enabled: false, ScopeBlock: true,
		Entries: []Entry{{CIDR: "203.0.113.7"}},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	r := NewResolver(s)
	if err := r.Rebuild(ctx); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if r.Lookup(netip.MustParseAddr("203.0.113.7"), CategoryBlock) {
		t.Error("an inactive allowlist must not exempt its IPs")
	}
}

// G_allowlist_scope (resolver level): an IP allowlisted for block only is
// not covered for throttle. Sibling guard.
func TestAllowlistScope_ResolverRespectsScope_G(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	if _, err := s.Create(ctx, Input{
		Name: "blockonly", Enabled: true, ScopeBlock: true, ScopeThrottle: false, ScopeAudit: false,
		Entries: []Entry{{CIDR: "198.51.100.4"}},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	r := NewResolver(s)
	if err := r.Rebuild(ctx); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	ip := netip.MustParseAddr("198.51.100.4")
	if !r.Lookup(ip, CategoryBlock) {
		t.Error("should be covered for block")
	}
	if r.Lookup(ip, CategoryThrottle) {
		t.Error("must NOT be covered for throttle (scope is block only)")
	}
}

// G_allowlist_cidr_validation: invalid IP/CIDR entries are rejected at
// Create. RED before validateEntries validates.
func TestAllowlistCIDRValidation_G(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	bad := []string{"not-an-ip", "10.0.0.0/33", "300.1.1.1", "", "10.0.0.1/-1"}
	for _, entry := range bad {
		if _, err := s.Create(ctx, Input{
			Name: "x", Enabled: true, ScopeBlock: true,
			Entries: []Entry{{CIDR: entry}},
		}); err == nil {
			t.Errorf("Create accepted invalid entry %q, want error", entry)
		}
	}
}

// G_allowlist_degraded: a resolver with a nil store (security.db unreadable
// at boot, #364 spec D-DEGRADED) is fail-closed: empty set, Lookup false,
// no panic, Rebuild is a harmless no-op. Sibling guard.
func TestAllowlistDegraded_NilStore_FailClosed_G(t *testing.T) {
	r := NewResolver(nil)
	if err := r.Rebuild(context.Background()); err != nil {
		t.Errorf("Rebuild on nil store should be a harmless no-op, got %v", err)
	}
	if r.Lookup(netip.MustParseAddr("10.0.0.1"), CategoryBlock) {
		t.Error("nil-store resolver must exempt nobody (fail-closed)")
	}
}
