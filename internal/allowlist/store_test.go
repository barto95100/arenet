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
	"errors"
	"testing"
)

func TestStore_CRUDRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)

	created, err := s.Create(ctx, Input{
		Name: "Office network", Description: "HQ egress", Enabled: true,
		ScopeBlock: true, ScopeThrottle: false, ScopeAudit: true,
		Entries: []Entry{{CIDR: "10.0.0.0/24", Note: "LAN"}, {CIDR: "203.0.113.9", Note: "VPN"}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Slug != "office-network" {
		t.Errorf("slug = %q, want office-network", created.Slug)
	}
	if created.ScopeThrottle {
		t.Error("ScopeThrottle should be false")
	}
	if len(created.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(created.Entries))
	}
	// Bare IP normalised to /32.
	if created.Entries[1].CIDR != "203.0.113.9/32" {
		t.Errorf("bare IP normalised to %q, want 203.0.113.9/32", created.Entries[1].CIDR)
	}

	got, err := s.Get(ctx, "office-network")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "Office network" || got.Description != "HQ egress" {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	// Update replaces entries wholesale.
	updated, err := s.Update(ctx, "office-network", Input{
		Name: "Office network", Enabled: false, ScopeBlock: true, ScopeThrottle: true, ScopeAudit: true,
		Entries: []Entry{{CIDR: "10.0.0.0/8"}},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Enabled {
		t.Error("Enabled should be false after update")
	}
	if len(updated.Entries) != 1 || updated.Entries[0].CIDR != "10.0.0.0/8" {
		t.Errorf("entries after update = %+v, want one 10.0.0.0/8", updated.Entries)
	}

	all, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("List len = %d, want 1", len(all))
	}

	if err := s.Delete(ctx, "office-network"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "office-network"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after delete: err = %v, want ErrNotFound", err)
	}
	if err := s.Delete(ctx, "office-network"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete missing: err = %v, want ErrNotFound", err)
	}
}

func TestStore_SlugUniqueness(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	for i, wantSlug := range []string{"dupe", "dupe-2", "dupe-3"} {
		a, err := s.Create(ctx, Input{Name: "Dupe", Enabled: true, ScopeBlock: true})
		if err != nil {
			t.Fatalf("Create #%d: %v", i, err)
		}
		if a.Slug != wantSlug {
			t.Errorf("Create #%d slug = %q, want %q", i, a.Slug, wantSlug)
		}
	}
}

func TestStore_EmptyNameRejected(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	if _, err := s.Create(ctx, Input{Name: "   ", Enabled: true, ScopeBlock: true}); err == nil {
		t.Error("Create accepted blank name, want error")
	}
}
