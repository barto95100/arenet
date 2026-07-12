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

package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestManagedDomain_NormalizeApex(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"example.com", "example.com"},
		{"Example.Com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"example.com.", "example.com"},
		{"Example.Com.", "example.com"},
		{"", ""},
		{".", ""},
	}
	for _, c := range cases {
		if got := NormalizeApex(c.in); got != c.want {
			t.Errorf("NormalizeApex(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestManagedDomain_Validate(t *testing.T) {
	cases := []struct {
		name    string
		md      ManagedDomain
		wantErr string // substring match; "" means expect nil error
	}{
		{
			name: "valid minimal",
			md:   ManagedDomain{Apex: "example.com", ProviderID: "ovh"},
		},
		{
			name: "valid with includeApex",
			md:   ManagedDomain{Apex: "example.com", IncludeApex: true, ProviderID: "ovh"},
		},
		{
			name: "valid single-label apex (homelab .lan)",
			md:   ManagedDomain{Apex: "lan", ProviderID: "ovh"},
		},
		{
			name:    "empty apex rejected",
			md:      ManagedDomain{ProviderID: "ovh"},
			wantErr: "apex must not be empty",
		},
		{
			name:    "wildcard form rejected",
			md:      ManagedDomain{Apex: "*.example.com", ProviderID: "ovh"},
			wantErr: `not the wildcard form`,
		},
		{
			name:    "uppercase rejected (not canonical)",
			md:      ManagedDomain{Apex: "Example.com", ProviderID: "ovh"},
			wantErr: "not in canonical form",
		},
		{
			name:    "trailing dot rejected (not canonical)",
			md:      ManagedDomain{Apex: "example.com.", ProviderID: "ovh"},
			wantErr: "not in canonical form",
		},
		{
			name:    "invalid hostname chars rejected",
			md:      ManagedDomain{Apex: "ex_ample.com", ProviderID: "ovh"},
			wantErr: "valid RFC 1123 hostname",
		},
		{
			name: "empty providerID accepted (unassigned → internal CA)",
			md:   ManagedDomain{Apex: "example.com"},
		},
		{
			name: "arbitrary providerID accepted (existence checked at API layer)",
			md:   ManagedDomain{Apex: "example.com", ProviderID: "any-uuid-like-string"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.md.validate()
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("expected nil err, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %q, want substring %q", err.Error(), c.wantErr)
			}
		})
	}
}

func TestManagedDomain_PutGet_Roundtrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	md := ManagedDomain{Apex: "example.com", IncludeApex: true, ProviderID: "ovh"}
	if err := s.PutManagedDomain(ctx, md); err != nil {
		t.Fatalf("PutManagedDomain: %v", err)
	}
	got, err := s.GetManagedDomain(ctx, "example.com")
	if err != nil {
		t.Fatalf("GetManagedDomain: %v", err)
	}
	if got != md {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", got, md)
	}
}

func TestManagedDomain_Get_NormalizesInput(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.PutManagedDomain(ctx, ManagedDomain{
		Apex: "example.com", ProviderID: "ovh",
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Caller passes non-canonical form; Get should normalise.
	got, err := s.GetManagedDomain(ctx, "Example.Com.")
	if err != nil {
		t.Fatalf("GetManagedDomain non-canonical: %v", err)
	}
	if got.Apex != "example.com" {
		t.Errorf("got apex %q, want %q", got.Apex, "example.com")
	}
}

func TestManagedDomain_Get_NotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetManagedDomain(context.Background(), "missing.example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestManagedDomain_List_OrderedByApex(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	apexes := []string{"zeta.com", "alpha.com", "mu.com"}
	for _, a := range apexes {
		if err := s.PutManagedDomain(ctx, ManagedDomain{Apex: a, ProviderID: "ovh"}); err != nil {
			t.Fatalf("Put %q: %v", a, err)
		}
	}
	got, err := s.ListManagedDomains(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d rows, want 3", len(got))
	}
	want := []string{"alpha.com", "mu.com", "zeta.com"}
	for i, md := range got {
		if md.Apex != want[i] {
			t.Errorf("row %d: got %q, want %q (lex order)", i, md.Apex, want[i])
		}
	}
}

func TestManagedDomain_List_EmptyOnFreshInstall(t *testing.T) {
	s := newTestStore(t)
	got, err := s.ListManagedDomains(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty list, got %d rows", len(got))
	}
}

func TestManagedDomain_Delete_Idempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Delete on missing row returns nil (idempotent).
	if err := s.DeleteManagedDomain(ctx, "missing.example.com"); err != nil {
		t.Errorf("Delete missing should be nil, got %v", err)
	}

	if err := s.PutManagedDomain(ctx, ManagedDomain{Apex: "example.com", ProviderID: "ovh"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.DeleteManagedDomain(ctx, "example.com"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.GetManagedDomain(ctx, "example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
	// Second delete same apex: idempotent.
	if err := s.DeleteManagedDomain(ctx, "example.com"); err != nil {
		t.Errorf("second Delete should be nil, got %v", err)
	}
}

func TestManagedDomain_Put_RejectsInvalid(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.PutManagedDomain(ctx, ManagedDomain{Apex: "", ProviderID: "ovh"}); err == nil {
		t.Error("expected validation error on empty apex, got nil")
	}
	if err := s.PutManagedDomain(ctx, ManagedDomain{Apex: "*.example.com", ProviderID: "ovh"}); err == nil {
		t.Error("expected validation error on wildcard apex, got nil")
	}
	// A non-empty ProviderID that does not map to a stored provider is
	// NOT rejected at the storage layer (referential integrity is an
	// API-layer concern via GetDNSProvider).
	if err := s.PutManagedDomain(ctx, ManagedDomain{Apex: "example.com", ProviderID: "fly"}); err != nil {
		t.Errorf("unexpected error for arbitrary providerID: %v", err)
	}
}

// TestManagedDomain_PutWithRouteMigration_AtomicMutation pins the
// D8.A invariant: when a managed domain is declared, every covered
// route's ACMEChallenge is set to "inherited" in the SAME BoltDB
// transaction as the managed-domain Put. Routes that opt out via
// UseDedicatedCert are left untouched.
func TestManagedDomain_PutWithRouteMigration_AtomicMutation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Seed three routes:
	//  - covered route with default ACMEChallenge ""
	//  - covered route with UseDedicatedCert=true (must NOT mutate)
	//  - uncovered route (must NOT mutate)
	mustCreate := func(host string, ud bool) Route {
		r := minimalRoute(host, "http://127.0.0.1:8080")
		r.UseDedicatedCert = ud
		out, err := s.CreateRoute(ctx, r)
		if err != nil {
			t.Fatalf("CreateRoute %q: %v", host, err)
		}
		return out
	}
	covered := mustCreate("app.example.com", false)
	dedicated := mustCreate("payments.example.com", true)
	uncovered := mustCreate("other.org", false)

	// isCovered closure mimics what the API layer passes
	// (caddymgr.IsHostCoveredByManagedDomain bound to the new md).
	isCovered := func(host string) bool {
		return strings.HasSuffix(host, ".example.com") || host == "example.com"
	}
	mutated, err := s.PutManagedDomainWithRouteMigration(ctx,
		ManagedDomain{Apex: "example.com", ProviderID: "ovh"}, isCovered)
	if err != nil {
		t.Fatalf("PutManagedDomainWithRouteMigration: %v", err)
	}
	if mutated != 1 {
		t.Errorf("mutated=%d, want 1 (only the covered+non-dedicated route)", mutated)
	}

	// Verify post-state.
	cAfter, _ := s.GetRoute(ctx, covered.ID)
	if cAfter.ACMEChallenge != ACMEChallengeInherited {
		t.Errorf("covered route ACMEChallenge = %q, want %q", cAfter.ACMEChallenge, ACMEChallengeInherited)
	}
	dAfter, _ := s.GetRoute(ctx, dedicated.ID)
	if dAfter.ACMEChallenge == ACMEChallengeInherited {
		t.Errorf("dedicated route should NOT be mutated (UseDedicatedCert=true)")
	}
	uAfter, _ := s.GetRoute(ctx, uncovered.ID)
	if uAfter.ACMEChallenge == ACMEChallengeInherited {
		t.Errorf("uncovered route should NOT be mutated")
	}

	// Idempotency: re-running the same Put leaves the state
	// unchanged AND returns 0 mutations (the already-inherited
	// row is skipped at the inner ACMEChallenge==Inherited check).
	mutated2, err := s.PutManagedDomainWithRouteMigration(ctx,
		ManagedDomain{Apex: "example.com", ProviderID: "ovh"}, isCovered)
	if err != nil {
		t.Fatalf("idempotent re-run: %v", err)
	}
	if mutated2 != 0 {
		t.Errorf("re-run mutated=%d, want 0 (idempotent)", mutated2)
	}
}

// TestManagedDomain_DeleteWithRouteMigration_ReversesInherited pins
// the reverse invariant: when a managed domain is deleted, every
// covered route whose ACMEChallenge is "inherited" reverts to "".
// Routes whose ACMEChallenge is something else are left untouched
// (operator may have manually set them).
func TestManagedDomain_DeleteWithRouteMigration_ReversesInherited(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Setup: declare managed domain, then create routes.
	if err := s.PutManagedDomain(ctx,
		ManagedDomain{Apex: "example.com", ProviderID: "ovh"}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	mustCreate := func(host, challenge string) Route {
		r := minimalRoute(host, "http://127.0.0.1:8080")
		r.ACMEChallenge = challenge
		out, err := s.CreateRoute(ctx, r)
		if err != nil {
			t.Fatalf("CreateRoute %q: %v", host, err)
		}
		return out
	}
	inherited := mustCreate("app.example.com", ACMEChallengeInherited)
	dedicated := mustCreate("payments.example.com", ACMEChallengeDNS01)
	uncovered := mustCreate("other.org", ACMEChallengeInherited) // synthetic edge

	isCovered := func(host string) bool {
		return strings.HasSuffix(host, ".example.com") || host == "example.com"
	}
	mutated, err := s.DeleteManagedDomainWithRouteMigration(ctx, "example.com", isCovered)
	if err != nil {
		t.Fatalf("DeleteManagedDomainWithRouteMigration: %v", err)
	}
	if mutated != 1 {
		t.Errorf("mutated=%d, want 1 (only the covered+inherited route)", mutated)
	}

	iAfter, _ := s.GetRoute(ctx, inherited.ID)
	if iAfter.ACMEChallenge != "" {
		t.Errorf("inherited route should revert to \"\", got %q", iAfter.ACMEChallenge)
	}
	dAfter, _ := s.GetRoute(ctx, dedicated.ID)
	if dAfter.ACMEChallenge != ACMEChallengeDNS01 {
		t.Errorf("dedicated-route ACMEChallenge should be preserved: got %q", dAfter.ACMEChallenge)
	}
	// Uncovered route was synthetically "inherited" but not covered
	// by example.com, so deleting example.com leaves it alone.
	uAfter, _ := s.GetRoute(ctx, uncovered.ID)
	if uAfter.ACMEChallenge != ACMEChallengeInherited {
		t.Errorf("uncovered synthetic-inherited route should be unchanged: got %q", uAfter.ACMEChallenge)
	}

	// Verify the managed-domain row is actually gone.
	if _, err := s.GetManagedDomain(ctx, "example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after Delete, got %v", err)
	}
}

func TestManagedDomain_DeleteWithRouteMigration_MissingManagedDomain(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Delete on a non-existent managed domain returns ErrNotFound.
	isCovered := func(string) bool { return false }
	if _, err := s.DeleteManagedDomainWithRouteMigration(ctx, "missing.example.com", isCovered); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}
