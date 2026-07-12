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
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// TestIsHostCoveredByManagedDomain_Predicate is the table-driven
// pin for the §3.2 coverage predicate. Covers every edge case
// called out in spec §5 risks "predicate regression" row:
// multi-label depth, bare apex with/without IncludeApex,
// case-insensitivity, trailing-dot canonicalisation, and the
// D5.A empty-mds short-circuit.
func TestIsHostCoveredByManagedDomain_Predicate(t *testing.T) {
	mds := []storage.ManagedDomain{
		{Apex: "example.com", IncludeApex: true, ProviderID: "ovh"},
		{Apex: "noapex.com", IncludeApex: false, ProviderID: "ovh"},
	}

	cases := []struct {
		name      string
		host      string
		mds       []storage.ManagedDomain
		wantApex  string // "" means not covered
		wantFound bool
	}{
		// Coverage hits.
		{
			name: "single-label subdomain covered",
			host: "app.example.com", mds: mds,
			wantApex: "example.com", wantFound: true,
		},
		{
			name: "bare apex covered when IncludeApex=true",
			host: "example.com", mds: mds,
			wantApex: "example.com", wantFound: true,
		},
		{
			name: "uppercase host normalised to lowercase",
			host: "App.Example.Com", mds: mds,
			wantApex: "example.com", wantFound: true,
		},
		{
			name: "trailing-dot host normalised",
			host: "app.example.com.", mds: mds,
			wantApex: "example.com", wantFound: true,
		},

		// Coverage misses.
		{
			name: "multi-label depth NOT covered (RFC 6125 §6.4.3)",
			host: "deep.app.example.com", mds: mds,
		},
		{
			name: "bare apex NOT covered when IncludeApex=false",
			host: "noapex.com", mds: mds,
		},
		{
			name: "single-label sub of IncludeApex=false IS covered (wildcard still applies)",
			host: "app.noapex.com", mds: mds,
			wantApex: "noapex.com", wantFound: true,
		},
		{
			name: "host with no managed-domain suffix NOT covered",
			host: "other.org", mds: mds,
		},
		{
			name: "wildcard route-host itself NOT covered (we emit it, not consume it)",
			host: "*.example.com", mds: mds,
		},
		{
			name: "double-wildcard NOT covered",
			host: "*.*.example.com", mds: mds,
		},
		{
			name: "empty host NOT covered",
			host: "", mds: mds,
		},
		{
			name: "empty mds short-circuit (D5.A invariant)",
			host: "app.example.com", mds: nil,
		},
		{
			name: "mds with empty apex skipped (defensive)",
			host: "app.example.com",
			mds:  []storage.ManagedDomain{{Apex: "", ProviderID: "ovh"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := IsHostCoveredByManagedDomain(c.host, c.mds)
			if ok != c.wantFound {
				t.Errorf("found=%v, want %v (got md=%+v)", ok, c.wantFound, got)
			}
			if c.wantFound && got.Apex != c.wantApex {
				t.Errorf("apex=%q, want %q", got.Apex, c.wantApex)
			}
		})
	}
}

// TestIsHostCoveredByManagedDomain_MultipleManagedDomains pins
// spec D6.A: multiple managed domains coexist; the predicate
// returns the first matching one (BoltDB lex order from
// ListManagedDomains, so deterministic).
func TestIsHostCoveredByManagedDomain_MultipleManagedDomains(t *testing.T) {
	mds := []storage.ManagedDomain{
		{Apex: "alpha.com", IncludeApex: true, ProviderID: "ovh"},
		{Apex: "beta.com", IncludeApex: true, ProviderID: "ovh"},
	}
	got, ok := IsHostCoveredByManagedDomain("app.beta.com", mds)
	if !ok {
		t.Fatal("expected coverage hit on beta.com")
	}
	if got.Apex != "beta.com" {
		t.Errorf("apex=%q, want beta.com", got.Apex)
	}

	got, ok = IsHostCoveredByManagedDomain("hello.alpha.com", mds)
	if !ok {
		t.Fatal("expected coverage hit on alpha.com")
	}
	if got.Apex != "alpha.com" {
		t.Errorf("apex=%q, want alpha.com", got.Apex)
	}
}
