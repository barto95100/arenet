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

package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// TestStoreDNS01Inconsistency pins the predicate that drives the
// boot WARN + the frontend bandeaux (the (β) safety net the
// edit-time guard cannot cover). A regression here would silence
// the WARN: an operator deleting the OVH provider config after
// dns-01 routes have been saved would get no signal until the
// next cert renewal fails in production. The four cases below
// exhaust the truth table.
func TestStoreDNS01Inconsistency(t *testing.T) {
	mkStore := func(t *testing.T) *storage.Store {
		t.Helper()
		dir := t.TempDir()
		s, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
		if err != nil {
			t.Fatalf("NewStore: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}

	ctx := context.Background()

	t.Run("no routes, no provider", func(t *testing.T) {
		s := mkStore(t)
		anyDNS01, providerOK, err := storeDNS01Inconsistency(ctx, s)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if anyDNS01 {
			t.Errorf("anyDNS01 = true on empty store")
		}
		// No dns-01 routes → providerOK is the trivially-true
		// "no problem to detect" sentinel. The boot WARN gate
		// requires anyDNS01 AND !providerOK, so this is correct
		// (no warn fires).
		if !providerOK {
			t.Errorf("providerOK = false on empty store; want true (no dns-01 routes ⇒ no inconsistency)")
		}
	})

	t.Run("dns-01 route, no provider", func(t *testing.T) {
		s := mkStore(t)
		_, err := s.CreateRoute(ctx, storage.Route{
			Host:          "wild.example.com",
			Upstreams:     []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:      storage.LBPolicyRoundRobin,
			ACMEChallenge: storage.ACMEChallengeDNS01,
			WAFMode:       "off",
		})
		if err != nil {
			t.Fatalf("CreateRoute: %v", err)
		}

		anyDNS01, providerOK, err := storeDNS01Inconsistency(ctx, s)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !anyDNS01 {
			t.Errorf("anyDNS01 = false; want true")
		}
		if providerOK {
			t.Errorf("providerOK = true with no provider configured")
		}
	})

	t.Run("dns-01 route, complete provider", func(t *testing.T) {
		s := mkStore(t)
		_, err := s.CreateRoute(ctx, storage.Route{
			Host:          "wild.example.com",
			Upstreams:     []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:      storage.LBPolicyRoundRobin,
			ACMEChallenge: storage.ACMEChallengeDNS01,
			WAFMode:       "off",
		})
		if err != nil {
			t.Fatalf("CreateRoute: %v", err)
		}
		if _, err := s.CreateDNSProvider(ctx, storage.DNSProviderConfig{
			Label:             "OVH",
			Type:              storage.DNSProviderTypeOVH,
			Endpoint:          "ovh-eu",
			ApplicationKey:    "k",
			ApplicationSecret: "s",
			ConsumerKey:       "c",
		}); err != nil {
			t.Fatalf("CreateDNSProvider: %v", err)
		}

		anyDNS01, providerOK, err := storeDNS01Inconsistency(ctx, s)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !anyDNS01 {
			t.Errorf("anyDNS01 = false; want true")
		}
		if !providerOK {
			t.Errorf("providerOK = false with complete provider")
		}
	})

	t.Run("http-01 routes only, complete provider", func(t *testing.T) {
		// The provider exists but no route uses it — a benign
		// pre-staging state. anyDNS01 must be false so the WARN
		// stays silent.
		s := mkStore(t)
		_, err := s.CreateRoute(ctx, storage.Route{
			Host:      "plain.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
		})
		if err != nil {
			t.Fatalf("CreateRoute: %v", err)
		}
		if _, err := s.CreateDNSProvider(ctx, storage.DNSProviderConfig{
			Label:             "OVH",
			Type:              storage.DNSProviderTypeOVH,
			Endpoint:          "ovh-eu",
			ApplicationKey:    "k",
			ApplicationSecret: "s",
			ConsumerKey:       "c",
		}); err != nil {
			t.Fatalf("CreateDNSProvider: %v", err)
		}

		anyDNS01, providerOK, err := storeDNS01Inconsistency(ctx, s)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if anyDNS01 {
			t.Errorf("anyDNS01 = true with only http-01 routes")
		}
		if !providerOK {
			t.Errorf("providerOK = false despite complete config (irrelevant here but tracks the truth)")
		}
	})
}
