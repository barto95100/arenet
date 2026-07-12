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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// TestIsHostCoveredByManagedDomain_FixtureFile drives the
// managed-domain coverage predicate from a JSON fixture under
// testdata/. The same fixture file is the contract for the
// frontend TS port `findCoveringManagedDomain` once a vitest
// harness lands (per docs/backlog-step-o.md #O.4-1).
//
// Why this exists, separately from
// TestIsHostCoveredByManagedDomain_Predicate (which is also
// table-driven, in-Go-only):
//
//   - That test is the in-Go regression gate. This one is the
//     CROSS-LANGUAGE regression gate: a future edit to the Go
//     predicate that doesn't have a mirror edit to the TS port
//     fails THIS test on the Go side (because we may add cases
//     covering the new rule) AND the parallel vitest test on
//     the TS side (when it exists). Until vitest lands, this
//     test alone exercises the fixture.
//
//   - The fixture file is a readable spec artifact: an operator
//     reviewing the coverage rules reads the JSON, not Go nor
//     TS. The two implementations stay subordinate.
//
// If the fixture file moves, drift it deliberately in both the
// Go and TS test paths in the same PR.
func TestIsHostCoveredByManagedDomain_FixtureFile(t *testing.T) {
	type fixtureCase struct {
		Name      string `json:"name"`
		MdsSet    string `json:"mds_set"`
		Host      string `json:"host"`
		WantFound bool   `json:"want_found"`
		WantApex  string `json:"want_apex"`
	}
	type fixtureMd struct {
		Apex        string `json:"apex"`
		IncludeApex bool   `json:"includeApex"`
		Provider    string `json:"provider"`
	}
	type fixture struct {
		ManagedDomainSets map[string][]fixtureMd `json:"managed_domain_sets"`
		Cases             []fixtureCase          `json:"cases"`
	}

	path := filepath.Join("testdata", "managed-domain-coverage-cases.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %q: %v", path, err)
	}
	var fix fixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	if len(fix.Cases) == 0 {
		t.Fatalf("fixture has zero cases — file is empty or malformed")
	}

	// Convert each named mds_set to []storage.ManagedDomain
	// once, share across cases that reference it.
	mdsSets := make(map[string][]storage.ManagedDomain, len(fix.ManagedDomainSets))
	for name, set := range fix.ManagedDomainSets {
		converted := make([]storage.ManagedDomain, 0, len(set))
		for _, m := range set {
			converted = append(converted, storage.ManagedDomain{
				Apex:        m.Apex,
				IncludeApex: m.IncludeApex,
				// The fixture's legacy "provider" (a type string) maps
				// to ProviderID here; the coverage predicate ignores it,
				// so the exact value is immaterial to these cases.
				ProviderID: m.Provider,
			})
		}
		mdsSets[name] = converted
	}

	for _, c := range fix.Cases {
		t.Run(c.Name, func(t *testing.T) {
			mds, ok := mdsSets[c.MdsSet]
			if !ok {
				t.Fatalf("fixture references unknown mds_set %q (case %q)", c.MdsSet, c.Name)
			}
			got, found := IsHostCoveredByManagedDomain(c.Host, mds)
			if found != c.WantFound {
				t.Errorf("found=%v, want %v (got md=%+v)", found, c.WantFound, got)
			}
			if c.WantFound && got.Apex != c.WantApex {
				t.Errorf("apex=%q, want %q", got.Apex, c.WantApex)
			}
		})
	}
}
