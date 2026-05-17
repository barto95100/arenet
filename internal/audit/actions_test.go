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

package audit

import "testing"

// TestAllActions_Count guards against accidental drift from D7 (15
// audit action values for Step D). Adding or removing actions in this
// package without updating decisions-final.md is a process violation;
// this test forces the conversation.
func TestAllActions_Count(t *testing.T) {
	const wantCount = 15
	if got := len(AllActions()); got != wantCount {
		t.Fatalf("AllActions count drift: got %d, want %d (per D7)", got, wantCount)
	}
}

// TestAllActions_NoDuplicates ensures every action string is unique
// within the enum.
func TestAllActions_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool, len(AllActions()))
	for _, a := range AllActions() {
		if seen[a] {
			t.Errorf("duplicate action in AllActions: %q", a)
		}
		seen[a] = true
	}
}

// TestAllActions_ReturnsFreshCopy guards against mutability leakage:
// each call must return an independent slice so callers cannot mutate
// the package-level source of truth.
func TestAllActions_ReturnsFreshCopy(t *testing.T) {
	a := AllActions()
	b := AllActions()
	if len(a) == 0 || len(b) == 0 {
		t.Fatal("AllActions returned empty slice")
	}
	if &a[0] == &b[0] {
		t.Error("AllActions returned same backing array on consecutive calls")
	}
	// Mutate the first copy; the second copy and a subsequent third
	// call must remain intact.
	a[0] = "MUTATED"
	if b[0] == "MUTATED" {
		t.Error("mutating one copy mutated another")
	}
	c := AllActions()
	if c[0] == "MUTATED" {
		t.Error("mutating a copy mutated the package source")
	}
}

// TestAllActions_ExactSet confirms the exact 15 values from D7.
// If you add or remove an action, this test will fail and force you
// to amend the decision document and re-tag the spec.
func TestAllActions_ExactSet(t *testing.T) {
	want := map[string]bool{
		"login_success":                 true,
		"login_failure":                 true,
		"logout":                        true,
		"unlock_success":                true,
		"unlock_failure":                true,
		"session_revoked":               true,
		"setup_admin_created":           true,
		"password_changed":              true,
		"route_created":                 true,
		"route_updated":                 true,
		"route_deleted":                 true,
		"audit_viewed":                  true,
		"password_hibp_clean":           true,
		"password_hibp_pending":         true,
		"password_compromised_detected": true,
	}
	for _, a := range AllActions() {
		if !want[a] {
			t.Errorf("unexpected action %q (not in D7)", a)
		}
		delete(want, a)
	}
	for missing := range want {
		t.Errorf("missing action %q from AllActions", missing)
	}
}
