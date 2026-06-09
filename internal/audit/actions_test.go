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

// TestAllActions_Count guards against accidental drift from D7
// (Step D shipped 15) + Step J.4 (+1 = 16) + Step K.1 (+2 = 18)
// + Step K.2 (+7 = 25) + Step K.3 (+3 = 28) + Step O.3 (+2 = 30)
// + Step P.3 (+2 = 32) + Step V.4 (+2 = 34). Adding or removing
// actions without updating the spec / decisions doc is a process
// violation; this test forces the conversation.
func TestAllActions_Count(t *testing.T) {
	const wantCount = 37
	if got := len(AllActions()); got != wantCount {
		t.Fatalf("AllActions count drift: got %d, want %d (D7=15 + J.4=1 + K.1=2 + K.2=7 + K.3=3 + O.3=2 + P.3=2 + V.4=2 + CS.1=2 + CS.2=1)", got, wantCount)
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

// TestAllActions_ExactSet confirms the exact set: 15 from D7
// + 1 added by Step J.4 (dns_provider_updated) + 2 added by
// Step K.1 (forward_auth_provider_updated /
// forward_auth_provider_deleted). If you add or remove an
// action, this test will fail and force you to amend the
// decision document / spec.
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
		"dns_provider_updated":          true,
		"forward_auth_provider_updated": true,
		"forward_auth_provider_deleted": true,
		"oidc_configured":               true,
		"oidc_updated":                  true,
		"oidc_login_rejected":           true,
		"oidc_callback_invalid":         true,
		"login_break_glass":             true,
		"local_admin_password_rotated":  true,
		"user_role_changed":             true,
		"config_exported":               true,
		"config_restored":               true,
		"config_restored_rejected":      true,
		// Step O.3 (+2) — managed-domain CRUD audit events.
		"managed_domain_created": true,
		"managed_domain_deleted": true,
		// Step P.3 (+2) — auto-classify lifecycle audit events.
		"automation_decision_pushed": true,
		"automation_rule_changed":    true,
		// Step V.4 (+2) — server geographic position admin
		// events. Updated emitted by PUT (manual override);
		// Redetected emitted by POST :redetect (re-run V.1
		// auto-detect).
		"server_position_updated":    true,
		"server_position_redetected": true,
		// Step CS.1 (+2) — CrowdSec bouncer config admin
		// events. Configured emitted on first PUT;
		// Updated emitted on subsequent PUTs.
		"crowdsec_configured": true,
		"crowdsec_updated":    true,
		// Step CS.2 follow-up (+1) — operator-pressed
		// Reset button on Settings UI. Distinct from
		// crowdsec_updated to make the deliberate
		// "bouncer disabled" intent visible in /audit.
		"crowdsec_reset": true,
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
