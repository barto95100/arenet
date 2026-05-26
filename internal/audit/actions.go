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

import "slices"

// Step D audit action constants, per decision D7 in
// docs/superpowers/decisions/2026-05-17-step-d-design-decisions-final.md.
// The 15 string values are the canonical names persisted in the audit
// bucket and exposed via the API. Tests in actions_test.go assert the
// enum is exactly these 15 values; the frontend audit page hardcodes
// the same set in its filter dropdown (Chunk 8).
const (
	// Authentication (3)
	ActionLoginSuccess = "login_success"
	ActionLoginFailure = "login_failure"
	ActionLogout       = "logout"

	// Lock screen (2)
	ActionUnlockSuccess = "unlock_success"
	ActionUnlockFailure = "unlock_failure"

	// Sessions (1)
	ActionSessionRevoked = "session_revoked"

	// Setup (1)
	ActionSetupAdminCreated = "setup_admin_created"

	// Password (1)
	ActionPasswordChanged = "password_changed"

	// Routes (3) — past tense per D7
	ActionRouteCreated = "route_created"
	ActionRouteUpdated = "route_updated"
	ActionRouteDeleted = "route_deleted"

	// Audit (1)
	ActionAuditViewed = "audit_viewed"

	// HIBP (3)
	ActionPasswordHIBPClean           = "password_hibp_clean"
	ActionPasswordHIBPPending         = "password_hibp_pending"
	ActionPasswordCompromisedDetected = "password_compromised_detected"

	// Step J.4 — DNS provider (1)
	//
	// The string value is duplicated as a separate constant in
	// internal/api/dns_provider.go (api.ActionDNSProviderUpdated)
	// to keep the API's source-of-truth near the only emission
	// site; tests in actions_test.go pin the enum count.
	ActionDNSProviderUpdated = "dns_provider_updated"

	// Step K.1 — forward-auth provider (2)
	ActionForwardAuthProviderUpdated = "forward_auth_provider_updated"
	ActionForwardAuthProviderDeleted = "forward_auth_provider_deleted"
)

// allActions is the canonical set of audit action values for Step D.
// Unexported to prevent callers from mutating the slice; use AllActions()
// to obtain a fresh copy.
var allActions = []string{
	ActionLoginSuccess,
	ActionLoginFailure,
	ActionLogout,
	ActionUnlockSuccess,
	ActionUnlockFailure,
	ActionSessionRevoked,
	ActionSetupAdminCreated,
	ActionPasswordChanged,
	ActionRouteCreated,
	ActionRouteUpdated,
	ActionRouteDeleted,
	ActionAuditViewed,
	ActionPasswordHIBPClean,
	ActionPasswordHIBPPending,
	ActionPasswordCompromisedDetected,
	ActionDNSProviderUpdated,
	ActionForwardAuthProviderUpdated,
	ActionForwardAuthProviderDeleted,
}

// AllActions returns a fresh copy of the canonical Step D action set.
// Used to validate enum cohesion (backend / frontend / tests).
//
// A new slice is returned on every call so callers cannot mutate the
// package-level source of truth.
func AllActions() []string {
	return slices.Clone(allActions)
}
