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

	// Step K.2 — OIDC admin auth + roles (7)
	ActionOIDCConfigured            = "oidc_configured"
	ActionOIDCUpdated               = "oidc_updated"
	ActionOIDCLoginRejected         = "oidc_login_rejected"
	ActionOIDCCallbackInvalid       = "oidc_callback_invalid"
	ActionLoginBreakGlass           = "login_break_glass"
	ActionLocalAdminPasswordRotated = "local_admin_password_rotated"
	ActionUserRoleChanged           = "user_role_changed"

	// Step K.3 — backup / restore (3). The restore is significantly
	// more destructive than the export; both must be audited and the
	// failure path emits its own dedicated event so a rejected
	// restore is still traceable ("did someone try to take over my
	// instance?" — spec §5.3).
	ActionConfigExported         = "config_exported"
	ActionConfigRestored         = "config_restored"
	ActionConfigRestoredRejected = "config_restored_rejected"

	// Step O.3 — managed-domain CRUD (2). The Created event
	// also carries the count of covered routes whose ACMEChallenge
	// was mutated to "inherited" (D8.A migration), so the audit
	// log records the cross-cutting effect of the operator action.
	// The Deleted event symmetrically carries the count of routes
	// reverted from "inherited" to the operator-chosen revertTo
	// value (AC #21).
	ActionManagedDomainCreated = "managed_domain_created"
	ActionManagedDomainDeleted = "managed_domain_deleted"

	// Step P.3 — auto-classify lifecycle (2). DecisionPushed
	// emitted by the trigger engine's writer goroutine after
	// a successful POST /v1/alerts to LAPI; carries
	// target_id = "<scope>:<value>" + after_json with the
	// scenario, duration, and triggering event ID for
	// operator drill-down. RuleChanged emitted by the
	// PUT /settings/automation/* handlers with before/after
	// JSON (watcher passwords redacted, J.4 pattern).
	ActionAutomationDecisionPushed = "automation_decision_pushed"
	ActionAutomationRuleChanged    = "automation_rule_changed"

	// Step V.4 — server geographic position admin actions.
	// PositionUpdated emitted by PUT /api/v1/observability/
	// server-position when the operator sets a manual override.
	// Carries target_id="default" (single-row bucket key) and
	// before/after JSON with the lat/lon/city/country diff.
	// PositionRedetected emitted by POST /api/v1/observability/
	// server-position:redetect — same target_id, after_json
	// reflects the newly-detected position, before_json
	// reflects whatever was persisted before the redetect.
	ActionServerPositionUpdated    = "server_position_updated"
	ActionServerPositionRedetected = "server_position_redetected"

	// Step CS.1 — CrowdSec bouncer config admin actions.
	// CrowdSecConfigured emitted by PUT /api/v1/settings/crowdsec
	// on the first write (no previous row in storage).
	// CrowdSecUpdated emitted by subsequent PUTs. Both carry
	// before/after JSON with APIKey scrubbed (SECRET — same
	// shape as oidcConfigForAudit / dnsProviderForAudit).
	ActionCrowdSecConfigured = "crowdsec_configured"
	ActionCrowdSecUpdated    = "crowdsec_updated"
	// Step CS.2 follow-up — operator-pressed Reset button on
	// the Settings UI emits this action. Distinct from
	// crowdsec_updated so the audit log makes the deliberate
	// "bouncer disabled" intent visible. BeforeJSON carries
	// the wiped row (APIKey scrubbed); AfterJSON is omitted
	// (the row no longer exists).
	ActionCrowdSecReset = "crowdsec_reset"
	// Step CS.3 Commit C — operator-pressed "Bannir une IP"
	// button on the Décisions actives tab. POST creates a
	// single LAPI alert+decision via the Security Automation
	// machine credentials. Scenario carries "manual:<user>|
	// <reason>". TargetID is the IP/CIDR value;
	// ActorUsernameSnapshot (auto-set by appendAudit)
	// duplicates the username so the audit log is searchable
	// by operator independently of the encoded scenario.
	ActionCrowdSecDecisionCreate = "crowdsec_decision_create"
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
	ActionOIDCConfigured,
	ActionOIDCUpdated,
	ActionOIDCLoginRejected,
	ActionOIDCCallbackInvalid,
	ActionLoginBreakGlass,
	ActionLocalAdminPasswordRotated,
	ActionUserRoleChanged,
	ActionConfigExported,
	ActionConfigRestored,
	ActionConfigRestoredRejected,
	ActionManagedDomainCreated,
	ActionManagedDomainDeleted,
	ActionAutomationDecisionPushed,
	ActionAutomationRuleChanged,
	ActionServerPositionUpdated,
	ActionServerPositionRedetected,
	ActionCrowdSecConfigured,
	ActionCrowdSecUpdated,
	ActionCrowdSecReset,
	ActionCrowdSecDecisionCreate,
}

// AllActions returns a fresh copy of the canonical Step D action set.
// Used to validate enum cohesion (backend / frontend / tests).
//
// A new slice is returned on every call so callers cannot mutate the
// package-level source of truth.
func AllActions() []string {
	return slices.Clone(allActions)
}

// authFailureActions is the canonical set of audit actions that
// represent an authentication-failure event. Listed in Step Q spec
// §1.2 as the source for the /security/auth-failures timeline.
//
// Note: ActionUnlockFailure is included because the unlock flow is
// the same credential surface (it shares the rate limiter); a
// credential-stuffing attack against /unlock looks identical to one
// against /login from an operator perspective.
var authFailureActions = []string{
	ActionLoginFailure,
	ActionUnlockFailure,
	ActionOIDCLoginRejected,
	ActionOIDCCallbackInvalid,
}

// AuthFailureActions returns a fresh copy of the auth-failure action
// set. Used by the Step Q audit-scan path (/security/auth-failures
// handler + /metrics/timeseries?metric=auth_failure_rate detour).
//
// A new slice is returned on every call so callers cannot mutate the
// package-level source of truth.
func AuthFailureActions() []string {
	return slices.Clone(authFailureActions)
}
