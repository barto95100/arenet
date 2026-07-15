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
	"bytes"
	"encoding/json"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
	"github.com/caddyserver/caddy/v2"
)

// ovhProviderFixtureID is the stable config ID the O.2 emission tests
// reference from their managed domains, matching the fixture provider
// returned by ovhProvidersFixture. Task 1d: managed domains dispatch by
// ProviderID, so the fixture domain must point at this id.
const ovhProviderFixtureID = "ovh-fixture-id"

// ovhProviderFixture returns a fully-populated DNSProviderConfig
// matching the buildOpts shape callers send when the operator has
// configured OVH credentials. Centralised so changes to the OVH
// shape land in one place across O.2 tests.
func ovhProviderFixture() storage.DNSProviderConfig {
	return storage.DNSProviderConfig{
		ID:                ovhProviderFixtureID,
		Label:             "OVH fixture",
		Type:              storage.DNSProviderTypeOVH,
		Endpoint:          "ovh-eu",
		ApplicationKey:    "ak",
		ApplicationSecret: "as",
		ConsumerKey:       "ck",
	}
}

// ovhProvidersFixture returns the DNSProviders map (keyed by config ID)
// that buildOpts now carries — the Task 1d replacement for the old
// singleton DNSProvider field.
func ovhProvidersFixture() map[string]storage.DNSProviderConfig {
	f := ovhProviderFixture()
	return map[string]storage.DNSProviderConfig{f.ID: f}
}

// tlsRoute is a TLS-enabled route fixture for ACME-policy tests.
// Shared shape avoids drift between O.2 tests. WAFMode is set to
// "off" to mirror the J-era TestBuildConfigJSON_LoadsCleanly_DNS01
// fixture — the WAF module's Provision path otherwise leaks
// Coraza handler state across tests in the same package, breaking
// downstream tests (e.g. TestSyncRegistry_NotCalledOnReloadFailure
// which expects a clean caddy global to reject a bad config).
func tlsRoute(id, host, challenge string, dedicated bool) storage.Route {
	return storage.Route{
		ID:               id,
		Host:             host,
		Upstreams:        []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}},
		LBPolicy:         storage.LBPolicyRoundRobin,
		TLSEnabled:       true,
		ACMEChallenge:    challenge,
		UseDedicatedCert: dedicated,
		WAFMode:          "off",
	}
}

// TestBuildConfigJSON_NoManagedDomains_EqualsStepJ_Bytes is the
// D5.A byte-equality invariant. Same inputs MINUS the
// ManagedDomains field must produce IDENTICAL Caddy JSON. Any
// structural drift in the no-managed-domains code path fails
// here at PR time — the strongest possible regression gate.
//
// The "Step J snapshot" is computed inline rather than persisted
// to testdata because the snapshot drifts naturally as Step J +
// later steps evolve. The invariant is: at any commit, the
// no-managed-domains output is byte-equal to itself across two
// calls that differ ONLY in ManagedDomains. If a future Step
// changes the no-managed-domains baseline, this test still
// passes — what it pins is the SHORT-CIRCUIT, not a fixed value.
func TestBuildConfigJSON_NoManagedDomains_EqualsStepJ_Bytes(t *testing.T) {
	routes := []storage.Route{
		tlsRoute("r1", "app.example.com", "", false),
		tlsRoute("r2", "api.other.com", storage.ACMEChallengeDNS01, false),
	}
	opts := buildOpts{
		DevMode:      true,
		ACMEEmail:    "ops@example.com",
		DNSProviders: ovhProvidersFixture(),
	}

	rawJ, err := buildConfigJSON(routes, opts)
	if err != nil {
		t.Fatalf("buildConfigJSON (J shape): %v", err)
	}

	// Same call with ManagedDomains explicitly set to empty
	// slice (vs nil). Both must produce byte-equal output.
	optsO := opts
	optsO.ManagedDomains = []storage.ManagedDomain{}
	rawO, err := buildConfigJSON(routes, optsO)
	if err != nil {
		t.Fatalf("buildConfigJSON (O empty-slice shape): %v", err)
	}

	if !bytes.Equal(rawJ, rawO) {
		t.Errorf("D5.A invariant broken: empty []ManagedDomains differs from nil\n--- nil ---\n%s\n--- empty ---\n%s",
			rawJ, rawO)
	}
}

// TestBuildConfigJSON_ManagedDomain_EmitsWildcardPolicy pins the
// happy path: one managed domain → one TLS policy with subjects
// ["*.example.com", "example.com"] (IncludeApex=true per D2.C),
// issuer = acme/ovh/dns-01 because OVH is configured.
func TestBuildConfigJSON_ManagedDomain_EmitsWildcardPolicy(t *testing.T) {
	routes := []storage.Route{
		tlsRoute("r1", "app.example.com", storage.ACMEChallengeInherited, false),
	}
	raw, err := buildConfigJSON(routes, buildOpts{
		DevMode:      true,
		ACMEEmail:    "ops@example.com",
		DNSProviders: ovhProvidersFixture(),
		ManagedDomains: []storage.ManagedDomain{
			{Apex: "example.com", IncludeApex: true, ProviderID: ovhProviderFixtureID},
		},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	if len(policies) != 2 {
		t.Fatalf("want 2 policies (wildcard + internal), got %d: %v", len(policies), policies)
	}
	// First policy: the wildcard.
	subjects, _ := policies[0]["subjects"].([]any)
	if len(subjects) != 2 {
		t.Fatalf("policies[0].subjects = %v, want 2 entries (wildcard + apex)", subjects)
	}
	if subjects[0] != "*.example.com" {
		t.Errorf("subjects[0] = %v, want *.example.com", subjects[0])
	}
	if subjects[1] != "example.com" {
		t.Errorf("subjects[1] = %v, want example.com (D2.C IncludeApex)", subjects[1])
	}
	issuers, _ := policies[0]["issuers"].([]any)
	issuer, _ := issuers[0].(map[string]any)
	if issuer["module"] != "acme" {
		t.Errorf("issuer module = %v, want acme", issuer["module"])
	}
	challenges, _ := issuer["challenges"].(map[string]any)
	dns, _ := challenges["dns"].(map[string]any)
	provider, _ := dns["provider"].(map[string]any)
	if provider["name"] != "ovh" {
		t.Errorf("provider.name = %v, want ovh", provider["name"])
	}
	// Second policy: internal catch-all.
	issuers2, _ := policies[1]["issuers"].([]any)
	internalIssuer, _ := issuers2[0].(map[string]any)
	if internalIssuer["module"] != "internal" {
		t.Errorf("catch-all module = %v, want internal", internalIssuer["module"])
	}
}

// TestBuildConfigJSON_ManagedDomain_IncludeApexFalse_OmitsApexSAN
// pins the D2.C operator-toggle path: IncludeApex=false emits a
// single-SAN cert covering only the wildcard.
func TestBuildConfigJSON_ManagedDomain_IncludeApexFalse_OmitsApexSAN(t *testing.T) {
	raw, err := buildConfigJSON(nil, buildOpts{
		DevMode:      true,
		DNSProviders: ovhProvidersFixture(),
		ManagedDomains: []storage.ManagedDomain{
			{Apex: "example.com", IncludeApex: false, ProviderID: ovhProviderFixtureID},
		},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	if len(policies) < 1 {
		t.Fatalf("no policies emitted")
	}
	subjects, _ := policies[0]["subjects"].([]any)
	if len(subjects) != 1 {
		t.Fatalf("subjects = %v, want exactly 1 (IncludeApex=false → wildcard only)", subjects)
	}
	if subjects[0] != "*.example.com" {
		t.Errorf("subjects[0] = %v, want *.example.com", subjects[0])
	}
}

// TestBuildConfigJSON_ManagedDomain_NoProvider_InternalIssuer pins
// the D4.A "loud unconfigured state" invariant: when OVH credentials
// are NOT configured, the wildcard TLS policy still emits (the
// reload doesn't drop the policy), but the issuer is `internal`
// (self-signed via Caddy's local CA) — no silent HTTP-01 fallback,
// no infinite ACME retry loop, no rate-limit damage.
func TestBuildConfigJSON_ManagedDomain_NoProvider_InternalIssuer(t *testing.T) {
	raw, err := buildConfigJSON(nil, buildOpts{
		DevMode: true,
		// DNSProviders intentionally left nil: the managed domain
		// references a ProviderID that resolves to no configured
		// provider, so the dispatch falls back to the internal issuer.
		ManagedDomains: []storage.ManagedDomain{
			{Apex: "example.com", IncludeApex: true, ProviderID: ovhProviderFixtureID},
		},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	if len(policies) < 1 {
		t.Fatalf("no policies emitted")
	}
	subjects, _ := policies[0]["subjects"].([]any)
	if len(subjects) != 2 || subjects[0] != "*.example.com" {
		t.Errorf("subjects = %v, want [*.example.com example.com] (policy still emitted)", subjects)
	}
	issuers, _ := policies[0]["issuers"].([]any)
	issuer, _ := issuers[0].(map[string]any)
	if issuer["module"] != "internal" {
		t.Errorf("issuer module = %v, want internal (D4.A loud unconfigured)", issuer["module"])
	}
}

// TestBuildConfigJSON_MultipleManagedDomains_EmitsAll pins D6.A:
// N managed domains produce N TLS policies, lex-ordered as the
// caller provides them.
func TestBuildConfigJSON_MultipleManagedDomains_EmitsAll(t *testing.T) {
	raw, err := buildConfigJSON(nil, buildOpts{
		DevMode:      true,
		DNSProviders: ovhProvidersFixture(),
		ManagedDomains: []storage.ManagedDomain{
			{Apex: "alpha.com", IncludeApex: true, ProviderID: ovhProviderFixtureID},
			{Apex: "beta.com", IncludeApex: false, ProviderID: ovhProviderFixtureID},
		},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	if len(policies) != 3 {
		t.Fatalf("want 3 policies (2 wildcard + internal), got %d", len(policies))
	}
	subj0, _ := policies[0]["subjects"].([]any)
	if subj0[0] != "*.alpha.com" {
		t.Errorf("policies[0].subjects[0] = %v, want *.alpha.com", subj0[0])
	}
	subj1, _ := policies[1]["subjects"].([]any)
	if subj1[0] != "*.beta.com" || len(subj1) != 1 {
		t.Errorf("policies[1].subjects = %v, want [*.beta.com] (IncludeApex=false)", subj1)
	}
}

// TestBuildConfigJSON_CoveredRoute_SkipsPerRoutePolicy pins the
// central efficiency invariant: a TLS-enabled route whose host is
// covered by a managed domain does NOT contribute to the per-
// route HTTP-01 / DNS-01 partition. The wildcard policy alone
// serves it (one ACME challenge for N routes).
func TestBuildConfigJSON_CoveredRoute_SkipsPerRoutePolicy(t *testing.T) {
	routes := []storage.Route{
		// Three covered routes under one apex.
		tlsRoute("r1", "app.example.com", storage.ACMEChallengeInherited, false),
		tlsRoute("r2", "blog.example.com", storage.ACMEChallengeInherited, false),
		tlsRoute("r3", "api.example.com", storage.ACMEChallengeInherited, false),
	}
	raw, err := buildConfigJSON(routes, buildOpts{
		DevMode:      true,
		DNSProviders: ovhProvidersFixture(),
		ManagedDomains: []storage.ManagedDomain{
			{Apex: "example.com", IncludeApex: true, ProviderID: ovhProviderFixtureID},
		},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	// Expect: wildcard policy + internal. NO per-route HTTP-01
	// or DNS-01 policy.
	if len(policies) != 2 {
		t.Fatalf("want 2 policies (wildcard + internal), got %d (per-route policy leaked?)", len(policies))
	}
	subj, _ := policies[0]["subjects"].([]any)
	if len(subj) != 2 || subj[0] != "*.example.com" {
		t.Errorf("policies[0].subjects = %v, want wildcard for example.com", subj)
	}
}

// TestBuildConfigJSON_CoveredRoute_UsesSkipCertificatesNotSkip pins the
// fix for the Caddy-API misuse in buildSkipList. A managed-domain-covered
// route's host must land in automatic_https.skip_certificates (json
// "skip_certificates"), NOT skip (json "skip").
//
// Semantics (caddy v2.11.3 autohttps.go): "skip" removes the host from
// auto-HTTPS ENTIRELY — no cert management AND no redirect handling —
// and excludes it from the server's domain set. "skip_certificates"
// keeps the host in auto-HTTPS, only suppressing per-host cert
// provisioning (the wildcard already serves the cert). Arenet's intent
// is purely "don't obtain a per-host cert, the wildcard covers it" =
// skip_certificates. Emitting into "skip" is a latent inconsistency
// (it also drops the host's redirect handling from Caddy's auto-HTTPS).
func TestBuildConfigJSON_CoveredRoute_UsesSkipCertificatesNotSkip(t *testing.T) {
	routes := []storage.Route{
		tlsRoute("r1", "app.example.com", storage.ACMEChallengeInherited, false),
	}
	raw, err := buildConfigJSON(routes, buildOpts{
		DevMode:      true,
		DNSProviders: ovhProvidersFixture(),
		ManagedDomains: []storage.ManagedDomain{
			{Apex: "example.com", IncludeApex: true, ProviderID: ovhProviderFixtureID},
		},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	apps := cfg["apps"].(map[string]any)
	httpApp := apps["http"].(map[string]any)
	servers := httpApp["servers"].(map[string]any)
	srv := servers["arenet_https"].(map[string]any)
	ah := srv["automatic_https"].(map[string]any)

	// The covered host must be in skip_certificates.
	skipCerts, hasSkipCerts := ah["skip_certificates"].([]any)
	if !hasSkipCerts {
		t.Fatalf("automatic_https.skip_certificates absent; covered host must land there, got automatic_https = %v", ah)
	}
	if len(skipCerts) != 1 || skipCerts[0] != "app.example.com" {
		t.Errorf("skip_certificates = %v; want [app.example.com]", skipCerts)
	}

	// And it must NOT be in the plain "skip" list (which would also drop
	// redirect handling for the host).
	if skip, hasSkip := ah["skip"]; hasSkip {
		t.Errorf("automatic_https.skip present (%v); covered hosts must use skip_certificates, not skip", skip)
	}
}

// TestBuildConfigJSON_DedicatedOptOut_EmitsPerRoutePolicyBeforeWildcard
// pins D1.B + the load-bearing ORDER invariant: a covered route
// flagged UseDedicatedCert=true emits its OWN per-route ACME
// policy ALONGSIDE the wildcard, and that per-route policy MUST
// precede the wildcard so Caddy's getAutomationPolicyForName
// (first-match) returns the dedicated policy for the opt-out host.
func TestBuildConfigJSON_DedicatedOptOut_EmitsPerRoutePolicyBeforeWildcard(t *testing.T) {
	routes := []storage.Route{
		// Covered + UseDedicatedCert=true → per-route HTTP-01 policy.
		tlsRoute("r-pay", "payments.example.com", "", true),
		// Covered + inherited → wildcard policy.
		tlsRoute("r-app", "app.example.com", storage.ACMEChallengeInherited, false),
	}
	raw, err := buildConfigJSON(routes, buildOpts{
		DevMode:      true,
		DNSProviders: ovhProvidersFixture(),
		ManagedDomains: []storage.ManagedDomain{
			{Apex: "example.com", IncludeApex: true, ProviderID: ovhProviderFixtureID},
		},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	// Expect 3: per-route HTTP-01 (payments) + wildcard + internal.
	if len(policies) != 3 {
		t.Fatalf("want 3 policies (per-route + wildcard + internal), got %d: %v", len(policies), policies)
	}
	// Per-route policy MUST come first.
	subj0, _ := policies[0]["subjects"].([]any)
	if len(subj0) != 1 || subj0[0] != "payments.example.com" {
		t.Errorf("policies[0].subjects = %v, want [payments.example.com] (per-route opt-out first)", subj0)
	}
	subj1, _ := policies[1]["subjects"].([]any)
	if len(subj1) < 1 || subj1[0] != "*.example.com" {
		t.Errorf("policies[1].subjects = %v, want wildcard second", subj1)
	}
}

// TestBuildConfigJSON_UncoveredRoute_UsesPerRoutePolicy pins the
// J carry-forward path: a TLS-enabled route on a host that's NOT
// covered by any managed domain still goes through the J HTTP-01
// / DNS-01 partition unchanged. Anti-regression for AC #15.
func TestBuildConfigJSON_UncoveredRoute_UsesPerRoutePolicy(t *testing.T) {
	routes := []storage.Route{
		tlsRoute("r-app", "app.example.com", "", false), // covered → wildcard
		tlsRoute("r-other", "other.org", "", false),     // uncovered → per-route HTTP-01
	}
	raw, err := buildConfigJSON(routes, buildOpts{
		DevMode:      true,
		DNSProviders: ovhProvidersFixture(),
		ManagedDomains: []storage.ManagedDomain{
			{Apex: "example.com", IncludeApex: true, ProviderID: ovhProviderFixtureID},
		},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	// Expect 3: per-route HTTP-01 for other.org + wildcard + internal.
	if len(policies) != 3 {
		t.Fatalf("want 3 policies, got %d: %v", len(policies), policies)
	}
	subj0, _ := policies[0]["subjects"].([]any)
	if len(subj0) != 1 || subj0[0] != "other.org" {
		t.Errorf("policies[0].subjects = %v, want [other.org] (per-route uncovered first)", subj0)
	}
}

// TestBuildConfigJSON_ManagedDomain_ReloadPreserves pins AC #14:
// the managed-domain TLS policies appear on EVERY reload, not just
// the initial boot. Mirror of TestBuildConfigJSON_WithCrowdSec_ReloadPreserves.
// Two successive calls with the same inputs MUST produce byte-equal
// outputs (deterministic JSON marshalling + no hidden state in the
// emission code).
func TestBuildConfigJSON_ManagedDomain_ReloadPreserves(t *testing.T) {
	opts := buildOpts{
		DevMode:      true,
		DNSProviders: ovhProvidersFixture(),
		ManagedDomains: []storage.ManagedDomain{
			{Apex: "example.com", IncludeApex: true, ProviderID: ovhProviderFixtureID},
		},
	}
	raw1, err := buildConfigJSON(nil, opts)
	if err != nil {
		t.Fatalf("first build: %v", err)
	}
	raw2, err := buildConfigJSON(nil, opts)
	if err != nil {
		t.Fatalf("second build: %v", err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Errorf("AC #14 broken: managed-domain JSON drifts between reloads\n--- 1 ---\n%s\n--- 2 ---\n%s",
			raw1, raw2)
	}
	// And the policy actually appears in the second build.
	policies := readPolicies(t, raw2)
	found := false
	for _, p := range policies {
		subj, _ := p["subjects"].([]any)
		if len(subj) > 0 && subj[0] == "*.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("wildcard policy missing on second reload — bouncer-style silent-drop bug?\n%s", raw2)
	}
}

// TestBuildConfigJSON_ManagedDomain_OVHProviderModuleResolves pins
// the empirical-verification rule from CLAUDE.md for the wildcard
// path: the `dns.providers.ovh` module is registered with Caddy so
// the wildcard policy's `provider.name: "ovh"` resolves at
// Provision time.
//
// We deliberately do NOT call caddy.Validate here. The existing
// TestBuildConfigJSON_LoadsCleanly_DNS01 covers the full
// Validate-with-OVH path in manager_test.go (which runs LATER in
// the suite, after TestSyncRegistry_NotCalledOnReloadFailure,
// so a Validate leak doesn't affect downstream tests). Adding a
// SECOND Validate-touching test in a file that sorts
// alphabetically BEFORE manager_test.go leaks Caddy global state
// into the sync-registry test and breaks it. The module-
// resolution check below catches the same class of bug
// (unknown-module / module-ID drift) without provisioning a
// full Caddy graph.
func TestBuildConfigJSON_ManagedDomain_OVHProviderModuleResolves(t *testing.T) {
	if _, err := caddy.GetModule("dns.providers.ovh"); err != nil {
		t.Fatalf("caddy module `dns.providers.ovh` not registered: %v — managed-domain wildcard issuance would fail at Provision time", err)
	}
	// Sanity: the wildcard policy emits `provider.name: "ovh"`,
	// matching the module ID above. The closed provider-type enum's
	// OVH value must equal that module ID. Drift in either direction
	// (rename the constant OR change the emitted value) surfaces
	// here as a missing-module error when the live smoke runs
	// at O.5.
	if storage.DNSProviderTypeOVH != "ovh" {
		t.Errorf("DNSProviderTypeOVH = %q, want \"ovh\" (must match Caddy module ID)",
			storage.DNSProviderTypeOVH)
	}
}

// TestBuildConfigJSON_InheritedWithoutCoverage_FallsBackToHTTP01 pins
// the defensive fallback: a route persisted as ACMEChallenge=
// "inherited" but whose host is NOT covered by any managed domain
// (programming-error path — storage should never produce this state,
// but defensive handling matters) falls back to HTTP-01 emission so
// the host still gets a cert rather than being silently dropped.
func TestBuildConfigJSON_InheritedWithoutCoverage_FallsBackToHTTP01(t *testing.T) {
	routes := []storage.Route{
		// "inherited" but no covering managed domain.
		tlsRoute("r1", "orphan.example.com", storage.ACMEChallengeInherited, false),
	}
	raw, err := buildConfigJSON(routes, buildOpts{
		DevMode: true,
		// No ManagedDomains.
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	policies := readPolicies(t, raw)
	if len(policies) != 2 {
		t.Fatalf("want 2 policies (HTTP-01 fallback + internal), got %d", len(policies))
	}
	subj, _ := policies[0]["subjects"].([]any)
	if len(subj) != 1 || subj[0] != "orphan.example.com" {
		t.Errorf("policies[0].subjects = %v, want HTTP-01 fallback for orphan host", subj)
	}
	issuers, _ := policies[0]["issuers"].([]any)
	issuer, _ := issuers[0].(map[string]any)
	if issuer["module"] != "acme" {
		t.Errorf("issuer module = %v, want acme (HTTP-01)", issuer["module"])
	}
	// HTTP-01 has no challenges sub-block.
	if _, has := issuer["challenges"]; has {
		t.Errorf("HTTP-01 issuer should have no challenges block, got %v", issuer["challenges"])
	}
}
