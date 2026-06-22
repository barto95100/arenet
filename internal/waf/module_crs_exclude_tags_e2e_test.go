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

package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Step X Option (e) — empirical end-to-end smoke for the
// per-route tag exclusion emit shape.
//
// The unit tests in internal/caddymgr/manager_waf_per_route_test.go
// pin the SecAction directive string the manager emits. The wire
// tests in internal/api/routes_waf_exclude_tags_wire_test.go pin
// the HTTP-side roundtrip. This file closes the runtime loop :
// provision a real coraza.WAF with the actual CRS v4.25.0 rules
// loaded + the SecAction shape the manager emits, then drive
// httptest requests through ArenetWafHandler.ServeHTTP and assert
// the runtime behaviour.
//
// CRS audit (rules selected empirically against v4.25.0) :
//
//   - 920170 : "GET or HEAD Request with Body Content".
//     SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" chain w/
//     REQUEST_HEADERS:Content-Length "!@rx ^0?$". Tagged
//     attack-protocol, paranoia-level/1, severity CRITICAL,
//     phase:1. Deterministic trigger : GET request with a
//     non-zero Content-Length + body. Reliable.
//
//   - 942100 : "@detectSQLi" libinjection on ARGS|cookies|UA.
//     Tagged attack-sqli, paranoia-level/1, severity CRITICAL,
//     phase:2. Deterministic trigger : ?id=1' OR '1'='1 in
//     query string. Reliable. Different tag from 920170 —
//     used as the control "non-excluded rule still fires"
//     for CAS 2.
//
// The SecAction injection mirrors the manager's emit shape
// at internal/caddymgr/manager.go:2526-2553 (id:999001,
// phase:1, pass, nolog, interleaved ctl:ruleRemoveById +
// ctl:ruleRemoveByTag, canonical order).

const crsAndExcludeBase = "Include @coraza.conf-recommended\n" +
	"Include @crs-setup.conf.example\n" +
	"Include @owasp_crs/*.conf"

// newCRSHandlerWithExcludeDirectives provisions a handler
// whose Directives field carries the per-route SecAction
// PREPENDED before the CRS Includes, mirroring the manager's
// emit order at caddymgr/manager.go:2540-2576. extra is the
// per-route SecAction string (or "" when no exclusion is
// configured — the no-exclusion baseline).
//
// Ordering matters : Coraza evaluates phase:1 rules in load
// order. A ctl:ruleRemove* action that runs AFTER its target
// rule has already fired is a no-op for the current
// transaction (event already emitted, request already
// blocked). The 2026-06-22 X (e) empirical smoke proved
// the prepend-vs-append distinction is load-bearing : with
// the SecAction appended, both ctl:ruleRemoveById and
// ctl:ruleRemoveByTag failed to bypass rule 920170 ; with
// the SecAction prepended, both pass.
func newCRSHandlerWithExcludeDirectives(t *testing.T, mode string, extraSecAction string) *ArenetWafHandler {
	t.Helper()
	dirs := crsAndExcludeBase
	if extraSecAction != "" {
		dirs = extraSecAction + "\n" + crsAndExcludeBase
	}
	h := &ArenetWafHandler{
		RouteID:      "r-exclude-tags-e2e",
		Mode:         mode,
		Directives:   dirs,
		LoadOWASPCRS: true,
	}
	if err := h.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v (provision must succeed — the SecAction directive shape MUST parse against coraza + CRS v4.25.0)", err)
	}
	t.Cleanup(func() { _ = h.Cleanup() })
	return h
}

// requestGETWithBody fabricates the canonical 920170 trigger
// shape : GET with a non-zero Content-Length + body content.
// httptest.NewRequest doesn't auto-set Content-Length on
// GET so we attach it explicitly.
func requestGETWithBody(t *testing.T) *http.Request {
	t.Helper()
	body := strings.NewReader("hello")
	req := httptest.NewRequest(http.MethodGet, "http://localhost/probe", body)
	req.Header.Set("Content-Length", "5")
	return req
}

// requestSQLiQuery fabricates the canonical 942100 trigger
// shape : libinjection-detectable SQLi payload in the query
// string ?id=...
func requestSQLiQuery() *http.Request {
	return httptest.NewRequest(
		http.MethodPost,
		"http://localhost/login?id=1%27%20OR%20%271%27=%271",
		nil,
	)
}

// --- CAS 1 — Baseline : route without WAFExcludeTags ----------
//
// With CRS loaded and NO exclusion directive, a GET-with-body
// request MUST trigger 920170 + at least one event MUST land on
// the sink. Pins the empirical pre-condition : the rule is
// actually active in the WAF's evaluation set when no
// exclusion is configured.

func TestExcludeTags_CAS1_Baseline_GETWithBodyTriggers920170(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newCRSHandlerWithExcludeDirectives(t, "block", "")
	next := &passthroughHandler{}
	req := requestGETWithBody(t)
	rec := httptest.NewRecorder()
	_ = h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP))

	// 920170 is anomaly-mode by default in CRS v4.25.0 —
	// at paranoia-level/1 + critical-anomaly-score (5) the
	// inbound score reaches 5 which is BELOW the default
	// blocking threshold (5 — equal does not trip 949110's
	// "@ge 5"; CRS uses >, not >=). The acceptance criterion
	// for CAS 1 is therefore "the rule's match emits a WAF
	// event", not "the request is blocked" — the empirical
	// invariant we care about is "920170 is in the evaluation
	// set when no exclusion is configured".
	if cap.eventCount() == 0 {
		t.Errorf("CAS 1 baseline failed : expected at least 1 WAF event from rule 920170 ; got 0 (the rule is not firing — the test setup is broken before X (e) can be evaluated)")
	}
	// Spot-check : at least one of the events should be the
	// 920170 match. The event's RuleID is the integer ID.
	found920170 := false
	for _, e := range cap.eventsCopy() {
		if e.RuleID == "920170" {
			found920170 = true
			break
		}
	}
	if !found920170 {
		t.Errorf("CAS 1 baseline : no 920170 event found ; events=%+v", cap.eventsCopy())
	}
}

// --- CAS 2 — WAFExcludeTags=["attack-protocol"] --------------
//
// The same GET-with-body request must NOT trigger 920170 when
// the SecAction excludes ctl:ruleRemoveByTag=attack-protocol.
// And a SECOND request carrying a SQLi payload (tag attack-sqli,
// different family) MUST still trigger 942100 — the exclusion
// scope is tag-precise, not a blanket disable.

func TestExcludeTags_CAS2_TagExcluded_GETWithBodyBypassed(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	// Mirror the manager's emit shape verbatim (no rule IDs,
	// single tag). Quote shape MUST match what caddymgr writes.
	excludeDirective := `SecAction "id:999001,phase:1,pass,nolog,ctl:ruleRemoveByTag=attack-protocol"`
	h := newCRSHandlerWithExcludeDirectives(t, "block", excludeDirective)
	next := &passthroughHandler{}

	req := requestGETWithBody(t)
	rec := httptest.NewRecorder()
	_ = h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP))

	// The attack-protocol family is removed from this
	// transaction's evaluation set, so 920170 MUST NOT fire.
	for _, e := range cap.eventsCopy() {
		if e.RuleID == "920170" {
			t.Errorf("CAS 2 : rule 920170 (tag attack-protocol) STILL fired despite ctl:ruleRemoveByTag=attack-protocol exclusion ; events=%+v", cap.eventsCopy())
		}
	}
	// Note we don't assert eventCount()==0 — there are 921xxx
	// rules that share the attack-protocol tag but the GET-
	// with-body shape doesn't trigger them ; if a future CRS
	// adds an attack-protocol rule that fires on this same
	// shape and the tag exclusion fails on it, the loop above
	// would catch it (assertion is per-RuleID, not bulk).
}

func TestExcludeTags_CAS2_TagExcluded_SQLiStillFires(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	// Same exclusion as the test above ; assert the scope
	// is precise — attack-sqli (different family) is NOT
	// excluded so 942100 MUST still fire.
	excludeDirective := `SecAction "id:999001,phase:1,pass,nolog,ctl:ruleRemoveByTag=attack-protocol"`
	h := newCRSHandlerWithExcludeDirectives(t, "block", excludeDirective)
	next := &passthroughHandler{}

	req := requestSQLiQuery()
	rec := httptest.NewRecorder()
	_ = h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP))

	if cap.eventCount() == 0 {
		t.Errorf("CAS 2 control : SQLi probe (tag attack-sqli, NOT in the exclusion) produced 0 events — the tag exclusion silently widened beyond attack-protocol")
	}
	found942100 := false
	for _, e := range cap.eventsCopy() {
		if e.RuleID == "942100" {
			found942100 = true
			break
		}
	}
	if !found942100 {
		t.Errorf("CAS 2 control : rule 942100 (tag attack-sqli) did NOT fire on a deterministic SQLi probe ; events=%+v", cap.eventsCopy())
	}
}

// --- Step X (c) regression guard — pin the prepend ordering --
//
// Step X (c) ctl:ruleRemoveById was shipped in v2.3.0 (commit
// a133a53) with an append-after-CRS-Includes emit order. Empirical
// X (e) smoke 2026-06-22 revealed this was a latent runtime bug :
// the ctl: action ran after its target rule had already fired,
// so per-rule exclusions were silently no-ops. The caddymgr emit
// fix moved the SecAction BEFORE the CRS Includes. This test
// pins the post-fix runtime behaviour : ctl:ruleRemoveById=920170
// MUST actually bypass rule 920170 on a GET-with-body request.

func TestExcludeTags_XcRegression_ExcludeByID_GETWithBodyBypassed(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	// Same SecAction shape Step X (c) emits when a route
	// carries WAFExcludeRules=[920170], without any tag
	// exclusion. Pre-fix : 920170 still fired despite this
	// directive. Post-fix : the rule is removed from the
	// transaction's evaluation set before phase:1 reaches it.
	excludeDirective := `SecAction "id:999001,phase:1,pass,nolog,ctl:ruleRemoveById=920170"`
	h := newCRSHandlerWithExcludeDirectives(t, "block", excludeDirective)
	next := &passthroughHandler{}

	req := requestGETWithBody(t)
	rec := httptest.NewRecorder()
	_ = h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP))

	for _, e := range cap.eventsCopy() {
		if e.RuleID == "920170" {
			t.Errorf("Step X (c) regression : rule 920170 STILL fired despite ctl:ruleRemoveById=920170 ; the per-route SecAction is back to being appended after the CRS Includes. events=%+v", cap.eventsCopy())
		}
	}
}

// --- CAS 3 — Combined wafExcludeRules + wafExcludeTags --------
//
// The manager interleaves ctl:ruleRemoveById and
// ctl:ruleRemoveByTag in the SAME SecAction id:999001 (one
// directive line, canonical order : rules ASC int, then tags
// alpha). The runtime behaviour MUST be the union of both
// exclusions :
//   - rule 942100 (excluded by ID) does NOT fire on SQLi
//   - rule 920170 (excluded by tag attack-protocol) does NOT
//     fire on GET-with-body
//   - and the directive shape MUST parse + provision cleanly
//     (no Coraza syntax error from the comma-separated ctl chain).

func TestExcludeTags_CAS3_CombinedRulesAndTags_BothBypassed(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	// The exact directive shape the manager emits when a
	// route carries WAFExcludeRules=[942100] +
	// WAFExcludeTags=["attack-protocol"]. Canonical order :
	// rule IDs ASC int first, then tags alpha.
	excludeDirective := `SecAction "id:999001,phase:1,pass,nolog,ctl:ruleRemoveById=942100,ctl:ruleRemoveByTag=attack-protocol"`
	h := newCRSHandlerWithExcludeDirectives(t, "block", excludeDirective)
	next := &passthroughHandler{}

	// Probe 1 : GET-with-body — attack-protocol family
	// excluded by TAG.
	req1 := requestGETWithBody(t)
	rec1 := httptest.NewRecorder()
	_ = h.ServeHTTP(rec1, req1, caddyhttp.HandlerFunc(next.ServeHTTP))
	for _, e := range cap.eventsCopy() {
		if e.RuleID == "920170" {
			t.Errorf("CAS 3 : rule 920170 (tag attack-protocol) STILL fired despite combined exclusion ; events=%+v", cap.eventsCopy())
		}
	}

	// Reset the capture sink between probes so probe 2's
	// assertion is independent.
	cap2 := newCaptureSink()
	setGlobalSinkFor(t, cap2)

	// Probe 2 : SQLi — 942100 excluded by RULE ID.
	req2 := requestSQLiQuery()
	rec2 := httptest.NewRecorder()
	_ = h.ServeHTTP(rec2, req2, caddyhttp.HandlerFunc(next.ServeHTTP))
	for _, e := range cap2.eventsCopy() {
		if e.RuleID == "942100" {
			t.Errorf("CAS 3 : rule 942100 (excluded by ID) STILL fired despite ctl:ruleRemoveById=942100 ; events=%+v", cap2.eventsCopy())
		}
	}
}
