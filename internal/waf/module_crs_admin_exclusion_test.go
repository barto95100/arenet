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
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Item 1 (#R-WAF-FP-uuid-paths) — CRS false-positive guard
// for admin API UUID paths.
//
// DETECT-mode smoke on 2026-06-08 caught CRS LFI / PROTOCOL
// / anomaly rules triggering on PUT /api/v1/routes/<UUID>
// (the hex-with-hyphens UUID happens to look like
// path-traversal-shaped input to rules 930120 / 931100 /
// 949110 / 911100). Switching the admin-side WAF to
// block mode without an exclusion would 403 every
// legitimate operator PUT/DELETE.
//
// adminAPIUUIDExclusionDirective injects a SecRule at
// phase:1 that removes those rule families on UUID-shaped
// admin API paths via ctl:ruleRemoveById. These tests
// pin (a) the exclusion fires on the admin API UUID
// pattern, (b) non-admin or non-UUID paths still face the
// full rule set.

// adminAPIDirectives composes the production directive
// chain the caddymgr emits at runtime (mirror of
// internal/caddymgr/manager.go's buildWAFHandler emit),
// so the exclusion is tested in its real placement
// relative to the CRS includes and the SecRuleEngine
// directive. The handler's buildWAF then appends
// adminAPIUUIDExclusionDirective + the SecRuleEngine
// trailer.
const adminAPIDirectives = "Include @coraza.conf-recommended\n" +
	"Include @crs-setup.conf.example\n" +
	"Include @owasp_crs/*.conf"

// newCRSProvisionedHandler builds a real-CRS-loaded
// handler so the rule families the exclusion targets are
// actually in the WAF's evaluation set. Reused by the
// two integration tests below; not a generic helper
// because the full CRS load is ~50 ms (vs ~1 ms for the
// minimalBlockDirectives path the existing tests use).
func newCRSProvisionedHandler(t *testing.T, mode string) *ArenetWafHandler {
	t.Helper()
	h := &ArenetWafHandler{
		RouteID:      "r-admin",
		Mode:         mode,
		Directives:   adminAPIDirectives,
		LoadOWASPCRS: true,
	}
	if err := h.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = h.Cleanup() })
	return h
}

// TestAdminAPIUUIDPath_BypassesCRSLFIRules — PUT to
// /api/v1/routes/<uuid> with a no-body request must NOT
// trigger any CRS rule. Pre-fix the UUID's hex-and-hyphen
// composition triggered 930120 (LFI restricted-file
// access); post-fix the phase:1 exclusion rule strips
// rules 930000-930999 + 931000-931999 + 949000-949999 +
// 911100-911199 from the transaction's scope on this URI.
func TestAdminAPIUUIDPath_BypassesCRSLFIRules(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newCRSProvisionedHandler(t, "block")
	next := &passthroughHandler{}

	// The smoke-observed false-positive URI shape.
	req := httptest.NewRequest(
		http.MethodPut,
		"http://localhost/api/v1/routes/2db59ddf-54a4-43f9-aa72-1eaed37a357a",
		nil,
	)
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP)); err != nil {
		t.Fatalf("ServeHTTP returned err: %v (the admin-path exclusion is supposed to keep the request alive)", err)
	}

	// The request must reach the upstream — no 403, no
	// interruption from the LFI / anomaly families. The
	// passthroughHandler writes 200.
	if !next.called {
		t.Error("next handler was NOT called — the admin-API UUID exclusion failed to bypass CRS")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; want 200 (admin-API UUID path should pass CRS unchallenged)", rec.Code)
	}

	// And NO rule should have emitted an event. A
	// surviving event would mean either (a) the exclusion
	// didn't fire, or (b) it fired but a non-excluded rule
	// family caught the URI (which would be a separate
	// issue to investigate).
	if cap.eventCount() != 0 {
		t.Errorf("expected 0 WAF events on admin-API UUID PUT; got %d (events: %+v)", cap.eventCount(), cap.eventsCopy())
	}
}

// TestAdminAPISettingsUUIDPath_BypassesCRS — same as
// routes/ above but for /api/v1/settings/<uuid>, the
// second arm of the admin-API exclusion pattern.
func TestAdminAPISettingsUUIDPath_BypassesCRS(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newCRSProvisionedHandler(t, "block")
	next := &passthroughHandler{}

	req := httptest.NewRequest(
		http.MethodPut,
		"http://localhost/api/v1/settings/abcdef12-3456-7890-abcd-ef1234567890",
		nil,
	)
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP)); err != nil {
		t.Fatalf("ServeHTTP returned err: %v", err)
	}
	if !next.called {
		t.Error("next handler was NOT called for /settings/<uuid>")
	}
	if cap.eventCount() != 0 {
		t.Errorf("expected 0 WAF events on admin-API UUID settings PUT; got %d", cap.eventCount())
	}
}

// TestAdminAPI_NoUUIDPath_FullCRSStillApplies — pin the
// exclusion's narrowness: paths NOT matching the UUID
// pattern still get the full CRS treatment. Without this
// guard, a future tightening of the exclusion regex
// could silently widen the bypass to legitimate attack
// targets.
//
// We hit the WAF with a textbook LFI probe (../../../etc/
// passwd) against a path that does NOT match the admin-
// UUID pattern. Rule 930120 (LFI restricted file access)
// should fire and the WAF should block.
func TestAdminAPI_NoUUIDPath_FullCRSStillApplies(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newCRSProvisionedHandler(t, "block")
	next := &passthroughHandler{}

	// Path is /api/v1/routes (no UUID) — does NOT match
	// the exclusion. Query string carries an LFI payload
	// that CRS rule 930120 (or similar) should catch.
	req := httptest.NewRequest(
		http.MethodGet,
		"http://localhost/api/v1/routes?file=../../../etc/passwd",
		nil,
	)
	rec := httptest.NewRecorder()
	_ = h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP))

	// We don't assert a specific status code here — the
	// CRS evaluation may interrupt at different phases
	// depending on the precise rule that catches the
	// payload. The invariant is "the WAF emitted at least
	// one event AND the upstream was NOT reached", proving
	// the exclusion didn't silently widen.
	if next.called {
		t.Error("upstream was reached on non-admin-UUID LFI probe; the exclusion widened beyond the intended scope")
	}
	if cap.eventCount() == 0 {
		t.Error("expected at least one WAF event on the LFI probe against a non-UUID path; got 0 (CRS rules not applying outside the exclusion?)")
	}
}

// TestAdminAPI_UUIDPath_SQLiStillObserved_ButDoesNotBlock
// pins the design trade-off: the admin API is fully
// trusted (operator-only authenticated surface), so
// removing the 949xxx anomaly-aggregator family on UUID
// paths suppresses blocking even for non-LFI attack
// shapes. Individual rule families like 942xxx (SQLi)
// still EMIT events (so the activity log records the
// shape for forensics), but without the 949xxx
// aggregator no transaction reaches the "block now"
// decision.
//
// This is the trade-off the brief made explicit: "admin
// API trusted, no end-user input". An operator running
// SQLi against their own routes API is logging into
// their own infrastructure — the WAF isn't the right
// gate (auth + RBAC are).
//
// Pins: SQLi rules still fire (events visible in the
// activity log) but the request passes through to the
// upstream — handing the blocking responsibility to the
// auth + RBAC layers further down the chain.
func TestAdminAPI_UUIDPath_SQLiStillObserved_ButDoesNotBlock(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newCRSProvisionedHandler(t, "block")
	next := &passthroughHandler{}

	req := httptest.NewRequest(
		http.MethodGet,
		"http://localhost/api/v1/routes/2db59ddf-54a4-43f9-aa72-1eaed37a357a?q=%27+OR+1%3D1+--+",
		nil,
	)
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP)); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	// Request reached the upstream (admin API is trusted;
	// auth/RBAC are the real gates downstream).
	if !next.called {
		t.Error("admin-UUID SQLi probe was blocked — expected the admin-trust trade-off to let it through")
	}
	// Individual SQLi rule family (942xxx) still emitted
	// events — operators see the attempt in the activity
	// log even though the WAF doesn't block. Forensic
	// visibility preserved.
	if cap.eventCount() == 0 {
		t.Error("expected at least one SQLi-family event for forensic visibility; got 0")
	}
}
