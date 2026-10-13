// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// v2.72 — the ban validator checked syntax and nothing else.
//
// net.ParseCIDR accepts 0.0.0.0/0 and net.ParseIP accepts the caller's
// own address, so one mistyped field put every proxied service behind
// a 403 for up to 30 days — and until the unban endpoint existed, the
// only way back was cscli on the host.

func TestClassifyBanTarget(t *testing.T) {
	cases := []struct {
		name           string
		scope          string
		value          string
		callerIP       string
		wantCaller     bool
		wantEverything bool
	}{
		// --- the caller's own address ---
		{"exact own IPv4", "Ip", "203.0.113.9", "203.0.113.9", true, false},
		{"exact own IPv6", "Ip", "2001:db8::1", "2001:db8::1", true, false},
		{
			// A dual-stack listener reports the caller as an
			// IPv4-mapped IPv6 address. net.IP.Equal compares the
			// address rather than the representation, so this matches;
			// a string comparison would have missed the common case.
			"IPv4-mapped IPv6 caller", "Ip", "203.0.113.9", "::ffff:203.0.113.9", true, false,
		},
		{"someone else's IP", "Ip", "198.51.100.7", "203.0.113.9", false, false},
		{"range containing the caller", "Range", "203.0.113.0/24", "203.0.113.9", true, false},
		{"range not containing the caller", "Range", "198.51.100.0/24", "203.0.113.9", false, false},
		{"IPv6 range containing the caller", "Range", "2001:db8::/32", "2001:db8::1", true, false},

		// --- the whole internet ---
		{"IPv4 default route", "Range", "0.0.0.0/0", "203.0.113.9", true, true},
		{"IPv6 default route", "Range", "::/0", "2001:db8::1", true, true},
		{
			// Everything, from a caller the guard cannot identify: the
			// whole-internet half must still fire.
			"IPv4 default route, no caller", "Range", "0.0.0.0/0", "", false, true,
		},
		{"a /1 is wide but not everything", "Range", "0.0.0.0/1", "203.0.113.9", false, false},

		// --- no caller address ---
		{
			// Refusing on an unknown caller would block the feature
			// outright behind a misconfigured proxy.
			"empty caller is skipped, not guessed", "Ip", "203.0.113.9", "", false, false,
		},
		{"garbage caller is skipped", "Ip", "203.0.113.9", "not-an-ip", false, false},
		{
			// Tolerated so a future change of source cannot silently
			// disable the guard.
			"host:port caller still matches", "Ip", "203.0.113.9", "203.0.113.9:54321", true, false,
		},

		// --- nothing to classify ---
		{"unknown scope", "Country", "FR", "203.0.113.9", false, false},
		{"unparseable range", "Range", "not-a-cidr", "203.0.113.9", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyBanTarget(tc.scope, tc.value, tc.callerIP)
			if got.CoversCaller != tc.wantCaller {
				t.Errorf("CoversCaller = %v, want %v", got.CoversCaller, tc.wantCaller)
			}
			if got.CoversEverything != tc.wantEverything {
				t.Errorf("CoversEverything = %v, want %v", got.CoversEverything, tc.wantEverything)
			}
		})
	}
}

// The code and the message have to agree on which half fired, because
// the UI picks its sentence from the code and a non-UI consumer reads
// the message.
func TestBanGuardCodeAndMessageAgree(t *testing.T) {
	caller := banGuardVerdict{CoversCaller: true}
	if banGuardCode(caller) != "crowdsec_ban_covers_caller" {
		t.Errorf("code = %q", banGuardCode(caller))
	}
	if !strings.Contains(banGuardMessage(caller), "connecting from") {
		t.Errorf("message = %q; want it to name the caller's address", banGuardMessage(caller))
	}

	everything := banGuardVerdict{CoversEverything: true}
	if banGuardCode(everything) != "crowdsec_ban_covers_everything" {
		t.Errorf("code = %q", banGuardCode(everything))
	}
	if !strings.Contains(banGuardMessage(everything), "whole internet") {
		t.Errorf("message = %q", banGuardMessage(everything))
	}

	// Both at once: the caller half is the actionable one and wins.
	both := banGuardVerdict{CoversCaller: true, CoversEverything: true}
	if banGuardCode(both) != "crowdsec_ban_covers_caller" {
		t.Errorf("code = %q; want the caller half to win", banGuardCode(both))
	}

	if banGuardCode(banGuardVerdict{}) != "" || banGuardMessage(banGuardVerdict{}) != "" {
		t.Error("a clean verdict must produce no code and no message")
	}
}

// banReq builds a manual-ban request from a given client address.
func banReq(t *testing.T, body, callerIP string) *http.Request {
	t.Helper()
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions",
		"user-uuid", "admin", callerIP, "test")
	req.Body = httpBody(body)
	return req
}

func TestAddManualBan_RefusesTheCallersOwnIP(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)
	appender := &fakeAuditAppender{}
	h := newTestHandler(t, appender, io.Discard)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"203.0.113.9","duration":"1h","type":"ban","reason":"oops"}`
	rec := httptest.NewRecorder()
	h.addManualBan(rec, banReq(t, body, "203.0.113.9"))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	var decoded struct {
		Error  string         `json:"error"`
		Code   string         `json:"code"`
		Params map[string]any `json:"params"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &decoded)
	if decoded.Code != "crowdsec_ban_covers_caller" {
		t.Errorf("code = %q", decoded.Code)
	}
	if decoded.Params["value"] != "203.0.113.9" {
		t.Errorf("params.value = %v", decoded.Params["value"])
	}
	// Nothing left Arenet and nothing is claimed in the audit trail.
	if fake.alertsCalls.Load() != 0 {
		t.Errorf("LAPI was called %d times; a refused ban must not reach it", fake.alertsCalls.Load())
	}
	if len(appender.events) != 0 {
		t.Errorf("audit events = %d, want 0", len(appender.events))
	}
}

func TestAddManualBan_RefusesTheWholeInternet(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)
	h := newTestHandler(t, &fakeAuditAppender{}, io.Discard)
	seedWatcherCredsForBan(t, h, srv.URL)

	// A caller from outside the range would still be covered by it, so
	// use an address the /0 contains to prove the code picks the
	// actionable half.
	body := `{"value":"0.0.0.0/0","duration":"1h","type":"ban","reason":"lockdown"}`
	rec := httptest.NewRecorder()
	h.addManualBan(rec, banReq(t, body, "203.0.113.9"))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	if fake.alertsCalls.Load() != 0 {
		t.Errorf("LAPI was called; a refused ban must not reach it")
	}
}

func TestAddManualBan_ConfirmBypassesAndIsAudited(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)
	appender := &fakeAuditAppender{}
	h := newTestHandler(t, appender, io.Discard)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"203.0.113.9","duration":"1h","type":"ban","reason":"stolen laptop","confirm":true}`
	rec := httptest.NewRecorder()
	h.addManualBan(rec, banReq(t, body, "203.0.113.9"))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	if fake.alertsCalls.Load() != 1 {
		t.Fatalf("LAPI calls = %d, want 1", fake.alertsCalls.Load())
	}
	if len(appender.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(appender.events))
	}
	// The override is the part someone goes looking for after an
	// outage, so it has to be in the trail.
	after := string(appender.events[0].AfterJSON)
	if !strings.Contains(after, `"confirmed":true`) {
		t.Errorf("audit payload does not record the override: %s", after)
	}
}

func TestAddManualBan_OrdinaryBanIsUnaffected(t *testing.T) {
	// The guard must not add friction to the normal case: a single
	// address that is not the operator's own goes straight through,
	// with no confirmed flag in the trail.
	fake := newFakeLAPIForBan()
	srv := fake.server(t)
	appender := &fakeAuditAppender{}
	h := newTestHandler(t, appender, io.Discard)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"198.51.100.7","duration":"1h","type":"ban","reason":"ssh brute force"}`
	rec := httptest.NewRecorder()
	h.addManualBan(rec, banReq(t, body, "203.0.113.9"))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(string(appender.events[0].AfterJSON), `"confirmed"`) {
		t.Errorf("an ordinary ban must not be recorded as confirmed: %s",
			appender.events[0].AfterJSON)
	}
}
