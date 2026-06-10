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

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// --- Unit: validators -----------------------------------------

func TestValidateManualBanValue_IPv4(t *testing.T) {
	scope, value, err := validateManualBanValue("203.0.113.42")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if scope != "Ip" || value != "203.0.113.42" {
		t.Errorf("scope=%q value=%q, want Ip + 203.0.113.42", scope, value)
	}
}

func TestValidateManualBanValue_IPv6(t *testing.T) {
	scope, value, err := validateManualBanValue("2001:db8::42")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if scope != "Ip" || value != "2001:db8::42" {
		t.Errorf("scope=%q value=%q, want Ip + 2001:db8::42", scope, value)
	}
}

func TestValidateManualBanValue_CIDRv4(t *testing.T) {
	// Non-canonical input gets normalised by net.ParseCIDR.
	scope, value, err := validateManualBanValue("10.0.0.1/8")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if scope != "Range" || value != "10.0.0.0/8" {
		t.Errorf("scope=%q value=%q, want Range + 10.0.0.0/8 (canonicalised)", scope, value)
	}
}

func TestValidateManualBanValue_CIDRv6(t *testing.T) {
	scope, value, err := validateManualBanValue("2001:db8::/32")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if scope != "Range" || value != "2001:db8::/32" {
		t.Errorf("scope=%q value=%q, want Range + 2001:db8::/32", scope, value)
	}
}

func TestValidateManualBanValue_Rejects(t *testing.T) {
	for _, raw := range []string{
		"",
		"   ",
		"not-an-ip",
		"999.999.999.999",
		"10.0.0.0/33", // bad mask
		"hello/world",
	} {
		t.Run(raw, func(t *testing.T) {
			_, _, err := validateManualBanValue(raw)
			if err == nil {
				t.Errorf("expected error for %q", raw)
			}
		})
	}
}

func TestValidateManualBanDuration(t *testing.T) {
	for _, tt := range []struct {
		raw     string
		wantErr bool
	}{
		{"1h", false},
		{"4h", false},
		{"24h", false},
		{"7d", false},
		{"30d", false},
		{"1h30m", false},
		{"", true},
		{"-1h", true},
		{"0s", true},
		{"forever", true},
		{"abc", true},
	} {
		t.Run(tt.raw, func(t *testing.T) {
			err := validateManualBanDuration(tt.raw)
			if tt.wantErr && err == nil {
				t.Errorf("expected error for %q", tt.raw)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tt.raw, err)
			}
		})
	}
}

func TestValidateManualBanType(t *testing.T) {
	for _, ok := range []string{"ban", "captcha", "throttle"} {
		got, err := validateManualBanType(ok)
		if err != nil || got != ok {
			t.Errorf("type %q: got (%q, %v), want (%q, nil)", ok, got, err, ok)
		}
	}
	for _, bad := range []string{"", "delete", "BAN", "ban "} {
		if bad == "ban " {
			// trimmed by validateManualBanType — should be accepted.
			got, err := validateManualBanType(bad)
			if err != nil || got != "ban" {
				t.Errorf("type %q (whitespace): got (%q, %v)", bad, got, err)
			}
			continue
		}
		if _, err := validateManualBanType(bad); err == nil {
			t.Errorf("type %q should be rejected", bad)
		}
	}
}

func TestValidateManualBanReason(t *testing.T) {
	ok, err := validateManualBanReason("smoke test ban")
	if err != nil || ok != "smoke test ban" {
		t.Errorf("got (%q, %v)", ok, err)
	}
	if _, err := validateManualBanReason(""); err == nil {
		t.Error("empty reason should be rejected")
	}
	if _, err := validateManualBanReason("   "); err == nil {
		t.Error("whitespace-only reason should be rejected")
	}
	long := strings.Repeat("x", crowdSecManualBanReasonMaxLen+1)
	if _, err := validateManualBanReason(long); err == nil {
		t.Error("over-cap reason should be rejected")
	}
	if _, err := validateManualBanReason("has\x00null"); err == nil {
		t.Error("non-printable reason should be rejected")
	}
	// Pipes ALLOWED in reason — they ride through to the
	// frontend parser which splits on the FIRST pipe.
	if _, err := validateManualBanReason("contains | pipe"); err != nil {
		t.Errorf("pipes in reason should be allowed: %v", err)
	}
}

func TestBuildManualBanScenario_FormatPinned(t *testing.T) {
	got := buildManualBanScenario("admin", "smoke test")
	want := "manual:admin|smoke test"
	if got != want {
		t.Errorf("scenario = %q, want %q", got, want)
	}
}

func TestParseLAPIDuration_DSuffix(t *testing.T) {
	d, err := parseLAPIDuration("7d")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if d != 7*24*time.Hour {
		t.Errorf("got %v, want 168h", d)
	}
}

// --- Integration: addManualBan handler ------------------------

// fakeLAPIForBan is a focused fake LAPI exposing /v1/watchers/
// login + POST /v1/alerts. Records the POST body so tests can
// assert payload shape.
type fakeLAPIForBan struct {
	loginCalls   atomic.Int32
	alertsCalls  atomic.Int32
	alertsHandler http.HandlerFunc
	loginHandler  http.HandlerFunc
	lastBody     atomic.Value // string
}

func newFakeLAPIForBan() *fakeLAPIForBan {
	f := &fakeLAPIForBan{}
	f.lastBody.Store("")
	return f
}

func (f *fakeLAPIForBan) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		f.loginCalls.Add(1)
		if f.loginHandler != nil {
			f.loginHandler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"token":"jwt-ok","expire":"` +
			time.Now().Add(1*time.Hour).UTC().Format(time.RFC3339) + `"}`))
	})
	mux.HandleFunc("/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		f.alertsCalls.Add(1)
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			f.lastBody.Store(string(body))
		}
		if f.alertsHandler != nil {
			f.alertsHandler(w, r)
			return
		}
		// Default: 201 Created.
		w.WriteHeader(http.StatusCreated)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func seedWatcherCredsForBan(t *testing.T, h *Handler, lapiURL string) {
	t.Helper()
	if err := h.store.PutWatcherCredentials(context.Background(), storage.WatcherCredentials{
		LAPIURL:   lapiURL,
		MachineID: "arenet-test",
		Password:  "watcher-secret",
	}); err != nil {
		t.Fatalf("seed creds: %v", err)
	}
}

func TestAddManualBan_HappyPath_IP(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)

	var logBuf bytes.Buffer
	appender := &fakeAuditAppender{}
	h := newTestHandler(t, appender, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"203.0.113.42","duration":"1h","type":"ban","reason":"smoke test ban"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "user-uuid", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}

	// Response echo.
	var resp manualBanResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Scenario != "manual:admin|smoke test ban" {
		t.Errorf("Scenario = %q, want manual:admin|smoke test ban", resp.Scenario)
	}
	if resp.Scope != "Ip" {
		t.Errorf("Scope = %q, want Ip", resp.Scope)
	}
	if resp.Value != "203.0.113.42" {
		t.Errorf("Value = %q, want 203.0.113.42", resp.Value)
	}
	if resp.Type != "ban" {
		t.Errorf("Type = %q", resp.Type)
	}
	if resp.Origin != "manual" {
		t.Errorf("Origin = %q, want manual", resp.Origin)
	}
	if resp.ExpiresAt == "" {
		t.Errorf("ExpiresAt empty; should echo expiry")
	}

	// LAPI received the payload.
	lastBody := fake.lastBody.Load().(string)
	if !strings.Contains(lastBody, `"scenario":"manual:admin|smoke test ban"`) {
		t.Errorf("LAPI payload missing scenario: %s", lastBody)
	}
	if !strings.Contains(lastBody, `"origin":"manual"`) {
		t.Errorf("LAPI payload missing origin: %s", lastBody)
	}
	if !strings.Contains(lastBody, `"scope":"Ip"`) {
		t.Errorf("LAPI payload missing scope Ip: %s", lastBody)
	}
	if !strings.Contains(lastBody, `"value":"203.0.113.42"`) {
		t.Errorf("LAPI payload missing value: %s", lastBody)
	}
	if !strings.Contains(lastBody, `"message":"smoke test ban"`) {
		t.Errorf("LAPI payload missing message: %s", lastBody)
	}
	if !strings.Contains(lastBody, `"duration":"1h"`) {
		t.Errorf("LAPI payload missing duration: %s", lastBody)
	}

	// Audit emitted.
	events := appender.Events()
	if len(events) != 1 {
		t.Fatalf("audit count = %d, want 1", len(events))
	}
	evt := events[0]
	if evt.Action != audit.ActionCrowdSecDecisionCreate {
		t.Errorf("audit action = %q, want %q", evt.Action, audit.ActionCrowdSecDecisionCreate)
	}
	if evt.TargetID != "203.0.113.42" {
		t.Errorf("audit target_id = %q, want 203.0.113.42", evt.TargetID)
	}
	if !strings.Contains(string(evt.AfterJSON), "manual:admin|smoke test ban") {
		t.Errorf("audit after_json missing scenario: %s", evt.AfterJSON)
	}
}

func TestAddManualBan_HappyPath_CIDR_CanonicalisedAndScopeRange(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"10.5.6.7/16","duration":"24h","type":"ban","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp manualBanResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Scope != "Range" || resp.Value != "10.5.0.0/16" {
		t.Errorf("Scope/Value = (%q, %q), want (Range, 10.5.0.0/16 canonicalised)", resp.Scope, resp.Value)
	}
}

func TestAddManualBan_NotConfigured_Returns412(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	// Don't seed credentials.

	body := `{"value":"1.1.1.1","duration":"1h","type":"ban","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusPreconditionFailed {
		t.Errorf("status = %d, want 412, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Security Automation") {
		t.Errorf("body lacks Security Automation hint: %s", rec.Body.String())
	}
}

func TestAddManualBan_BadJSON_Returns400(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(`{not json`)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestAddManualBan_BadIP_Returns400(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"not-an-ip","duration":"1h","type":"ban","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if fake.alertsCalls.Load() != 0 {
		t.Errorf("LAPI alerts hit despite validation failure: %d", fake.alertsCalls.Load())
	}
}

func TestAddManualBan_BadType_Returns400(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"1.1.1.1","duration":"1h","type":"delete","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestAddManualBan_LAPILoginRejected_Returns502_AfterRetry(t *testing.T) {
	fake := newFakeLAPIForBan()
	fake.loginHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"1.1.1.1","duration":"1h","type":"ban","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "machine credentials rejected") {
		t.Errorf("body lacks credential-rejected msg: %s", rec.Body.String())
	}
}

func TestAddManualBan_LAPIPost401_RetriesOnce_Success(t *testing.T) {
	fake := newFakeLAPIForBan()
	var postHits atomic.Int32
	fake.alertsHandler = func(w http.ResponseWriter, r *http.Request) {
		hit := postHits.Add(1)
		if hit == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"1.1.1.1","duration":"1h","type":"ban","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 after retry, body=%s", rec.Code, rec.Body.String())
	}
	if got := fake.loginCalls.Load(); got != 2 {
		t.Errorf("login calls = %d, want 2 (initial + retry)", got)
	}
	if got := postHits.Load(); got != 2 {
		t.Errorf("post hits = %d, want 2 (first 401 + retry success)", got)
	}
}

func TestAddManualBan_LAPIPost401Twice_Returns502_NoLoop(t *testing.T) {
	fake := newFakeLAPIForBan()
	fake.alertsHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"1.1.1.1","duration":"1h","type":"ban","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if got := fake.loginCalls.Load(); got != 2 {
		t.Errorf("login calls = %d, want exactly 2 (no loop)", got)
	}
	if got := fake.alertsCalls.Load(); got != 2 {
		t.Errorf("alerts attempts = %d, want exactly 2 (no loop)", got)
	}
}

func TestAddManualBan_LAPIRefused_Returns502(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	// Bad creds pointing at an unbound port.
	if err := h.store.PutWatcherCredentials(context.Background(), storage.WatcherCredentials{
		LAPIURL: "http://127.0.0.1:1", MachineID: "arenet", Password: "x",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_ = h.store.PutCrowdSecConfig(context.Background(), storage.CrowdSecConfig{
		LAPIURL: "http://127.0.0.1:1", APIKey: "k", BouncerName: "arenet", TimeoutSeconds: 1,
	})

	body := `{"value":"1.1.1.1","duration":"1h","type":"ban","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

func TestAddManualBan_UsernameFromAuthContext_EncodedInScenario(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"1.1.1.1","duration":"1h","type":"ban","reason":"check"}`
	// Note: reqWithAuth signature is (method, target, userID, username, clientIP, userAgent).
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u-uuid", "operator-jane", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d", rec.Code)
	}

	// LAPI body carries the username.
	lastBody := fake.lastBody.Load().(string)
	if !strings.Contains(lastBody, "manual:operator-jane|check") {
		t.Errorf("scenario missing username: %s", lastBody)
	}
}

func TestAddManualBan_NoAuthContext_FallsBackToUnknown(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	// httptest.NewRequest does NOT inject auth context. So
	// the handler should fall back to "unknown" without
	// crashing.
	body := `{"value":"1.1.1.1","duration":"1h","type":"ban","reason":"r"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/security/crowdsec/decisions", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	lastBody := fake.lastBody.Load().(string)
	if !strings.Contains(lastBody, "manual:unknown|r") {
		t.Errorf("scenario missing unknown fallback: %s", lastBody)
	}
}

// --- Lapi-with-JWT shared helper (CS.3 Commit C refactor) -----

func TestLapiWithJWT_PassesMethodAndBody_ContentTypeOnPostOnly(t *testing.T) {
	var capturedMethod string
	var capturedBody []byte
	var capturedCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/watchers/login":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":200,"token":"jwt","expire":"` +
				time.Now().Add(1*time.Hour).UTC().Format(time.RFC3339) + `"}`))
		case "/v1/alerts":
			capturedMethod = r.Method
			capturedBody, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
			capturedCT = r.Header.Get("Content-Type")
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	creds := storage.WatcherCredentials{LAPIURL: srv.URL, MachineID: "m", Password: "p"}

	// POST path — body + Content-Type expected.
	payload := []byte(`{"hello":"world"}`)
	body, status, err := h.lapiWithJWT(context.Background(), creds, 5*time.Second,
		http.MethodPost, "/v1/alerts", payload, false)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status != http.StatusCreated {
		t.Errorf("status = %d, want 201", status)
	}
	if len(body) != 0 {
		t.Errorf("expected empty body on 201, got %q", body)
	}
	if capturedMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", capturedMethod)
	}
	if string(capturedBody) != string(payload) {
		t.Errorf("body = %q, want %q", capturedBody, payload)
	}
	if capturedCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", capturedCT)
	}

	// GET path — no body, no Content-Type.
	capturedMethod = ""
	capturedBody = nil
	capturedCT = ""
	_, _, _ = h.lapiWithJWT(context.Background(), creds, 5*time.Second,
		http.MethodGet, "/v1/alerts", nil, false)
	if capturedMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", capturedMethod)
	}
	if len(capturedBody) != 0 {
		t.Errorf("GET shouldn't carry body, got %q", capturedBody)
	}
	if capturedCT != "" {
		t.Errorf("GET shouldn't set Content-Type, got %q", capturedCT)
	}
}
