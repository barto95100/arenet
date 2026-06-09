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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

var errBoom = errors.New("boom")

// fakeCrowdSecApplier records ApplyCrowdSecConfig calls so the
// PUT handler tests can assert the hot-reload contract without
// booting Caddy.
type fakeCrowdSecApplier struct {
	mu        sync.Mutex
	calls     []fakeCrowdSecApplierCall
	nextErr   error
}

type fakeCrowdSecApplierCall struct {
	apiURL string
	apiKey string
}

func (f *fakeCrowdSecApplier) ApplyCrowdSecConfig(_ context.Context, apiURL, apiKey string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeCrowdSecApplierCall{apiURL: apiURL, apiKey: apiKey})
	return f.nextErr
}

func (f *fakeCrowdSecApplier) Calls() []fakeCrowdSecApplierCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeCrowdSecApplierCall, len(f.calls))
	copy(out, f.calls)
	return out
}

// --- GET -----------------------------------------------------

func TestGetCrowdSecSettings_FreshInstall_ReturnsDefaultsNotConfigured(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/crowdsec", nil)
	rec := httptest.NewRecorder()
	h.getCrowdSecSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp crowdSecResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp.Configured {
		t.Error("Configured = true on fresh install, want false")
	}
	if resp.LAPIURL == "" {
		t.Error("LAPIURL is blank on fresh install, want default")
	}
	if resp.APIKey != "" {
		t.Error("APIKey emitted on fresh install — must be redacted")
	}
}

func TestGetCrowdSecSettings_StoredRow_RedactsAPIKey(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)

	// Seed a stored row directly via the store.
	if err := h.store.PutCrowdSecConfig(context.Background(), storage.CrowdSecConfig{
		LAPIURL:        "http://127.0.0.1:8080",
		APIKey:         "secret-must-not-leak",
		BouncerName:    "arenet",
		TimeoutSeconds: 5,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/crowdsec", nil)
	rec := httptest.NewRecorder()
	h.getCrowdSecSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "secret-must-not-leak") {
		t.Errorf("response body leaks API key: %s", body)
	}
	var resp crowdSecResponse
	_ = json.Unmarshal([]byte(body), &resp)
	if !resp.Configured {
		t.Error("Configured = false despite stored row, want true")
	}
	if resp.LAPIURL != "http://127.0.0.1:8080" {
		t.Errorf("LAPIURL = %q, want stored value", resp.LAPIURL)
	}
}

// --- PUT -----------------------------------------------------

func TestPutCrowdSecSettings_PersistsAndReloads(t *testing.T) {
	var logBuf bytes.Buffer
	appender := &fakeAuditAppender{}
	h := newTestHandler(t, appender, &logBuf)
	applier := &fakeCrowdSecApplier{}
	h.SetCrowdSecApplier(applier)

	body := `{
		"lapiUrl":"http://crowdsec:8080",
		"apiKey":"new-key-123",
		"bouncerName":"arenet",
		"timeoutSeconds":5
	}`
	req := reqWithAuth(http.MethodPut, "/api/v1/settings/crowdsec", "user-uuid", "admin", "203.0.113.5", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.putCrowdSecSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	stored, err := h.store.GetCrowdSecConfig(context.Background())
	if err != nil {
		t.Fatalf("stored read: %v", err)
	}
	if stored.APIKey != "new-key-123" {
		t.Errorf("APIKey not persisted: %q", stored.APIKey)
	}
	if stored.LAPIURL != "http://crowdsec:8080" {
		t.Errorf("LAPIURL not persisted: %q", stored.LAPIURL)
	}

	calls := applier.Calls()
	if len(calls) != 1 {
		t.Fatalf("applier calls = %d, want 1", len(calls))
	}
	if calls[0].apiKey != "new-key-123" || calls[0].apiURL != "http://crowdsec:8080" {
		t.Errorf("applier received wrong creds: %+v", calls[0])
	}

	// Audit: first PUT emits ActionCrowdSecConfigured.
	events := appender.Events()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if events[0].Action != audit.ActionCrowdSecConfigured {
		t.Errorf("audit action = %q, want %q", events[0].Action, audit.ActionCrowdSecConfigured)
	}
	if strings.Contains(string(events[0].AfterJSON), "new-key-123") {
		t.Errorf("audit AfterJSON leaks API key: %s", events[0].AfterJSON)
	}
}

func TestPutCrowdSecSettings_SecondPUT_EmitsUpdatedAction(t *testing.T) {
	var logBuf bytes.Buffer
	appender := &fakeAuditAppender{}
	h := newTestHandler(t, appender, &logBuf)
	h.SetCrowdSecApplier(&fakeCrowdSecApplier{})

	// First PUT.
	req1 := reqWithAuth(http.MethodPut, "/api/v1/settings/crowdsec", "user", "admin", "1.2.3.4", "test")
	req1.Body = httpBody(`{"lapiUrl":"http://127.0.0.1:8080","apiKey":"k1","bouncerName":"arenet","timeoutSeconds":5}`)
	h.putCrowdSecSettings(httptest.NewRecorder(), req1)

	// Second PUT.
	req2 := reqWithAuth(http.MethodPut, "/api/v1/settings/crowdsec", "user", "admin", "1.2.3.4", "test")
	req2.Body = httpBody(`{"lapiUrl":"http://127.0.0.1:8080","apiKey":"k2","bouncerName":"arenet","timeoutSeconds":5}`)
	rec := httptest.NewRecorder()
	h.putCrowdSecSettings(rec, req2)
	if rec.Code != http.StatusOK {
		t.Fatalf("second PUT status = %d, body=%s", rec.Code, rec.Body.String())
	}

	events := appender.Events()
	if len(events) != 2 {
		t.Fatalf("audit events = %d, want 2", len(events))
	}
	if events[0].Action != audit.ActionCrowdSecConfigured {
		t.Errorf("first event action = %q, want %q", events[0].Action, audit.ActionCrowdSecConfigured)
	}
	if events[1].Action != audit.ActionCrowdSecUpdated {
		t.Errorf("second event action = %q, want %q", events[1].Action, audit.ActionCrowdSecUpdated)
	}
}

func TestPutCrowdSecSettings_PreservesAPIKeyOnEmptyField(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	h.SetCrowdSecApplier(&fakeCrowdSecApplier{})

	// Seed with a key.
	if err := h.store.PutCrowdSecConfig(context.Background(), storage.CrowdSecConfig{
		LAPIURL:        "http://127.0.0.1:8080",
		APIKey:         "preserved-secret",
		BouncerName:    "arenet",
		TimeoutSeconds: 5,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// PUT with empty apiKey → must preserve.
	req := reqWithAuth(http.MethodPut, "/api/v1/settings/crowdsec", "user", "admin", "1.2.3.4", "test")
	req.Body = httpBody(`{"lapiUrl":"http://192.168.99.10:8080","apiKey":"","bouncerName":"arenet","timeoutSeconds":5}`)
	rec := httptest.NewRecorder()
	h.putCrowdSecSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}

	stored, _ := h.store.GetCrowdSecConfig(context.Background())
	if stored.APIKey != "preserved-secret" {
		t.Errorf("APIKey not preserved: got %q, want %q", stored.APIKey, "preserved-secret")
	}
	if stored.LAPIURL != "http://192.168.99.10:8080" {
		t.Errorf("LAPIURL not updated: %q", stored.LAPIURL)
	}
}

func TestPutCrowdSecSettings_RollbackOnReloadFailure(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)

	// Seed previous row.
	previous := storage.CrowdSecConfig{
		LAPIURL: "http://127.0.0.1:8080", APIKey: "old-key", BouncerName: "arenet", TimeoutSeconds: 5,
	}
	if err := h.store.PutCrowdSecConfig(context.Background(), previous); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Wire an applier that errors.
	applier := &fakeCrowdSecApplier{nextErr: errBoom}
	h.SetCrowdSecApplier(applier)

	req := reqWithAuth(http.MethodPut, "/api/v1/settings/crowdsec", "user", "admin", "1.2.3.4", "test")
	req.Body = httpBody(`{"lapiUrl":"http://127.0.0.1:9999","apiKey":"new-bad-key","bouncerName":"arenet","timeoutSeconds":5}`)
	rec := httptest.NewRecorder()
	h.putCrowdSecSettings(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}

	// Storage must be rolled back to the previous values.
	stored, _ := h.store.GetCrowdSecConfig(context.Background())
	if stored.APIKey != "old-key" {
		t.Errorf("rollback failed — APIKey is %q, want %q", stored.APIKey, "old-key")
	}
	if stored.LAPIURL != "http://127.0.0.1:8080" {
		t.Errorf("rollback failed — LAPIURL is %q, want %q", stored.LAPIURL, "http://127.0.0.1:8080")
	}
}

func TestPutCrowdSecSettings_BadJSON_Returns400(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	req := reqWithAuth(http.MethodPut, "/api/v1/settings/crowdsec", "user", "admin", "1.2.3.4", "test")
	req.Body = httpBody(`{not valid json`)
	rec := httptest.NewRecorder()
	h.putCrowdSecSettings(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestPutCrowdSecSettings_InvalidURLScheme_Returns400(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	h.SetCrowdSecApplier(&fakeCrowdSecApplier{})

	req := reqWithAuth(http.MethodPut, "/api/v1/settings/crowdsec", "user", "admin", "1.2.3.4", "test")
	req.Body = httpBody(`{"lapiUrl":"ftp://wat","apiKey":"k","bouncerName":"arenet","timeoutSeconds":5}`)
	rec := httptest.NewRecorder()
	h.putCrowdSecSettings(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "scheme") {
		t.Errorf("body lacks scheme error: %s", rec.Body.String())
	}
}

// --- TEST endpoint -------------------------------------------

func TestTestCrowdSecConnection_Success_ReturnsOK(t *testing.T) {
	// Fake LAPI: 200 with version header.
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "good-key" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("X-Crowdsec-Version", "v1.6.3")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer lapi.Close()

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)

	body := `{"lapiUrl":"` + lapi.URL + `","apiKey":"good-key","timeoutSeconds":5}`
	req := reqWithAuth(http.MethodPost, "/api/v1/settings/crowdsec/test", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.testCrowdSecConnection(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp crowdSecTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !resp.OK {
		t.Errorf("OK = false, want true; err=%q", resp.Error)
	}
	if resp.Version != "v1.6.3" {
		t.Errorf("Version = %q, want v1.6.3", resp.Version)
	}
	if resp.EffectiveURL != lapi.URL {
		t.Errorf("EffectiveURL = %q, want %q", resp.EffectiveURL, lapi.URL)
	}
}

func TestTestCrowdSecConnection_AuthFailed_ReturnsOKBadgeFalse(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer lapi.Close()

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)

	body := `{"lapiUrl":"` + lapi.URL + `","apiKey":"wrong-key","timeoutSeconds":5}`
	req := reqWithAuth(http.MethodPost, "/api/v1/settings/crowdsec/test", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.testCrowdSecConnection(rec, req)

	// The endpoint returns 200 with ok=false (the probe ran;
	// the LAPI rejected the creds).
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp crowdSecTestResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.OK {
		t.Error("OK = true on 403, want false")
	}
	if !strings.Contains(resp.Error, "authentication") {
		t.Errorf("Error doesn't mention auth: %q", resp.Error)
	}
}

func TestTestCrowdSecConnection_204NoContent_AcceptedAsOK(t *testing.T) {
	// LAPI returns 204 when there are no active decisions —
	// the probe must treat that as a successful auth handshake.
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer lapi.Close()

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)

	body := `{"lapiUrl":"` + lapi.URL + `","apiKey":"k","timeoutSeconds":5}`
	req := reqWithAuth(http.MethodPost, "/api/v1/settings/crowdsec/test", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.testCrowdSecConnection(rec, req)

	var resp crowdSecTestResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.OK {
		t.Errorf("204 not accepted as OK: err=%q", resp.Error)
	}
}

func TestTestCrowdSecConnection_ConnectionRefused_FriendlyError(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)

	// Point at an unbound localhost port.
	body := `{"lapiUrl":"http://127.0.0.1:1","apiKey":"k","timeoutSeconds":1}`
	req := reqWithAuth(http.MethodPost, "/api/v1/settings/crowdsec/test", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.testCrowdSecConnection(rec, req)

	var resp crowdSecTestResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.OK {
		t.Errorf("OK = true on connection refused, want false")
	}
	if resp.Error == "" {
		t.Errorf("Error empty on connection refused")
	}
}

func TestTestCrowdSecConnection_EmptyKey_Returns400(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	body := `{"lapiUrl":"http://127.0.0.1:8080","apiKey":""}`
	req := reqWithAuth(http.MethodPost, "/api/v1/settings/crowdsec/test", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.testCrowdSecConnection(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestTestCrowdSecConnection_UseStored_PullsFromStorage(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") == "stored-key" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer lapi.Close()

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	_ = h.store.PutCrowdSecConfig(context.Background(), storage.CrowdSecConfig{
		LAPIURL:        lapi.URL,
		APIKey:         "stored-key",
		BouncerName:    "arenet",
		TimeoutSeconds: 5,
	})

	body := `{"useStored":true}`
	req := reqWithAuth(http.MethodPost, "/api/v1/settings/crowdsec/test", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.testCrowdSecConnection(rec, req)

	var resp crowdSecTestResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.OK {
		t.Errorf("useStored probe failed: err=%q", resp.Error)
	}
}

// --- DELETE (Step CS.2 follow-up) -----------------------------

func TestDeleteCrowdSecSettings_RemovesRow_AndCallsApplierWithBlanks(t *testing.T) {
	var logBuf bytes.Buffer
	appender := &fakeAuditAppender{}
	h := newTestHandler(t, appender, &logBuf)
	applier := &fakeCrowdSecApplier{}
	h.SetCrowdSecApplier(applier)

	// Seed a configured row.
	if err := h.store.PutCrowdSecConfig(context.Background(), storage.CrowdSecConfig{
		LAPIURL:        "http://127.0.0.1:8080",
		APIKey:         "to-be-wiped",
		BouncerName:    "arenet",
		TimeoutSeconds: 5,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := reqWithAuth(http.MethodDelete, "/api/v1/settings/crowdsec", "user", "admin", "1.2.3.4", "test")
	rec := httptest.NewRecorder()
	h.deleteCrowdSecSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	// Row gone.
	if _, err := h.store.GetCrowdSecConfig(context.Background()); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("row not deleted: err = %v", err)
	}

	// Response shape: configured=false + defaults.
	var resp crowdSecResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Configured {
		t.Errorf("response configured=true, want false after delete")
	}
	if resp.LAPIURL == "" {
		t.Errorf("response LAPIURL should fall back to default, got empty")
	}

	// Applier called with BOTH blank — AC #13 fail-open
	// signal so buildConfigJSON omits apps.crowdsec.
	calls := applier.Calls()
	if len(calls) != 1 {
		t.Fatalf("applier calls = %d, want 1", len(calls))
	}
	if calls[0].apiURL != "" || calls[0].apiKey != "" {
		t.Errorf("applier called with non-blank creds: %+v", calls[0])
	}

	// Audit: crowdsec_reset action, BeforeJSON has the
	// wiped row (APIKey scrubbed), AfterJSON nil.
	events := appender.Events()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	evt := events[0]
	if evt.Action != audit.ActionCrowdSecReset {
		t.Errorf("audit action = %q, want %q", evt.Action, audit.ActionCrowdSecReset)
	}
	if evt.AfterJSON != nil {
		t.Errorf("AfterJSON should be nil on reset, got %s", evt.AfterJSON)
	}
	if strings.Contains(string(evt.BeforeJSON), "to-be-wiped") {
		t.Errorf("BeforeJSON leaks API key: %s", evt.BeforeJSON)
	}
	if !strings.Contains(string(evt.BeforeJSON), "127.0.0.1:8080") {
		t.Errorf("BeforeJSON should carry the wiped row's URL: %s", evt.BeforeJSON)
	}
}

func TestDeleteCrowdSecSettings_FreshInstall_StillCallsApplier_NoAuditNoise(t *testing.T) {
	var logBuf bytes.Buffer
	appender := &fakeAuditAppender{}
	h := newTestHandler(t, appender, &logBuf)
	applier := &fakeCrowdSecApplier{}
	h.SetCrowdSecApplier(applier)

	// No seed — fresh install.
	req := reqWithAuth(http.MethodDelete, "/api/v1/settings/crowdsec", "user", "admin", "1.2.3.4", "test")
	rec := httptest.NewRecorder()
	h.deleteCrowdSecSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	// Applier still called — clears any straggler bouncer
	// state on a hot-reload boundary.
	if got := len(applier.Calls()); got != 1 {
		t.Errorf("applier calls = %d, want 1 (even on fresh-install delete)", got)
	}

	// No audit row — a no-op DELETE shouldn't add noise.
	if got := len(appender.Events()); got != 0 {
		t.Errorf("audit events = %d, want 0 on fresh-install delete", got)
	}
}

func TestDeleteCrowdSecSettings_RollbackOnReloadFailure(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)

	previous := storage.CrowdSecConfig{
		LAPIURL: "http://127.0.0.1:8080", APIKey: "persist-on-rollback", BouncerName: "arenet", TimeoutSeconds: 5,
	}
	if err := h.store.PutCrowdSecConfig(context.Background(), previous); err != nil {
		t.Fatalf("seed: %v", err)
	}

	applier := &fakeCrowdSecApplier{nextErr: errBoom}
	h.SetCrowdSecApplier(applier)

	req := reqWithAuth(http.MethodDelete, "/api/v1/settings/crowdsec", "user", "admin", "1.2.3.4", "test")
	rec := httptest.NewRecorder()
	h.deleteCrowdSecSettings(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	// Row restored.
	got, err := h.store.GetCrowdSecConfig(context.Background())
	if err != nil {
		t.Fatalf("after rollback: %v", err)
	}
	if got.APIKey != "persist-on-rollback" {
		t.Errorf("rollback failed — APIKey = %q, want %q", got.APIKey, "persist-on-rollback")
	}
}

func TestDeleteCrowdSecSettings_NilApplier_DeletesRow_NoCrash(t *testing.T) {
	// Mirror of the put-handler nil-tolerance: tests that
	// don't wire an applier should still see the row erased.
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)

	if err := h.store.PutCrowdSecConfig(context.Background(), storage.CrowdSecConfig{
		LAPIURL: "http://127.0.0.1:8080", APIKey: "k", BouncerName: "arenet", TimeoutSeconds: 5,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := reqWithAuth(http.MethodDelete, "/api/v1/settings/crowdsec", "user", "admin", "1.2.3.4", "test")
	rec := httptest.NewRecorder()
	h.deleteCrowdSecSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if _, err := h.store.GetCrowdSecConfig(context.Background()); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("row should be deleted even without an applier: %v", err)
	}
}

// --- helpers -------------------------------------------------

// httpBody builds an io.ReadCloser for assignment to http.Request.Body
// in a test. Adapter for the existing reqWithAuth helper which only
// fills the URL/method/context.
func httpBody(s string) interface {
	Read(p []byte) (n int, err error)
	Close() error
} {
	return &nopCloser{Reader: strings.NewReader(s)}
}

type nopCloser struct {
	*strings.Reader
}

func (n *nopCloser) Close() error { return nil }
