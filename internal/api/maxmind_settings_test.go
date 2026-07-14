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
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// --- GET -----------------------------------------------------

// TestGetMaxMindSettings_StoredRow_RedactsLicenseKey mirrors
// TestGetCrowdSecSettings_StoredRow_RedactsAPIKey: seed a config
// with a secret key directly via the store, then assert the raw
// JSON response body never contains that secret string.
func TestGetMaxMindSettings_StoredRow_RedactsLicenseKey(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)

	if err := h.store.PutMaxMindConfig(context.Background(), storage.MaxMindConfig{
		AccountID:  12345,
		LicenseKey: "secret-must-not-leak",
		EditionID:  "GeoLite2-City",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/maxmind", nil)
	rec := httptest.NewRecorder()
	h.getMaxMindSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "secret-must-not-leak") {
		t.Errorf("response body leaks license key: %s", body)
	}
	if strings.Contains(body, "licenseKey") {
		t.Errorf("response body must not carry a licenseKey field at all: %s", body)
	}
	var resp maxMindResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !resp.Configured {
		t.Error("Configured = false despite stored row, want true")
	}
	if resp.AccountID != 12345 {
		t.Errorf("AccountID = %d, want 12345", resp.AccountID)
	}
	if resp.EditionID != "GeoLite2-City" {
		t.Errorf("EditionID = %q, want GeoLite2-City", resp.EditionID)
	}
}

// TestGetMaxMindSettings_FreshInstall_ReturnsNotConfigured mirrors
// CrowdSec's GET-fresh behaviour: no row in storage → 200 (not
// 404) with configured:false.
func TestGetMaxMindSettings_FreshInstall_ReturnsNotConfigured(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/maxmind", nil)
	rec := httptest.NewRecorder()
	h.getMaxMindSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fresh install must not 404)", rec.Code)
	}
	var resp maxMindResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp.Configured {
		t.Error("Configured = true on fresh install, want false")
	}
}

// --- PUT -----------------------------------------------------

// TestPutMaxMindSettings_BlankKey_PreservesStored mirrors
// TestPutCrowdSecSettings_PreservesAPIKeyOnEmptyField.
func TestPutMaxMindSettings_BlankKey_PreservesStored(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)

	if err := h.store.PutMaxMindConfig(context.Background(), storage.MaxMindConfig{
		AccountID:  1,
		LicenseKey: "preserved-secret",
		EditionID:  "GeoLite2-City",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := reqWithAuth(http.MethodPut, "/api/v1/settings/maxmind", "user", "admin", "1.2.3.4", "test")
	req.Body = httpBody(`{"accountId":2,"licenseKey":""}`)
	rec := httptest.NewRecorder()
	h.putMaxMindSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	stored, err := h.store.GetMaxMindConfig(context.Background())
	if err != nil {
		t.Fatalf("stored read: %v", err)
	}
	if stored.LicenseKey != "preserved-secret" {
		t.Errorf("LicenseKey not preserved: got %q, want %q", stored.LicenseKey, "preserved-secret")
	}
	if stored.AccountID != 2 {
		t.Errorf("AccountID not updated: got %d, want 2", stored.AccountID)
	}

	var resp maxMindResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Configured {
		t.Error("response Configured = false after preserve-merge PUT, want true")
	}
}

// TestPutMaxMindSettings_SetsKey mirrors
// TestPutCrowdSecSettings_PersistsAndReloads (minus the reload).
func TestPutMaxMindSettings_SetsKey(t *testing.T) {
	var logBuf bytes.Buffer
	appender := &fakeAuditAppender{}
	h := newTestHandler(t, appender, &logBuf)

	req := reqWithAuth(http.MethodPut, "/api/v1/settings/maxmind", "user-uuid", "admin", "203.0.113.5", "test")
	req.Body = httpBody(`{"accountId":1,"licenseKey":"newkey","editionId":"GeoLite2-City"}`)
	rec := httptest.NewRecorder()
	h.putMaxMindSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	stored, err := h.store.GetMaxMindConfig(context.Background())
	if err != nil {
		t.Fatalf("stored read: %v", err)
	}
	if stored.LicenseKey != "newkey" {
		t.Errorf("LicenseKey not persisted: %q", stored.LicenseKey)
	}
	if stored.AccountID != 1 {
		t.Errorf("AccountID not persisted: %d", stored.AccountID)
	}

	events := appender.Events()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if events[0].Action != audit.ActionMaxMindConfigUpdated {
		t.Errorf("audit action = %q, want %q", events[0].Action, audit.ActionMaxMindConfigUpdated)
	}
}

func TestPutMaxMindSettings_BadJSON_Returns400(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	req := reqWithAuth(http.MethodPut, "/api/v1/settings/maxmind", "user", "admin", "1.2.3.4", "test")
	req.Body = httpBody(`{not valid json`)
	rec := httptest.NewRecorder()
	h.putMaxMindSettings(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// --- DELETE ----------------------------------------------------

// TestDeleteMaxMindSettings_RemovesRow mirrors
// TestDeleteCrowdSecSettings_RemovesRow_AndCallsApplierWithBlanks
// (minus the applier call, which doesn't apply to MaxMind).
func TestDeleteMaxMindSettings_RemovesRow(t *testing.T) {
	var logBuf bytes.Buffer
	appender := &fakeAuditAppender{}
	h := newTestHandler(t, appender, &logBuf)

	if err := h.store.PutMaxMindConfig(context.Background(), storage.MaxMindConfig{
		AccountID:  1,
		LicenseKey: "to-be-wiped",
		EditionID:  "GeoLite2-City",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := reqWithAuth(http.MethodDelete, "/api/v1/settings/maxmind", "user", "admin", "1.2.3.4", "test")
	rec := httptest.NewRecorder()
	h.deleteMaxMindSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	if _, err := h.store.GetMaxMindConfig(context.Background()); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("row not deleted: err = %v", err)
	}

	var resp maxMindResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Configured {
		t.Errorf("response configured=true, want false after delete")
	}

	events := appender.Events()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if events[0].Action != audit.ActionMaxMindConfigDeleted {
		t.Errorf("audit action = %q, want %q", events[0].Action, audit.ActionMaxMindConfigDeleted)
	}

	// Subsequent GET reflects configured:false.
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/settings/maxmind", nil)
	getRec := httptest.NewRecorder()
	h.getMaxMindSettings(getRec, getReq)
	var getResp maxMindResponse
	_ = json.Unmarshal(getRec.Body.Bytes(), &getResp)
	if getResp.Configured {
		t.Errorf("GET after DELETE: configured=true, want false")
	}
}

// --- Admin gating ----------------------------------------------

// TestRequireAdmin_ViewerRejectedOnMaxMindSettings mirrors the
// CrowdSec / OIDC viewer-gating pattern: a viewer session must get
// 403 on the write endpoints, exercised through the real router
// (not the direct handler call) so the RequireAdminMiddleware is
// actually in the request path.
func TestRequireAdmin_ViewerRejectedOnMaxMindSettings(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	viewer, err := newTestUserStore(t, env).CreateOIDCUser(ctx, "viewer-maxmind", "Viewer MaxMind", "", "sub-viewer-maxmind")
	if err != nil {
		t.Fatalf("seed viewer: %v", err)
	}
	if viewer.Role != auth.UserRoleViewer {
		t.Fatalf("seed-viewer role = %q; want viewer (CreateOIDCUser default)", viewer.Role)
	}
	sessionStore := auth.NewSessionStore(env.store.DB())
	s, err := sessionStore.Create(ctx, viewer.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// PUT rejected.
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/settings/maxmind", strings.NewReader(`{"accountId":1,"licenseKey":"x"}`))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: s.ID})
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusForbidden {
		t.Fatalf("VIEWER ESCALATION REGRESSION: viewer PUT /settings/maxmind status=%d body=%s", putRec.Code, putRec.Body)
	}
	if !strings.Contains(putRec.Body.String(), "admin role required") {
		t.Errorf("rejection message does not name the cause: %s", putRec.Body)
	}

	// DELETE rejected.
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/settings/maxmind", nil)
	delReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: s.ID})
	delRec := httptest.NewRecorder()
	env.router.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusForbidden {
		t.Fatalf("VIEWER ESCALATION REGRESSION: viewer DELETE /settings/maxmind status=%d body=%s", delRec.Code, delRec.Body)
	}
}

// --- Audit scrub -------------------------------------------------

// TestPutMaxMindSettings_Audit_ScrubsLicenseKey is the explicit
// secret-redaction guard on the audit trail: BeforeJSON/AfterJSON
// for a PUT must never contain the plaintext license key.
func TestPutMaxMindSettings_Audit_ScrubsLicenseKey(t *testing.T) {
	var logBuf bytes.Buffer
	appender := &fakeAuditAppender{}
	h := newTestHandler(t, appender, &logBuf)

	// Seed a previous row so BeforeJSON is populated too.
	if err := h.store.PutMaxMindConfig(context.Background(), storage.MaxMindConfig{
		AccountID:  1,
		LicenseKey: "old-secret-canary",
		EditionID:  "GeoLite2-City",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := reqWithAuth(http.MethodPut, "/api/v1/settings/maxmind", "user", "admin", "1.2.3.4", "test")
	req.Body = httpBody(`{"accountId":1,"licenseKey":"new-secret-canary","editionId":"GeoLite2-City"}`)
	rec := httptest.NewRecorder()
	h.putMaxMindSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	events := appender.Events()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	evt := events[0]
	if strings.Contains(string(evt.AfterJSON), "new-secret-canary") {
		t.Errorf("audit AfterJSON leaks new license key: %s", evt.AfterJSON)
	}
	if strings.Contains(string(evt.BeforeJSON), "old-secret-canary") {
		t.Errorf("audit BeforeJSON leaks old license key: %s", evt.BeforeJSON)
	}
}
