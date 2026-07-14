// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/geoipupdate"
	"github.com/barto95100/arenet/internal/storage"
)

// fakeGeoIPUpdater is a test double for the geoIPUpdater seam. UpdateOnce
// records that it was called and returns a canned result; Status returns
// a canned snapshot.
type fakeGeoIPUpdater struct {
	updateCalled bool
	updateResult geoipupdate.UpdateResult
	status       geoipupdate.UpdateResult
}

func (f *fakeGeoIPUpdater) UpdateOnce(_ context.Context) geoipupdate.UpdateResult {
	f.updateCalled = true
	return f.updateResult
}

func (f *fakeGeoIPUpdater) Status() geoipupdate.UpdateResult {
	return f.status
}

func TestGetGeoIPUpdateConfig_Fresh_ReportsDisabled(t *testing.T) {
	env := newTestEnv(t, false)
	rec := getRec(t, env, "/api/v1/system/geoip/update-config")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["enabled"] != false {
		t.Errorf("enabled=%v; want false on fresh install", body["enabled"])
	}
	if body["intervalHours"] != float64(168) {
		t.Errorf("intervalHours=%v; want 168 (weekly default)", body["intervalHours"])
	}
}

func TestPutGeoIPUpdateConfig_PersistsAndFiresHook(t *testing.T) {
	env := newTestEnv(t, false)

	var hookCalled bool
	var hookCfg storage.GeoIPUpdateConfig
	env.handler.SetGeoIPConfigHook(func(c storage.GeoIPUpdateConfig) {
		hookCalled = true
		hookCfg = c
	})

	body := map[string]any{"enabled": true, "intervalHours": 24}
	rec := putJSONRaw(t, env, "/api/v1/system/geoip/update-config", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", rec.Code, rec.Body)
	}

	got, err := env.store.GetGeoIPUpdateConfig(context.Background())
	if err != nil {
		t.Fatalf("GetGeoIPUpdateConfig: %v", err)
	}
	if !got.Enabled {
		t.Error("config PUT did not persist enabled=true")
	}

	if !hookCalled {
		t.Fatal("PUT did not fire onGeoIPConfigChange hook")
	}
	if !hookCfg.Enabled {
		t.Errorf("hook received enabled=%v; want true", hookCfg.Enabled)
	}
}

func TestPostGeoIPUpdate_NilUpdater_409(t *testing.T) {
	env := newTestEnv(t, false)
	// No SetGeoIPUpdater call — nil-tolerant path.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/geoip/update", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s; want 409 when updater is nil", rec.Code, rec.Body)
	}
}

func TestPostGeoIPUpdate_CallsUpdateOnce(t *testing.T) {
	env := newTestEnv(t, false)
	fake := &fakeGeoIPUpdater{
		updateResult: geoipupdate.UpdateResult{
			Status:       geoipupdate.StatusUpdated,
			LastModified: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	env.handler.SetGeoIPUpdater(fake)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/geoip/update", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if !fake.updateCalled {
		t.Fatal("POST /system/geoip/update did not call UpdateOnce")
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != geoipupdate.StatusUpdated {
		t.Errorf("status=%v; want %q", body["status"], geoipupdate.StatusUpdated)
	}
}

func TestGetGeoIPStatus_ReturnsSnapshot(t *testing.T) {
	env := newTestEnv(t, false)
	fake := &fakeGeoIPUpdater{
		status: geoipupdate.UpdateResult{
			Status: geoipupdate.StatusError,
			Error:  "boom",
			At:     time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	env.handler.SetGeoIPUpdater(fake)

	rec := getRec(t, env, "/api/v1/system/geoip/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["lastStatus"] != geoipupdate.StatusError {
		t.Errorf("lastStatus=%v; want %q", body["lastStatus"], geoipupdate.StatusError)
	}
	if body["lastError"] != "boom" {
		t.Errorf("lastError=%v; want boom", body["lastError"])
	}
}

// --- Admin gating ----------------------------------------------

// TestRequireAdmin_ViewerRejectedOnGeoIPUpdateEndpoints mirrors the
// MaxMind/CrowdSec/OIDC viewer-gating pattern: a viewer session must get
// 403 on all 4 GeoIP update endpoints, exercised through the real router
// so RequireAdminMiddleware is actually in the request path.
func TestRequireAdmin_ViewerRejectedOnGeoIPUpdateEndpoints(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	viewer, err := newTestUserStore(t, env).CreateOIDCUser(ctx, "viewer-geoip", "Viewer GeoIP", "", "sub-viewer-geoip")
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

	cases := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/api/v1/system/geoip/update-config", ""},
		{http.MethodPut, "/api/v1/system/geoip/update-config", `{"enabled":true,"intervalHours":24}`},
		{http.MethodPost, "/api/v1/system/geoip/update", ""},
		{http.MethodGet, "/api/v1/system/geoip/status", ""},
	}
	for _, tc := range cases {
		var req *http.Request
		if tc.body != "" {
			req = httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
		} else {
			req = httptest.NewRequest(tc.method, tc.path, nil)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: s.ID})
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("VIEWER ESCALATION REGRESSION: %s %s status=%d body=%s", tc.method, tc.path, rec.Code, rec.Body)
		}
	}
}
