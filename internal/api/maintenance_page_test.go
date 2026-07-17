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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/caddymgr"
)

// Task 7 — global maintenance page GET/PUT handler tests. Mirrors the
// error-templates handler tests' shape (newTestEnv harness, real router)
// and the GeoIP-update viewer-gating pattern for the admin-only PUT.

// TestMaintenancePage_GET_FreshStore_ReturnsBuiltinDefault pins the
// v2.17.1 Item E behavior change: a fresh store (stored HTML empty)
// no longer returns an empty HTML string — it returns the branded
// built-in default (caddymgr.DefaultMaintenancePageHTML) with
// IsDefault=true, so the frontend editor has something real to show
// instead of a blank buffer.
func TestMaintenancePage_GET_FreshStore_ReturnsBuiltinDefault(t *testing.T) {
	env := newTestEnv(t, false)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/maintenance-page", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var got maintenancePageResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.HTML == "" {
		t.Error("HTML is empty on fresh store; want the built-in default HTML")
	}
	if got.HTML != caddymgr.DefaultMaintenancePageHTML() {
		t.Errorf("HTML = %q; want the exact built-in default", got.HTML)
	}
	if !got.IsDefault {
		t.Error("IsDefault = false on fresh store; want true")
	}
}

func TestMaintenancePage_PUT_AdminPersists_GET_Echoes(t *testing.T) {
	env := newTestEnv(t, false)

	putBody := `{"html":"<h1>Back soon</h1>"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/maintenance-page", strings.NewReader(putBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", rec.Code, rec.Body)
	}
	var putGot maintenancePageResponse
	if err := json.NewDecoder(rec.Body).Decode(&putGot); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	if putGot.IsDefault {
		t.Error("PUT IsDefault = true for a non-empty saved page; want false")
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/settings/maintenance-page", nil)
	getRec := httptest.NewRecorder()
	env.router.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", getRec.Code, getRec.Body)
	}
	var got maintenancePageResponse
	if err := json.NewDecoder(getRec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.HTML != "<h1>Back soon</h1>" {
		t.Errorf("HTML = %q; want echoed persisted value", got.HTML)
	}
	if got.IsDefault {
		t.Error("IsDefault = true after saving a custom page; want false")
	}

	if env.caddy.CallCount() < 1 {
		t.Errorf("expected Caddy reload after PUT; CallCount=%d", env.caddy.CallCount())
	}
}

func TestMaintenancePage_PUT_SanitizesScriptTag(t *testing.T) {
	env := newTestEnv(t, false)

	putBody := `{"html":"<h1>Down</h1><script>alert(1)</script>"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/maintenance-page", strings.NewReader(putBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", rec.Code, rec.Body)
	}

	stored, err := env.store.GetMaintenancePageConfig(context.Background())
	if err != nil {
		t.Fatalf("GetMaintenancePageConfig: %v", err)
	}
	if strings.Contains(stored.HTML, "<script>") {
		t.Errorf("stored HTML still contains <script>: %q", stored.HTML)
	}
	if !strings.Contains(stored.HTML, "<h1>Down</h1>") {
		t.Errorf("stored HTML lost the safe content: %q", stored.HTML)
	}
}

// TestRequireAdmin_ViewerRejectedOnMaintenancePagePUT mirrors the
// GeoIP-update viewer-gating pattern (TestRequireAdmin_ViewerRejectedOnGeoIPUpdateEndpoints):
// a viewer session must get 403 on the admin-only PUT, exercised through
// the real router so RequireAdminMiddleware is actually in the request path.
func TestRequireAdmin_ViewerRejectedOnMaintenancePagePUT(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	viewer, err := newTestUserStore(t, env).CreateOIDCUser(ctx, "viewer-maint", "Viewer Maintenance", "", "sub-viewer-maint")
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

	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/maintenance-page", strings.NewReader(`{"html":"<h1>x</h1>"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: s.ID})
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("VIEWER ESCALATION REGRESSION: status=%d body=%s", rec.Code, rec.Body)
	}
}
