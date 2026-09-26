// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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
	"time"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.39 follow-ups of the OpenAPI pass: a partial PUT must not
// resurrect a disabled route, an aggregate interval of 0 must not
// divide by zero, exports must carry the real version, and accounts
// without a local password must get a clear 400 instead of a 500.

func putRouteBody(t *testing.T, env *testEnv, id, extra string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"host":"waf.local","upstreams":[{"url":"http://10.0.0.50:5000","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],` +
		`"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":"off"` + extra + `}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func TestUpdateRoute_PartialPutKeepsDisabledAndMaintenance(t *testing.T) {
	env := newTestEnv(t, false)
	route := seedWAFRoute(t, env, storage.Route{
		Disabled:          true,
		MaintenanceConfig: &storage.MaintenanceConfig{RetryAfterSeconds: 300},
	})

	// A script's partial PUT: neither field present.
	if rec := putRouteBody(t, env, route.ID, ""); rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body)
	}
	stored, _ := env.store.GetRoute(context.Background(), route.ID)
	if !stored.Disabled {
		t.Error("an omitted `disabled` must keep the route disabled")
	}
	if stored.MaintenanceConfig == nil {
		t.Error("an omitted `maintenanceConfig` must keep maintenance")
	}

	// Explicit values still apply (what the UI sends).
	if rec := putRouteBody(t, env, route.ID, `,"disabled":false`); rec.Code != http.StatusOK {
		t.Fatalf("PUT enable: %d %s", rec.Code, rec.Body)
	}
	stored, _ = env.store.GetRoute(context.Background(), route.ID)
	if stored.Disabled || stored.MaintenanceConfig != nil {
		t.Errorf("explicit disabled=false must enable and leave maintenance: %+v", stored.MaintenanceConfig)
	}
	if rec := putRouteBody(t, env, route.ID, `,"disabled":true`); rec.Code != http.StatusOK {
		t.Fatalf("PUT disable: %d", rec.Code)
	}
	if stored, _ = env.store.GetRoute(context.Background(), route.ID); !stored.Disabled {
		t.Error("explicit disabled=true must disable")
	}
}

func TestCreateRoute_DisabledDefaultsToEnabled(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"new.local","upstreams":[{"url":"http://10.0.0.50:5000","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],` +
		`"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST: %d %s", rec.Code, rec.Body)
	}
	var resp routeResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	stored, _ := env.store.GetRoute(context.Background(), resp.ID)
	if stored.Disabled {
		t.Error("a route created without `disabled` must be enabled")
	}
}

func TestParseDurationParam_RefusesZeroAndNegativeDays(t *testing.T) {
	// "0d" used to return (0, nil): aggregateCertEvents then divided by
	// a zero interval and the request died as a 500.
	for _, raw := range []string{"0d", "-1d", "-3d", "0h", "xd"} {
		if got, err := parseDurationParam(raw, time.Hour, time.Minute, 24*time.Hour); err == nil {
			t.Errorf("parseDurationParam(%q) = %v, nil; want an error", raw, got)
		}
	}
	if got, err := parseDurationParam("2d", time.Hour, time.Minute, 30*24*time.Hour); err != nil || got != 48*time.Hour {
		t.Errorf("parseDurationParam(2d) = %v, %v", got, err)
	}
	if got, err := parseDurationParam("", 6*time.Hour, time.Minute, 24*time.Hour); err != nil || got != 6*time.Hour {
		t.Errorf("empty must use the default: %v, %v", got, err)
	}
}

func TestBackupExport_CarriesTheBinaryVersion(t *testing.T) {
	env := newTestEnv(t, false)
	if got := env.handler.backupVersion(); got != arenetVersionForBackup {
		t.Errorf("without SetVersion: %q, want the fallback", got)
	}
	env.handler.SetVersion("v2.39.0")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/backup", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d %s", rec.Code, rec.Body)
	}
	var snap map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if snap["arenet_version"] != "v2.39.0" {
		t.Errorf("arenet_version = %v, want the running version (it was hard-coded)", snap["arenet_version"])
	}
}

// v2.39 — an account with no local password (a service account, an
// OIDC user changing a password) used to reach argon2id with an empty
// hash and get a 500.
func TestUnlockAndPasswordChange_NoLocalPassword(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()
	users := newTestUserStore(t, env)
	sa, err := users.CreateServiceAccount(ctx, "bot", string(auth.UserRoleAdmin))
	if err != nil {
		t.Fatalf("create service account: %v", err)
	}
	if sa.PasswordHash != "" {
		t.Fatalf("a service account must have no password hash")
	}
	sess, err := auth.NewSessionStore(env.store.DB()).Create(ctx, sa.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("session: %v", err)
	}

	for _, tc := range []struct{ path, body string }{
		{"/api/v1/auth/unlock", `{"password":"whatever-1234567"}`},
		{"/api/v1/auth/me/password", `{"currentPassword":"whatever-1234567","newPassword":"Another-Passw0rd-42!"}`},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "no_local_password") {
			t.Errorf("%s: status = %d body = %s, want 400 no_local_password", tc.path, rec.Code, rec.Body)
		}
	}
}
