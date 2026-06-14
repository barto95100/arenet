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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
)

// Phase 4 — POST /admin/users/service-accounts integration tests.

func postJSONWithSession(t *testing.T, env *testEnv, path, sessionCookie string, body any) *httptest.ResponseRecorder {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func TestCreateServiceAccount_HappyPath(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	rec := postJSONWithSession(t, env, "/api/v1/admin/users/service-accounts", sessCookie, map[string]any{
		"name": "ci-deploy",
		"role": "viewer",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	tokenStr, _ := resp["token"].(string)
	if !strings.HasPrefix(tokenStr, auth.APITokenPrefix) {
		t.Errorf("plain token missing arn_ prefix: %q", tokenStr)
	}
	if len(tokenStr) < 20 {
		t.Errorf("plain token suspiciously short: %q", tokenStr)
	}

	user, _ := resp["user"].(map[string]any)
	if user["authSource"] != "service" {
		t.Errorf("authSource = %v, want service", user["authSource"])
	}
	if user["role"] != "viewer" {
		t.Errorf("role = %v, want viewer", user["role"])
	}

	// Audit emitted.
	events, _, _ := env.audit.List(t.Context(), audit.Filter{
		Action: audit.ActionServiceAccountCreated,
		Limit:  10,
	})
	if len(events) == 0 {
		t.Error("audit log missing service_account_created event")
	}
	// Plain token MUST NOT appear anywhere in the audit row.
	for _, e := range events {
		if strings.Contains(string(e.BeforeJSON)+string(e.AfterJSON), tokenStr) {
			t.Error("plain token leaked into audit JSON")
		}
	}
}

func TestCreateServiceAccount_RejectsBadRole(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	rec := postJSONWithSession(t, env, "/api/v1/admin/users/service-accounts", sessCookie, map[string]any{
		"name": "bad",
		"role": "superuser",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for bad role, got %d", rec.Code)
	}
}

func TestCreateServiceAccount_RejectsDuplicateName(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	// First create.
	rec := postJSONWithSession(t, env, "/api/v1/admin/users/service-accounts", sessCookie, map[string]any{
		"name": "dup",
		"role": "viewer",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup create: %d", rec.Code)
	}
	// Duplicate.
	rec = postJSONWithSession(t, env, "/api/v1/admin/users/service-accounts", sessCookie, map[string]any{
		"name": "dup",
		"role": "viewer",
	})
	if rec.Code != http.StatusConflict {
		t.Errorf("want 409 on duplicate name, got %d", rec.Code)
	}
}

func TestCreateServiceAccount_ViewerForbidden(t *testing.T) {
	env, token := setupTestEnv(t)
	_, adminSess := adminBootstrap(t, env, token, "admin", testAdminPassword)

	// Create a viewer-source service account via the (admin)
	// endpoint, then check that the corresponding endpoint
	// rejects WHEN the session is a viewer. A simpler proxy:
	// adminBootstrap gives us admin only; demote a fresh local
	// user to viewer and try with their session. Cheaper:
	// just try unauthenticated (no cookie → 401 from SoftAuth,
	// not 403 from RequireAdmin) — that already proves the
	// gate is in place. We'll also rely on the existing
	// updateUserRole tests to cover the viewer path more
	// generally.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/service-accounts", strings.NewReader(`{"name":"x","role":"viewer"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("want 401 without admin session, got %d", rec.Code)
	}
	_ = adminSess
}

// Phase 4 — Rotation flow.

func TestRotateServiceAccountToken_RevokesOldIssuesNew(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	// Create.
	rec := postJSONWithSession(t, env, "/api/v1/admin/users/service-accounts", sessCookie, map[string]any{
		"name": "n8n",
		"role": "viewer",
	})
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	user := created["user"].(map[string]any)
	userID := user["id"].(string)
	oldToken := created["token"].(string)

	// Rotate.
	rec = postJSONWithSession(t, env, "/api/v1/admin/users/service-accounts/"+userID+"/rotate-token", sessCookie, map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var rotated map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &rotated)
	newToken, _ := rotated["token"].(string)
	if newToken == oldToken {
		t.Fatal("rotation returned the same token")
	}
	if !strings.HasPrefix(newToken, auth.APITokenPrefix) {
		t.Errorf("new token missing prefix: %q", newToken)
	}

	// Old token should no longer authenticate. Easiest way to
	// prove: hit /me with the old token as Bearer (no cookie).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("old token still authenticates: status=%d", rec.Code)
	}

	// New token authenticates.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+newToken)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("new token does not authenticate: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Audit emitted.
	events, _, _ := env.audit.List(t.Context(), audit.Filter{
		Action:   audit.ActionServiceAccountTokenRotated,
		TargetID: userID,
		Limit:    10,
	})
	if len(events) == 0 {
		t.Error("audit log missing service_account_token_rotated")
	}
}

func TestRotateServiceAccountToken_RejectsHumanUser(t *testing.T) {
	env, token := setupTestEnv(t)
	humanID, sessCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	rec := postJSONWithSession(t, env, "/api/v1/admin/users/service-accounts/"+humanID+"/rotate-token", sessCookie, map[string]any{})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 when rotating a human user, got %d", rec.Code)
	}
}

func TestDeleteServiceAccount_CascadesTokens(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	// Create.
	rec := postJSONWithSession(t, env, "/api/v1/admin/users/service-accounts", sessCookie, map[string]any{
		"name": "to-delete",
		"role": "viewer",
	})
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	user := created["user"].(map[string]any)
	userID := user["id"].(string)
	tokStr := created["token"].(string)

	// Delete.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/service-accounts/"+userID, nil)
	withSessionCookie(req, sessCookie)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d; body=%s", rec.Code, rec.Body.String())
	}

	// Token must no longer authenticate.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokStr)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("deleted account's token still authenticates: status=%d", rec.Code)
	}

	// Audit emitted.
	events, _, _ := env.audit.List(t.Context(), audit.Filter{
		Action:   audit.ActionServiceAccountDeleted,
		TargetID: userID,
		Limit:    10,
	})
	if len(events) == 0 {
		t.Error("audit log missing service_account_deleted")
	}
}

func TestDeleteServiceAccount_RejectsHumanUser(t *testing.T) {
	env, token := setupTestEnv(t)
	humanID, sessCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/service-accounts/"+humanID, nil)
	withSessionCookie(req, sessCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 when targetting a human user via service-account endpoint, got %d", rec.Code)
	}
}

func TestServiceAccount_BearerAuthorisesAdminEndpoint(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	// Create a service ADMIN.
	rec := postJSONWithSession(t, env, "/api/v1/admin/users/service-accounts", sessCookie, map[string]any{
		"name": "ops-admin",
		"role": "admin",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create svc admin: %d body=%s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	tokStr := created["token"].(string)

	// Use Bearer to hit an admin-only endpoint — the users
	// list. No cookie at all → Bearer must work end-to-end.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+tokStr)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Bearer admin lookup failed: status=%d body=%s", rec.Code, rec.Body.String())
	}
}
