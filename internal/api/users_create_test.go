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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.48 — POST /admin/users.
//
// The gates are the ones the design named: a created account can
// actually sign in, it is then made to change its password, and that
// password exists in exactly one response and nowhere else.

func createUser(t *testing.T, env *testEnv, cookie string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	return postJSONWithSession(t, env, "/api/v1/admin/users", cookie, body)
}

func getWithSession(t *testing.T, env *testEnv, path, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := withSessionCookie(httptest.NewRequest(http.MethodGet, path, nil), cookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func sessionCookieFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c.Value
		}
	}
	t.Fatalf("no session cookie in the response: %s", rec.Body.String())
	return ""
}

func TestCreateUser_GeneratesAPasswordThatWorksOnce(t *testing.T) {
	env, token := setupTestEnv(t)
	_, cookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	rec := createUser(t, env, cookie, map[string]any{
		"username":    "alice",
		"displayName": "Alice",
		"email":       "alice@example.org",
		"role":        "viewer",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		User              map[string]any `json:"user"`
		GeneratedPassword string         `json:"generatedPassword"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if resp.GeneratedPassword == "" {
		t.Fatal("no password was returned, so the account is unusable")
	}
	// Long enough to clear the policy, and grouped so it survives
	// being read off a screen and typed somewhere else.
	if len(resp.GeneratedPassword) < 15 || !strings.Contains(resp.GeneratedPassword, "-") {
		t.Errorf("generated password shape: %q", resp.GeneratedPassword)
	}
	if resp.User["role"] != "viewer" {
		t.Errorf("role = %v, want viewer", resp.User["role"])
	}
	if resp.User["authSource"] != "local" {
		t.Errorf("authSource = %v, want local", resp.User["authSource"])
	}

	// The gate that matters: it works, and it is then required to
	// change. Asserted against the real login handler.
	loginRec := postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
		"username": "alice",
		"password": resp.GeneratedPassword,
	})
	if loginRec.Code != http.StatusOK {
		t.Fatalf("the returned password must let the account in: %d %s",
			loginRec.Code, loginRec.Body.String())
	}
	// The login response is deliberately minimal (id, username,
	// display name); the frontend reads session state from /auth/me,
	// so that is where the flag has to be visible.
	meRec := getWithSession(t, env, "/api/v1/auth/me", sessionCookieFrom(t, loginRec))
	var me map[string]any
	_ = json.Unmarshal(meRec.Body.Bytes(), &me)
	if me["mustChangePassword"] != true {
		t.Errorf("the creator knows this password, so a change must be required: %v", me)
	}
}

// The password must exist in the creation response and nowhere else.
func TestCreateUser_PasswordLeaksNowhere(t *testing.T) {
	env, token := setupTestEnv(t)
	_, cookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	rec := createUser(t, env, cookie, map[string]any{
		"username": "bob", "displayName": "Bob", "email": "bob@example.org", "role": "viewer",
	})
	var resp struct {
		GeneratedPassword string `json:"generatedPassword"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.GeneratedPassword == "" {
		t.Fatal("setup: no password returned")
	}

	// Not in the list.
	listRec := getWithSession(t, env, "/api/v1/admin/users", cookie)
	if strings.Contains(listRec.Body.String(), resp.GeneratedPassword) {
		t.Error("the password is readable from the users list")
	}

	// Not in the audit trail. An audit log that holds credentials is
	// a credential store.
	events, _, _ := env.audit.List(t.Context(), audit.Filter{
		Action: audit.ActionUserCreated, Limit: 10,
	})
	if len(events) == 0 {
		t.Fatal("the creation was not audited")
	}
	for _, e := range events {
		blob := string(e.BeforeJSON) + string(e.AfterJSON) + e.Message
		if strings.Contains(blob, resp.GeneratedPassword) {
			t.Error("the password leaked into the audit row")
		}
	}
	// And the event still says enough to be useful.
	if !strings.Contains(events[0].Message, "bob") {
		t.Errorf("the audit event must name the account: %q", events[0].Message)
	}
}

// A typed password is accepted and is NOT echoed back: the admin
// already has it.
func TestCreateUser_TypedPasswordIsNotEchoed(t *testing.T) {
	env, token := setupTestEnv(t)
	_, cookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	rec := createUser(t, env, cookie, map[string]any{
		"username": "carol", "displayName": "Carol", "email": "carol@example.org",
		"role": "admin", "password": "a-perfectly-long-chosen-password",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "a-perfectly-long-chosen-password") {
		t.Error("a typed password must not be echoed back")
	}

	loginRec := postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
		"username": "carol", "password": "a-perfectly-long-chosen-password",
	})
	if loginRec.Code != http.StatusOK {
		t.Fatalf("the typed password must work: %d %s", loginRec.Code, loginRec.Body.String())
	}
}

func TestCreateUser_RefusesADuplicateUsername(t *testing.T) {
	env, token := setupTestEnv(t)
	_, cookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	body := map[string]any{
		"username": "dave", "displayName": "Dave", "email": "dave@example.org", "role": "viewer",
	}
	if rec := createUser(t, env, cookie, body); rec.Code != http.StatusCreated {
		t.Fatalf("first create: %d %s", rec.Code, rec.Body.String())
	}
	rec := createUser(t, env, cookie, body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("a duplicate must be a 409, not a 500: %d %s", rec.Code, rec.Body.String())
	}
	var errBody struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &errBody)
	if errBody.Code != "user_username_taken" {
		t.Errorf("the refusal must carry a code the UI can translate: %q", errBody.Code)
	}
}

// A role is a privilege decision, so there is no default: forgetting
// it is a refusal rather than a silent grant.
func TestCreateUser_RefusesAMissingRole(t *testing.T) {
	env, token := setupTestEnv(t)
	_, cookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	rec := createUser(t, env, cookie, map[string]any{
		"username": "erin", "displayName": "Erin", "email": "erin@example.org",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	var errBody struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &errBody)
	if errBody.Code != "user_role_invalid" {
		t.Errorf("code = %q", errBody.Code)
	}
}

// Two identities for one person, one password-based and one federated,
// with the landing page decided by which button they pressed.
func TestCreateUser_RefusesAnEmailSSOAlreadyClaims(t *testing.T) {
	env, token := setupTestEnv(t)
	_, cookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	if err := env.store.PutOIDCConfig(t.Context(), storage.OIDCConfig{
		AllowedIdentities: []storage.OIDCAllowedIdentity{{Email: "frank@example.org"}},
	}); err != nil {
		t.Fatalf("seed oidc config: %v", err)
	}

	rec := createUser(t, env, cookie, map[string]any{
		"username": "frank", "displayName": "Frank",
		"email": "Frank@Example.org", // case must not slip past it
		"role":  "viewer",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	var errBody struct {
		Code   string            `json:"code"`
		Params map[string]string `json:"params"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &errBody)
	if errBody.Code != "user_email_on_oidc_allowlist" {
		t.Errorf("code = %q", errBody.Code)
	}
	if errBody.Params["email"] == "" {
		t.Errorf("the address must travel as a parameter: %v", errBody.Params)
	}
}

func TestCreateUser_ViewerForbidden(t *testing.T) {
	env, token := setupTestEnv(t)
	_, adminCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	// Make a viewer, then act as them.
	rec := createUser(t, env, adminCookie, map[string]any{
		"username": "grace", "displayName": "Grace", "email": "grace@example.org", "role": "viewer",
	})
	var resp struct {
		GeneratedPassword string `json:"generatedPassword"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	loginRec := postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
		"username": "grace", "password": resp.GeneratedPassword,
	})
	viewerCookie := sessionCookieFrom(t, loginRec)

	forbidden := createUser(t, env, viewerCookie, map[string]any{
		"username": "heidi", "displayName": "Heidi", "email": "heidi@example.org", "role": "admin",
	})
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("a viewer must not create accounts: %d %s",
			forbidden.Code, forbidden.Body.String())
	}
}
