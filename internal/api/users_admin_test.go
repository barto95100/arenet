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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
)

// Users-page Phase 1: DELETE /api/v1/admin/users/{id}

// withDeleteAdminUserSession is a small helper that wraps the
// shared test env around a single admin bootstrap so each test
// starts from a clean slate.
func bootstrapTwoLocalAdmins(t *testing.T, env *testEnv, token, sessionCookie string) (firstID, secondID string) {
	t.Helper()
	// First user already created via adminBootstrap. Add a second
	// local admin so the last-admin guard doesn't fire when we
	// delete the first one.
	created, err := auth.NewUserStore(env.store.DB()).Create(
		t.Context(), "bob", "Bob", "bob@example.test", "another correct password 15",
	)
	if err != nil {
		t.Fatalf("seed second local admin: %v", err)
	}
	return "", created.ID
}

func TestDeleteAdminUser_HappyPath(t *testing.T) {
	env, token := setupTestEnv(t)
	firstID, sessCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)
	_ = firstID
	_, secondID := bootstrapTwoLocalAdmins(t, env, token, sessCookie)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+secondID, nil)
	withSessionCookie(req, sessCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	// Storage: user gone.
	if _, err := auth.NewUserStore(env.store.DB()).GetByID(t.Context(), secondID); err == nil {
		t.Errorf("user still in storage after DELETE")
	}
	// Audit: emitted with the expected action + target.
	events, _, _ := env.audit.List(t.Context(), audit.Filter{
		Action:   audit.ActionUserDeleted,
		TargetID: secondID,
		Limit:    10,
	})
	if len(events) == 0 {
		t.Errorf("audit log missing user_deleted action for %s", secondID)
	}
	if len(events) > 0 && len(events[0].BeforeJSON) == 0 {
		t.Error("BeforeJSON empty on user_deleted audit")
	}
}

func TestDeleteAdminUser_LastLocalAdmin_Blocked(t *testing.T) {
	// Only the bootstrap admin exists → guard fires.
	env, token := setupTestEnv(t)
	soleID, sessCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+soleID, nil)
	withSessionCookie(req, sessCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "break-glass") {
		t.Errorf("body = %s; want mention of break-glass guard", rec.Body.String())
	}
	// User must still exist.
	if _, err := auth.NewUserStore(env.store.DB()).GetByID(t.Context(), soleID); err != nil {
		t.Errorf("user gone despite blocked delete: %v", err)
	}
}

func TestDeleteAdminUser_NotFound(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/no-such-id", nil)
	withSessionCookie(req, sessCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestDeleteAdminUser_PurgesSessions(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)
	_, secondID := bootstrapTwoLocalAdmins(t, env, token, sessCookie)

	// Issue a session for the second user before delete.
	sessStore := auth.NewSessionStore(env.store.DB())
	sess, err := sessStore.Create(t.Context(), secondID, false, "1.1.1.1", "test")
	if err != nil {
		t.Fatalf("seed session for bob: %v", err)
	}

	// Delete.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+secondID, nil)
	withSessionCookie(req, sessCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", rec.Code)
	}

	// Session must be gone.
	if _, err := sessStore.Get(t.Context(), sess.ID); err == nil {
		t.Errorf("session still resolvable after user delete; cascade failed")
	}
}

// --- listAdminUsers shape tests (Email + activity fields)

func TestListAdminUsers_ResponseShape(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	withSessionCookie(req, sessCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var users []adminUserResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &users); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("len = %d; want 1", len(users))
	}
	u := users[0]
	// Email surfaced from the setup flow.
	if u.Email != "admin@example.test" {
		t.Errorf("Email = %q; want admin@example.test", u.Email)
	}
	// At least one active session (the cookie we logged in
	// with). ActiveSessionCount >= 1 is the structural pin —
	// in practice it's exactly 1 since we only issued one
	// cookie.
	if u.ActiveSessionCount < 1 {
		t.Errorf("ActiveSessionCount = %d; want ≥1", u.ActiveSessionCount)
	}
	if u.LastActivityAt == "" {
		t.Errorf("LastActivityAt empty despite a live session: %+v", u)
	}
}
