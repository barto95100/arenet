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

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A MustChangePassword account's one-time initial password is relayed in
// the clear (chat, mail, screenshot). The SPA overlay stops a browser
// user, but the server must stop the API too — otherwise a reader of
// that password drives every endpoint the role allows for as long as the
// account exists (F23). HardAuthMiddleware refuses every hard endpoint
// but the password-change one.
func serveHardMustChange(t *testing.T, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	store := &mockSessionStore{sessions: map[string]Session{"sid": freshSession("sid", "uid")}}
	users := &mockUserStore{users: map[string]User{
		"uid": {ID: "uid", Username: "alice", Role: UserRoleAdmin, MustChangePassword: true},
	}}
	inner := &passthroughHandler{}
	h := HardAuthMiddleware(store, users, nil, false)(inner)
	r := httptest.NewRequest(method, path, nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestHardAuthMiddleware_MustChange_BlocksWork(t *testing.T) {
	rec := serveHardMustChange(t, http.MethodGet, "/api/v1/routes")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a must-change account reached a work endpoint: status %d, want 403", rec.Code)
	}
}

func TestHardAuthMiddleware_MustChange_AllowsPasswordChange(t *testing.T) {
	rec := serveHardMustChange(t, http.MethodPost, "/api/v1/auth/me/password")
	if rec.Code != http.StatusOK {
		t.Fatalf("a must-change account must be able to rotate its password: status %d, want 200", rec.Code)
	}
}

// A normal account is unaffected: the gate must not fire when the flag
// is false.
func TestHardAuthMiddleware_NoMustChange_Unaffected(t *testing.T) {
	store := &mockSessionStore{sessions: map[string]Session{"sid": freshSession("sid", "uid")}}
	users := &mockUserStore{users: map[string]User{
		"uid": {ID: "uid", Username: "bob", Role: UserRoleAdmin},
	}}
	inner := &passthroughHandler{}
	h := HardAuthMiddleware(store, users, nil, false)(inner)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK || !inner.called.Load() {
		t.Fatalf("a normal account was blocked: status %d", rec.Code)
	}
}
