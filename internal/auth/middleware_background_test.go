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

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func serveHard(t *testing.T, sess Session, background bool) (*httptest.ResponseRecorder, *mockSessionStore, *passthroughHandler) {
	t.Helper()
	store := &mockSessionStore{sessions: map[string]Session{"sid": sess}}
	users := &mockUserStore{users: map[string]User{"uid": {ID: "uid", Username: "admin"}}}
	inner := &passthroughHandler{}
	h := HardAuthMiddleware(store, users, nil, false)(inner)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/version", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
	if background {
		r.Header.Set(BackgroundRequestHeader, "1")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec, store, inner
}

// TestHardAuthMiddleware_BackgroundRequest_DoesNotTouch: polling on a
// fresh session is served but does not refresh LastActivity — an
// unattended open tab must still lock after SessionIdleTimeout.
func TestHardAuthMiddleware_BackgroundRequest_DoesNotTouch(t *testing.T) {
	rec, store, inner := serveHard(t, freshSession("sid", "uid"), true)
	if rec.Code != http.StatusOK || !inner.called.Load() {
		t.Fatalf("background request not served: %d", rec.Code)
	}
	if n := store.touchCallCount.Load(); n != 0 {
		t.Errorf("background request touched the session %d times; polling would keep it awake forever", n)
	}
}

// TestHardAuthMiddleware_BackgroundRequest_StillLocked: the lock is
// enforced on background requests (the poll is how the UI learns it).
func TestHardAuthMiddleware_BackgroundRequest_StillLocked(t *testing.T) {
	rec, store, inner := serveHard(t, idleSession("sid", "uid"), true)
	if rec.Code != http.StatusForbidden || inner.called.Load() {
		t.Fatalf("locked session served a background request: %d", rec.Code)
	}
	if store.touchCallCount.Load() != 0 {
		t.Error("locked session touched")
	}
}

// TestHardAuthMiddleware_UserRequest_Touches pins the unchanged path.
func TestHardAuthMiddleware_UserRequest_Touches(t *testing.T) {
	rec, store, _ := serveHard(t, freshSession("sid", "uid"), false)
	if rec.Code != http.StatusOK || store.touchCallCount.Load() != 1 {
		t.Fatalf("user request: status %d, touches %d (want 200, 1)", rec.Code, store.touchCallCount.Load())
	}
}
