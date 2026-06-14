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
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Phase 4 — SoftAuthMiddleware Bearer fallback matrix.
//
// The 6 scenarios from the brief, each with its own t.Run:
//   1. Cookie valid + Bearer valid              → use cookie (Bearer ignored)
//   2. Cookie absent + Bearer valid             → use Bearer
//   3. Cookie absent + Bearer invalid           → 401
//   4. Cookie expired + Bearer valid            → use Bearer
//   5. Cookie expired + Bearer absent           → 401 (existing behaviour preserved)
//   6. Token revoked                            → 401
//   7. Token expired (TTL field)                → 401
//   8. tokens=nil + Bearer present              → 401 (Bearer ignored when wired off)
//   9. Bearer wrong prefix                      → 401
//
// The downstream handler captures r.Context() values so the
// test can assert the correct identity was attached.

// mockTokenStore implements APITokenLookup. Backed by a single
// keyed-by-plain-token map for hash-free test simplicity (the
// store's internal SHA-256 path is exercised by tokenstore_test.go).
type mockTokenStore struct {
	tokens         map[string]APIToken // plain → row
	touchCallCount atomic.Int32
}

func (m *mockTokenStore) LookupToken(_ context.Context, plain string) (APIToken, error) {
	t, ok := m.tokens[plain]
	if !ok {
		return APIToken{}, ErrAPITokenInvalid
	}
	return t, nil
}

func (m *mockTokenStore) TouchLastUsed(_ context.Context, _ string) error {
	m.touchCallCount.Add(1)
	return nil
}

func captureIdentityHandler() (http.Handler, *struct {
	userID, authSource, role string
	called                   bool
}) {
	captured := &struct {
		userID, authSource, role string
		called                   bool
	}{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.userID, _ = r.Context().Value(UserIDKey).(string)
		captured.authSource, _ = r.Context().Value(AuthSourceKey).(string)
		captured.role, _ = r.Context().Value(RoleKey).(string)
		captured.called = true
		w.WriteHeader(http.StatusOK)
	})
	return h, captured
}

func TestSoftAuthMiddleware_Bearer_CookieValidIgnoresBearer(t *testing.T) {
	humanUser := User{ID: "human-uid", Username: "alice", Role: UserRoleAdmin, AuthSource: UserAuthSourceLocal}
	serviceUser := User{ID: "svc-uid", Username: "ci", Role: UserRoleViewer, AuthSource: UserAuthSourceService}

	sessions := &mockSessionStore{sessions: map[string]Session{
		"sess-1": {ID: "sess-1", UserID: humanUser.ID, LastActivity: time.Now().UTC()},
	}}
	users := &mockUserStore{users: map[string]User{
		humanUser.ID:   humanUser,
		serviceUser.ID: serviceUser,
	}}
	tokens := &mockTokenStore{tokens: map[string]APIToken{
		"arn_validvalidvalidvalidvalidvalidvalidvalidvalid": {ID: "tok-1", UserID: serviceUser.ID},
	}}

	handler, captured := captureIdentityHandler()
	mw := SoftAuthMiddleware(sessions, users, tokens, false)(handler)

	req := httptest.NewRequest("GET", "/x", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sess-1"})
	req.Header.Set("Authorization", "Bearer arn_validvalidvalidvalidvalidvalidvalidvalidvalid")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if !captured.called {
		t.Fatal("handler not invoked")
	}
	if captured.userID != humanUser.ID {
		t.Errorf("want cookie identity %q, got %q (Bearer leaked through)", humanUser.ID, captured.userID)
	}
	if captured.authSource != UserAuthSourceLocal {
		t.Errorf("want authSource=local, got %q", captured.authSource)
	}
}

func TestSoftAuthMiddleware_Bearer_NoCookieValidBearer_UsesBearer(t *testing.T) {
	serviceUser := User{ID: "svc-uid", Username: "ci", Role: UserRoleAdmin, AuthSource: UserAuthSourceService}

	sessions := &mockSessionStore{sessions: map[string]Session{}}
	users := &mockUserStore{users: map[string]User{serviceUser.ID: serviceUser}}
	tokens := &mockTokenStore{tokens: map[string]APIToken{
		"arn_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {ID: "tok-1", UserID: serviceUser.ID},
	}}

	handler, captured := captureIdentityHandler()
	mw := SoftAuthMiddleware(sessions, users, tokens, false)(handler)

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer arn_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if captured.userID != serviceUser.ID {
		t.Errorf("want Bearer identity %q, got %q", serviceUser.ID, captured.userID)
	}
	if captured.authSource != UserAuthSourceService {
		t.Errorf("want authSource=service, got %q", captured.authSource)
	}
	if captured.role != UserRoleAdmin {
		t.Errorf("want role=admin from token's user, got %q", captured.role)
	}
}

func TestSoftAuthMiddleware_Bearer_NoCookieInvalidBearer_401(t *testing.T) {
	sessions := &mockSessionStore{sessions: map[string]Session{}}
	users := &mockUserStore{users: map[string]User{}}
	tokens := &mockTokenStore{tokens: map[string]APIToken{}}

	handler, captured := captureIdentityHandler()
	mw := SoftAuthMiddleware(sessions, users, tokens, false)(handler)

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer arn_unknownunknownunknownunknownunknownunknown")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != 401 {
		t.Errorf("want 401, got %d", rec.Code)
	}
	if captured.called {
		t.Errorf("handler must not be invoked on invalid Bearer")
	}
}

func TestSoftAuthMiddleware_Bearer_CookieExpiredBearerValid_UsesBearer(t *testing.T) {
	serviceUser := User{ID: "svc-uid", Username: "ci", Role: UserRoleViewer, AuthSource: UserAuthSourceService}

	// Empty sessions map → "sess-stale" lookup returns ErrSessionNotFound (same path as expired).
	sessions := &mockSessionStore{sessions: map[string]Session{}}
	users := &mockUserStore{users: map[string]User{serviceUser.ID: serviceUser}}
	tokens := &mockTokenStore{tokens: map[string]APIToken{
		"arn_validvalidvalidvalidvalidvalidvalidvalidvali": {ID: "tok-1", UserID: serviceUser.ID},
	}}

	handler, captured := captureIdentityHandler()
	mw := SoftAuthMiddleware(sessions, users, tokens, false)(handler)

	req := httptest.NewRequest("GET", "/x", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sess-stale"})
	req.Header.Set("Authorization", "Bearer arn_validvalidvalidvalidvalidvalidvalidvalidvali")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if captured.userID != serviceUser.ID {
		t.Errorf("want Bearer identity (cookie failed → fallback), got %q", captured.userID)
	}
}

func TestSoftAuthMiddleware_Bearer_CookieExpiredNoBearer_401(t *testing.T) {
	sessions := &mockSessionStore{sessions: map[string]Session{}}
	users := &mockUserStore{users: map[string]User{}}
	tokens := &mockTokenStore{tokens: map[string]APIToken{}}

	handler, captured := captureIdentityHandler()
	mw := SoftAuthMiddleware(sessions, users, tokens, false)(handler)

	req := httptest.NewRequest("GET", "/x", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sess-stale"})
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != 401 {
		t.Errorf("want 401, got %d", rec.Code)
	}
	if captured.called {
		t.Errorf("handler must not be invoked")
	}
}

func TestSoftAuthMiddleware_Bearer_RevokedToken_401(t *testing.T) {
	serviceUser := User{ID: "svc-uid", AuthSource: UserAuthSourceService, Role: UserRoleViewer}
	revoked := time.Now().UTC().Add(-1 * time.Hour)

	sessions := &mockSessionStore{sessions: map[string]Session{}}
	users := &mockUserStore{users: map[string]User{serviceUser.ID: serviceUser}}
	tokens := &mockTokenStore{tokens: map[string]APIToken{
		"arn_revokedrevokedrevokedrevokedrevokedrevokedrev": {ID: "tok-1", UserID: serviceUser.ID, RevokedAt: &revoked},
	}}

	handler, captured := captureIdentityHandler()
	mw := SoftAuthMiddleware(sessions, users, tokens, false)(handler)

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer arn_revokedrevokedrevokedrevokedrevokedrevokedrev")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != 401 {
		t.Errorf("want 401 for revoked token, got %d", rec.Code)
	}
	if captured.called {
		t.Errorf("handler must not be invoked on revoked Bearer")
	}
}

func TestSoftAuthMiddleware_Bearer_ExpiredToken_401(t *testing.T) {
	serviceUser := User{ID: "svc-uid", AuthSource: UserAuthSourceService, Role: UserRoleViewer}
	past := time.Now().UTC().Add(-1 * time.Hour)

	sessions := &mockSessionStore{sessions: map[string]Session{}}
	users := &mockUserStore{users: map[string]User{serviceUser.ID: serviceUser}}
	tokens := &mockTokenStore{tokens: map[string]APIToken{
		"arn_expiredexpiredexpiredexpiredexpiredexpiredexp": {ID: "tok-1", UserID: serviceUser.ID, ExpiresAt: &past},
	}}

	handler, captured := captureIdentityHandler()
	mw := SoftAuthMiddleware(sessions, users, tokens, false)(handler)

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer arn_expiredexpiredexpiredexpiredexpiredexpiredexp")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != 401 {
		t.Errorf("want 401 for expired token, got %d", rec.Code)
	}
	if captured.called {
		t.Errorf("handler must not be invoked on expired Bearer")
	}
}

func TestSoftAuthMiddleware_Bearer_NilTokensStore_BearerIgnored(t *testing.T) {
	sessions := &mockSessionStore{sessions: map[string]Session{}}
	users := &mockUserStore{users: map[string]User{}}

	handler, captured := captureIdentityHandler()
	mw := SoftAuthMiddleware(sessions, users, nil, false)(handler)

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer arn_anytokenanytokenanytokenanytokenanytokenanytoken")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != 401 {
		t.Errorf("want 401 when tokens store is nil, got %d", rec.Code)
	}
	if captured.called {
		t.Errorf("handler must not be invoked")
	}
}

func TestSoftAuthMiddleware_Bearer_WrongHeaderScheme_NoBearerPath(t *testing.T) {
	sessions := &mockSessionStore{sessions: map[string]Session{}}
	users := &mockUserStore{users: map[string]User{}}
	tokens := &mockTokenStore{tokens: map[string]APIToken{}}

	handler, captured := captureIdentityHandler()
	mw := SoftAuthMiddleware(sessions, users, tokens, false)(handler)

	req := httptest.NewRequest("GET", "/x", nil)
	// Basic instead of Bearer.
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != 401 {
		t.Errorf("want 401 for non-Bearer Authorization, got %d", rec.Code)
	}
	if captured.called {
		t.Errorf("handler must not be invoked")
	}
}

func TestHardAuthMiddleware_Bearer_DoesNotCallSessionTouch(t *testing.T) {
	serviceUser := User{ID: "svc-uid", AuthSource: UserAuthSourceService, Role: UserRoleViewer}

	sessions := &mockSessionStore{sessions: map[string]Session{}}
	users := &mockUserStore{users: map[string]User{serviceUser.ID: serviceUser}}
	tokens := &mockTokenStore{tokens: map[string]APIToken{
		"arn_bearerbearerbearerbearerbearerbearerbearerbe": {ID: "tok-1", UserID: serviceUser.ID},
	}}

	handler, captured := captureIdentityHandler()
	mw := HardAuthMiddleware(sessions, users, tokens, false)(handler)

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer arn_bearerbearerbearerbearerbearerbearerbearerbe")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if !captured.called {
		t.Fatal("handler not invoked")
	}
	// Bearer requests have no session — Touch must be skipped.
	if got := sessions.touchCallCount.Load(); got != 0 {
		t.Errorf("Touch called %d times on Bearer request, want 0", got)
	}
}
