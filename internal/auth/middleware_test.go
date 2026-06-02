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
	"crypto/tls" 
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- Hand-rolled mocks ----------------------------------------------------

// mockSessionStore implements the unexported sessionStore interface.
// touchCallCount and lastTouchedID expose call observation for the
// security-critical TestHardAuthMiddleware_TouchAfterCheck.
type mockSessionStore struct {
	sessions map[string]Session
	getErr   error // when non-nil, Get returns this instead of looking up

	touchCallCount atomic.Int32
	lastTouchedID  string
	touchErr       error // when non-nil, Touch returns this

	deleteCallCount atomic.Int32
}

func (m *mockSessionStore) Get(_ context.Context, id string) (Session, error) {
	if m.getErr != nil {
		return Session{}, m.getErr
	}
	s, ok := m.sessions[id]
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	return s, nil
}

func (m *mockSessionStore) Touch(_ context.Context, id string) error {
	m.touchCallCount.Add(1)
	m.lastTouchedID = id
	return m.touchErr
}

func (m *mockSessionStore) Delete(_ context.Context, id string) error {
	m.deleteCallCount.Add(1)
	delete(m.sessions, id)
	return nil
}

// mockUserStore implements the unexported userStore interface.
type mockUserStore struct {
	users  map[string]User
	getErr error // when non-nil, GetByID returns this
}

func (m *mockUserStore) GetByID(_ context.Context, id string) (User, error) {
	if m.getErr != nil {
		return User{}, m.getErr
	}
	u, ok := m.users[id]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return u, nil
}

// passthroughHandler always responds 200 and exposes the request
// context it was called with (for ctx-key assertions in tests).
type passthroughHandler struct {
	called    atomic.Bool
	seenCtx   context.Context
	bodyToSet string
}

func (h *passthroughHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called.Store(true)
	h.seenCtx = r.Context()
	w.WriteHeader(http.StatusOK)
	if h.bodyToSet != "" {
		_, _ = w.Write([]byte(h.bodyToSet))
	}
}

// freshSession returns a Session that just got created (LastActivity = now,
// not idle). Stored in the mock store under sessionID.
func freshSession(sessionID, userID string) Session {
	now := time.Now().UTC()
	return Session{
		ID:           sessionID,
		UserID:       userID,
		IssuedAt:     now,
		ExpiresAt:    now.Add(SessionTTLDefault),
		LastActivity: now,
		RememberMe:   false,
		IP:           "10.0.0.1",
		UserAgent:    "test/1",
	}
}

// idleSession returns a Session whose LastActivity is 16 minutes in
// the past (1 minute over the idle threshold). Used by sub-test #1.
func idleSession(sessionID, userID string) Session {
	now := time.Now().UTC()
	return Session{
		ID:           sessionID,
		UserID:       userID,
		IssuedAt:     now.Add(-time.Hour),
		ExpiresAt:    now.Add(SessionTTLDefault),
		LastActivity: now.Add(-(SessionIdleTimeout + time.Minute)),
		RememberMe:   false,
		IP:           "10.0.0.1",
		UserAgent:    "test/1",
	}
}

// --- SoftAuthMiddleware tests --------------------------------------------

func TestSoftAuthMiddleware_NilSessionStorePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = SoftAuthMiddleware(nil, &mockUserStore{}, false)
}

func TestSoftAuthMiddleware_NilUserStorePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = SoftAuthMiddleware(&mockSessionStore{}, nil, false)
}

func TestSoftAuthMiddleware_NoCookie_401(t *testing.T) {
	mw := SoftAuthMiddleware(&mockSessionStore{sessions: map[string]Session{}}, &mockUserStore{users: map[string]User{}}, false)
	inner := &passthroughHandler{}
	h := mw(inner)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if inner.called.Load() {
		t.Error("inner handler must NOT be called without a cookie")
	}
	if !strings.Contains(rec.Body.String(), `"no active session"`) {
		t.Errorf("body = %q, want it to contain \"no active session\"", rec.Body.String())
	}
}

func TestSoftAuthMiddleware_SessionNotFound_401AndClearsCookie(t *testing.T) {
	store := &mockSessionStore{sessions: map[string]Session{}}
	mw := SoftAuthMiddleware(store, &mockUserStore{}, false)
	inner := &passthroughHandler{}
	h := mw(inner)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "stale"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if inner.called.Load() {
		t.Error("inner handler must NOT be called for not-found session")
	}
	// Verify the Set-Cookie header instructs the browser to drop the cookie.
	setCookie := rec.Header().Get("Set-Cookie")
	if setCookie == "" {
		t.Fatal("expected Set-Cookie clearing header")
	}
	if !strings.Contains(setCookie, sessionCookieName+"=") || !strings.Contains(setCookie, "Max-Age=0") {
		t.Errorf("Set-Cookie does not clear the cookie: %q", setCookie)
	}
}

func TestSoftAuthMiddleware_SessionExpired_401AndClearsCookie(t *testing.T) {
	store := &mockSessionStore{
		sessions: map[string]Session{},
		getErr:   ErrSessionExpired,
	}
	mw := SoftAuthMiddleware(store, &mockUserStore{}, false)
	inner := &passthroughHandler{}
	h := mw(inner)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "expired"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Error("expected cookie clearance on expired session")
	}
}

func TestSoftAuthMiddleware_UserDeleted_401AndCleansUpSession(t *testing.T) {
	store := &mockSessionStore{
		sessions: map[string]Session{
			"sid": {ID: "sid", UserID: "ghost", LastActivity: time.Now().UTC()},
		},
	}
	users := &mockUserStore{users: map[string]User{}} // user "ghost" doesn't exist
	mw := SoftAuthMiddleware(store, users, false)
	inner := &passthroughHandler{}
	h := mw(inner)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if store.deleteCallCount.Load() != 1 {
		t.Errorf("orphan session not cleaned up; Delete called %d times", store.deleteCallCount.Load())
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Error("expected cookie clearance")
	}
}

func TestSoftAuthMiddleware_StorageError_503(t *testing.T) {
	store := &mockSessionStore{
		sessions: map[string]Session{"sid": freshSession("sid", "uid")},
	}
	users := &mockUserStore{getErr: errors.New("simulated db failure")}
	mw := SoftAuthMiddleware(store, users, false)
	inner := &passthroughHandler{}
	h := mw(inner)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "authentication service temporarily unavailable") {
		t.Errorf("body lacks expected message: %q", rec.Body.String())
	}
}

func TestSoftAuthMiddleware_ValidSession_PopulatesContext(t *testing.T) {
	store := &mockSessionStore{
		sessions: map[string]Session{"sid": freshSession("sid", "uid")},
	}
	users := &mockUserStore{
		users: map[string]User{"uid": {ID: "uid", Username: "admin"}},
	}
	mw := SoftAuthMiddleware(store, users, false)
	inner := &passthroughHandler{}
	h := mw(inner)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !inner.called.Load() {
		t.Fatal("inner handler not called")
	}
	if got := UserIDFromContext(inner.seenCtx); got != "uid" {
		t.Errorf("UserID = %q, want uid", got)
	}
	if got := UsernameFromContext(inner.seenCtx); got != "admin" {
		t.Errorf("Username = %q, want admin", got)
	}
	if got := SessionIDFromContext(inner.seenCtx); got != "sid" {
		t.Errorf("SessionID = %q, want sid", got)
	}
	if IsLockedFromContext(inner.seenCtx) {
		t.Error("IsLocked = true; want false for fresh session")
	}
}

func TestSoftAuthMiddleware_IdleSession_PassesWithIsLockedTrue(t *testing.T) {
	// Critical: soft-auth must allow idle sessions to pass (so /me and
	// /unlock can run), populating IsLockedKey=true. Hard-auth then
	// rejects them.
	store := &mockSessionStore{
		sessions: map[string]Session{"sid": idleSession("sid", "uid")},
	}
	users := &mockUserStore{
		users: map[string]User{"uid": {ID: "uid", Username: "admin"}},
	}
	mw := SoftAuthMiddleware(store, users, false)
	inner := &passthroughHandler{}
	h := mw(inner)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (idle session passes soft-auth)", rec.Code)
	}
	if !inner.called.Load() {
		t.Fatal("inner handler not called; soft-auth wrongly rejected idle session")
	}
	if !IsLockedFromContext(inner.seenCtx) {
		t.Error("IsLocked = false; want true for idle session")
	}
}

// TestSoftAuthMiddleware_DoesNotCallTouch verifies that soft-auth
// NEVER invokes Touch, regardless of the session state. This is the
// reason /me does not push back the idle timeout (spec §5.6).
func TestSoftAuthMiddleware_DoesNotCallTouch(t *testing.T) {
	store := &mockSessionStore{
		sessions: map[string]Session{"sid": freshSession("sid", "uid")},
	}
	users := &mockUserStore{
		users: map[string]User{"uid": {ID: "uid", Username: "admin"}},
	}
	mw := SoftAuthMiddleware(store, users, false)
	h := mw(&passthroughHandler{})

	for i := 0; i < 5; i++ {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if n := store.touchCallCount.Load(); n != 0 {
		t.Errorf("soft-auth must NEVER call Touch; got %d calls", n)
	}
}

// --- HardAuthMiddleware tests --------------------------------------------

// TestHardAuthMiddleware_TouchAfterCheck is SUB-TEST SECURITY #1
// (plan §4.2 + §7.3 risk register).
//
// Failure scenario protected: a future refactor that moves
// sessions.Touch() BEFORE the IsLocked check would refresh
// LastActivity on an idle session that we are about to reject. The
// session would never lock, making the entire lock screen flow
// unreachable.
//
// Test setup: mock SessionStore returns an idle session (LastActivity
// 16 min in the past). Hit a hard-auth endpoint and assert:
//
//  1. The response is 403 ("session locked").
//  2. The inner handler is NOT called.
//  3. Touch was NOT called (touchCallCount == 0).
//
// If Touch were moved before the lock check, claim 3 would fail
// (touchCallCount would be 1) and this test would FAIL.
func TestHardAuthMiddleware_TouchAfterCheck(t *testing.T) {
	store := &mockSessionStore{
		sessions: map[string]Session{"sid": idleSession("sid", "uid")},
	}
	users := &mockUserStore{
		users: map[string]User{"uid": {ID: "uid", Username: "admin"}},
	}
	mw := HardAuthMiddleware(store, users, false)
	inner := &passthroughHandler{}
	h := mw(inner)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	// Claim 1: 403 returned.
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (session locked)", rec.Code)
	}
	// Body must say "session locked".
	if !strings.Contains(rec.Body.String(), `"session locked"`) {
		t.Errorf("body = %q, want it to contain \"session locked\"", rec.Body.String())
	}

	// Claim 2: inner handler NOT called.
	if inner.called.Load() {
		t.Error("inner handler was called on idle session; should be blocked at 403")
	}

	// Claim 3: Touch NOT called. THIS IS THE SECURITY-CRITICAL ASSERT.
	if n := store.touchCallCount.Load(); n != 0 {
		t.Errorf("SECURITY VIOLATION: Touch called %d times on idle session; must be 0. "+
			"This indicates Touch is being invoked BEFORE the idle check, making the lock screen unreachable.", n)
	}
}

func TestHardAuthMiddleware_FreshSession_TouchCalledAfterCheck(t *testing.T) {
	store := &mockSessionStore{
		sessions: map[string]Session{"sid": freshSession("sid", "uid")},
	}
	users := &mockUserStore{
		users: map[string]User{"uid": {ID: "uid", Username: "admin"}},
	}
	mw := HardAuthMiddleware(store, users, false)
	inner := &passthroughHandler{}
	h := mw(inner)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !inner.called.Load() {
		t.Error("inner handler NOT called for fresh session")
	}
	if n := store.touchCallCount.Load(); n != 1 {
		t.Errorf("Touch calls = %d, want 1 (called once after successful idle check)", n)
	}
	if store.lastTouchedID != "sid" {
		t.Errorf("Touch called with id %q, want sid", store.lastTouchedID)
	}
}

func TestHardAuthMiddleware_TouchFailure_NonFatal(t *testing.T) {
	// Touch is best-effort. If it fails (DB hiccup), the request
	// should still succeed — the user has already passed auth.
	store := &mockSessionStore{
		sessions: map[string]Session{"sid": freshSession("sid", "uid")},
		touchErr: errors.New("simulated db hiccup"),
	}
	users := &mockUserStore{
		users: map[string]User{"uid": {ID: "uid", Username: "admin"}},
	}
	mw := HardAuthMiddleware(store, users, false)
	inner := &passthroughHandler{}
	h := mw(inner)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (Touch failure must not fail the request)", rec.Code)
	}
	if !inner.called.Load() {
		t.Error("inner handler not called; Touch error wrongly aborted the request")
	}
}

func TestHardAuthMiddleware_NoCookie_DelegatesToSoftAuth401(t *testing.T) {
	// Hard-auth wraps soft-auth. A missing cookie returns 401, not 403.
	mw := HardAuthMiddleware(&mockSessionStore{sessions: map[string]Session{}}, &mockUserStore{}, false)
	inner := &passthroughHandler{}
	h := mw(inner)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (delegated from soft-auth)", rec.Code)
	}
}

// --- Cookie attribute tests ----------------------------------------------
// Step #S-11: Secure is set based on the actual request scheme,
// not a devMode flag. A request with r.TLS != nil represents an
// HTTPS handshake that terminated at this server, so the cookie
// is flagged Secure.
func TestClearSessionCookie_TLSRequest_IncludesSecure(t *testing.T) {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{} // non-nil marker: request came over TLS
	clearSessionCookie(rec, r)
	got := rec.Header().Get("Set-Cookie")
	if !strings.Contains(got, "Secure") {
		t.Errorf("TLS-request cookie clear should include Secure; got %q", got)
	}
	if !strings.Contains(got, "HttpOnly") {
		t.Errorf("missing HttpOnly: %q", got)
	}
	if !strings.Contains(got, "SameSite=Strict") {
		t.Errorf("missing SameSite=Strict: %q", got)
	}
	if !strings.Contains(got, "Path=/") {
		t.Errorf("missing Path=/: %q", got)
	}
	if !strings.Contains(got, "Max-Age=0") {
		t.Errorf("missing Max-Age=0: %q", got)
	}
}

// Step #S-11: a plain HTTP request (r.TLS == nil) means the browser
// is on a non-secure context, so the cookie must NOT be flagged
// Secure — the browser would otherwise silently refuse it.
func TestClearSessionCookie_PlainHTTPRequest_OmitsSecure(t *testing.T) {	
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil) // r.TLS is nil
	clearSessionCookie(rec, r)
	got := rec.Header().Get("Set-Cookie")
	if strings.Contains(got, "Secure") {
		t.Errorf("plain-HTTP request cookie clear must NOT include Secure; got %q", got)
	}
	if !strings.Contains(got, "HttpOnly") {
		t.Errorf("HttpOnly must still be set in dev mode: %q", got)
	}
}
