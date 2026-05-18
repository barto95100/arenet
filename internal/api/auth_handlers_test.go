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
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// setupTestEnv constructs a router exercising the auth subtree with
// the setup endpoint enabled and a known token. Returns the env and
// the token string so tests can submit it.
func setupTestEnv(t *testing.T) (*testEnv, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	caddy := &fakeReloader{}
	auditAppender := &fakeAuditAppender{}
	userStore := auth.NewUserStore(store.DB())
	sessionStore := auth.NewSessionStore(store.DB())
	t.Setenv("ARENET_HIBP_DISABLED", "true")
	hibpClient := auth.NewHIBPClient() // disabled by default (zero value)
	rateLimiter := auth.NewRateLimiter(logger)
	setupTokenHolder := NewSetupTokenHolder()
	token := setupTokenHolder.Generate()
	ipExtractor, _ := auth.NewIPExtractor("")

	h := NewHandler(store, caddy, auditAppender, userStore, sessionStore, hibpClient, rateLimiter, setupTokenHolder, false, logger)
	router := NewRouter(h, false, ipExtractor)

	return &testEnv{
		router:     router,
		store:      store,
		caddy:      caddy,
		audit:      auditAppender,
		setupToken: setupTokenHolder,
	}, token
}

// postJSON sends a POST request with a JSON body, returning the recorder.
func postJSON(t *testing.T, router http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(buf)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// --- POST /api/v1/auth/setup tests ---------------------------------------

func TestSetup_HappyPath(t *testing.T) {
	env, token := setupTestEnv(t)

	rec := postJSON(t, env.router, "/api/v1/auth/setup", map[string]string{
		"setupToken":  token,
		"username":    "admin",
		"displayName": "Site Admin",
		"password":    "correct horse battery staple",
	})

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}

	// Body shape check (no PasswordHash).
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body not JSON: %s (%v)", rec.Body.String(), err)
	}
	if resp["username"] != "admin" {
		t.Errorf("username = %v, want admin", resp["username"])
	}
	if resp["displayName"] != "Site Admin" {
		t.Errorf("displayName = %v, want Site Admin", resp["displayName"])
	}
	if _, ok := resp["passwordHash"]; ok {
		t.Error("passwordHash leaked into response body")
	}
	if _, ok := resp["password_hash"]; ok {
		t.Error("password_hash leaked into response body")
	}

	// Session cookie set with the documented attributes.
	setCookie := rec.Header().Get("Set-Cookie")
	if setCookie == "" {
		t.Fatal("missing Set-Cookie")
	}
	for _, attr := range []string{"arenet_session=", "HttpOnly", "Secure", "SameSite=Strict", "Path=/", "Max-Age=86400"} {
		if !strings.Contains(setCookie, attr) {
			t.Errorf("Set-Cookie missing %q: %s", attr, setCookie)
		}
	}

	// Audit event emitted, no PasswordHash leak.
	events := env.audit.Events()
	if len(events) != 1 {
		t.Fatalf("want 1 audit event, got %d", len(events))
	}
	e := events[0]
	if e.Action != audit.ActionSetupAdminCreated {
		t.Errorf("audit action = %q, want %q", e.Action, audit.ActionSetupAdminCreated)
	}
	if e.TargetType != "user" {
		t.Errorf("audit TargetType = %q, want user", e.TargetType)
	}
	if e.TargetID == "" {
		t.Error("audit TargetID empty")
	}
	if strings.Contains(string(e.AfterJSON), `"password_hash"`) && !strings.Contains(string(e.AfterJSON), `"password_hash":""`) {
		t.Errorf("PasswordHash leaked in audit AfterJSON: %s", string(e.AfterJSON))
	}
}

func TestSetup_DevMode_OmitsSecure(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	caddy := &fakeReloader{}
	auditAppender := &fakeAuditAppender{}
	userStore := auth.NewUserStore(store.DB())
	sessionStore := auth.NewSessionStore(store.DB())
	t.Setenv("ARENET_HIBP_DISABLED", "true")
	hibpClient := auth.NewHIBPClient()
	rateLimiter := auth.NewRateLimiter(logger)
	setupTokenHolder := NewSetupTokenHolder()
	token := setupTokenHolder.Generate()
	ipExtractor, _ := auth.NewIPExtractor("")

	h := NewHandler(store, caddy, auditAppender, userStore, sessionStore, hibpClient, rateLimiter, setupTokenHolder, true /* devMode */, logger)
	router := NewRouter(h, true, ipExtractor)

	rec := postJSON(t, router, "/api/v1/auth/setup", map[string]string{
		"setupToken": token,
		"username":   "admin",
		"password":   "correct horse battery staple",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	setCookie := rec.Header().Get("Set-Cookie")
	if strings.Contains(setCookie, "Secure") {
		t.Errorf("dev mode cookie must NOT include Secure; got %q", setCookie)
	}
}

func TestSetup_404WhenAdminExists(t *testing.T) {
	env, token := setupTestEnv(t)

	// First setup succeeds.
	rec := postJSON(t, env.router, "/api/v1/auth/setup", map[string]string{
		"setupToken": token,
		"username":   "admin",
		"password":   "correct horse battery staple",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("first setup failed: %d %s", rec.Code, rec.Body.String())
	}

	// Second attempt: 404 per spec §4.2.
	rec = postJSON(t, env.router, "/api/v1/auth/setup", map[string]string{
		"setupToken": token, // even with a valid token, must 404
		"username":   "admin2",
		"password":   "another correct passphrase",
	})
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "setup unavailable") {
		t.Errorf("body lacks expected message: %s", rec.Body.String())
	}
}

func TestSetup_403WhenTokenInvalid(t *testing.T) {
	env, _ := setupTestEnv(t)
	rec := postJSON(t, env.router, "/api/v1/auth/setup", map[string]string{
		"setupToken": "wrong-token",
		"username":   "admin",
		"password":   "correct horse battery staple",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "setup token invalid") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestSetup_400OnPasswordTooShort(t *testing.T) {
	env, token := setupTestEnv(t)
	rec := postJSON(t, env.router, "/api/v1/auth/setup", map[string]string{
		"setupToken": token,
		"username":   "admin",
		"password":   "short",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "at least 15") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestSetup_400OnUsernameInvalid(t *testing.T) {
	env, token := setupTestEnv(t)
	rec := postJSON(t, env.router, "/api/v1/auth/setup", map[string]string{
		"setupToken": token,
		"username":   "Admin", // uppercase rejected
		"password":   "correct horse battery staple",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "lowercase") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestSetup_400OnCommonPassword(t *testing.T) {
	env, token := setupTestEnv(t)
	// "Mailcreated5240" is in the top-10k list (verified in
	// password_test.go fixture).
	rec := postJSON(t, env.router, "/api/v1/auth/setup", map[string]string{
		"setupToken": token,
		"username":   "admin",
		"password":   "Mailcreated5240",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "common compromised") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestSetup_400OnInvalidJSON(t *testing.T) {
	env, _ := setupTestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/setup",
		strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "invalid JSON") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestSetup_400OnDisplayNameTooLong(t *testing.T) {
	env, token := setupTestEnv(t)
	long := strings.Repeat("a", 65)
	rec := postJSON(t, env.router, "/api/v1/auth/setup", map[string]string{
		"setupToken":  token,
		"username":    "admin",
		"displayName": long,
		"password":    "correct horse battery staple",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
}

// TestSetup_TokenInvalidatedAfterSuccess verifies the single-use
// semantics (spec §4.2 "preventing replay"): after a successful
// setup, the SetupTokenHolder must be invalidated regardless of
// whether subsequent requests reach the token-check or short-circuit
// earlier (the Count gate fires first in practice).
//
// We assert the holder directly via testEnv.setupToken — the
// indirect "second setup → 404" route would not distinguish "token
// invalidated" from "Count short-circuited before token verification".
func TestSetup_TokenInvalidatedAfterSuccess(t *testing.T) {
	env, token := setupTestEnv(t)

	// Sanity: token is active before setup.
	if !env.setupToken.Active() {
		t.Fatal("setupToken not Active before setup")
	}
	if !env.setupToken.Verify(token) {
		t.Fatal("setupToken does not Verify the generated token before setup")
	}

	rec := postJSON(t, env.router, "/api/v1/auth/setup", map[string]string{
		"setupToken": token,
		"username":   "admin",
		"password":   "correct horse battery staple",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup failed: %d %s", rec.Code, rec.Body.String())
	}

	// After successful setup, the holder must report Active() == false
	// and Verify(token) == false. This is the contract that prevents
	// replay even if the Count gate were bypassed in a future refactor.
	if env.setupToken.Active() {
		t.Error("setupToken still Active after successful setup; replay risk")
	}
	if env.setupToken.Verify(token) {
		t.Error("setupToken still Verifies the consumed token; replay risk")
	}
}

// --- SetupTokenHolder unit tests -----------------------------------------

func TestSetupTokenHolder_GenerateProducesHex(t *testing.T) {
	h := NewSetupTokenHolder()
	tok := h.Generate()
	if len(tok) != SetupTokenByteLen*2 {
		t.Errorf("token len = %d, want %d (hex of 32 bytes)", len(tok), SetupTokenByteLen*2)
	}
	for _, c := range tok {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("non-hex char %q in token", c)
			break
		}
	}
}

func TestSetupTokenHolder_VerifyMatches(t *testing.T) {
	h := NewSetupTokenHolder()
	tok := h.Generate()
	if !h.Verify(tok) {
		t.Error("Verify rejected the generated token")
	}
	if h.Verify("wrong") {
		t.Error("Verify accepted a wrong token")
	}
}

func TestSetupTokenHolder_VerifyRejectsEmptyHolder(t *testing.T) {
	h := NewSetupTokenHolder()
	if h.Verify("") {
		t.Error("Verify accepted empty candidate on empty holder")
	}
	if h.Verify("anything") {
		t.Error("Verify accepted candidate on empty holder")
	}
}

func TestSetupTokenHolder_Invalidate(t *testing.T) {
	h := NewSetupTokenHolder()
	tok := h.Generate()
	if !h.Active() {
		t.Error("Active false after Generate")
	}
	h.Invalidate()
	if h.Active() {
		t.Error("Active true after Invalidate")
	}
	if h.Verify(tok) {
		t.Error("token still verifies after Invalidate")
	}
}

func TestSetupTokenHolder_RegenerateReplacesToken(t *testing.T) {
	h := NewSetupTokenHolder()
	tok1 := h.Generate()
	tok2 := h.Generate()
	if tok1 == tok2 {
		t.Error("Generate produced the same token twice")
	}
	if h.Verify(tok1) {
		t.Error("old token still verifies after regenerate")
	}
	if !h.Verify(tok2) {
		t.Error("new token does not verify")
	}
}

// TestSetupTokenHolder_ConstantTimeBehavior is a smoke test: Verify
// must accept correct tokens and reject equal-length wrong ones
// without panic.
func TestSetupTokenHolder_ConstantTimeBehavior(t *testing.T) {
	h := NewSetupTokenHolder()
	tok := h.Generate()
	wrongSameLen := strings.Repeat("0", len(tok))
	if h.Verify(wrongSameLen) {
		t.Error("Verify accepted wrong same-length token")
	}
	wrongShorter := tok[:len(tok)-1]
	if h.Verify(wrongShorter) {
		t.Error("Verify accepted shorter token")
	}
	wrongLonger := tok + "0"
	if h.Verify(wrongLonger) {
		t.Error("Verify accepted longer token")
	}
}

// Smoke test: the handler reads ClientIPFromContext correctly when
// IPExtractMiddleware has populated it. Mirrors a real request flow.
func TestSetup_ClientIPCapturedInSession(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	userStore := auth.NewUserStore(store.DB())
	sessionStore := auth.NewSessionStore(store.DB())
	t.Setenv("ARENET_HIBP_DISABLED", "true")
	hibpClient := auth.NewHIBPClient()
	rateLimiter := auth.NewRateLimiter(logger)
	setupTokenHolder := NewSetupTokenHolder()
	token := setupTokenHolder.Generate()
	ipExtractor, _ := auth.NewIPExtractor("")

	h := NewHandler(store, &fakeReloader{}, &fakeAuditAppender{}, userStore, sessionStore, hibpClient, rateLimiter, setupTokenHolder, false, logger)
	router := NewRouter(h, false, ipExtractor)

	body, _ := json.Marshal(map[string]string{
		"setupToken": token,
		"username":   "admin",
		"password":   "correct horse battery staple",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/setup", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.42:12345"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("setup failed: %d %s", rec.Code, rec.Body.String())
	}

	// Verify the session row carries the resolved client IP.
	sessions, err := sessionStore.ListForUser(context.Background(), "")
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	_ = sessions // ListForUser(userID="") returns nil per implementation;
	// the IP propagation is exercised; deeper assertion requires
	// fetching the new user's ID via the response body.

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	uid, _ := resp["id"].(string)
	if uid == "" {
		t.Fatal("response missing user id")
	}
	userSessions, err := sessionStore.ListForUser(context.Background(), uid)
	if err != nil {
		t.Fatalf("ListForUser(%s): %v", uid, err)
	}
	if len(userSessions) != 1 {
		t.Fatalf("want 1 session, got %d", len(userSessions))
	}
	if userSessions[0].IP != "203.0.113.42" {
		t.Errorf("session IP = %q, want 203.0.113.42", userSessions[0].IP)
	}
}

// --- Test helpers ---------------------------------------------------------

// adminBootstrap runs /auth/setup with the supplied env to create an admin
// user. Returns the user ID and the session cookie issued by setup.
// Used by login/logout/me/unlock/sessions tests.
func adminBootstrap(t *testing.T, env *testEnv, token, username, password string) (userID, sessionCookie string) {
	t.Helper()
	rec := postJSON(t, env.router, "/api/v1/auth/setup", map[string]any{
		"setupToken":  token,
		"username":    username,
		"displayName": "Admin",
		"password":    password,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("bootstrap setup failed: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	uid, _ := resp["id"].(string)

	// Extract cookie value.
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return uid, c.Value
		}
	}
	t.Fatal("setup did not return arenet_session cookie")
	return "", ""
}

// withSessionCookie adds the arenet_session cookie to req.
func withSessionCookie(req *http.Request, value string) *http.Request {
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: value})
	return req
}

// --- /auth/login tests ----------------------------------------------------

const testAdminPassword = "correct horse battery staple"

func TestLogin_HappyPath(t *testing.T) {
	env, token := setupTestEnv(t)
	uid, _ := adminBootstrap(t, env, token, "admin", testAdminPassword)

	// Reset the audit captures so we only see login events.
	env.audit = &fakeAuditAppender{} // detached; the running handler still has the old appender
	// Note: the embedded appender is the one bound at handler creation.
	// To check login audit, we'll look at env.audit's events after.
	// (Reset above is mostly cosmetic; we use len(events)-N comparisons.)
	_ = uid

	rec := postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
		"username":   "admin",
		"password":   testAdminPassword,
		"rememberMe": false,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body not JSON: %s (%v)", rec.Body.String(), err)
	}
	if resp["username"] != "admin" {
		t.Errorf("username = %v", resp["username"])
	}
	// Cookie attributes.
	setCookie := rec.Header().Get("Set-Cookie")
	for _, attr := range []string{"arenet_session=", "HttpOnly", "Secure", "SameSite=Strict", "Path=/", "Max-Age=86400"} {
		if !strings.Contains(setCookie, attr) {
			t.Errorf("Set-Cookie missing %q: %s", attr, setCookie)
		}
	}
}

func TestLogin_RememberMe_30DayCookie(t *testing.T) {
	env, token := setupTestEnv(t)
	_, _ = adminBootstrap(t, env, token, "admin", testAdminPassword)

	rec := postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
		"username":   "admin",
		"password":   testAdminPassword,
		"rememberMe": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "Max-Age=2592000") {
		t.Errorf("rememberMe must produce Max-Age=2592000; got: %s", setCookie)
	}
}

func TestLogin_BadPassword_401(t *testing.T) {
	env, token := setupTestEnv(t)
	_, _ = adminBootstrap(t, env, token, "admin", testAdminPassword)

	rec := postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
		"username": "admin",
		"password": "wrong-password-but-15c",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid credentials") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestLogin_UnknownUser_401SameAsBadPassword(t *testing.T) {
	env, token := setupTestEnv(t)
	_, _ = adminBootstrap(t, env, token, "admin", testAdminPassword)

	rec := postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
		"username": "ghost",
		"password": testAdminPassword,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	// Spec §4.3: same message as bad password (no enumeration).
	if !strings.Contains(rec.Body.String(), "invalid credentials") {
		t.Errorf("body = %s; want \"invalid credentials\"", rec.Body.String())
	}
}

func TestLogin_MissingFields_400(t *testing.T) {
	env, _ := setupTestEnv(t)
	rec := postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
		"username": "",
		"password": "",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestLogin_AuditOnSuccess(t *testing.T) {
	env, token := setupTestEnv(t)
	_, _ = adminBootstrap(t, env, token, "admin", testAdminPassword)
	auditCount := len(env.audit.Events())

	rec := postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
		"username": "admin",
		"password": testAdminPassword,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}

	events := env.audit.Events()
	if len(events) != auditCount+1 {
		t.Fatalf("want %d audit events, got %d", auditCount+1, len(events))
	}
	e := events[len(events)-1]
	if e.Action != audit.ActionLoginSuccess {
		t.Errorf("Action = %q, want %q", e.Action, audit.ActionLoginSuccess)
	}
	if e.ActorUsernameSnapshot != "admin" {
		t.Errorf("ActorUsernameSnapshot = %q", e.ActorUsernameSnapshot)
	}
}

func TestLogin_AuditOnFailure_TruncatesUsername(t *testing.T) {
	env, _ := setupTestEnv(t)
	auditCount := len(env.audit.Events())

	// 100-char username to trigger truncation to 32 chars.
	longUsername := strings.Repeat("x", 100)
	rec := postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
		"username": longUsername,
		"password": "irrelevant-here-15c",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	events := env.audit.Events()
	if len(events) != auditCount+1 {
		t.Fatalf("want 1 new event, got %d new", len(events)-auditCount)
	}
	e := events[len(events)-1]
	if e.Action != audit.ActionLoginFailure {
		t.Errorf("Action = %q, want %q", e.Action, audit.ActionLoginFailure)
	}
	if got := len(e.ActorUsernameSnapshot); got != truncatedUsernameMaxLen {
		t.Errorf("ActorUsernameSnapshot length = %d, want %d (truncated)", got, truncatedUsernameMaxLen)
	}
	if e.Message != "user_not_found" {
		t.Errorf("Message = %q, want \"user_not_found\"", e.Message)
	}
}

// --- /auth/logout tests ---------------------------------------------------

func TestLogout_HappyPath_ClearsCookieAndAudits(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)
	auditCount := len(env.audit.Events())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}
	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "arenet_session=") || !strings.Contains(setCookie, "Max-Age=0") {
		t.Errorf("logout did not clear cookie: %s", setCookie)
	}

	events := env.audit.Events()
	if len(events) != auditCount+1 {
		t.Fatalf("want 1 new audit event, got %d new", len(events)-auditCount)
	}
	last := events[len(events)-1]
	if last.Action != audit.ActionLogout {
		t.Errorf("Action = %q, want %q", last.Action, audit.ActionLogout)
	}
	if last.Message != "manual" {
		t.Errorf("Message = %q, want \"manual\"", last.Message)
	}
}

func TestLogout_NoCookie_401(t *testing.T) {
	env, _ := setupTestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// --- /auth/me tests -------------------------------------------------------

func TestMe_ReturnsUserState(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body not JSON: %s (%v)", rec.Body.String(), err)
	}
	for _, key := range []string{"id", "username", "displayName", "locked", "passwordCompromised", "hibpCheckStatus"} {
		if _, ok := resp[key]; !ok {
			t.Errorf("response missing key %q: %v", key, resp)
		}
	}
	if resp["username"] != "admin" {
		t.Errorf("username = %v", resp["username"])
	}
	if resp["locked"] != false {
		t.Errorf("locked = %v, want false for fresh session", resp["locked"])
	}
}

func TestMe_NoCookie_401(t *testing.T) {
	env, _ := setupTestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// TestMe_DoesNotTouchSession is critical (spec §4.5): /me must NOT
// extend the session's LastActivity, otherwise polling /me from the
// lock screen would silently lift the lock.
func TestMe_DoesNotTouchSession(t *testing.T) {
	env, token := setupTestEnv(t)
	uid, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	// Snapshot LastActivity.
	storeSessions, err := env.store.DB().Begin(false)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	_ = storeSessions.Rollback()
	// Use SessionStore.Get via a fresh SessionStore over the same DB.
	ss := auth.NewSessionStore(env.store.DB())
	before, err := ss.Get(context.Background(), sessionCookie)
	if err != nil {
		t.Fatalf("session lookup: %v", err)
	}

	// Wait > resolution so any Touch would be observable.
	time.Sleep(10 * time.Millisecond)

	// Hit /me several times.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
		withSessionCookie(req, sessionCookie)
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("/me iter %d: status %d", i, rec.Code)
		}
	}

	after, err := ss.Get(context.Background(), sessionCookie)
	if err != nil {
		t.Fatalf("session lookup after: %v", err)
	}
	if !after.LastActivity.Equal(before.LastActivity) {
		t.Errorf("LastActivity MUST NOT change across /me calls; before=%v after=%v", before.LastActivity, after.LastActivity)
	}
	_ = uid
}

// --- /auth/unlock tests ---------------------------------------------------

func TestUnlock_HappyPath(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/unlock",
		strings.NewReader(`{"password":"`+testAdminPassword+`"}`))
	req.Header.Set("Content-Type", "application/json")
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"unlocked":true`) {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestUnlock_BadPassword_401(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)
	auditCount := len(env.audit.Events())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/unlock",
		strings.NewReader(`{"password":"wrong-password-yyy"}`))
	req.Header.Set("Content-Type", "application/json")
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	events := env.audit.Events()
	if len(events) != auditCount+1 {
		t.Fatalf("want 1 new event, got %d new", len(events)-auditCount)
	}
	last := events[len(events)-1]
	if last.Action != audit.ActionUnlockFailure {
		t.Errorf("Action = %q, want %q", last.Action, audit.ActionUnlockFailure)
	}
}

// --- /auth/heartbeat tests ------------------------------------------------

func TestHeartbeat_HappyPath_204(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/heartbeat", nil)
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}
}

func TestHeartbeat_NoCookie_401(t *testing.T) {
	env, _ := setupTestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/heartbeat", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// --- /auth/sessions tests -------------------------------------------------

func TestListSessions_HappyPath_MarksIsCurrent(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body not JSON: %s (%v)", rec.Body.String(), err)
	}
	if len(resp.Sessions) != 1 {
		t.Fatalf("want 1 session, got %d", len(resp.Sessions))
	}
	if isCurrent, _ := resp.Sessions[0]["isCurrent"].(bool); !isCurrent {
		t.Errorf("isCurrent = false, want true for the calling session")
	}
}

func TestDeleteSession_HappyPath(t *testing.T) {
	env, token := setupTestEnv(t)
	uid, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	// Create a second session for the same user (mimicking a "phone" login).
	ss := auth.NewSessionStore(env.store.DB())
	other, err := ss.Create(context.Background(), uid, false, "1.2.3.4", "Mobile")
	if err != nil {
		t.Fatalf("create second session: %v", err)
	}
	auditCount := len(env.audit.Events())

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/"+other.ID, nil)
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}

	// Session must actually be gone.
	if _, err := ss.Get(context.Background(), other.ID); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Errorf("session not deleted: err = %v", err)
	}

	events := env.audit.Events()
	if len(events) != auditCount+1 {
		t.Fatalf("want 1 new audit event, got %d new", len(events)-auditCount)
	}
	last := events[len(events)-1]
	if last.Action != audit.ActionSessionRevoked {
		t.Errorf("Action = %q, want %q", last.Action, audit.ActionSessionRevoked)
	}
}

func TestDeleteSession_ForeignSession_404(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	// Create a session for a different user.
	ss := auth.NewSessionStore(env.store.DB())
	other, err := ss.Create(context.Background(), "different-user-id", false, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("create foreign session: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/"+other.ID, nil)
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	// Per spec §4.9: 404, NOT 403, to prevent enumeration.
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (anti-enumeration)", rec.Code)
	}

	// The foreign session must STILL exist (we cannot delete others' sessions).
	if _, err := ss.Get(context.Background(), other.ID); err != nil {
		t.Errorf("foreign session erroneously deleted: %v", err)
	}
}

func TestDeleteSession_NonExistent_404(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/nonexistent-id", nil)
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}
