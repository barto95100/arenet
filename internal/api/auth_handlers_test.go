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
	"crypto/tls"
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
	router := NewRouter(h, false, ipExtractor, nil)

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

// postJSONTLS is identical to postJSON but marks the request as
// TLS-terminated (r.TLS != nil). Used to assert cookie attributes
// that depend on the scheme — Step #S-11 made the Secure flag
// scheme-aware, so a test that verifies the production-like
// behaviour (admin GUI served over HTTPS → cookies flagged Secure)
// must use this variant instead of postJSON.
func postJSONTLS(t *testing.T, router http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(buf)))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// --- POST /api/v1/auth/setup tests ---------------------------------------

func TestSetup_HappyPath(t *testing.T) {
	env, token := setupTestEnv(t)

	rec := postJSONTLS(t, env.router, "/api/v1/auth/setup", map[string]string{
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
	router := NewRouter(h, true, ipExtractor, nil)

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
	router := NewRouter(h, false, ipExtractor, nil)

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

	rec := postJSONTLS(t, env.router, "/api/v1/auth/login", map[string]any{
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

// --- /auth/me/password tests ---------------------------------------------

func TestChangePassword_HappyPath(t *testing.T) {
	env, token := setupTestEnv(t)
	uid, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/me/password",
		strings.NewReader(`{"currentPassword":"`+testAdminPassword+`","newPassword":"new-strong-password-15+"}`))
	req.Header.Set("Content-Type", "application/json")
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}

	// Current session is still valid (we can still call /me).
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	withSessionCookie(req, sessionCookie)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("after password change, /me on current session = %d, want 200", rec.Code)
	}

	// Audit event emitted with the expected shape.
	events := env.audit.Events()
	var pwc *audit.Event
	for i := range events {
		if events[i].Action == audit.ActionPasswordChanged {
			pwc = &events[i]
		}
	}
	if pwc == nil {
		t.Fatal("password_changed audit event not emitted")
	}
	if pwc.ActorUserID != uid {
		t.Errorf("ActorUserID = %q, want %q", pwc.ActorUserID, uid)
	}
	if pwc.TargetID != uid {
		t.Errorf("TargetID = %q, want %q", pwc.TargetID, uid)
	}
	// D3: no BeforeJSON/AfterJSON (only changed field is the hash, forbidden in audit).
	if pwc.BeforeJSON != nil {
		t.Errorf("BeforeJSON should be nil, got %s", string(pwc.BeforeJSON))
	}
	if pwc.AfterJSON != nil {
		t.Errorf("AfterJSON should be nil, got %s", string(pwc.AfterJSON))
	}
}

func TestChangePassword_RevokesOtherSessionsKeepsCurrent(t *testing.T) {
	env, token := setupTestEnv(t)
	uid, currentCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	// Create 2 other sessions for the same user (mimicking "phone" and "tablet").
	ss := auth.NewSessionStore(env.store.DB())
	other1, _ := ss.Create(context.Background(), uid, false, "1.2.3.4", "Phone")
	other2, _ := ss.Create(context.Background(), uid, true, "5.6.7.8", "Tablet")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/me/password",
		strings.NewReader(`{"currentPassword":"`+testAdminPassword+`","newPassword":"new-strong-password-15+"}`))
	req.Header.Set("Content-Type", "application/json")
	withSessionCookie(req, currentCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}

	// Other sessions are gone.
	for _, id := range []string{other1.ID, other2.ID} {
		if _, err := ss.Get(context.Background(), id); !errors.Is(err, auth.ErrSessionNotFound) {
			t.Errorf("session %s not revoked: err = %v", id, err)
		}
	}
	// Current session preserved.
	if _, err := ss.Get(context.Background(), currentCookie); err != nil {
		t.Errorf("current session erroneously revoked: %v", err)
	}
}

func TestChangePassword_WrongCurrentPassword_401(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/me/password",
		strings.NewReader(`{"currentPassword":"wrong-password-15c","newPassword":"new-strong-password-15+"}`))
	req.Header.Set("Content-Type", "application/json")
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "current password is incorrect") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestChangePassword_NewPasswordTooShort_400(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/me/password",
		strings.NewReader(`{"currentPassword":"`+testAdminPassword+`","newPassword":"short"}`))
	req.Header.Set("Content-Type", "application/json")
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestChangePassword_MissingFields_400(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/me/password",
		strings.NewReader(`{"currentPassword":"","newPassword":""}`))
	req.Header.Set("Content-Type", "application/json")
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// --- /audit tests ---------------------------------------------------------

func TestListAudit_ReturnsEventsAndAuditViewed(t *testing.T) {
	env, token := setupTestEnv(t)
	uid, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	beforeCount := len(env.audit.Events())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	var resp listAuditResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body not JSON: %s (%v)", rec.Body.String(), err)
	}
	// At least the setup_admin_created event is present.
	if len(resp.Events) == 0 {
		t.Error("audit list empty; expected at least setup_admin_created")
	}

	// audit_viewed self-event emitted (decision Q5).
	events := env.audit.Events()
	var seen bool
	for _, e := range events[beforeCount:] {
		if e.Action == audit.ActionAuditViewed && e.ActorUserID == uid {
			seen = true
			break
		}
	}
	if !seen {
		t.Error("audit_viewed self-event not emitted")
	}
}

func TestListAudit_FilterByAction(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?action=setup_admin_created", nil)
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp listAuditResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	for _, e := range resp.Events {
		if e.Action != "setup_admin_created" {
			t.Errorf("filter leaked: got action %q", e.Action)
		}
	}
}

func TestListAudit_InvalidFromTimestamp_400(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?from=not-rfc3339", nil)
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "invalid 'from'") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestListAudit_InvalidLimit_400(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?limit=not-an-int", nil)
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestListAudit_NoCookie_401(t *testing.T) {
	env, _ := setupTestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// --- POST /api/v1/auth/me/theme tests (Step F §3) -------------------------

// TestPatchTheme_RequiresHardAuth proves an unauthenticated request is
// rejected by the middleware before the handler ever runs. (No cookie =>
// 401, as for every other hard-auth endpoint.)
func TestPatchTheme_RequiresHardAuth(t *testing.T) {
	env, _ := setupTestEnv(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/me/theme",
		strings.NewReader(`{"theme":"light"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// TestPatchTheme_Success exercises the happy path: 204 + persistence
// visible through GET /auth/me (themePreference echoed back).
func TestPatchTheme_Success(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/me/theme",
		strings.NewReader(`{"theme":"light"}`))
	req.Header.Set("Content-Type", "application/json")
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}

	// /me must now return the new preference.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	withSessionCookie(req, sessionCookie)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/me after theme set: status = %d, want 200", rec.Code)
	}
	var meBody map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &meBody); err != nil {
		t.Fatalf("decode /me: %v", err)
	}
	if got := meBody["themePreference"]; got != "light" {
		t.Errorf("themePreference = %v, want \"light\"", got)
	}

	// Step F §3.4: no audit event for a theme change. Walk the recorded
	// audit events and assert nothing references a theme action. (The
	// D7 set has 15 actions; this test would catch a regression where
	// someone added a "theme_changed" action without spec amendment.)
	for _, ev := range env.audit.Events() {
		if strings.Contains(string(ev.Action), "theme") {
			t.Errorf("unexpected theme-related audit event: %+v", ev)
		}
	}
}

// TestPatchTheme_InvalidBody covers the three rejection paths the
// handler distinguishes: malformed JSON, missing field, unknown value.
func TestPatchTheme_InvalidBody(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	cases := []struct {
		name string
		body string
	}{
		{"not_json", `{not json`},
		{"missing_theme", `{}`},
		{"unknown_value", `{"theme":"blue"}`},
		{"empty_value", `{"theme":""}`},
		{"capitalized", `{"theme":"Dark"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/me/theme",
				strings.NewReader(c.body))
			req.Header.Set("Content-Type", "application/json")
			withSessionCookie(req, sessionCookie)
			rec := httptest.NewRecorder()
			env.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("body=%q: status = %d, want 400", c.body, rec.Code)
			}
		})
	}
}

// TestPatchTheme_LockedSession_403 proves the idle-lock window also
// gates the theme endpoint. Same mechanism as /me/password: backdate
// the session's LastActivity past SessionIdleTimeout via PutForTest,
// hard-auth middleware then refuses with 403.
func TestPatchTheme_LockedSession_403(t *testing.T) {
	env, token := setupTestEnv(t)
	uid, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	// Backdate the session's LastActivity well past the idle threshold.
	ss := auth.NewSessionStore(env.store.DB())
	sess, err := ss.Get(context.Background(), sessionCookie)
	if err != nil {
		t.Fatalf("Get session: %v", err)
	}
	sess.LastActivity = time.Now().Add(-(auth.SessionIdleTimeout + time.Minute)).UTC()
	if err := ss.PutForTest(context.Background(), sess); err != nil {
		t.Fatalf("PutForTest: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/me/theme",
		strings.NewReader(`{"theme":"light"}`))
	req.Header.Set("Content-Type", "application/json")
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("idle-locked session: status = %d, want 403", rec.Code)
	}

	// The stored preference MUST remain unchanged after a 403.
	users := auth.NewUserStore(env.store.DB())
	u, err := users.GetByID(context.Background(), uid)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if u.ThemePreference != "" {
		t.Errorf("locked-session 403 silently mutated theme to %q", u.ThemePreference)
	}
}

func TestFilterToString_ReadableFormat(t *testing.T) {
	f := audit.Filter{
		ActorUserID: "uid",
		Action:      "login_success",
		Limit:       50,
	}
	got := filterToString(f)
	if !strings.Contains(got, "actor_user_id=uid") {
		t.Errorf("got %q, missing actor_user_id", got)
	}
	if !strings.Contains(got, "action=login_success") {
		t.Errorf("got %q, missing action", got)
	}
	if !strings.Contains(got, "limit=50") {
		t.Errorf("got %q, missing limit", got)
	}
}

// --- arenet_theme cookie lifecycle tests (Step F §4.5) -------------------

// findCookie returns the first Set-Cookie matching name, or nil. We can't
// use http.Response.Cookies() because httptest.ResponseRecorder doesn't
// reconstruct the response object — we parse raw headers instead.
func findCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	resp := &http.Response{Header: rec.Result().Header}
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestLogin_SetsThemeCookie covers spec §4.5: a successful login must
// emit Set-Cookie: arenet_theme=... with the user's stored preference
// (defaulting to "dark" if the user is pre-Step-F empty-string state).
// Attributes match the design spec exactly.
func TestLogin_SetsThemeCookie(t *testing.T) {
	env, token := setupTestEnv(t)
	// adminBootstrap goes through /setup (which also sets the cookie);
	// run a fresh /login on top so we exercise the login path itself.
	_, _ = adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		strings.NewReader(`{"username":"admin","password":"`+testAdminPassword+`","rememberMe":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{} // Step #S-11: simulate HTTPS-terminated request
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	c := findCookie(rec, "arenet_theme")
	if c == nil {
		t.Fatal("Set-Cookie arenet_theme not emitted on successful login")
	}
	// Empty-string ThemePreference (pre-Step-F user) normalizes to "dark".
	if c.Value != "dark" {
		t.Errorf("cookie value = %q, want \"dark\" (default for empty preference)", c.Value)
	}
	if c.HttpOnly {
		t.Error("HttpOnly = true; want false (bootstrap script must read it from JS)")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax (FOUC first-navigation requirement)", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want \"/\"", c.Path)
	}
	if c.MaxAge != 30*24*60*60 {
		t.Errorf("MaxAge = %d, want 2592000 (30 days)", c.MaxAge)
	}
	// Step #S-11: TLS-terminated request → cookie flagged Secure.
	if !c.Secure {
		t.Error("Secure = false; want true on TLS request")
	}
}

// TestLogin_SetsThemeCookieReflectsStoredPref proves the cookie value
// tracks UserStore.ThemePreference rather than a hardcoded default.
func TestLogin_SetsThemeCookieReflectsStoredPref(t *testing.T) {
	env, token := setupTestEnv(t)
	uid, _ := adminBootstrap(t, env, token, "admin", testAdminPassword)

	// Persist "light" directly via the store, then re-login.
	users := auth.NewUserStore(env.store.DB())
	if err := users.UpdateThemePreference(context.Background(), uid, auth.ThemeLight); err != nil {
		t.Fatalf("UpdateThemePreference: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		strings.NewReader(`{"username":"admin","password":"`+testAdminPassword+`","rememberMe":false}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200", rec.Code)
	}

	c := findCookie(rec, "arenet_theme")
	if c == nil || c.Value != "light" {
		t.Errorf("cookie = %+v, want value=\"light\"", c)
	}
}

// TestLogout_ClearsThemeCookie covers the explicit-logout lifecycle
// path in spec §4.5: both cookies (session + theme) are cleared.
func TestLogout_ClearsThemeCookie(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want 204", rec.Code)
	}

	c := findCookie(rec, "arenet_theme")
	if c == nil {
		t.Fatal("Set-Cookie arenet_theme not emitted on logout")
	}
	if c.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1 (clear marker)", c.MaxAge)
	}
	if c.Value != "" {
		t.Errorf("Value = %q, want \"\" on clear", c.Value)
	}
	// SameSite + Path must match the set-time attributes or some
	// browsers refuse the deletion.
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("clear SameSite = %v, want Lax (must match set)", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("clear Path = %q, want \"/\"", c.Path)
	}
}

// TestPatchTheme_RefreshesThemeCookie covers the third lifecycle path:
// every successful POST /me/theme refreshes the cookie so the next
// FOUC bootstrap picks up the new value.
func TestPatchTheme_RefreshesThemeCookie(t *testing.T) {
	env, token := setupTestEnv(t)
	_, sessionCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/me/theme",
		strings.NewReader(`{"theme":"light"}`))
	req.Header.Set("Content-Type", "application/json")
	withSessionCookie(req, sessionCookie)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("updateTheme status = %d, want 204", rec.Code)
	}

	c := findCookie(rec, "arenet_theme")
	if c == nil {
		t.Fatal("Set-Cookie arenet_theme not emitted on successful theme update")
	}
	if c.Value != "light" {
		t.Errorf("cookie value = %q, want \"light\"", c.Value)
	}
	if c.HttpOnly {
		t.Error("HttpOnly = true; want false")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.MaxAge != 30*24*60*60 {
		t.Errorf("MaxAge = %d, want 2592000", c.MaxAge)
	}
}

// TestSetup_SetsThemeCookieAsDark covers the setup path: a brand-new
// user has ThemePreference="" so the cookie must carry "dark" (the
// FOUC bootstrap default).
func TestSetup_SetsThemeCookieAsDark(t *testing.T) {
	env, token := setupTestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/setup",
		strings.NewReader(`{"setupToken":"`+token+`","username":"admin","displayName":"","password":"`+testAdminPassword+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	c := findCookie(rec, "arenet_theme")
	if c == nil {
		t.Fatal("Set-Cookie arenet_theme not emitted on setup")
	}
	if c.Value != "dark" {
		t.Errorf("setup cookie = %q, want \"dark\"", c.Value)
	}
}
