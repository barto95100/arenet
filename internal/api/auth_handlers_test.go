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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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
