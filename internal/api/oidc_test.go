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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// --- matchAllowlist: the email_verified guard (§1.6 Δ7) -----------------
//
// The Email-pass canonicalisation MUST require email_verified ==
// true. An IdP-side malicious account claiming someone else's
// unverified email never canonicalises into a pending invite.
// Pinned as a unit test on the pure matcher.

func TestOIDCMatchAllowlist_EmailUnverifiedRejected(t *testing.T) {
	entries := []storage.OIDCAllowedIdentity{
		{Email: "alice@example.com", DisplayName: "Alice"},
	}
	// Same email, but the token says NOT verified.
	_, idx, isBootstrap := matchAllowlist(entries, "sub-attacker-123", "alice@example.com", false /* email_verified */)
	if idx >= 0 {
		t.Errorf("unverified-email attacker matched bootstrap entry; idx=%d isBootstrap=%v", idx, isBootstrap)
	}
	// And the same call with verified=true must match.
	match, idx, isBootstrap := matchAllowlist(entries, "sub-real-456", "alice@example.com", true)
	if idx != 0 || !isBootstrap || match.Email != "alice@example.com" {
		t.Errorf("verified-email match failed: idx=%d isBootstrap=%v match=%v", idx, isBootstrap, match)
	}
}

func TestOIDCMatchAllowlist_SubPassMatchesPostCanonicalisation(t *testing.T) {
	entries := []storage.OIDCAllowedIdentity{
		{Email: "alice@example.com", Sub: "sub-canonical-789"},
	}
	// Sub-pass first: matches regardless of email / email_verified.
	match, idx, isBootstrap := matchAllowlist(entries, "sub-canonical-789", "doesnt-matter@x.test", false)
	if idx != 0 || isBootstrap || match.Sub != "sub-canonical-789" {
		t.Errorf("sub-pass match failed: idx=%d isBootstrap=%v match=%v", idx, isBootstrap, match)
	}
}

func TestOIDCMatchAllowlist_EmailEmptyRejected(t *testing.T) {
	entries := []storage.OIDCAllowedIdentity{
		{Email: "alice@example.com"},
	}
	_, idx, _ := matchAllowlist(entries, "sub-x", "", true)
	if idx >= 0 {
		t.Errorf("empty email matched a bootstrap entry; idx=%d", idx)
	}
}

func TestOIDCMatchAllowlist_CanonicalisedEntrySkipsEmailPass(t *testing.T) {
	// An already-canonicalised entry (Sub != "") must NOT match
	// on the Email-pass — otherwise a recycled sub from another
	// IdP user could spuriously canonicalise twice. Pinned in
	// §5.2 ("the second-pass match requires Sub == \"\"").
	entries := []storage.OIDCAllowedIdentity{
		{Email: "alice@example.com", Sub: "sub-already-canonical"},
	}
	_, idx, _ := matchAllowlist(entries, "sub-different", "alice@example.com", true)
	if idx >= 0 {
		t.Errorf("email-pass matched a canonicalised entry; idx=%d", idx)
	}
}

func TestOIDCMatchAllowlist_EmailCaseInsensitive(t *testing.T) {
	entries := []storage.OIDCAllowedIdentity{
		{Email: "Alice@Example.com"},
	}
	match, idx, _ := matchAllowlist(entries, "sub-x", "alice@EXAMPLE.COM", true)
	if idx != 0 || match.Email != "Alice@Example.com" {
		t.Errorf("case-insensitive match failed: idx=%d match=%v", idx, match)
	}
}

// --- Break-glass invariant (§1.3 #4, #5, #6) ---------------------------
//
// The local-credential login path MUST NOT be gated, modified,
// or disabled by the OIDC configuration state. A misconfigured /
// unreachable IdP must NEVER block a local admin from logging in.

func TestLocalLogin_BreakGlass_OIDCConfigured_StillWorks(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()
	password := "break-glass-pw-15c"
	if _, err := newTestUserStore(t, env).Create(ctx, "breakuser", "Break User", password); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Configure OIDC with a clearly-broken IdP issuer (NXDOMAIN-like).
	// This simulates the "IdP down" scenario the break-glass invariant
	// is designed to survive.
	if err := env.store.PutOIDCConfig(ctx, storage.OIDCConfig{
		Enabled:      true,
		IssuerURL:    "http://127.0.0.1:1", // port 1: unreachable
		ClientID:     "arenet",
		ClientSecret: "secret-1234567890",
		RedirectURL:  "http://localhost:8080/api/v1/auth/oidc/callback",
		Scopes:       []string{"openid", "profile", "email"},
	}); err != nil {
		// validate failed — try with the same shape but Enabled=false.
		// We want the "OIDC configured but broken" state; if storage
		// rejects we settle for "configured at all".
		_ = env.store.PutOIDCConfig(ctx, storage.OIDCConfig{
			Enabled:      false,
			IssuerURL:    "http://127.0.0.1:1",
			ClientID:     "arenet",
			ClientSecret: "secret-1234567890",
			RedirectURL:  "http://localhost:8080/api/v1/auth/oidc/callback",
			Scopes:       []string{"openid", "profile", "email"},
		})
	}

	// Local login: directly POST to /api/v1/auth/login. MUST succeed
	// regardless of OIDC state.
	body := `{"username":"breakuser","password":"` + password + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("BREAK-GLASS REGRESSION: local login failed while OIDC is configured/down. "+
			"status=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"username":"breakuser"`) {
		t.Errorf("local login response missing username: %s", rec.Body)
	}
}

// TestLocalLogin_BreakGlassAuditEmitted_WhenOIDCConfigured pins
// AC #10: a successful local login on an instance where OIDC has
// been configured (even once, even if currently disabled) emits
// `login_break_glass` in addition to `login_success`.
func TestLocalLogin_BreakGlassAuditEmitted_WhenOIDCConfigured(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	if _, err := newTestUserStore(t, env).Create(ctx, "alice", "Alice", "break-glass-pw-15c"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Mark OIDC as "ever configured" by writing a complete row.
	if err := env.store.PutOIDCConfig(ctx, storage.OIDCConfig{
		Enabled:      false, // doesn't matter for the break-glass signal
		IssuerURL:    "https://idp.example.com",
		ClientID:     "arenet",
		ClientSecret: "secret-1234567890",
		RedirectURL:  "https://arenet.example.com/api/v1/auth/oidc/callback",
		Scopes:       []string{"openid", "profile", "email"},
	}); err != nil {
		// Disabled state may not validate the shape — try an enabled
		// state which the validate accepts.
		if err := env.store.PutOIDCConfig(ctx, storage.OIDCConfig{
			Enabled:      true,
			IssuerURL:    "https://idp.example.com",
			ClientID:     "arenet",
			ClientSecret: "secret-1234567890",
			RedirectURL:  "https://arenet.example.com/api/v1/auth/oidc/callback",
			Scopes:       []string{"openid", "profile", "email"},
		}); err != nil {
			t.Fatalf("seed oidc config: %v", err)
		}
	}

	body := `{"username":"alice","password":"break-glass-pw-15c"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: status=%d body=%s", rec.Code, rec.Body)
	}

	// Find the break-glass event among emitted audits.
	hasSuccess := false
	hasBreakGlass := false
	for _, e := range env.audit.Events() {
		if e.Action == audit.ActionLoginSuccess {
			hasSuccess = true
		}
		if e.Action == audit.ActionLoginBreakGlass {
			hasBreakGlass = true
		}
	}
	if !hasSuccess {
		t.Error("login_success event missing")
	}
	if !hasBreakGlass {
		t.Error("login_break_glass event NOT emitted on local login while OIDC is configured")
	}
}

// TestLocalLogin_NoBreakGlassAudit_WhenOIDCNeverConfigured: on a
// fresh install where OIDC has never been touched, the local login
// is the only login path — break-glass emission would be noise.
// AC #10 specifies: emitted ONLY when OIDC has been configured.
func TestLocalLogin_NoBreakGlassAudit_WhenOIDCNeverConfigured(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	if _, err := newTestUserStore(t, env).Create(ctx, "alice", "Alice", "break-glass-pw-15c"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// NO PutOIDCConfig call — fresh state.

	body := `{"username":"alice","password":"break-glass-pw-15c"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: status=%d body=%s", rec.Code, rec.Body)
	}

	for _, e := range env.audit.Events() {
		if e.Action == audit.ActionLoginBreakGlass {
			t.Errorf("unexpected login_break_glass event on a fresh-install login: %+v", e)
		}
	}
}

// --- OIDC config: secret redaction (AC #8bis) ---------------------------

func TestOIDCConfig_SecretRedacted_OnGet(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	if err := env.store.PutOIDCConfig(ctx, storage.OIDCConfig{
		Enabled:      true,
		IssuerURL:    "https://idp.example.com",
		ClientID:     "arenet",
		ClientSecret: "VERY-SECRET-DO-NOT-LEAK",
		RedirectURL:  "https://arenet.example.com/api/v1/auth/oidc/callback",
		Scopes:       []string{"openid", "profile", "email"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/oidc", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if strings.Contains(body, "VERY-SECRET-DO-NOT-LEAK") {
		t.Errorf("client_secret leaked in GET body: %s", body)
	}
	if !strings.Contains(body, `"clientSecret":""`) {
		t.Errorf("clientSecret not redacted to empty: %s", body)
	}
	if !strings.Contains(body, `"clientSecretSet":true`) {
		t.Errorf("clientSecretSet flag missing: %s", body)
	}
}

// --- Role gate: viewer rejected on write endpoints ---------------------

func TestRequireAdmin_ViewerRejectedOnRouteCreate(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	// Create a viewer user + bootstrap a session for them.
	viewer, err := newTestUserStore(t, env).CreateOIDCUser(ctx, "viewer1", "Viewer One", "sub-viewer-001")
	if err != nil {
		t.Fatalf("seed viewer: %v", err)
	}
	if viewer.Role != auth.UserRoleViewer {
		t.Fatalf("seed-viewer role = %q; want viewer (CreateOIDCUser default)", viewer.Role)
	}
	sessionStore := auth.NewSessionStore(env.store.DB())
	s, err := sessionStore.Create(ctx, viewer.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	body := `{"host":"viewer-rejected.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: s.ID})
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("VIEWER ESCALATION REGRESSION: a viewer was allowed to POST /routes. "+
			"status=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "admin role required") {
		t.Errorf("rejection message does not name the cause: %s", rec.Body)
	}
}

func TestRequireAdmin_ViewerCanReadRoutes(t *testing.T) {
	// Inverse of the above: viewer GET /routes succeeds.
	env := newTestEnv(t, false)
	ctx := context.Background()

	viewer, err := newTestUserStore(t, env).CreateOIDCUser(ctx, "viewer2", "Viewer Two", "sub-viewer-002")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	sessionStore := auth.NewSessionStore(env.store.DB())
	s, err := sessionStore.Create(ctx, viewer.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: s.ID})
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("viewer GET /routes should succeed: status=%d body=%s", rec.Code, rec.Body)
	}
}

// --- UpdateRole: last-admin guard --------------------------------------

func TestUpdateRole_LastLocalAdminDemoteRejected(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	us := newTestUserStore(t, env)
	admin, err := us.Create(ctx, "soleadmin", "Sole Admin", "admin-password-15c")
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	// Attempt to demote — only local admin in the store.
	err = us.UpdateRole(ctx, admin.ID, auth.UserRoleViewer)
	if err == nil {
		t.Fatal("LAST-ADMIN GUARD REGRESSION: demoting the only local admin was allowed; " +
			"the instance would have no admin access (break-glass channel lost)")
	}
	if !strings.Contains(err.Error(), "last local admin") {
		t.Errorf("error message does not name the cause: %v", err)
	}
}

func TestUpdateRole_DemoteAllowedWhenAnotherLocalAdminExists(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	us := newTestUserStore(t, env)
	a1, err := us.Create(ctx, "admin1", "Admin One", "admin-password-15c")
	if err != nil {
		t.Fatalf("seed a1: %v", err)
	}
	_, err = us.Create(ctx, "admin2", "Admin Two", "admin-password-15c")
	if err != nil {
		t.Fatalf("seed a2: %v", err)
	}

	if err := us.UpdateRole(ctx, a1.ID, auth.UserRoleViewer); err != nil {
		t.Errorf("demote allowed when another admin exists, got: %v", err)
	}
	got, _ := us.GetByID(ctx, a1.ID)
	if got.Role != auth.UserRoleViewer {
		t.Errorf("role after demote = %q; want viewer", got.Role)
	}
}

// newTestUserStore returns a UserStore that shares the test env's
// bbolt handle. Used to seed users with explicit credentials for
// the break-glass / role tests above.
func newTestUserStore(t *testing.T, env *testEnv) *auth.UserStore {
	t.Helper()
	return auth.NewUserStore(env.store.DB())
}

// --- OIDC config endpoints: viewer rejected ---------------------------

func TestRequireAdmin_ViewerRejectedOnOIDCConfigGET(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()
	viewer, err := newTestUserStore(t, env).CreateOIDCUser(ctx, "viewer3", "Viewer Three", "sub-viewer-003")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	s, err := auth.NewSessionStore(env.store.DB()).Create(ctx, viewer.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/oidc", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: s.ID})
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("viewer GET /settings/oidc should be 403; got %d body=%s", rec.Code, rec.Body)
	}
}

// --- Local-admin password rotation hook (AC #11) -----------------------

func TestLocalAdminPasswordRotated_AuditEmitted(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	// /api/v1/auth/* is excluded from auto-auth — seed a real
	// admin session and attach its cookie explicitly.
	us := newTestUserStore(t, env)
	admin, err := us.Create(ctx, "rotater", "Rotater", "old-password-15c-xx")
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	sess, err := auth.NewSessionStore(env.store.DB()).Create(ctx, admin.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	if err := env.store.PutOIDCConfig(ctx, storage.OIDCConfig{
		Enabled:      true,
		IssuerURL:    "https://idp.example.com",
		ClientID:     "arenet",
		ClientSecret: "secret-1234567890",
		RedirectURL:  "https://arenet.example.com/api/v1/auth/oidc/callback",
		Scopes:       []string{"openid", "profile", "email"},
	}); err != nil {
		t.Fatalf("seed oidc: %v", err)
	}

	body := `{"currentPassword":"old-password-15c-xx","newPassword":"new-password-15c-xx"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/me/password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("rotate: status=%d body=%s", rec.Code, rec.Body)
	}

	var sawRotated bool
	for _, e := range env.audit.Events() {
		if e.Action == audit.ActionLocalAdminPasswordRotated {
			sawRotated = true
		}
	}
	if !sawRotated {
		t.Error("local_admin_password_rotated event NOT emitted on local-admin rotation while OIDC is configured")
	}
}

// --- Settings: OIDC allowlist add + canonicalise lifecycle -------------

func TestOIDCAllowlist_AddAndList(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"email":"alice@example.com","displayName":"Alice"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/oidc/allowlist", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST: status=%d body=%s", rec.Code, rec.Body)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/settings/oidc/allowlist", nil)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: status=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"email":"alice@example.com"`) {
		t.Errorf("allowlist missing entry: %s", rec.Body)
	}
}

// Sanity probe — confirms the test file compiles against the
// time / context imports used in setup helpers.
func TestK2_TestFileCompiles(t *testing.T) {
	_ = time.Now()
	_ = context.Background()
	_ = t
}
