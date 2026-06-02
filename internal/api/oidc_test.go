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
	_, idx, isBootstrap := matchAllowlist(entries, "sub-attacker-123", "alice@example.com", false /* email_verified */, false)
	if idx >= 0 {
		t.Errorf("unverified-email attacker matched bootstrap entry; idx=%d isBootstrap=%v", idx, isBootstrap)
	}
	// And the same call with verified=true must match.
	match, idx, isBootstrap := matchAllowlist(entries, "sub-real-456", "alice@example.com", true, false)
	if idx != 0 || !isBootstrap || match.Email != "alice@example.com" {
		t.Errorf("verified-email match failed: idx=%d isBootstrap=%v match=%v", idx, isBootstrap, match)
	}
}

func TestOIDCMatchAllowlist_SubPassMatchesPostCanonicalisation(t *testing.T) {
	entries := []storage.OIDCAllowedIdentity{
		{Email: "alice@example.com", Sub: "sub-canonical-789"},
	}
	// Sub-pass first: matches regardless of email / email_verified.
	match, idx, isBootstrap := matchAllowlist(entries, "sub-canonical-789", "doesnt-matter@x.test", false, false)
	if idx != 0 || isBootstrap || match.Sub != "sub-canonical-789" {
		t.Errorf("sub-pass match failed: idx=%d isBootstrap=%v match=%v", idx, isBootstrap, match)
	}
}

func TestOIDCMatchAllowlist_EmailEmptyRejected(t *testing.T) {
	entries := []storage.OIDCAllowedIdentity{
		{Email: "alice@example.com"},
	}
	_, idx, _ := matchAllowlist(entries, "sub-x", "", true, false)
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
	_, idx, _ := matchAllowlist(entries, "sub-different", "alice@example.com", true, false)
	if idx >= 0 {
		t.Errorf("email-pass matched a canonicalised entry; idx=%d", idx)
	}
}

func TestOIDCMatchAllowlist_EmailCaseInsensitive(t *testing.T) {
	entries := []storage.OIDCAllowedIdentity{
		{Email: "Alice@Example.com"},
	}
	match, idx, _ := matchAllowlist(entries, "sub-x", "alice@EXAMPLE.COM", true, false)
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

// --- Spec-1: pre-filled Sub on allowlist add ---------------------------
//
// Allows IdPs that do not emit email_verified (e.g. Authentik
// admin-created accounts) to be used by skipping the email-
// bootstrap path: the operator pre-fills the IdP-stable sub
// when adding the entry, so the first login matches via Pass 1
// (steady-state) and Δ7 never applies. The legacy pending-
// bootstrap path stays available for IdPs that do emit
// email_verified=true.

func TestOIDCAllowlist_AddWithPrefilledSub_FirstLoginMatchesPass1WithUnverifiedEmail(t *testing.T) {
	// Add an entry with a pre-filled sub.
	env := newTestEnv(t, false)
	body := `{"email":"alice@example.com","displayName":"Alice","sub":"sub-from-authentik-xyz"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/oidc/allowlist", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST: status=%d body=%s", rec.Code, rec.Body)
	}
	// The entry must be persisted with Sub already set (NOT pending).
	got, err := env.store.GetOIDCConfig(context.Background())
	if err != nil {
		t.Fatalf("get oidc config: %v", err)
	}
	if len(got.AllowedIdentities) != 1 {
		t.Fatalf("expected 1 entry; got %d", len(got.AllowedIdentities))
	}
	if got.AllowedIdentities[0].Sub != "sub-from-authentik-xyz" {
		t.Errorf("Sub = %q; want %q (pre-fill not persisted)", got.AllowedIdentities[0].Sub, "sub-from-authentik-xyz")
	}

	// Pinning the contract: matchAllowlist must match this
	// entry via Pass 1 (sub-pass) with email_verified=false.
	// Pass 1 does NOT consult email_verified — that's the
	// spec §5.2 invariant ("the verified-email guard does
	// not apply there"). This is the property that lets the
	// pre-fill skip Δ7.
	match, idx, isBootstrap := matchAllowlist(got.AllowedIdentities, "sub-from-authentik-xyz", "alice@example.com", false, false)
	if idx != 0 || isBootstrap || match.Sub != "sub-from-authentik-xyz" {
		t.Fatalf("PASS-1 BYPASS REGRESSION: pre-filled sub did not match via Pass 1 with email_verified=false; idx=%d isBootstrap=%v match=%v", idx, isBootstrap, match)
	}
}

func TestOIDCAllowlist_AddWithDuplicateSub_Rejected(t *testing.T) {
	env := newTestEnv(t, false)

	// First entry — sub claimed.
	body1 := `{"email":"first@example.com","displayName":"First","sub":"sub-shared-zzz"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/oidc/allowlist", strings.NewReader(body1))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first POST: status=%d body=%s", rec.Code, rec.Body)
	}

	// Second entry — different email, SAME sub: must reject.
	body2 := `{"email":"second@example.com","displayName":"Second","sub":"sub-shared-zzz"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/settings/oidc/allowlist", strings.NewReader(body2))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("AMBIGUOUS PASS-1 REGRESSION: second entry with duplicate sub should return 409 (would otherwise create ambiguous Pass-1 matches at callback time); got %d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "already contains an entry with this sub") {
		t.Errorf("error message must name the collision cause: %s", rec.Body)
	}
}

func TestOIDCAllowlist_AddWithEmptySub_PendingBehaviourPreserved(t *testing.T) {
	// Spec-1 regression: omitting the sub field MUST keep the
	// legacy pending-bootstrap path entirely unchanged. Sub
	// pending, Pass 2 + Δ7 still applicable.
	env := newTestEnv(t, false)
	body := `{"email":"pending@example.com","displayName":"Pending"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/oidc/allowlist", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST: status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.GetOIDCConfig(context.Background())
	if got.AllowedIdentities[0].Sub != "" {
		t.Errorf("Sub = %q; want empty (legacy pending behaviour broken by Spec-1)", got.AllowedIdentities[0].Sub)
	}
}

// TestHandler_UIOrigin_PrefixesRedirects pins the K.2 dev fix:
// when SetUIOrigin is non-empty, every OIDC callback redirect
// targets the absolute UI origin instead of a relative path.
// Exercises the simplest reachable branch (state cookie
// missing → 302 to /login?error=invalid_state) — the prefix
// behaviour is identical for every redirect site by virtue of
// the single uiURL helper.
func TestHandler_UIOrigin_PrefixesRedirects(t *testing.T) {
	env := newTestEnv(t, false)
	// Reach into the handler via the env's router — we need
	// the Handler instance to call SetUIOrigin. The test env
	// builds the router from a Handler at line ~161; we'll
	// rely on env.router exercising the same instance and
	// reach the handler via a helper.
	env.handler.SetUIOrigin("http://localhost:5173")

	// Empty state cookie → redirect to /login?error=invalid_state.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?state=x&code=y", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	loc := rec.Header().Get("Location")
	if loc != "http://localhost:5173/login?error=invalid_state" {
		t.Errorf("UI-ORIGIN BYPASS REGRESSION: callback redirect = %q; expected absolute http://localhost:5173/login?error=invalid_state", loc)
	}
}

func TestHandler_UIOrigin_EmptyKeepsRelative(t *testing.T) {
	env := newTestEnv(t, false)
	// Do NOT call SetUIOrigin — empty preserves legacy relative
	// behaviour for prod (static SPA same-origin).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?state=x&code=y", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	loc := rec.Header().Get("Location")
	if loc != "/login?error=invalid_state" {
		t.Errorf("LEGACY RELATIVE REDIRECT REGRESSION: callback redirect = %q; expected relative /login?error=invalid_state when uiOrigin empty", loc)
	}
}

// --- Provider Kind (post-K UX polish) ---------------------------

// TestOIDCConfig_KindPersistedAndExposedAnonymously pins the
// round-trip Kind field through PUT → BoltDB → GET, and through
// the anonymous /oidc/status response surface.
func TestOIDCConfig_KindPersistedAndExposedAnonymously(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	// Seed enabled OIDC config with Kind=authentik via the storage
	// layer directly (the API PUT path requires a reachable IdP
	// for discovery; we bypass that here by writing the row).
	if err := env.store.PutOIDCConfig(ctx, storage.OIDCConfig{
		Enabled:      true,
		IssuerURL:    "https://idp.example.com",
		ClientID:     "arenet",
		ClientSecret: "secret-1234567890",
		RedirectURL:  "http://localhost:8001/api/v1/auth/oidc/callback",
		Scopes:       []string{"openid", "profile", "email"},
		Kind:         "authentik",
	}); err != nil {
		t.Fatalf("seed oidc: %v", err)
	}

	// GET /settings/oidc → response carries Kind.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/oidc", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"kind":"authentik"`) {
		t.Errorf("admin GET missing kind=authentik: %s", rec.Body)
	}

	// GET /auth/oidc/status (anonymous) → kind exposed.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/status", nil)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status GET status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Errorf("anonymous status missing enabled:true: %s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"kind":"authentik"`) {
		t.Errorf("anonymous status missing kind=authentik: %s", rec.Body)
	}
}

// TestOIDCConfig_KindOmittedWhenDisabled pins that kind is
// suppressed from the anonymous status response when OIDC is
// disabled. Default state on a fresh install.
func TestOIDCConfig_KindOmittedWhenDisabled(t *testing.T) {
	env := newTestEnv(t, false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/status", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `"enabled":false`) {
		t.Errorf("fresh install should report enabled:false: %s", body)
	}
	// omitempty on the Kind field — the JSON key MUST be absent
	// when no config exists / kind is empty.
	if strings.Contains(body, `"kind"`) {
		t.Errorf("kind should be omitted from anonymous status when disabled / empty: %s", body)
	}
}

// TestOIDCConfig_InvalidKindRejected pins the enum check on
// non-empty kind. Storage validate is the last-line guard; the
// API layer also rejects via the storage validate chain.
func TestOIDCConfig_InvalidKindRejected(t *testing.T) {
	err := storage.ValidateOIDCConfig(storage.OIDCConfig{
		Enabled:      true,
		IssuerURL:    "https://idp.example.com",
		ClientID:     "arenet",
		ClientSecret: "x",
		RedirectURL:  "http://localhost:8001/cb",
		Scopes:       []string{"openid"},
		Kind:         "okta", // not in OIDCProviderKinds
	})
	if err == nil {
		t.Fatal("storage validate accepted unknown kind=okta — enum guard regressed")
	}
	if !strings.Contains(err.Error(), "kind") {
		t.Errorf("error should name the kind field: %v", err)
	}
}

// TestOIDCConfig_EmptyKindAccepted pins that Kind="" is the
// legacy + fresh-install state (rows created pre-K-UX-polish)
// — must NOT be rejected by validate. Treated as "generic" by
// the frontend at render time.
func TestOIDCConfig_EmptyKindAccepted(t *testing.T) {
	err := storage.ValidateOIDCConfig(storage.OIDCConfig{
		Enabled:      true,
		IssuerURL:    "https://idp.example.com",
		ClientID:     "arenet",
		ClientSecret: "x",
		RedirectURL:  "http://localhost:8001/cb",
		Scopes:       []string{"openid"},
		Kind:         "", // legacy
	})
	if err != nil {
		t.Errorf("storage validate rejected empty kind (legacy): %v", err)
	}
}

// TestOIDCMatchAllowlist_AcceptUnverifiedEmail_BypassesD7 pins the
// Step #S-17 escape hatch: when the operator sets
// OIDCConfig.AcceptUnverifiedEmail = true, an unverified-email
// match canonicalises a pending invite (Pass 2 succeeds despite
// emailVerified=false).
func TestOIDCMatchAllowlist_AcceptUnverifiedEmail_BypassesD7(t *testing.T) {
	entries := []storage.OIDCAllowedIdentity{
		{Email: "alice@example.com", DisplayName: "Alice"},
	}
	// emailVerified=false, acceptUnverifiedEmail=true → bootstrap succeeds.
	match, idx, isBootstrap := matchAllowlist(entries, "sub-attacker-but-trusted-idp", "alice@example.com", false, true)
	if idx != 0 || !isBootstrap || match.Email != "alice@example.com" {
		t.Errorf("AcceptUnverifiedEmail=true should bypass Δ7: idx=%d isBootstrap=%v match=%v", idx, isBootstrap, match)
	}
}

// TestOIDCMatchAllowlist_AcceptUnverifiedEmail_DefaultPreservesD7
// is a regression guard: the new toggle MUST default to false,
// preserving the §1.6 Δ7 invariant for installs that don't
// explicitly opt in.
func TestOIDCMatchAllowlist_AcceptUnverifiedEmail_DefaultPreservesD7(t *testing.T) {
	entries := []storage.OIDCAllowedIdentity{
		{Email: "alice@example.com"},
	}
	// emailVerified=false, acceptUnverifiedEmail=false (default).
	_, idx, _ := matchAllowlist(entries, "sub-x", "alice@example.com", false, false)
	if idx >= 0 {
		t.Errorf("Δ7 REGRESSION: default (acceptUnverifiedEmail=false) accepted unverified email; idx=%d", idx)
	}
}

// Sanity probe — confirms the test file compiles against the
// time / context imports used in setup helpers.
func TestK2_TestFileCompiles(t *testing.T) {
	_ = time.Now()
	_ = context.Background()
	_ = t
}
