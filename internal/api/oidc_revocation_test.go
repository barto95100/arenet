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

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// seedOIDCUserWithSession provisions an OIDC user + a live session and
// returns the user id. Writes go to the same DB the handler reads.
func seedOIDCUserWithSession(t *testing.T, env *testEnv, username, email, sub string) string {
	t.Helper()
	ctx := context.Background()
	us := auth.NewUserStore(env.store.DB())
	ss := auth.NewSessionStore(env.store.DB())
	u, err := us.CreateOIDCUser(ctx, username, username, email, sub)
	if err != nil {
		t.Fatalf("CreateOIDCUser: %v", err)
	}
	if _, err := ss.Create(ctx, u.ID, false, "1.2.3.4", "ua/1"); err != nil {
		t.Fatalf("session Create: %v", err)
	}
	return u.ID
}

func sessionsFor(t *testing.T, env *testEnv, userID string) int {
	t.Helper()
	ss := auth.NewSessionStore(env.store.DB())
	s, err := ss.ListForUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	return len(s)
}

// Removing an identity from the OIDC allowlist is the documented
// revocation action, but before F38 it only stopped NEW sign-ins. The
// deprovisioned user's live session kept resolving. The DELETE now
// purges it.
func TestDeleteOIDCAllowlist_RevokesLiveSessions(t *testing.T) {
	env := newTestEnv(t, false)
	uid := seedOIDCUserWithSession(t, env, "contractor", "contractor@x.test", "sub-123")

	if err := env.store.PutOIDCConfig(context.Background(), storage.OIDCConfig{
		Enabled: false, // disabled: storage skips field validation
		AllowedIdentities: []storage.OIDCAllowedIdentity{
			{Email: "contractor@x.test", Sub: "sub-123"},
		},
	}); err != nil {
		t.Fatalf("PutOIDCConfig: %v", err)
	}
	if sessionsFor(t, env, uid) != 1 {
		t.Fatalf("precondition: want 1 live session")
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/settings/oidc/allowlist/contractor@x.test", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete allowlist status=%d body=%s", rec.Code, rec.Body)
	}

	if n := sessionsFor(t, env, uid); n != 0 {
		t.Errorf("the revoked identity still has %d live session(s) — removing the allowlist entry must purge them", n)
	}
}

// Disabling OIDC closes the sign-in gate; every existing OIDC session
// must be purged too (F38, the enabled true→false transition).
func TestPutOIDCConfig_DisableRevokesAllOIDCSessions(t *testing.T) {
	env := newTestEnv(t, false)
	uid := seedOIDCUserWithSession(t, env, "ssouser", "sso@x.test", "sub-abc")

	// Previous stored config is ENABLED (valid dummy fields; no dial on
	// the store write).
	if err := env.store.PutOIDCConfig(context.Background(), storage.OIDCConfig{
		Enabled:      true,
		IssuerURL:    "https://idp.test",
		ClientID:     "cid",
		ClientSecret: "secret",
		RedirectURL:  "https://arenet.test/api/v1/auth/oidc/callback",
		Scopes:       []string{"openid", "email"},
	}); err != nil {
		t.Fatalf("seed enabled config: %v", err)
	}
	if sessionsFor(t, env, uid) != 1 {
		t.Fatalf("precondition: want 1 live session")
	}

	// PUT the config with enabled=false → transition true→false.
	rec := putJSONRaw(t, env, "/api/v1/settings/oidc", map[string]any{
		"enabled": false,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("put oidc disable status=%d body=%s", rec.Code, rec.Body)
	}

	if n := sessionsFor(t, env, uid); n != 0 {
		t.Errorf("disabling OIDC left %d live OIDC session(s) — they must be revoked", n)
	}
}
