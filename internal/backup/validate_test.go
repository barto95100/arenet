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

package backup

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// Step K.3 — business-invariant re-check tests. These pin the
// property that an Import does NOT smuggle a malformed snapshot
// into BoltDB by bypassing the domain validators that the live
// API path runs. A regression here would let a restore land an
// instance in an invalid / non-bootable state.
//
// Each test that pins a structural invariant carries a named
// anti-regression assertion (BUSINESS VALIDATOR BYPASS,
// LOCKOUT REGRESSION, CROSS-RULE BYPASS).

// TestValidate_MalformedRoute_Rejected pins that a snapshot
// carrying a route with no Host (or no upstreams, or invalid LB
// policy) is rejected. Storage.RestoreSnapshot would happily
// write this row; the upstream validator stops it.
func TestValidate_MalformedRoute_Rejected(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	// Live admin so we don't trip the local-admin guard.
	_ = seedLiveUser(t, us, "admin", "admin-password-15c-xx")

	snap := minimalSnapshot()
	seeded, _ := us.List(context.Background())
	snap.Users = []auth.User{seeded[0]}
	snap.Routes = []storage.Route{
		{
			ID:        "route-no-host",
			Host:      "", // ← malformed
			Upstreams: []storage.Upstream{{URL: "http://x", Weight: 1}},
			LBPolicy:  "round_robin",
			AuthMode:  "none",
			WAFMode:   "off",
		},
	}

	_, err := Import(context.Background(), store, us, snap, ImportOptions{})
	if err == nil {
		t.Fatal("BUSINESS VALIDATOR BYPASS: malformed route (empty host) was accepted by Import")
	}
	if !strings.Contains(err.Error(), "host must not be empty") {
		t.Errorf("error should name the violated field; got: %s", err)
	}
}

// TestValidate_RouteAuthModeMutex_Rejected pins that the K.1
// auth-mode invariant survives the restore path. A route with
// auth_mode="basic" but empty basic_auth.username (or empty
// password_hash WITHOUT the dérogation flag) must reject.
func TestValidate_RouteAuthModeMutex_Rejected(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	_ = seedLiveUser(t, us, "admin", "admin-password-15c-xx")

	snap := minimalSnapshot()
	seeded, _ := us.List(context.Background())
	snap.Users = []auth.User{seeded[0]}
	snap.Routes = []storage.Route{
		{
			ID:        "route-bad-basic-auth",
			Host:      "bad.example.com",
			Upstreams: []storage.Upstream{{URL: "http://x", Weight: 1}},
			LBPolicy:  "round_robin",
			AuthMode:  "basic",
			BasicAuth: storage.BasicAuthRouteConfig{
				Username:     "", // ← missing username under basic
				PasswordHash: "$argon2id$some-real-hash",
			},
			WAFMode: "off",
		},
	}

	_, err := Import(context.Background(), store, us, snap, ImportOptions{})
	if err == nil {
		t.Fatal("BUSINESS VALIDATOR BYPASS: K.1 auth-mode mutex (basic without username) accepted by Import")
	}
}

// TestValidate_ForwardAuthRouteRefersToMissingProvider_Rejected pins
// the cross-rule: a route with auth_mode="forward_auth" must
// reference a provider that EXISTS in the snapshot's own
// forward_auth_providers set. The live store is about to be
// replaced, so we check against the snapshot, not the live state.
func TestValidate_ForwardAuthRouteRefersToMissingProvider_Rejected(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	_ = seedLiveUser(t, us, "admin", "admin-password-15c-xx")

	snap := minimalSnapshot()
	seeded, _ := us.List(context.Background())
	snap.Users = []auth.User{seeded[0]}
	snap.ForwardAuthProviders = []storage.ForwardAuthProvider{
		// Snapshot has provider "p-exists" only.
		{
			Name:           "p-exists",
			Kind:           "generic",
			VerifyURL:      "http://x/verify",
			AuthRequestURI: "/auth",
		},
	}
	snap.Routes = []storage.Route{
		{
			ID:        "route-dangling-fwdauth",
			Host:      "dangling.example.com",
			Upstreams: []storage.Upstream{{URL: "http://x", Weight: 1}},
			LBPolicy:  "round_robin",
			AuthMode:  "forward_auth",
			ForwardAuth: storage.ForwardAuthRouteConfig{
				ProviderName: "p-missing", // ← not in snapshot
			},
			WAFMode: "off",
		},
	}

	_, err := Import(context.Background(), store, us, snap, ImportOptions{})
	if err == nil {
		t.Fatal("CROSS-RULE BYPASS: route referencing a missing forward-auth provider accepted by Import")
	}
	if !strings.Contains(err.Error(), "p-missing") {
		t.Errorf("error should name the missing provider; got: %s", err)
	}
}

// TestValidate_DNS01RouteWithoutDNSProvider_Rejected pins the J.4
// cross-rule on the restore path.
func TestValidate_DNS01RouteWithoutDNSProvider_Rejected(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	_ = seedLiveUser(t, us, "admin", "admin-password-15c-xx")

	snap := minimalSnapshot()
	seeded, _ := us.List(context.Background())
	snap.Users = []auth.User{seeded[0]}
	// Snapshot has NO dns_providers.
	snap.Routes = []storage.Route{
		{
			ID:            "route-dns01-no-provider",
			Host:          "wildcard.example.com",
			Upstreams:     []storage.Upstream{{URL: "http://x", Weight: 1}},
			LBPolicy:      "round_robin",
			AuthMode:      "none",
			WAFMode:       "off",
			TLSEnabled:    true,
			ACMEChallenge: "dns-01", // ← needs a DNS provider
		},
	}

	_, err := Import(context.Background(), store, us, snap, ImportOptions{})
	if err == nil {
		t.Fatal("CROSS-RULE BYPASS: dns-01 route without a DNS provider accepted by Import")
	}
}

// TestValidate_PostStateNoLocalAdmin_Rejected pins the lockout
// guard: a snapshot whose users are all OIDC or all viewers
// would leave the instance with no break-glass channel.
func TestValidate_PostStateNoLocalAdmin_Rejected(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	// Snapshot with one viewer (local) — no admin.
	now := time.Now().UTC()
	snap := minimalSnapshot()
	snap.SchemaVersion = SchemaVersion
	snap.Users = []auth.User{
		{
			ID: "u-viewer-only", Username: "viewer-only", DisplayName: "Viewer Only",
			PasswordHash: "$argon2id$..hash..",
			AuthSource:   auth.UserAuthSourceLocal,
			Role:         auth.UserRoleViewer, // ← not admin
			CreatedAt:    now, UpdatedAt: now,
		},
	}

	_, err := Import(context.Background(), store, us, snap, ImportOptions{})
	if !errors.Is(err, ErrNoLocalAdmin) {
		t.Fatalf("LOCKOUT REGRESSION: viewer-only snapshot accepted (expected ErrNoLocalAdmin); got %v", err)
	}
}

// TestValidate_PostStateAllOIDCAdmins_Rejected — the subtler
// lockout: all admins are OIDC. The IdP becoming unreachable would
// lock the operator out; the break-glass channel requires at
// least one LOCAL admin.
func TestValidate_PostStateAllOIDCAdmins_Rejected(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	now := time.Now().UTC()
	snap := minimalSnapshot()
	snap.Users = []auth.User{
		{
			ID: "u-oidc-admin", Username: "oidc-admin", DisplayName: "OIDC Admin",
			PasswordHash: "",
			AuthSource:   auth.UserAuthSourceOIDC,
			OIDCSub:      "sub-x",
			Role:         auth.UserRoleAdmin,
			CreatedAt:    now, UpdatedAt: now,
		},
	}

	_, err := Import(context.Background(), store, us, snap, ImportOptions{})
	if !errors.Is(err, ErrNoLocalAdmin) {
		t.Fatalf("LOCKOUT REGRESSION: OIDC-only-admins snapshot accepted (expected ErrNoLocalAdmin); got %v", err)
	}
}

// TestValidate_BadRole_Rejected pins the role enum on the restore
// path.
func TestValidate_BadRole_Rejected(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	now := time.Now().UTC()
	snap := minimalSnapshot()
	snap.Users = []auth.User{
		{
			ID: "u-bad-role", Username: "bad-role", DisplayName: "Bad Role",
			PasswordHash: "$argon2id$..hash..",
			AuthSource:   auth.UserAuthSourceLocal,
			Role:         "superuser", // ← out of enum
			CreatedAt:    now, UpdatedAt: now,
		},
	}

	_, err := Import(context.Background(), store, us, snap, ImportOptions{})
	if err == nil {
		t.Fatal("BUSINESS VALIDATOR BYPASS: out-of-enum role accepted by Import")
	}
	if !strings.Contains(err.Error(), "role") {
		t.Errorf("error should name the violated field; got: %s", err)
	}
}

// TestValidate_DuplicateUsernameInSnapshot_Rejected pins that two
// users sharing the same username are rejected — the live store
// would otherwise let one silently overwrite the other in the
// bucket map (single username key collision).
func TestValidate_DuplicateUsernameInSnapshot_Rejected(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	now := time.Now().UTC()
	snap := minimalSnapshot()
	snap.Users = []auth.User{
		{ID: "u-1", Username: "shared", DisplayName: "First", PasswordHash: "h1",
			AuthSource: auth.UserAuthSourceLocal, Role: auth.UserRoleAdmin,
			CreatedAt: now, UpdatedAt: now},
		{ID: "u-2", Username: "shared", DisplayName: "Second", PasswordHash: "h2",
			AuthSource: auth.UserAuthSourceLocal, Role: auth.UserRoleAdmin,
			CreatedAt: now, UpdatedAt: now},
	}

	_, err := Import(context.Background(), store, us, snap, ImportOptions{})
	if err == nil {
		t.Fatal("BUSINESS VALIDATOR BYPASS: duplicate username in snapshot accepted by Import")
	}
}

// TestValidate_DerogationIsNarrow_BasicAuth pins that the
// dérogation for cleared password_hash applies ONLY when the
// resolver actually cleared that specific (route, field). A route
// with auth_mode=basic and password_hash="" but NOT in the
// cleared set must reject, even with --allow-incomplete-restore.
func TestValidate_DerogationIsNarrow_BasicAuth(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	_ = seedLiveRoute(t, store, "alice.example.com")
	_ = seedLiveUser(t, us, "admin", "admin-password-15c-xx")

	snap := minimalSnapshot()
	seeded, _ := us.List(context.Background())
	snap.Users = []auth.User{seeded[0]}
	// A route with auth_mode=basic, password_hash="" (NOT a
	// sentinel, so the resolver does not record it), AND no
	// matching live route. The dérogation must NOT apply — this
	// is a hand-edited snapshot trying to smuggle a malformed row.
	snap.Routes = []storage.Route{
		{
			ID:        "route-handcrafted-empty-hash",
			Host:      "handcrafted.example.com",
			Upstreams: []storage.Upstream{{URL: "http://x", Weight: 1}},
			LBPolicy:  "round_robin",
			AuthMode:  "basic",
			BasicAuth: storage.BasicAuthRouteConfig{
				Username:     "admin",
				PasswordHash: "", // ← empty literal, not the sentinel
			},
			WAFMode: "off",
		},
	}

	_, err := Import(context.Background(), store, us, snap, ImportOptions{
		AllowIncompleteRestore: true, // even with the flag set
	})
	if err == nil {
		t.Fatal("BUSINESS VALIDATOR BYPASS: hand-edited snapshot with empty password_hash (no sentinel) accepted under --allow-incomplete-restore — dérogation must apply only to fields the resolver actually cleared")
	}
}

// TestValidate_DerogationIsActive_OnLegitimateClearedField pins
// the positive case: when AllowIncompleteRestore IS the path
// that cleared the field (sentinel that couldn't inherit), the
// validator accepts the cleared field.
func TestValidate_DerogationIsActive_OnLegitimateClearedField(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	// Live admin so the local-admin guard passes.
	_ = seedLiveUser(t, us, "admin", "admin-password-15c-xx")
	// Live route to make the target "not fresh" so the pre-flight
	// doesn't fire on its own.
	_ = seedLiveRoute(t, store, "alice.example.com")

	snap := minimalSnapshot()
	snap.SecretsIncluded = false
	seeded, _ := us.List(context.Background())
	snap.Users = []auth.User{seeded[0]}
	snap.Users[0].PasswordHash = SentinelLiteral // legit sentinel — will inherit live
	// Route whose ID does NOT match the live route → sentinel
	// unresolvable → cleared under AllowIncomplete.
	snap.Routes = []storage.Route{
		{
			ID:        "route-fresh-id-aaaaaaaaaaaaaaaa",
			Host:      "fresh.example.com",
			Upstreams: []storage.Upstream{{URL: "http://x", Weight: 1}},
			LBPolicy:  "round_robin",
			AuthMode:  "basic",
			BasicAuth: storage.BasicAuthRouteConfig{
				Username:     "admin",
				PasswordHash: SentinelLiteral, // ← will clear, dérogation applies
			},
			WAFMode: "off",
		},
	}

	report, err := Import(context.Background(), store, us, snap, ImportOptions{
		AllowIncompleteRestore: true,
	})
	if err != nil {
		t.Fatalf("legitimate dérogation should be accepted; got %v", err)
	}
	if report.SentinelsUnresolvedTotal < 1 {
		t.Errorf("expected >= 1 unresolved sentinel; got %d", report.SentinelsUnresolvedTotal)
	}
}
