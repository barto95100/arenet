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
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// newTokenTestDB spins up an isolated bbolt file with the
// users + api_tokens buckets pre-created. Mirrors the harness
// used by userstore_test.go to keep the test surface small.
func newTokenTestDB(t *testing.T) (*bolt.DB, *UserStore, *APITokenStore) {
	t.Helper()
	dir := t.TempDir()
	db, err := bolt.Open(filepath.Join(dir, "test.db"), 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("open bbolt: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{usersBucketName, apiTokensBucketName} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("create buckets: %v", err)
	}

	return db, NewUserStore(db), NewAPITokenStore(db)
}

func createServiceUserForToken(t *testing.T, us *UserStore, name, role string) User {
	t.Helper()
	u, err := us.CreateServiceAccount(context.Background(), name, role)
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	return u
}

func TestGeneratePlainToken_FormatAndUniqueness(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 100; i++ {
		plain, hash, err := generatePlainToken()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if !strings.HasPrefix(plain, APITokenPrefix) {
			t.Errorf("missing prefix: %q", plain)
		}
		if len(plain) != len(APITokenPrefix)+43 {
			t.Errorf("unexpected length %d for %q", len(plain), plain)
		}
		if len(hash) != 64 {
			t.Errorf("hash not 64-hex chars: %q", hash)
		}
		if _, dup := seen[plain]; dup {
			t.Fatalf("duplicate token in 100 generates: %q", plain)
		}
		seen[plain] = struct{}{}
	}
}

func TestAPITokenStore_CreateAndValidate_HappyPath(t *testing.T) {
	_, us, ts := newTokenTestDB(t)
	owner := createServiceUserForToken(t, us, "ci-deploy", UserRoleViewer)

	plain, row, err := ts.CreateToken(context.Background(), owner.ID, "ci-deploy", "admin-uid", nil)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if row.UserID != owner.ID {
		t.Errorf("UserID mismatch: got %q want %q", row.UserID, owner.ID)
	}
	if row.TokenHash == "" {
		t.Errorf("TokenHash empty")
	}
	if !strings.HasPrefix(plain, APITokenPrefix) {
		t.Errorf("plain has no prefix: %q", plain)
	}

	tok, validatedUser, err := ts.ValidateAuthToken(context.Background(), us, plain)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if tok.ID != row.ID {
		t.Errorf("validated token id mismatch: %q vs %q", tok.ID, row.ID)
	}
	if validatedUser.ID != owner.ID {
		t.Errorf("validated user id mismatch: %q vs %q", validatedUser.ID, owner.ID)
	}
	if validatedUser.AuthSource != UserAuthSourceService {
		t.Errorf("validated user authSource %q, want service", validatedUser.AuthSource)
	}
}

func TestAPITokenStore_Validate_RejectsInvalidPrefix(t *testing.T) {
	_, us, ts := newTokenTestDB(t)
	_, _, err := ts.ValidateAuthToken(context.Background(), us, "not-our-prefix-abc")
	if !errors.Is(err, ErrAPITokenInvalid) {
		t.Errorf("want ErrAPITokenInvalid, got %v", err)
	}
}

func TestAPITokenStore_Validate_RejectsUnknownToken(t *testing.T) {
	_, us, ts := newTokenTestDB(t)
	// Pretend-token with the right prefix but never persisted.
	_, _, err := ts.ValidateAuthToken(context.Background(), us, APITokenPrefix+"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if !errors.Is(err, ErrAPITokenInvalid) {
		t.Errorf("want ErrAPITokenInvalid, got %v", err)
	}
}

func TestAPITokenStore_Validate_RejectsRevokedToken(t *testing.T) {
	_, us, ts := newTokenTestDB(t)
	owner := createServiceUserForToken(t, us, "n8n", UserRoleViewer)

	plain, row, err := ts.CreateToken(context.Background(), owner.ID, "n8n", "admin-uid", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.RevokeToken(context.Background(), row.ID, "admin-uid"); err != nil {
		t.Fatal(err)
	}

	_, _, err = ts.ValidateAuthToken(context.Background(), us, plain)
	if !errors.Is(err, ErrAPITokenRevoked) {
		t.Errorf("want ErrAPITokenRevoked, got %v", err)
	}
}

func TestAPITokenStore_Validate_RejectsExpiredToken(t *testing.T) {
	_, us, ts := newTokenTestDB(t)
	owner := createServiceUserForToken(t, us, "monitor", UserRoleViewer)

	past := time.Now().UTC().Add(-1 * time.Hour)
	plain, _, err := ts.CreateToken(context.Background(), owner.ID, "monitor", "admin-uid", &past)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = ts.ValidateAuthToken(context.Background(), us, plain)
	if !errors.Is(err, ErrAPITokenExpired) {
		t.Errorf("want ErrAPITokenExpired, got %v", err)
	}
}

func TestAPITokenStore_Validate_AcceptsFutureExpiry(t *testing.T) {
	_, us, ts := newTokenTestDB(t)
	owner := createServiceUserForToken(t, us, "future", UserRoleAdmin)

	future := time.Now().UTC().Add(24 * time.Hour)
	plain, _, err := ts.CreateToken(context.Background(), owner.ID, "future", "admin-uid", &future)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := ts.ValidateAuthToken(context.Background(), us, plain); err != nil {
		t.Errorf("want valid future-expiry token, got %v", err)
	}
}

func TestAPITokenStore_TouchLastUsed_PersistsTimestamp(t *testing.T) {
	_, us, ts := newTokenTestDB(t)
	owner := createServiceUserForToken(t, us, "touch", UserRoleViewer)

	_, row, err := ts.CreateToken(context.Background(), owner.ID, "touch", "admin-uid", nil)
	if err != nil {
		t.Fatal(err)
	}
	if row.LastUsedAt != nil {
		t.Errorf("LastUsedAt should be nil on fresh token, got %v", row.LastUsedAt)
	}

	before := time.Now().UTC()
	if err := ts.TouchLastUsed(context.Background(), row.ID); err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC()

	got, err := ts.GetByID(context.Background(), row.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastUsedAt == nil {
		t.Fatalf("LastUsedAt nil after Touch")
	}
	if got.LastUsedAt.Before(before) || got.LastUsedAt.After(after) {
		t.Errorf("LastUsedAt %v outside [%v, %v]", got.LastUsedAt, before, after)
	}
}

func TestAPITokenStore_RevokeAllByUser_CascadesAcrossTokens(t *testing.T) {
	_, us, ts := newTokenTestDB(t)
	owner := createServiceUserForToken(t, us, "multi", UserRoleViewer)

	// V1 only ever has one active token per user (the API
	// rotation flow revokes the old before issuing the new) —
	// but the cascade helper must handle the pathological
	// case of multiple lingering rows correctly.
	for i := 0; i < 3; i++ {
		if _, _, err := ts.CreateToken(context.Background(), owner.ID, "multi", "admin-uid", nil); err != nil {
			t.Fatal(err)
		}
	}

	if err := ts.RevokeAllByUser(context.Background(), owner.ID, "admin-uid"); err != nil {
		t.Fatal(err)
	}

	tokens, err := ts.ListByUser(context.Background(), owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 3 {
		t.Fatalf("want 3 token rows post-cascade, got %d", len(tokens))
	}
	for _, tok := range tokens {
		if tok.RevokedAt == nil {
			t.Errorf("token %q not revoked after cascade", tok.ID)
		}
	}
}

func TestAPITokenStore_FindActiveByUser_PicksTheLiveOne(t *testing.T) {
	_, us, ts := newTokenTestDB(t)
	owner := createServiceUserForToken(t, us, "active", UserRoleViewer)

	// Revoked token.
	_, revoked, err := ts.CreateToken(context.Background(), owner.ID, "active", "admin-uid", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.RevokeToken(context.Background(), revoked.ID, "admin-uid"); err != nil {
		t.Fatal(err)
	}

	// Live token.
	_, live, err := ts.CreateToken(context.Background(), owner.ID, "active", "admin-uid", nil)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ts.FindActiveByUser(context.Background(), owner.ID)
	if err != nil {
		t.Fatalf("FindActiveByUser: %v", err)
	}
	if got.ID != live.ID {
		t.Errorf("FindActiveByUser returned %q, want %q", got.ID, live.ID)
	}
}

func TestUserStore_CreateServiceAccount_Defaults(t *testing.T) {
	_, us, _ := newTokenTestDB(t)
	u, err := us.CreateServiceAccount(context.Background(), "svc-1", UserRoleViewer)
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	if u.AuthSource != UserAuthSourceService {
		t.Errorf("AuthSource %q, want service", u.AuthSource)
	}
	if u.PasswordHash != "" {
		t.Errorf("service account must have empty PasswordHash, got %q", u.PasswordHash)
	}
	if u.OIDCSub != "" {
		t.Errorf("service account must have empty OIDCSub, got %q", u.OIDCSub)
	}
	if u.Role != UserRoleViewer {
		t.Errorf("Role %q, want viewer", u.Role)
	}
}

func TestUserStore_CreateServiceAccount_RejectsBadRole(t *testing.T) {
	_, us, _ := newTokenTestDB(t)
	_, err := us.CreateServiceAccount(context.Background(), "svc-x", "superuser")
	if err == nil {
		t.Fatal("want error for invalid role")
	}
}

func TestUserStore_CreateServiceAccount_RejectsBadName(t *testing.T) {
	_, us, _ := newTokenTestDB(t)
	if _, err := us.CreateServiceAccount(context.Background(), "Bad Name With Spaces", UserRoleViewer); err == nil {
		t.Error("want error for name with spaces")
	}
}

func TestUserStore_CreateServiceAccount_RejectsDuplicateName(t *testing.T) {
	_, us, _ := newTokenTestDB(t)
	if _, err := us.CreateServiceAccount(context.Background(), "dup", UserRoleViewer); err != nil {
		t.Fatal(err)
	}
	if _, err := us.CreateServiceAccount(context.Background(), "dup", UserRoleAdmin); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("want ErrUsernameTaken, got %v", err)
	}
}

func TestValidateUserForRestore_AcceptsService(t *testing.T) {
	u := User{
		ID:         "x",
		Username:   "svc",
		AuthSource: UserAuthSourceService,
		Role:       UserRoleAdmin,
	}
	if err := ValidateUserForRestore(u, false); err != nil {
		t.Errorf("want service AuthSource accepted, got %v", err)
	}
}
