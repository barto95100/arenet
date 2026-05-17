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

	"github.com/alexedwards/argon2id"
	bolt "go.etcd.io/bbolt"
)

// newTestDB opens a fresh bbolt database with the users and sessions
// buckets pre-created. Callers construct UserStore or SessionStore on
// top of it.
func newTestDB(t *testing.T) *bolt.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := bolt.Open(filepath.Join(dir, "auth_test.db"), 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{usersBucketName, sessionsBucketName} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("create buckets: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return db
}

func TestNewUserStore_NilPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic, got none")
		}
	}()
	_ = NewUserStore(nil)
}

func TestUserStore_Create_HappyPath(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()

	u, err := s.Create(ctx, "admin", "Site Admin", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.ID == "" {
		t.Error("expected non-empty ID")
	}
	if u.Username != "admin" {
		t.Errorf("username = %q, want admin", u.Username)
	}
	if u.DisplayName != "Site Admin" {
		t.Errorf("displayName lost: %q", u.DisplayName)
	}
	if u.PasswordHash == "" || u.PasswordHash == "correct horse battery staple" {
		t.Error("password not hashed")
	}
	if u.HIBPCheckStatus != HIBPStatusPending {
		t.Errorf("HIBPCheckStatus = %q, want pending", u.HIBPCheckStatus)
	}
	if u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() {
		t.Error("timestamps not set")
	}
}

// TestUserStore_Create_Argon2idParams covers AC-AUTH-11: verify the
// PHC string contains the exact parameters from spec §3.2 / Q4
// (m=64MiB, t=3, p=4).
func TestUserStore_Create_Argon2idParams(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	u, err := s.Create(context.Background(), "admin", "", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// PHC format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	if !strings.HasPrefix(u.PasswordHash, "$argon2id$v=19$") {
		t.Errorf("PHC does not start with $argon2id$v=19$: %q", u.PasswordHash)
	}
	if !strings.Contains(u.PasswordHash, "m=65536") {
		t.Errorf("PHC missing m=65536: %q", u.PasswordHash)
	}
	if !strings.Contains(u.PasswordHash, "t=3") {
		t.Errorf("PHC missing t=3: %q", u.PasswordHash)
	}
	if !strings.Contains(u.PasswordHash, "p=4") {
		t.Errorf("PHC missing p=4: %q", u.PasswordHash)
	}

	// Sanity: the hash must verify the original password.
	match, err := argon2id.ComparePasswordAndHash("correct horse battery staple", u.PasswordHash)
	if err != nil {
		t.Fatalf("ComparePasswordAndHash: %v", err)
	}
	if !match {
		t.Error("hash does not verify against original password")
	}
}

func TestUserStore_Create_UsernameValidation(t *testing.T) {
	tests := []struct {
		name     string
		username string
		want     error
	}{
		{name: "too short", username: "ab", want: ErrUsernameInvalid},
		{name: "too long", username: strings.Repeat("a", 33), want: ErrUsernameInvalid},
		{name: "uppercase rejected", username: "Admin", want: ErrUsernameInvalid},
		{name: "spaces rejected", username: "admin user", want: ErrUsernameInvalid},
		{name: "special chars rejected", username: "admin@host", want: ErrUsernameInvalid},
		{name: "empty after trim", username: "   ", want: ErrUsernameInvalid},
		{name: "valid with hyphen", username: "admin-user", want: nil},
		{name: "valid with underscore", username: "admin_user", want: nil},
		{name: "valid digits", username: "admin123", want: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewUserStore(newTestDB(t))
			_, err := s.Create(context.Background(), tc.username, "", "correct horse battery staple")
			if tc.want == nil {
				if err != nil {
					t.Errorf("want nil, got %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestUserStore_Create_PasswordLength(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()

	// 14 chars: too short.
	_, err := s.Create(ctx, "admin1", "", strings.Repeat("a", 14))
	if !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("14 chars: want ErrPasswordTooShort, got %v", err)
	}
	// 129 chars: too long.
	_, err = s.Create(ctx, "admin2", "", strings.Repeat("a", 129))
	if !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("129 chars: want ErrPasswordTooLong, got %v", err)
	}
	// 15 chars: OK boundary.
	_, err = s.Create(ctx, "admin3", "", strings.Repeat("a", 15))
	if err != nil {
		t.Errorf("15 chars: want nil, got %v", err)
	}
	// 128 chars: OK boundary.
	_, err = s.Create(ctx, "admin4", "", strings.Repeat("a", 128))
	if err != nil {
		t.Errorf("128 chars: want nil, got %v", err)
	}
}

func TestUserStore_Create_DisplayNameTooLong(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	_, err := s.Create(context.Background(), "admin", strings.Repeat("a", 65), "correct horse battery staple")
	if !errors.Is(err, ErrDisplayNameTooLong) {
		t.Errorf("want ErrDisplayNameTooLong, got %v", err)
	}
}

func TestUserStore_Create_UsernameTaken(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()

	if _, err := s.Create(ctx, "admin", "", "correct horse battery staple"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := s.Create(ctx, "admin", "", "another correct password long")
	if !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("want ErrUsernameTaken, got %v", err)
	}
}

func TestUserStore_Create_UsernameTrimmed(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	u, err := s.Create(context.Background(), "  admin  ", "", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.Username != "admin" {
		t.Errorf("username not trimmed: got %q", u.Username)
	}
}

func TestUserStore_GetByID(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()

	created, err := s.Create(ctx, "admin", "", "correct horse battery staple")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := s.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != created.ID || got.Username != "admin" {
		t.Errorf("got %+v, want %+v", got, created)
	}

	if _, err := s.GetByID(ctx, ""); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("empty id: want ErrUserNotFound, got %v", err)
	}
	if _, err := s.GetByID(ctx, "nonexistent"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("nonexistent id: want ErrUserNotFound, got %v", err)
	}
}

func TestUserStore_GetByUsername(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()

	created, err := s.Create(ctx, "admin", "", "correct horse battery staple")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := s.GetByUsername(ctx, "admin")
	if err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("got id=%q, want %q", got.ID, created.ID)
	}

	// Whitespace trimmed.
	got, err = s.GetByUsername(ctx, "  admin  ")
	if err != nil {
		t.Fatalf("GetByUsername trimmed: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("trimmed lookup mismatch: got %q want %q", got.ID, created.ID)
	}

	if _, err := s.GetByUsername(ctx, ""); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("empty: want ErrUserNotFound, got %v", err)
	}
	if _, err := s.GetByUsername(ctx, "ghost"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("ghost: want ErrUserNotFound, got %v", err)
	}
}

func TestUserStore_Count(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()

	n, err := s.Count(ctx)
	if err != nil {
		t.Fatalf("Count empty: %v", err)
	}
	if n != 0 {
		t.Errorf("want 0, got %d", n)
	}

	if _, err := s.Create(ctx, "admin", "", "correct horse battery staple"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	n, err = s.Count(ctx)
	if err != nil {
		t.Fatalf("Count after create: %v", err)
	}
	if n != 1 {
		t.Errorf("want 1, got %d", n)
	}
}

func TestUserStore_UpdatePassword(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()

	created, err := s.Create(ctx, "admin", "", "first password 15 chars")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	oldHash := created.PasswordHash

	// Simulate a prior HIBP clean check that we expect to be reset.
	if err := s.UpdateHIBPStatus(ctx, created.ID, HIBPStatusClean, false); err != nil {
		t.Fatalf("UpdateHIBPStatus seed: %v", err)
	}

	if err := s.UpdatePassword(ctx, created.ID, "second password 15 chars"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}

	updated, err := s.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID after update: %v", err)
	}
	if updated.PasswordHash == oldHash {
		t.Error("PasswordHash not changed")
	}
	if updated.HIBPCheckStatus != HIBPStatusPending {
		t.Errorf("HIBPCheckStatus not reset to pending: %q", updated.HIBPCheckStatus)
	}
	if updated.PasswordCompromised {
		t.Error("PasswordCompromised not reset to false")
	}
	if !updated.HIBPCheckedAt.IsZero() {
		t.Error("HIBPCheckedAt not reset to zero")
	}
	if !updated.UpdatedAt.After(created.UpdatedAt) {
		t.Error("UpdatedAt not refreshed")
	}

	match, err := argon2id.ComparePasswordAndHash("second password 15 chars", updated.PasswordHash)
	if err != nil {
		t.Fatalf("verify new password: %v", err)
	}
	if !match {
		t.Error("new password does not verify against new hash")
	}
}

func TestUserStore_UpdatePassword_Errors(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()

	if err := s.UpdatePassword(ctx, "", "correct horse battery staple"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("empty id: want ErrUserNotFound, got %v", err)
	}
	if err := s.UpdatePassword(ctx, "ghost", "correct horse battery staple"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("ghost id: want ErrUserNotFound, got %v", err)
	}

	created, _ := s.Create(ctx, "admin", "", "correct horse battery staple")
	if err := s.UpdatePassword(ctx, created.ID, "short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("short: want ErrPasswordTooShort, got %v", err)
	}
	if err := s.UpdatePassword(ctx, created.ID, strings.Repeat("a", 129)); !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("long: want ErrPasswordTooLong, got %v", err)
	}
}

func TestUserStore_UpdateHIBPStatus(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()

	created, err := s.Create(ctx, "admin", "", "correct horse battery staple")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := s.UpdateHIBPStatus(ctx, created.ID, HIBPStatusCompromised, true); err != nil {
		t.Fatalf("UpdateHIBPStatus: %v", err)
	}

	got, err := s.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.HIBPCheckStatus != HIBPStatusCompromised {
		t.Errorf("status = %q, want compromised", got.HIBPCheckStatus)
	}
	if !got.PasswordCompromised {
		t.Error("PasswordCompromised not set")
	}
	if got.HIBPCheckedAt.IsZero() {
		t.Error("HIBPCheckedAt not updated")
	}
}

func TestUserStore_RecordLogin(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()

	created, err := s.Create(ctx, "admin", "", "correct horse battery staple")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !created.LastLoginAt.IsZero() {
		t.Error("LastLoginAt unexpectedly set at create")
	}

	before := time.Now().UTC()
	if err := s.RecordLogin(ctx, created.ID); err != nil {
		t.Fatalf("RecordLogin: %v", err)
	}
	after := time.Now().UTC()

	got, err := s.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.LastLoginAt.Before(before) || got.LastLoginAt.After(after) {
		t.Errorf("LastLoginAt not in [before, after]: %v not in [%v, %v]", got.LastLoginAt, before, after)
	}

	if err := s.RecordLogin(ctx, ""); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("empty id: want ErrUserNotFound, got %v", err)
	}
}
