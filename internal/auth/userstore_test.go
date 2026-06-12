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

	u, err := s.Create(ctx, "admin", "Site Admin", "", "correct horse battery staple")
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
	u, err := s.Create(context.Background(), "admin", "", "", "correct horse battery staple")
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
			_, err := s.Create(context.Background(), tc.username, "", "", "correct horse battery staple")
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
	_, err := s.Create(ctx, "admin1", "", "", strings.Repeat("a", 14))
	if !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("14 chars: want ErrPasswordTooShort, got %v", err)
	}
	// 129 chars: too long.
	_, err = s.Create(ctx, "admin2", "", "", strings.Repeat("a", 129))
	if !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("129 chars: want ErrPasswordTooLong, got %v", err)
	}
	// 15 chars: OK boundary.
	_, err = s.Create(ctx, "admin3", "", "", strings.Repeat("a", 15))
	if err != nil {
		t.Errorf("15 chars: want nil, got %v", err)
	}
	// 128 chars: OK boundary.
	_, err = s.Create(ctx, "admin4", "", "", strings.Repeat("a", 128))
	if err != nil {
		t.Errorf("128 chars: want nil, got %v", err)
	}
}

func TestUserStore_Create_DisplayNameTooLong(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	_, err := s.Create(context.Background(), "admin", strings.Repeat("a", 65), "", "correct horse battery staple")
	if !errors.Is(err, ErrDisplayNameTooLong) {
		t.Errorf("want ErrDisplayNameTooLong, got %v", err)
	}
}

func TestUserStore_Create_UsernameTaken(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()

	if _, err := s.Create(ctx, "admin", "", "", "correct horse battery staple"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := s.Create(ctx, "admin", "", "", "another correct password long")
	if !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("want ErrUsernameTaken, got %v", err)
	}
}

func TestUserStore_Create_UsernameTrimmed(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	u, err := s.Create(context.Background(), "  admin  ", "", "", "correct horse battery staple")
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

	created, err := s.Create(ctx, "admin", "", "", "correct horse battery staple")
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

	created, err := s.Create(ctx, "admin", "", "", "correct horse battery staple")
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

	if _, err := s.Create(ctx, "admin", "", "", "correct horse battery staple"); err != nil {
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

	created, err := s.Create(ctx, "admin", "", "", "first password 15 chars")
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

	created, _ := s.Create(ctx, "admin", "", "", "correct horse battery staple")
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

	created, err := s.Create(ctx, "admin", "", "", "correct horse battery staple")
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

// TestUpdateThemePreference_ValidDark covers the happy-path for the
// "dark" value: persistence, UpdatedAt touched, GetByID re-reads it.
func TestUpdateThemePreference_ValidDark(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()

	created, err := s.Create(ctx, "admin", "", "", "correct horse battery staple")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if created.ThemePreference != "" {
		t.Errorf("fresh user ThemePreference = %q, want empty", created.ThemePreference)
	}

	before := time.Now().UTC()
	if err := s.UpdateThemePreference(ctx, created.ID, ThemeDark); err != nil {
		t.Fatalf("UpdateThemePreference: %v", err)
	}
	after := time.Now().UTC()

	got, err := s.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ThemePreference != ThemeDark {
		t.Errorf("ThemePreference = %q, want %q", got.ThemePreference, ThemeDark)
	}
	if got.UpdatedAt.Before(before) || got.UpdatedAt.After(after) {
		t.Errorf("UpdatedAt = %v, want between %v and %v", got.UpdatedAt, before, after)
	}
}

// TestUpdateThemePreference_ValidLight covers the symmetric "light"
// value and confirms a second call overwrites the first.
func TestUpdateThemePreference_ValidLight(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()

	created, err := s.Create(ctx, "admin", "", "", "correct horse battery staple")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := s.UpdateThemePreference(ctx, created.ID, ThemeDark); err != nil {
		t.Fatalf("UpdateThemePreference dark: %v", err)
	}
	if err := s.UpdateThemePreference(ctx, created.ID, ThemeLight); err != nil {
		t.Fatalf("UpdateThemePreference light: %v", err)
	}

	got, err := s.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ThemePreference != ThemeLight {
		t.Errorf("ThemePreference = %q, want %q", got.ThemePreference, ThemeLight)
	}
}

// TestUpdateThemePreference_InvalidRejected covers ErrThemeInvalid for
// every non-{dark,light} input (including "", "Dark" with caps, garbage).
// The store value MUST be unchanged after the rejected calls.
func TestUpdateThemePreference_InvalidRejected(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()

	created, err := s.Create(ctx, "admin", "", "", "correct horse battery staple")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Seed with a known good value so we can prove the rejected calls
	// don't silently overwrite it.
	if err := s.UpdateThemePreference(ctx, created.ID, ThemeDark); err != nil {
		t.Fatalf("seed theme: %v", err)
	}

	invalid := []string{"", "Dark", "LIGHT", "blue", "system", "  dark  "}
	for _, val := range invalid {
		if err := s.UpdateThemePreference(ctx, created.ID, val); !errors.Is(err, ErrThemeInvalid) {
			t.Errorf("UpdateThemePreference(%q) err = %v, want ErrThemeInvalid", val, err)
		}
	}

	got, err := s.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ThemePreference != ThemeDark {
		t.Errorf("ThemePreference clobbered: got %q, want %q (rejected calls must not mutate)", got.ThemePreference, ThemeDark)
	}
}

// TestUpdateThemePreference_EmptyIDError covers the early-exit guard
// (parallel to UpdateHIBPStatus / UpdatePassword behavior).
func TestUpdateThemePreference_EmptyIDError(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	if err := s.UpdateThemePreference(context.Background(), "", ThemeDark); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("err = %v, want ErrUserNotFound", err)
	}
}

// TestUpdateThemePreference_PersistenceRoundtrip closes and re-opens
// the bbolt DB to prove the field actually hits disk (catches a
// hypothetical bug where we forget the b.Put line).
func TestUpdateThemePreference_PersistenceRoundtrip(t *testing.T) {
	db := newTestDB(t)
	s := NewUserStore(db)
	ctx := context.Background()

	created, err := s.Create(ctx, "admin", "", "", "correct horse battery staple")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.UpdateThemePreference(ctx, created.ID, ThemeLight); err != nil {
		t.Fatalf("UpdateThemePreference: %v", err)
	}

	// Re-open the store on the same DB handle — simulates a fresh
	// process load of the same on-disk bucket.
	s2 := NewUserStore(db)
	got, err := s2.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID after reopen: %v", err)
	}
	if got.ThemePreference != ThemeLight {
		t.Errorf("after reopen, ThemePreference = %q, want %q", got.ThemePreference, ThemeLight)
	}
}

func TestUserStore_RecordLogin(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()

	created, err := s.Create(ctx, "admin", "", "", "correct horse battery staple")
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

// --- Users-page Phase 1 refactor: Email + Delete + UpdateEmail tests

func TestUserStore_Email_RoundTrip(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()
	u, err := s.Create(ctx, "alice", "Alice", "alice@example.test", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.Email != "alice@example.test" {
		t.Errorf("returned Email = %q; want %q", u.Email, "alice@example.test")
	}
	got, err := s.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Email != "alice@example.test" {
		t.Errorf("persisted Email = %q; want %q", got.Email, "alice@example.test")
	}
}

func TestUserStore_Email_EmptyStringPersists(t *testing.T) {
	// Empty email is a legitimate Phase-1 state (pre-fix
	// local users that haven't gone through a future email-
	// edit flow; OIDC users whose IdP didn't emit the claim).
	// The omitempty JSON tag means the stored row may not
	// have an "email" key at all — both Create("") and
	// GetByID must surface Email="" without surprises.
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()
	u, err := s.Create(ctx, "alice", "Alice", "", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, _ := s.GetByID(ctx, u.ID)
	if got.Email != "" {
		t.Errorf("Email = %q; want empty", got.Email)
	}
}

func TestUserStore_Delete_HappyPath(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()
	// Two local admins so the last-admin guard doesn't fire
	// when we delete one.
	a, err := s.Create(ctx, "alice", "Alice", "alice@example.test", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Create alice: %v", err)
	}
	if _, err := s.Create(ctx, "bob", "Bob", "bob@example.test", "another correct password 15"); err != nil {
		t.Fatalf("Create bob: %v", err)
	}
	if err := s.Delete(ctx, a.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.GetByID(ctx, a.ID); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("post-delete GetByID = %v; want ErrUserNotFound", err)
	}
}

func TestUserStore_Delete_LastLocalAdmin_Blocked(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()
	a, err := s.Create(ctx, "alice", "Alice", "alice@example.test", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Create alice: %v", err)
	}
	err = s.Delete(ctx, a.ID)
	if err == nil {
		t.Fatal("Delete of last local admin succeeded; want guard-error")
	}
	if !strings.Contains(err.Error(), "break-glass") {
		t.Errorf("error = %v; want message mentioning break-glass", err)
	}
	// And the user must still exist.
	if _, err := s.GetByID(ctx, a.ID); err != nil {
		t.Errorf("user evaporated despite blocked delete: %v", err)
	}
}

func TestUserStore_Delete_OIDCAdmin_DoesNotTriggerGuard(t *testing.T) {
	// OIDC-source admins don't count for the break-glass
	// channel. Deleting the only OIDC admin while a local
	// admin exists is fine; deleting the only LOCAL admin
	// while OIDC admins exist would still be blocked
	// (covered by the LastLocalAdmin_Blocked test).
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()
	if _, err := s.Create(ctx, "alice", "Alice", "alice@example.test", "correct horse battery staple"); err != nil {
		t.Fatalf("Create alice: %v", err)
	}
	oidc, err := s.CreateOIDCUser(ctx, "carol", "Carol", "carol@example.test", "oidc-sub-carol")
	if err != nil {
		t.Fatalf("CreateOIDCUser: %v", err)
	}
	// Elevate Carol to admin so the guard would fire if she
	// counted toward the break-glass quota.
	if err := s.UpdateRole(ctx, oidc.ID, UserRoleAdmin); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	if err := s.Delete(ctx, oidc.ID); err != nil {
		t.Fatalf("Delete OIDC admin: %v", err)
	}
}

func TestUserStore_Delete_NotFound(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()
	if err := s.Delete(ctx, "no-such-user"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("Delete unknown id = %v; want ErrUserNotFound", err)
	}
}

func TestUserStore_UpdateEmail_RoundTrip(t *testing.T) {
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()
	u, err := s.Create(ctx, "alice", "Alice", "", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.UpdateEmail(ctx, u.ID, "alice@new.test"); err != nil {
		t.Fatalf("UpdateEmail: %v", err)
	}
	got, _ := s.GetByID(ctx, u.ID)
	if got.Email != "alice@new.test" {
		t.Errorf("Email = %q; want %q", got.Email, "alice@new.test")
	}
}

func TestUserStore_UpdateEmail_NoChange_NoOp(t *testing.T) {
	// Calling UpdateEmail with the already-stored value
	// must not touch UpdatedAt — the OIDC callback hits
	// this path on every login.
	s := NewUserStore(newTestDB(t))
	ctx := context.Background()
	u, err := s.Create(ctx, "alice", "Alice", "alice@example.test", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	originalUpdatedAt := u.UpdatedAt
	time.Sleep(10 * time.Millisecond) // make sure now() differs
	if err := s.UpdateEmail(ctx, u.ID, "alice@example.test"); err != nil {
		t.Fatalf("UpdateEmail: %v", err)
	}
	got, _ := s.GetByID(ctx, u.ID)
	if !got.UpdatedAt.Equal(originalUpdatedAt) {
		t.Errorf("UpdatedAt drifted on no-op UpdateEmail: %v vs %v", got.UpdatedAt, originalUpdatedAt)
	}
}
