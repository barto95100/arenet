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
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// usersBucketName is the BoltDB bucket where users live.
const usersBucketName = "users"

// usernameRegex enforces decision D5: lowercase letters, digits,
// underscore, and hyphen only.
var usernameRegex = regexp.MustCompile(`^[a-z0-9_-]+$`)

// argon2idParams is the configuration used by UserStore.Create and
// UpdatePassword. Values come from spec §3.2 / decision Q4.
var argon2idParams = &argon2id.Params{
	Memory:      Argon2idMemory,
	Iterations:  Argon2idIterations,
	Parallelism: Argon2idParallelism,
	SaltLength:  Argon2idSaltLength,
	KeyLength:   Argon2idKeyLength,
}

// UserStore persists admin users into the BoltDB "users" bucket.
//
// UserStore is safe for concurrent use: bbolt serializes writes
// through a single-writer transaction model. Reads use MVCC snapshots.
type UserStore struct {
	db *bolt.DB
}

// NewUserStore returns a user store backed by the given bbolt handle.
// The handle is shared with the rest of the application; the caller
// retains ownership.
func NewUserStore(db *bolt.DB) *UserStore {
	if db == nil {
		panic("auth.NewUserStore: db is nil")
	}
	return &UserStore{db: db}
}

// Create persists a new user. The username is normalized (trimmed)
// and validated against the D5 regex. The password is validated for
// length (D6) and hashed with argon2id (Q4). Returns ErrUsernameTaken
// if the username already exists.
//
// Phase 1 does not check the password against the top-10k list or
// HIBP here; those checks happen in Chunk 2's password validation
// layer that wraps this method.
//
// The hash is computed BEFORE the bbolt transaction starts, so the
// ~100 ms argon2id cost does not hold the single-writer lock. A
// theoretical race where two concurrent Create calls both pass the
// pre-transaction validation is resolved inside the transaction: the
// second caller observes the first's insertion and gets ErrUsernameTaken.
func (s *UserStore) Create(ctx context.Context, username, displayName, password string) (User, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	username = strings.TrimSpace(username)
	if !usernameRegex.MatchString(username) || len(username) < UsernameMinLen || len(username) > UsernameMaxLen {
		return User{}, ErrUsernameInvalid
	}
	if len(displayName) > DisplayNameMaxLen {
		return User{}, ErrDisplayNameTooLong
	}
	if len(password) < PasswordMinLen {
		return User{}, ErrPasswordTooShort
	}
	if len(password) > PasswordMaxLen {
		return User{}, ErrPasswordTooLong
	}

	hash, err := argon2id.CreateHash(password, argon2idParams)
	if err != nil {
		return User{}, fmt.Errorf("auth: hash password: %w", err)
	}

	now := time.Now().UTC()
	user := User{
		ID:              uuid.NewString(),
		Username:        username,
		DisplayName:     displayName,
		PasswordHash:    hash,
		HIBPCheckStatus: HIBPStatusPending,
		HIBPCheckedAt:   now,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		// Check uniqueness in-transaction so concurrent Create calls
		// cannot both succeed with the same username. Corrupted rows
		// are logged and skipped rather than blocking new creations.
		var taken bool
		_ = b.ForEach(func(k, v []byte) error {
			var existing User
			if err := json.Unmarshal(v, &existing); err != nil {
				slog.Default().Warn("auth: corrupted user row in bucket, skipping",
					slog.String("key", string(k)),
					slog.String("err", err.Error()),
				)
				return nil
			}
			if existing.Username == username {
				taken = true
			}
			return nil
		})
		if taken {
			return ErrUsernameTaken
		}
		value, err := json.Marshal(user)
		if err != nil {
			return fmt.Errorf("auth: marshal user: %w", err)
		}
		return b.Put([]byte(user.ID), value)
	})
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// GetByID returns the user with the given ID, or ErrUserNotFound.
func (s *UserStore) GetByID(ctx context.Context, id string) (User, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return User{}, ErrUserNotFound
	}

	var user User
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrUserNotFound
		}
		return json.Unmarshal(v, &user)
	})
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// GetByUsername returns the user with the given username, or
// ErrUserNotFound. O(n) scan; acceptable for Phase 1 single-admin
// per spec §3.6.
func (s *UserStore) GetByUsername(ctx context.Context, username string) (User, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return User{}, ErrUserNotFound
	}

	var user User
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		return b.ForEach(func(k, v []byte) error {
			if found {
				return nil
			}
			var u User
			if err := json.Unmarshal(v, &u); err != nil {
				slog.Default().Warn("auth: corrupted user row in bucket, skipping",
					slog.String("key", string(k)),
					slog.String("err", err.Error()),
				)
				return nil
			}
			if u.Username == username {
				user = u
				found = true
			}
			return nil
		})
	})
	if err != nil {
		return User{}, err
	}
	if !found {
		return User{}, ErrUserNotFound
	}
	return user, nil
}

// Count returns the number of users currently in the bucket. Used by
// the bootstrap flow (count == 0 → setup mode).
func (s *UserStore) Count(ctx context.Context) (int, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	var n int
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		n = b.Stats().KeyN
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// UpdatePassword re-hashes and stores a new password, updates
// UpdatedAt, and resets HIBPCheckStatus to "pending" so the new
// password gets re-verified at next login.
//
// Validates length only at this layer; top-10k and HIBP checks
// belong to Chunk 2.
func (s *UserStore) UpdatePassword(ctx context.Context, id, newPassword string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return ErrUserNotFound
	}
	if len(newPassword) < PasswordMinLen {
		return ErrPasswordTooShort
	}
	if len(newPassword) > PasswordMaxLen {
		return ErrPasswordTooLong
	}

	hash, err := argon2id.CreateHash(newPassword, argon2idParams)
	if err != nil {
		return fmt.Errorf("auth: hash password: %w", err)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrUserNotFound
		}
		var u User
		if err := json.Unmarshal(v, &u); err != nil {
			return fmt.Errorf("auth: unmarshal user: %w", err)
		}
		u.PasswordHash = hash
		u.HIBPCheckStatus = HIBPStatusPending
		u.HIBPCheckedAt = time.Time{} // re-verified at next login
		u.PasswordCompromised = false
		u.UpdatedAt = time.Now().UTC()
		out, err := json.Marshal(u)
		if err != nil {
			return fmt.Errorf("auth: marshal user: %w", err)
		}
		return b.Put([]byte(id), out)
	})
}

// UpdateHIBPStatus updates the HIBP fields after a deferred re-check
// at login. Best-effort: callers should log and continue rather than
// propagating the error to the user-facing response.
func (s *UserStore) UpdateHIBPStatus(ctx context.Context, id string, status string, compromised bool) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return ErrUserNotFound
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrUserNotFound
		}
		var u User
		if err := json.Unmarshal(v, &u); err != nil {
			return fmt.Errorf("auth: unmarshal user: %w", err)
		}
		u.HIBPCheckStatus = status
		u.HIBPCheckedAt = time.Now().UTC()
		u.PasswordCompromised = compromised
		u.UpdatedAt = u.HIBPCheckedAt
		out, err := json.Marshal(u)
		if err != nil {
			return fmt.Errorf("auth: marshal user: %w", err)
		}
		return b.Put([]byte(id), out)
	})
}

// UpdateThemePreference persists the user's UI theme preference. The
// value MUST be one of `ThemeDark` or `ThemeLight` exactly — any other
// input (including the empty string, which is a valid *storage* value
// for legacy rows but a forbidden *input* value) returns ErrThemeInvalid.
//
// Pattern: read, mutate, marshal, write — identical to UpdateHIBPStatus.
// Touches UpdatedAt because the user-visible profile changed.
//
// Step F spec §3.2.
func (s *UserStore) UpdateThemePreference(ctx context.Context, id, theme string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return ErrUserNotFound
	}
	if theme != ThemeDark && theme != ThemeLight {
		return ErrThemeInvalid
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrUserNotFound
		}
		var u User
		if err := json.Unmarshal(v, &u); err != nil {
			return fmt.Errorf("auth: unmarshal user: %w", err)
		}
		u.ThemePreference = theme
		u.UpdatedAt = time.Now().UTC()
		out, err := json.Marshal(u)
		if err != nil {
			return fmt.Errorf("auth: marshal user: %w", err)
		}
		return b.Put([]byte(id), out)
	})
}

// RecordLogin updates LastLoginAt only. UpdatedAt is intentionally NOT
// touched: LastLoginAt is observability metadata, not a profile mutation.
// Frequent logins should not signal "profile changed".
//
// Best-effort: callers should log and continue rather than propagating
// the error to the user-facing response.
func (s *UserStore) RecordLogin(ctx context.Context, id string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return ErrUserNotFound
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrUserNotFound
		}
		var u User
		if err := json.Unmarshal(v, &u); err != nil {
			return fmt.Errorf("auth: unmarshal user: %w", err)
		}
		u.LastLoginAt = time.Now().UTC()
		out, err := json.Marshal(u)
		if err != nil {
			return fmt.Errorf("auth: marshal user: %w", err)
		}
		return b.Put([]byte(id), out)
	})
}
