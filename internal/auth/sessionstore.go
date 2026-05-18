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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// sessionsBucketName is the BoltDB bucket where sessions live.
const sessionsBucketName = "sessions"

// SessionStore persists authenticated sessions into the BoltDB
// "sessions" bucket. The session ID is the cookie value sent to the
// browser.
//
// SessionStore is safe for concurrent use; bbolt serializes writes.
type SessionStore struct {
	db *bolt.DB
}

// NewSessionStore returns a session store backed by the given bbolt
// handle.
func NewSessionStore(db *bolt.DB) *SessionStore {
	if db == nil {
		panic("auth.NewSessionStore: db is nil")
	}
	return &SessionStore{db: db}
}

// Create generates a new session ID (32 bytes from crypto/rand, base64
// url-safe encoded without padding) and persists the session. ExpiresAt
// is set to now+24h or now+30d depending on rememberMe.
//
// IssuedAt and LastActivity are both initialized to now; LastActivity
// must equal IssuedAt at creation so the session does not appear idle
// at birth.
func (s *SessionStore) Create(ctx context.Context, userID string, rememberMe bool, ip, userAgent string) (Session, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if userID == "" {
		return Session{}, fmt.Errorf("auth: SessionStore.Create: userID is empty")
	}

	id, err := generateSessionID()
	if err != nil {
		return Session{}, fmt.Errorf("auth: generate session id: %w", err)
	}

	now := time.Now().UTC()
	ttl := SessionTTLDefault
	if rememberMe {
		ttl = SessionTTLRememberMe
	}

	sess := Session{
		ID:           id,
		UserID:       userID,
		IssuedAt:     now,
		ExpiresAt:    now.Add(ttl),
		LastActivity: now,
		RememberMe:   rememberMe,
		IP:           ip,
		UserAgent:    userAgent,
	}

	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(sessionsBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", sessionsBucketName)
		}
		v, err := json.Marshal(sess)
		if err != nil {
			return fmt.Errorf("auth: marshal session: %w", err)
		}
		return b.Put([]byte(sess.ID), v)
	})
	if err != nil {
		return Session{}, err
	}
	return sess, nil
}

// Get returns the session by ID. If ExpiresAt < now, the session is
// deleted (lazy purge) and ErrSessionExpired is returned. The idle
// check (LastActivity + 15min) is NOT performed here; the hard-auth
// middleware (Chunk 2) does it separately so that /auth/me and
// /auth/unlock can retrieve an idle session.
func (s *SessionStore) Get(ctx context.Context, id string) (Session, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return Session{}, ErrSessionNotFound
	}

	var sess Session
	var expired bool
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(sessionsBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", sessionsBucketName)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrSessionNotFound
		}
		if err := json.Unmarshal(v, &sess); err != nil {
			return fmt.Errorf("auth: unmarshal session: %w", err)
		}
		if time.Now().UTC().After(sess.ExpiresAt) {
			expired = true
		}
		return nil
	})
	if err != nil {
		return Session{}, err
	}
	if expired {
		// Lazy purge in a separate Update transaction; best-effort.
		_ = s.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(sessionsBucketName))
			if b == nil {
				return nil
			}
			return b.Delete([]byte(id))
		})
		return Session{}, ErrSessionExpired
	}
	return sess, nil
}

// Touch updates LastActivity to now and extends ExpiresAt by the
// sliding TTL window (24h or 30d depending on RememberMe). Best-effort:
// callers log and continue on error.
func (s *SessionStore) Touch(ctx context.Context, id string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return ErrSessionNotFound
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(sessionsBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", sessionsBucketName)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrSessionNotFound
		}
		var sess Session
		if err := json.Unmarshal(v, &sess); err != nil {
			return fmt.Errorf("auth: unmarshal session: %w", err)
		}
		now := time.Now().UTC()
		ttl := SessionTTLDefault
		if sess.RememberMe {
			ttl = SessionTTLRememberMe
		}
		sess.LastActivity = now
		sess.ExpiresAt = now.Add(ttl)
		out, err := json.Marshal(sess)
		if err != nil {
			return fmt.Errorf("auth: marshal session: %w", err)
		}
		return b.Put([]byte(id), out)
	})
}

// Delete removes the session. Idempotent (no error if absent).
func (s *SessionStore) Delete(ctx context.Context, id string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(sessionsBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", sessionsBucketName)
		}
		return b.Delete([]byte(id))
	})
}

// DeleteAllForUser deletes every session owned by userID. Returns the
// number of sessions deleted. Used by "logout everywhere" actions and
// by the password-change flow.
func (s *SessionStore) DeleteAllForUser(ctx context.Context, userID string) (int, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if userID == "" {
		return 0, nil
	}

	var deleted int
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(sessionsBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", sessionsBucketName)
		}
		// Collect matching keys first; deleting during iteration is
		// not safe in bbolt cursors.
		var keys [][]byte
		err := b.ForEach(func(k, v []byte) error {
			var sess Session
			if err := json.Unmarshal(v, &sess); err != nil {
				// Skip malformed entries rather than failing the whole batch.
				return nil
			}
			if sess.UserID == userID {
				// Copy the key — bbolt reuses the underlying slice.
				kc := make([]byte, len(k))
				copy(kc, k)
				keys = append(keys, kc)
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range keys {
			if err := b.Delete(k); err != nil {
				return err
			}
			deleted++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// DeleteAllForUserExcept deletes every session owned by userID
// EXCEPT the one whose ID equals keepSessionID. Used by the
// password-change flow (spec §4.9bis): revoking all sessions of a
// user when they change their password, while preserving the
// session that just performed the change so the user does not get
// logged out of the device they just used.
//
// Returns the number of sessions deleted.
func (s *SessionStore) DeleteAllForUserExcept(ctx context.Context, userID, keepSessionID string) (int, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if userID == "" {
		return 0, nil
	}

	var deleted int
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(sessionsBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", sessionsBucketName)
		}
		var keys [][]byte
		err := b.ForEach(func(k, v []byte) error {
			var sess Session
			if err := json.Unmarshal(v, &sess); err != nil {
				return nil
			}
			if sess.UserID == userID && sess.ID != keepSessionID {
				kc := make([]byte, len(k))
				copy(kc, k)
				keys = append(keys, kc)
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range keys {
			if err := b.Delete(k); err != nil {
				return err
			}
			deleted++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// ListForUser returns all sessions for userID, including expired ones
// not yet lazy-purged. The UI filters expired entries client-side.
func (s *SessionStore) ListForUser(ctx context.Context, userID string) ([]Session, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if userID == "" {
		return nil, nil
	}

	var out []Session
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(sessionsBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", sessionsBucketName)
		}
		return b.ForEach(func(k, v []byte) error {
			var sess Session
			if err := json.Unmarshal(v, &sess); err != nil {
				return nil // skip malformed
			}
			if sess.UserID == userID {
				out = append(out, sess)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CleanupExpired deletes all sessions with ExpiresAt < now. Called by
// the background cleanup goroutine every 6 hours (wired in Chunk 4).
// Returns the number of sessions deleted.
func (s *SessionStore) CleanupExpired(ctx context.Context) (int, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	var deleted int
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(sessionsBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", sessionsBucketName)
		}
		now := time.Now().UTC()
		var keys [][]byte
		err := b.ForEach(func(k, v []byte) error {
			var sess Session
			if err := json.Unmarshal(v, &sess); err != nil {
				return nil
			}
			if now.After(sess.ExpiresAt) {
				kc := make([]byte, len(k))
				copy(kc, k)
				keys = append(keys, kc)
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range keys {
			if err := b.Delete(k); err != nil {
				return err
			}
			deleted++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// generateSessionID returns 32 bytes from crypto/rand encoded with
// base64 url-safe encoding without padding (43 characters).
func generateSessionID() (string, error) {
	buf := make([]byte, SessionIDByteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
