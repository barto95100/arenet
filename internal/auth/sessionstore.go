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

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// sessionsBucketName is the BoltDB bucket where sessions live.
const sessionsBucketName = "sessions"

// SessionStore persists authenticated sessions into the BoltDB
// "sessions" bucket. The session ID is the cookie value sent to the
// browser; it is never stored. Rows are keyed by its handle,
// SessionHandle(id) (v2.30), which is also the ID the sessions API
// lists and revokes — so neither the database nor the API nor the
// audit log ever holds a usable cookie value.
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
		stored := sess
		stored.ID = SessionHandle(sess.ID)
		v, err := json.Marshal(stored)
		if err != nil {
			return fmt.Errorf("auth: marshal session: %w", err)
		}
		return b.Put([]byte(stored.ID), v)
	})
	if err != nil {
		return Session{}, err
	}
	return sess, nil
}

// SessionHandle is the non-secret identifier of the session whose
// cookie value is id: hex SHA-256. The ID has 256 bits of entropy, so
// a plain hash is enough (same model as API tokens).
func SessionHandle(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// isSessionHandle reports whether a bucket key is a handle (64 lowercase
// hex chars); anything else is a pre-v2.30 row keyed by the raw ID.
func isSessionHandle(k []byte) bool {
	if len(k) != sha256.Size*2 {
		return false
	}
	for _, c := range k {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Get returns the session by ID. If ExpiresAt < now, the session is
// deleted (lazy purge) and ErrSessionExpired is returned. The idle
// check (LastActivity + 15min) is NOT performed here; the hard-auth
// middleware (Chunk 2) does it separately so that /auth/me and
// /auth/unlock can retrieve an idle session.
func (s *SessionStore) Get(ctx context.Context, id string) (Session, error) {
	if id == "" {
		return Session{}, ErrSessionNotFound
	}
	sess, err := s.getByHandle(ctx, SessionHandle(id))
	if err != nil {
		return Session{}, err
	}
	sess.ID = id
	return sess, nil
}

// GetByHandle returns the session whose handle is given (the ID the
// sessions API exposes). The returned Session.ID is the handle.
func (s *SessionStore) GetByHandle(ctx context.Context, handle string) (Session, error) {
	if handle == "" {
		return Session{}, ErrSessionNotFound
	}
	return s.getByHandle(ctx, handle)
}

func (s *SessionStore) getByHandle(ctx context.Context, id string) (Session, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
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
	key := []byte(SessionHandle(id))

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(sessionsBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", sessionsBucketName)
		}
		v := b.Get(key)
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
		return b.Put(key, out)
	})
}

// Delete removes the session. Idempotent (no error if absent).
func (s *SessionStore) Delete(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	return s.DeleteByHandle(ctx, SessionHandle(id))
}

// DeleteByHandle removes the session with the given handle.
// Idempotent.
func (s *SessionStore) DeleteByHandle(ctx context.Context, id string) error {
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
		keep := SessionHandle(keepSessionID)
		var keys [][]byte
		err := b.ForEach(func(k, v []byte) error {
			var sess Session
			if err := json.Unmarshal(v, &sess); err != nil {
				return nil
			}
			if sess.UserID == userID && string(k) != keep {
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
// Each Session.ID is the handle, not the cookie value.
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
				sess.ID = string(k)
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

// UserActivity is one entry of ListAllActive's result map.
// LastActivity is the timestamp of the most-recent live
// session for the user (the freshest Touch); ActiveCount is
// how many non-expired sessions exist (multi-device aware).
type UserActivity struct {
	LastActivity time.Time
	ActiveCount  int
}

// ListAllActive returns one entry per user with at least one
// non-expired session, keyed by user ID. The map's
// LastActivity is the most-recent activity across the user's
// sessions; ActiveCount is the number of non-expired sessions
// (multi-device sign-in surfaces). Expired sessions are
// silently skipped — the lazy cleanup goroutine will purge
// them on its own schedule.
//
// Used by the /utilisateurs page (users-page Phase 1
// refactor) to render the per-row "online / active / offline"
// indicator: threshold buckets are computed client-side from
// LastActivity (≤5min = online, ≤1h = active, else offline).
//
// Single-pass bucket scan; runs in O(N) where N is the total
// session count. On a homelab with at most a few admin users
// this is trivially cheap; defensive 5s timeout matches the
// rest of the SessionStore API.
func (s *SessionStore) ListAllActive(ctx context.Context) (map[string]UserActivity, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	now := time.Now().UTC()
	out := map[string]UserActivity{}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(sessionsBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", sessionsBucketName)
		}
		return b.ForEach(func(_, v []byte) error {
			var sess Session
			if err := json.Unmarshal(v, &sess); err != nil {
				return nil // skip malformed
			}
			if !sess.ExpiresAt.After(now) {
				return nil // expired — lazy cleanup will purge
			}
			entry := out[sess.UserID]
			entry.ActiveCount++
			if sess.LastActivity.After(entry.LastActivity) {
				entry.LastActivity = sess.LastActivity
			}
			out[sess.UserID] = entry
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

// PurgeLegacySessions deletes the rows written before v2.30, keyed by
// the raw session ID: their owners log in once more. Returns the
// number of rows deleted. Idempotent.
func (s *SessionStore) PurgeLegacySessions(ctx context.Context) (int, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	var deleted int
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(sessionsBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", sessionsBucketName)
		}
		var keys [][]byte
		if err := b.ForEach(func(k, _ []byte) error {
			if !isSessionHandle(k) {
				keys = append(keys, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range keys {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		deleted = len(keys)
		return nil
	})
	return deleted, err
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

// PutForTest writes sess into the store verbatim, bypassing all
// validation. Used exclusively by tests that need to construct
// pathological session states (e.g., backdated LastActivity to
// simulate idle-lock for HardAuthMiddleware tests). The "ForTest"
// suffix is the package convention; production callers must use
// Create / Touch / Delete.
func (s *SessionStore) PutForTest(ctx context.Context, sess Session) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if sess.ID == "" {
		return fmt.Errorf("auth: session id must not be empty")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(sessionsBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", sessionsBucketName)
		}
		sess.ID = SessionHandle(sess.ID)
		buf, err := json.Marshal(sess)
		if err != nil {
			return fmt.Errorf("auth: marshal session: %w", err)
		}
		return b.Put([]byte(sess.ID), buf)
	})
}
