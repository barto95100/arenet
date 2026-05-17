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
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestNewSessionStore_NilPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic, got none")
		}
	}()
	_ = NewSessionStore(nil)
}

func TestSessionStore_Create_HappyPath(t *testing.T) {
	db := newTestDB(t)
	s := NewSessionStore(db)
	ctx := context.Background()

	before := time.Now().UTC()
	sess, err := s.Create(ctx, "user-123", false, "203.0.113.5", "Mozilla/5.0")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	after := time.Now().UTC()

	if sess.ID == "" {
		t.Error("ID empty")
	}
	// 32 bytes base64url no padding = 43 chars.
	if len(sess.ID) != 43 {
		t.Errorf("session ID length = %d, want 43", len(sess.ID))
	}
	// Decoded ID must be exactly 32 bytes.
	decoded, err := base64.RawURLEncoding.DecodeString(sess.ID)
	if err != nil {
		t.Errorf("session ID not valid base64url: %v", err)
	}
	if len(decoded) != SessionIDByteLen {
		t.Errorf("decoded session ID = %d bytes, want %d", len(decoded), SessionIDByteLen)
	}

	if sess.UserID != "user-123" {
		t.Errorf("UserID = %q", sess.UserID)
	}
	if sess.IP != "203.0.113.5" {
		t.Errorf("IP = %q", sess.IP)
	}
	if sess.UserAgent != "Mozilla/5.0" {
		t.Errorf("UserAgent = %q", sess.UserAgent)
	}
	if sess.RememberMe {
		t.Error("RememberMe must be false")
	}
	if sess.IssuedAt.Before(before) || sess.IssuedAt.After(after) {
		t.Errorf("IssuedAt out of range: %v", sess.IssuedAt)
	}
	// LastActivity must equal IssuedAt at birth (Q4).
	if !sess.LastActivity.Equal(sess.IssuedAt) {
		t.Errorf("LastActivity (%v) != IssuedAt (%v) at creation", sess.LastActivity, sess.IssuedAt)
	}
	// Expires must be ~24h from IssuedAt.
	wantExpiry := sess.IssuedAt.Add(SessionTTLDefault)
	if sess.ExpiresAt.Sub(wantExpiry).Abs() > time.Second {
		t.Errorf("ExpiresAt = %v, want close to %v", sess.ExpiresAt, wantExpiry)
	}
}

func TestSessionStore_Create_RememberMe(t *testing.T) {
	s := NewSessionStore(newTestDB(t))
	sess, err := s.Create(context.Background(), "user-1", true, "1.1.1.1", "ua")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !sess.RememberMe {
		t.Error("RememberMe not set")
	}
	wantExpiry := sess.IssuedAt.Add(SessionTTLRememberMe)
	if sess.ExpiresAt.Sub(wantExpiry).Abs() > time.Second {
		t.Errorf("ExpiresAt = %v, want ~ %v", sess.ExpiresAt, wantExpiry)
	}
}

func TestSessionStore_Create_EmptyUserID(t *testing.T) {
	s := NewSessionStore(newTestDB(t))
	_, err := s.Create(context.Background(), "", false, "", "")
	if err == nil {
		t.Fatal("expected error for empty userID, got nil")
	}
}

func TestSessionStore_Create_UniqueIDs(t *testing.T) {
	s := NewSessionStore(newTestDB(t))
	ctx := context.Background()
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		sess, err := s.Create(ctx, "user-1", false, "", "")
		if err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
		if seen[sess.ID] {
			t.Fatalf("duplicate session ID at iteration %d: %s", i, sess.ID)
		}
		seen[sess.ID] = true
	}
}

func TestSessionStore_Get(t *testing.T) {
	s := NewSessionStore(newTestDB(t))
	ctx := context.Background()

	created, err := s.Create(ctx, "user-1", false, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := s.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.UserID != "user-1" || got.IP != "1.2.3.4" {
		t.Errorf("session round-trip mismatch: %+v", got)
	}

	if _, err := s.Get(ctx, ""); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("empty id: want ErrSessionNotFound, got %v", err)
	}
	if _, err := s.Get(ctx, "ghost"); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("ghost: want ErrSessionNotFound, got %v", err)
	}
}

func TestSessionStore_Get_LazyPurgeOnExpiry(t *testing.T) {
	db := newTestDB(t)
	s := NewSessionStore(db)
	ctx := context.Background()

	created, err := s.Create(ctx, "user-1", false, "", "")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Backdate ExpiresAt to the past via a direct bbolt write.
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(sessionsBucketName))
		v := b.Get([]byte(created.ID))
		var sess Session
		if err := json.Unmarshal(v, &sess); err != nil {
			return err
		}
		sess.ExpiresAt = time.Now().UTC().Add(-time.Hour)
		out, err := json.Marshal(sess)
		if err != nil {
			return err
		}
		return b.Put([]byte(created.ID), out)
	})
	if err != nil {
		t.Fatalf("backdate: %v", err)
	}

	if _, err := s.Get(ctx, created.ID); !errors.Is(err, ErrSessionExpired) {
		t.Errorf("expired: want ErrSessionExpired, got %v", err)
	}

	// Verify lazy purge actually deleted the row.
	var stillThere bool
	_ = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(sessionsBucketName))
		stillThere = b.Get([]byte(created.ID)) != nil
		return nil
	})
	if stillThere {
		t.Error("expired session not purged after Get")
	}
}

func TestSessionStore_Touch(t *testing.T) {
	s := NewSessionStore(newTestDB(t))
	ctx := context.Background()

	created, err := s.Create(ctx, "user-1", false, "", "")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Ensure detectable time advance.
	time.Sleep(5 * time.Millisecond)

	if err := s.Touch(ctx, created.ID); err != nil {
		t.Fatalf("Touch: %v", err)
	}

	got, err := s.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get after Touch: %v", err)
	}
	if !got.LastActivity.After(created.LastActivity) {
		t.Errorf("LastActivity not updated: was %v, now %v", created.LastActivity, got.LastActivity)
	}
	if !got.ExpiresAt.After(created.ExpiresAt) {
		t.Errorf("ExpiresAt not extended: was %v, now %v", created.ExpiresAt, got.ExpiresAt)
	}

	if err := s.Touch(ctx, ""); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("empty id: want ErrSessionNotFound, got %v", err)
	}
	if err := s.Touch(ctx, "ghost"); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("ghost: want ErrSessionNotFound, got %v", err)
	}
}

func TestSessionStore_Delete(t *testing.T) {
	s := NewSessionStore(newTestDB(t))
	ctx := context.Background()

	created, err := s.Create(ctx, "user-1", false, "", "")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, created.ID); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("after delete: want ErrSessionNotFound, got %v", err)
	}

	// Idempotent: deleting twice is OK.
	if err := s.Delete(ctx, created.ID); err != nil {
		t.Errorf("second delete: want nil, got %v", err)
	}
	// Empty id is a no-op.
	if err := s.Delete(ctx, ""); err != nil {
		t.Errorf("empty id: want nil, got %v", err)
	}
}

func TestSessionStore_DeleteAllForUser(t *testing.T) {
	s := NewSessionStore(newTestDB(t))
	ctx := context.Background()

	// Seed 3 sessions for alice, 2 for bob.
	for i := 0; i < 3; i++ {
		if _, err := s.Create(ctx, "alice", false, "", ""); err != nil {
			t.Fatalf("seed alice %d: %v", i, err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := s.Create(ctx, "bob", false, "", ""); err != nil {
			t.Fatalf("seed bob %d: %v", i, err)
		}
	}

	deleted, err := s.DeleteAllForUser(ctx, "alice")
	if err != nil {
		t.Fatalf("DeleteAllForUser: %v", err)
	}
	if deleted != 3 {
		t.Errorf("deleted = %d, want 3", deleted)
	}

	// Alice's sessions are gone, bob's remain.
	alice, err := s.ListForUser(ctx, "alice")
	if err != nil {
		t.Fatalf("ListForUser alice: %v", err)
	}
	if len(alice) != 0 {
		t.Errorf("alice still has %d sessions", len(alice))
	}
	bob, err := s.ListForUser(ctx, "bob")
	if err != nil {
		t.Fatalf("ListForUser bob: %v", err)
	}
	if len(bob) != 2 {
		t.Errorf("bob lost sessions: got %d, want 2", len(bob))
	}

	// Empty userID is a no-op.
	deleted, err = s.DeleteAllForUser(ctx, "")
	if err != nil {
		t.Errorf("empty userID: want nil, got %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0", deleted)
	}
}

func TestSessionStore_ListForUser(t *testing.T) {
	s := NewSessionStore(newTestDB(t))
	ctx := context.Background()

	out, err := s.ListForUser(ctx, "alice")
	if err != nil {
		t.Fatalf("empty bucket: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want empty, got %d", len(out))
	}

	for i := 0; i < 4; i++ {
		if _, err := s.Create(ctx, "alice", false, "", ""); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	out, err = s.ListForUser(ctx, "alice")
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(out) != 4 {
		t.Errorf("want 4 sessions, got %d", len(out))
	}
	for _, sess := range out {
		if sess.UserID != "alice" {
			t.Errorf("foreign session leaked: %+v", sess)
		}
	}

	if out, _ := s.ListForUser(ctx, ""); out != nil {
		t.Errorf("empty userID: want nil slice, got %v", out)
	}
}

func TestSessionStore_CleanupExpired(t *testing.T) {
	db := newTestDB(t)
	s := NewSessionStore(db)
	ctx := context.Background()

	// Two live, two expired.
	live1, _ := s.Create(ctx, "u1", false, "", "")
	live2, _ := s.Create(ctx, "u2", false, "", "")
	expired1, _ := s.Create(ctx, "u3", false, "", "")
	expired2, _ := s.Create(ctx, "u4", false, "", "")

	for _, id := range []string{expired1.ID, expired2.ID} {
		err := db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(sessionsBucketName))
			v := b.Get([]byte(id))
			var sess Session
			if err := json.Unmarshal(v, &sess); err != nil {
				return err
			}
			sess.ExpiresAt = time.Now().UTC().Add(-time.Hour)
			out, _ := json.Marshal(sess)
			return b.Put([]byte(id), out)
		})
		if err != nil {
			t.Fatalf("backdate %s: %v", id, err)
		}
	}

	n, err := s.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("CleanupExpired: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2", n)
	}

	// Live sessions remain.
	if _, err := s.Get(ctx, live1.ID); err != nil {
		t.Errorf("live1 gone: %v", err)
	}
	if _, err := s.Get(ctx, live2.ID); err != nil {
		t.Errorf("live2 gone: %v", err)
	}
}

// TestGenerateSessionID_Entropy: 100 generations must all be unique
// and decode to 32 bytes.
func TestGenerateSessionID_Entropy(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		id, err := generateSessionID()
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if seen[id] {
			t.Fatalf("duplicate session ID at iter %d", i)
		}
		seen[id] = true
		decoded, err := base64.RawURLEncoding.DecodeString(id)
		if err != nil {
			t.Errorf("invalid base64url: %v", err)
		}
		if len(decoded) != SessionIDByteLen {
			t.Errorf("decoded len = %d, want %d", len(decoded), SessionIDByteLen)
		}
	}
}
