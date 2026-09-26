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
	"bytes"
	"context"
	"errors"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// TestSession_RawIDNeverStored: the cookie value appears neither as a
// key nor inside a value of the sessions bucket.
func TestSession_RawIDNeverStored(t *testing.T) {
	db := newTestDB(t)
	s := NewSessionStore(db)
	ctx := context.Background()
	sess, err := s.Create(ctx, "u1", false, "203.0.113.5", "ua")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(sessionsBucketName)).ForEach(func(k, v []byte) error {
			if bytes.Contains(k, []byte(sess.ID)) || bytes.Contains(v, []byte(sess.ID)) {
				t.Errorf("raw session ID stored: key=%s value=%s", k, v)
			}
			if string(k) != SessionHandle(sess.ID) {
				t.Errorf("key %s is not the handle", k)
			}
			return nil
		})
	})
	got, err := s.Get(ctx, sess.ID)
	if err != nil || got.ID != sess.ID || got.UserID != "u1" {
		t.Fatalf("Get by cookie value: %+v %v", got, err)
	}
	if err := s.Touch(ctx, sess.ID); err != nil {
		t.Fatalf("Touch: %v", err)
	}
}

func TestSession_ListAndRevokeByHandle(t *testing.T) {
	db := newTestDB(t)
	s := NewSessionStore(db)
	ctx := context.Background()
	current, _ := s.Create(ctx, "u1", false, "", "")
	other, _ := s.Create(ctx, "u1", true, "", "")

	list, err := s.ListForUser(ctx, "u1")
	if err != nil || len(list) != 2 {
		t.Fatalf("ListForUser: %d %v", len(list), err)
	}
	for _, l := range list {
		if l.ID == current.ID || l.ID == other.ID {
			t.Fatalf("ListForUser leaked a cookie value: %s", l.ID)
		}
	}
	h := SessionHandle(other.ID)
	if got, err := s.GetByHandle(ctx, h); err != nil || got.ID != h {
		t.Fatalf("GetByHandle: %+v %v", got, err)
	}
	if err := s.DeleteByHandle(ctx, h); err != nil {
		t.Fatalf("DeleteByHandle: %v", err)
	}
	if _, err := s.Get(ctx, other.ID); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("revoked session still valid: %v", err)
	}
	if _, err := s.Get(ctx, current.ID); err != nil {
		t.Errorf("current session lost: %v", err)
	}
}

func TestSession_DeleteAllForUserExceptKeepsCurrent(t *testing.T) {
	db := newTestDB(t)
	s := NewSessionStore(db)
	ctx := context.Background()
	keep, _ := s.Create(ctx, "u1", false, "", "")
	_, _ = s.Create(ctx, "u1", false, "", "")
	_, _ = s.Create(ctx, "u2", false, "", "")
	n, err := s.DeleteAllForUserExcept(ctx, "u1", keep.ID)
	if err != nil || n != 1 {
		t.Fatalf("DeleteAllForUserExcept = %d %v", n, err)
	}
	if _, err := s.Get(ctx, keep.ID); err != nil {
		t.Errorf("kept session deleted: %v", err)
	}
}

// TestSession_PurgeLegacySessions: rows keyed by a raw ID (pre-v2.30)
// are removed; handle-keyed rows survive.
func TestSession_PurgeLegacySessions(t *testing.T) {
	db := newTestDB(t)
	s := NewSessionStore(db)
	ctx := context.Background()
	current, _ := s.Create(ctx, "u1", false, "", "")
	legacyID, _ := generateSessionID()
	_ = db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(sessionsBucketName)).Put([]byte(legacyID), []byte(`{"id":"`+legacyID+`","user_id":"u1"}`))
	})
	n, err := s.PurgeLegacySessions(ctx)
	if err != nil || n != 1 {
		t.Fatalf("PurgeLegacySessions = %d %v", n, err)
	}
	if n, _ := s.PurgeLegacySessions(ctx); n != 0 {
		t.Errorf("second purge deleted %d", n)
	}
	if _, err := s.Get(ctx, current.ID); err != nil {
		t.Errorf("current session purged: %v", err)
	}
}
