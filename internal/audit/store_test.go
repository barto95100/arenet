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

package audit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// newTestStore opens a fresh bbolt database in a temp dir and returns
// an audit.Store ready for use. The database is closed at test cleanup.
func newTestStore(t *testing.T) (*Store, *bolt.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := bolt.Open(filepath.Join(dir, "audit_test.db"), 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return NewStore(db), db
}

func TestNewStore_NilPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic, got none")
		}
	}()
	_ = NewStore(nil)
}

func TestAppend_GeneratesIDAndTimestamp(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	before := time.Now().UTC()
	evt := Event{
		// Caller tries to set ID and Timestamp; Append must overwrite them.
		ID:        "fake-caller-id",
		Timestamp: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		Action:    ActionLoginSuccess,
	}
	if err := s.Append(ctx, evt); err != nil {
		t.Fatalf("Append: %v", err)
	}
	after := time.Now().UTC()

	// Read back the only event in the bucket.
	got := readAll(t, s)
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d", len(got))
	}
	if got[0].ID == "fake-caller-id" {
		t.Error("Append did not overwrite caller-supplied ID")
	}
	if _, err := uuid.Parse(got[0].ID); err != nil {
		t.Errorf("ID is not a valid UUID: %q (%v)", got[0].ID, err)
	}
	if got[0].Timestamp.Before(before) || got[0].Timestamp.After(after) {
		t.Errorf("Timestamp not in [before, after]: %v not in [%v, %v]", got[0].Timestamp, before, after)
	}
	if got[0].Action != ActionLoginSuccess {
		t.Errorf("Action lost: got %q want %q", got[0].Action, ActionLoginSuccess)
	}
}

func TestAppend_OrderingViaUUIDv7(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Append 10 events; UUID v7 should sort them in insertion order.
	for i := 0; i < 10; i++ {
		if err := s.Append(ctx, Event{Action: ActionLoginSuccess, Message: string(rune('a' + i))}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		// Tiny pause so UUID v7's ms-precision timestamp can advance.
		time.Sleep(2 * time.Millisecond)
	}

	got := readAll(t, s)
	if len(got) != 10 {
		t.Fatalf("want 10 events, got %d", len(got))
	}
	// readAll returns in bucket order (ascending raw key bytes), which
	// for UUID v7 is chronological ascending. Verify timestamps are
	// monotonically increasing.
	for i := 1; i < len(got); i++ {
		if got[i].Timestamp.Before(got[i-1].Timestamp) {
			t.Errorf("event %d timestamp %v predates event %d %v", i, got[i].Timestamp, i-1, got[i-1].Timestamp)
		}
	}
}

func TestList_EmptyBucket(t *testing.T) {
	s, _ := newTestStore(t)
	events, cursor, err := s.List(context.Background(), Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("want empty list, got %d", len(events))
	}
	if cursor != "" {
		t.Errorf("want empty cursor, got %q", cursor)
	}
}

func TestList_ReverseChronologicalOrder(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := s.Append(ctx, Event{Action: ActionLoginSuccess, Message: string(rune('a' + i))}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		time.Sleep(2 * time.Millisecond)
	}

	events, _, err := s.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("want 5 events, got %d", len(events))
	}
	// Most recent first: messages should be "e", "d", "c", "b", "a".
	for i := 1; i < len(events); i++ {
		if !events[i].Timestamp.Before(events[i-1].Timestamp) {
			t.Errorf("events not in reverse chrono order at i=%d: %v vs %v", i, events[i-1].Timestamp, events[i].Timestamp)
		}
	}
	if events[0].Message != "e" || events[4].Message != "a" {
		t.Errorf("unexpected message order: %q ... %q", events[0].Message, events[4].Message)
	}
}

func TestList_LimitDefaultAndClamp(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Seed 250 events.
	for i := 0; i < 250; i++ {
		if err := s.Append(ctx, Event{Action: ActionLoginSuccess}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	tests := []struct {
		name   string
		limit  int
		want   int
		cursor bool
	}{
		{name: "zero defaults to 50", limit: 0, want: DefaultLimit, cursor: true},
		{name: "negative defaults to 50", limit: -5, want: DefaultLimit, cursor: true},
		{name: "exact 50", limit: 50, want: 50, cursor: true},
		{name: "200 max", limit: 200, want: 200, cursor: true},
		{name: "300 clamped to 200", limit: 300, want: MaxLimit, cursor: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events, cursor, err := s.List(ctx, Filter{Limit: tc.limit})
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(events) != tc.want {
				t.Errorf("limit=%d: want %d events, got %d", tc.limit, tc.want, len(events))
			}
			if tc.cursor && cursor == "" {
				t.Error("expected non-empty nextCursor")
			}
		})
	}
}

func TestList_CursorPagination(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Seed 120 events (>100 per plan §4.1).
	for i := 0; i < 120; i++ {
		if err := s.Append(ctx, Event{Action: ActionLoginSuccess, Message: "evt"}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// Page through with limit=30.
	pages := [][]Event{}
	cursor := ""
	for page := 0; page < 10; page++ {
		events, next, err := s.List(ctx, Filter{Limit: 30, Cursor: cursor})
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		if len(events) == 0 {
			break
		}
		pages = append(pages, events)
		if next == "" {
			break
		}
		cursor = next
	}

	total := 0
	seen := make(map[string]bool)
	for _, p := range pages {
		for _, e := range p {
			if seen[e.ID] {
				t.Errorf("duplicate event across pages: %s", e.ID)
			}
			seen[e.ID] = true
			total++
		}
	}
	if total != 120 {
		t.Errorf("want 120 unique events across pages, got %d", total)
	}

	// Last page should not request a further page.
	last := pages[len(pages)-1]
	_, finalNext, err := s.List(ctx, Filter{Limit: 30, Cursor: last[len(last)-1].ID})
	if err != nil {
		t.Fatalf("final page: %v", err)
	}
	if finalNext != "" {
		t.Errorf("expected no further cursor past last event, got %q", finalNext)
	}
}

func TestList_FilterByAction(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	for _, a := range []string{
		ActionLoginSuccess, ActionLoginFailure, ActionLoginSuccess,
		ActionRouteCreated, ActionLoginFailure,
	} {
		if err := s.Append(ctx, Event{Action: a}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	events, _, err := s.List(ctx, Filter{Action: ActionLoginFailure})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 login_failure events, got %d", len(events))
	}
	for _, e := range events {
		if e.Action != ActionLoginFailure {
			t.Errorf("filter leaked: got action %q", e.Action)
		}
	}
}

func TestList_FilterByActorAndTarget(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	alice := "user-alice"
	bob := "user-bob"
	r1 := "route-1"
	r2 := "route-2"

	if err := s.Append(ctx, Event{Action: ActionRouteCreated, ActorUserID: alice, TargetType: "route", TargetID: r1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ctx, Event{Action: ActionRouteCreated, ActorUserID: bob, TargetType: "route", TargetID: r2}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ctx, Event{Action: ActionRouteDeleted, ActorUserID: alice, TargetType: "route", TargetID: r1}); err != nil {
		t.Fatal(err)
	}

	// Filter by actor.
	events, _, err := s.List(ctx, Filter{ActorUserID: alice})
	if err != nil {
		t.Fatalf("List actor: %v", err)
	}
	if len(events) != 2 {
		t.Errorf("want 2 alice events, got %d", len(events))
	}

	// Filter by target.
	events, _, err = s.List(ctx, Filter{TargetType: "route", TargetID: r1})
	if err != nil {
		t.Fatalf("List target: %v", err)
	}
	if len(events) != 2 {
		t.Errorf("want 2 r1 events, got %d", len(events))
	}

	// Combined.
	events, _, err = s.List(ctx, Filter{ActorUserID: bob, TargetID: r2})
	if err != nil {
		t.Fatalf("List combined: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("want 1 combined event, got %d", len(events))
	}
}

func TestList_FilterByTimeRange(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Append 5 events with small spacing.
	for i := 0; i < 5; i++ {
		if err := s.Append(ctx, Event{Action: ActionLoginSuccess}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(3 * time.Millisecond)
	}
	all := readAll(t, s)
	if len(all) != 5 {
		t.Fatalf("expected 5 events, got %d", len(all))
	}

	// From inclusive at all[1].Timestamp, To exclusive at all[4].Timestamp.
	// Should return all[1], all[2], all[3] — three events.
	events, _, err := s.List(ctx, Filter{From: all[1].Timestamp, To: all[4].Timestamp})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("want 3 events in range, got %d", len(events))
	}
}

func TestList_InvalidCursor(t *testing.T) {
	s, _ := newTestStore(t)
	_, _, err := s.List(context.Background(), Filter{Cursor: "not-a-uuid"})
	if err == nil {
		t.Fatal("expected error for invalid cursor, got nil")
	}
}

func TestAppend_Immutability(t *testing.T) {
	// After append, attempting to overwrite the same key via Put should
	// not be possible through the public Store API (Store has no update
	// method). This test verifies the contract by inspecting the bucket
	// after two Appends: keys are distinct, values not overwritten.
	s, db := newTestStore(t)
	ctx := context.Background()

	if err := s.Append(ctx, Event{Action: ActionLoginSuccess, Message: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ctx, Event{Action: ActionLoginSuccess, Message: "second"}); err != nil {
		t.Fatal(err)
	}

	// Bucket should have 2 distinct keys.
	var keyCount int
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		return b.ForEach(func(k, v []byte) error {
			keyCount++
			return nil
		})
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if keyCount != 2 {
		t.Errorf("expected 2 distinct keys, got %d", keyCount)
	}
}

// readAll returns every event in the bucket in ascending key order
// (which, for UUID v7 keys, is chronological ascending). For test use.
func readAll(t *testing.T, s *Store) []Event {
	t.Helper()
	var out []Event
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		return b.ForEach(func(k, v []byte) error {
			var e Event
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			out = append(out, e)
			return nil
		})
	})
	if err != nil {
		t.Fatalf("readAll: %v", err)
	}
	return out
}
