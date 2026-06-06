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

package observability

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func openAuthTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "metrics.db")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestInsertAuthEventBatch_RoundTrip(t *testing.T) {
	store := openAuthTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	events := []AuthEvent{
		{Ts: now, Kind: AuthEventKindLoginFailure, SrcIP: "1.2.3.4", Username: "alice", Path: "/auth/login", Details: "wrong password"},
		{Ts: now.Add(time.Second), Kind: AuthEventKindSessionExpired, SrcIP: "5.6.7.8", Path: "/api/v1/whoami"},
		{Ts: now.Add(2 * time.Second), Kind: AuthEventKindForbidden, SrcIP: "9.9.9.9", Username: "bob", Path: "/api/v1/admin"},
	}
	if err := store.InsertAuthEventBatch(ctx, events); err != nil {
		t.Fatalf("InsertAuthEventBatch: %v", err)
	}

	got, err := store.QueryAuthEvents(ctx, AuthEventFilter{Limit: 10})
	if err != nil {
		t.Fatalf("QueryAuthEvents: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	// ts-DESC ordering.
	if got[0].Kind != AuthEventKindForbidden {
		t.Errorf("got[0].Kind = %v, want Forbidden", got[0].Kind)
	}
	if got[0].Username != "bob" {
		t.Errorf("got[0].Username = %q, want bob", got[0].Username)
	}
	if got[2].SrcIP != "1.2.3.4" {
		t.Errorf("got[2].SrcIP = %q, want 1.2.3.4", got[2].SrcIP)
	}
}

func TestInsertAuthEventBatch_Empty(t *testing.T) {
	store := openAuthTestStore(t)
	if err := store.InsertAuthEventBatch(context.Background(), nil); err != nil {
		t.Fatalf("empty batch should be no-op, got: %v", err)
	}
}

func TestInsertAuthEventBatch_NilStore(t *testing.T) {
	var s *Store
	err := s.InsertAuthEventBatch(context.Background(), []AuthEvent{{Kind: AuthEventKindLoginFailure}})
	if err == nil {
		t.Fatal("expected error on nil store")
	}
}

func TestQueryAuthEvents_SrcIPFilter(t *testing.T) {
	store := openAuthTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	events := []AuthEvent{
		{Ts: now, Kind: AuthEventKindLoginFailure, SrcIP: "1.1.1.1"},
		{Ts: now.Add(time.Second), Kind: AuthEventKindLoginFailure, SrcIP: "2.2.2.2"},
		{Ts: now.Add(2 * time.Second), Kind: AuthEventKindLoginFailure, SrcIP: "1.1.1.1"},
	}
	if err := store.InsertAuthEventBatch(ctx, events); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := store.QueryAuthEvents(ctx, AuthEventFilter{SrcIP: "1.1.1.1", Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("len = %d, want 2 (filtered to 1.1.1.1)", len(got))
	}
	for _, e := range got {
		if e.SrcIP != "1.1.1.1" {
			t.Errorf("unexpected SrcIP %q", e.SrcIP)
		}
	}
}

func TestQueryAuthEvents_KindFilter(t *testing.T) {
	store := openAuthTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	events := []AuthEvent{
		{Ts: now, Kind: AuthEventKindLoginFailure, SrcIP: "1.1.1.1"},
		{Ts: now.Add(time.Second), Kind: AuthEventKindSessionExpired, SrcIP: "1.1.1.1"},
		{Ts: now.Add(2 * time.Second), Kind: AuthEventKindForbidden, SrcIP: "1.1.1.1"},
	}
	if err := store.InsertAuthEventBatch(ctx, events); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Single-value Kind.
	got, err := store.QueryAuthEvents(ctx, AuthEventFilter{Kind: "forbidden", Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 1 || got[0].Kind != AuthEventKindForbidden {
		t.Errorf("single-kind filter mismatch: %+v", got)
	}

	// Multi-value Kinds — precedes single Kind.
	got, err = store.QueryAuthEvents(ctx, AuthEventFilter{
		Kind:  "forbidden", // should be overridden by Kinds
		Kinds: []AuthEventKind{AuthEventKindLoginFailure, AuthEventKindSessionExpired},
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("multi-kind query: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("Kinds precedence broken; got %d events, want 2", len(got))
	}
}

func TestQueryAuthEvents_SearchAcrossColumns(t *testing.T) {
	store := openAuthTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	events := []AuthEvent{
		{Ts: now, Kind: AuthEventKindLoginFailure, SrcIP: "1.1.1.1", Username: "alice", Path: "/auth/login"},
		{Ts: now.Add(time.Second), Kind: AuthEventKindForbidden, SrcIP: "2.2.2.2", Username: "bob", Path: "/api/v1/admin", Details: "admin role required"},
	}
	if err := store.InsertAuthEventBatch(ctx, events); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Match by Details substring.
	got, err := store.QueryAuthEvents(ctx, AuthEventFilter{Search: "admin role", Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 1 || got[0].Username != "bob" {
		t.Errorf("search mismatch: %+v", got)
	}

	// Case-insensitive match by Username.
	got, err = store.QueryAuthEvents(ctx, AuthEventFilter{Search: "ALICE", Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 1 || got[0].Username != "alice" {
		t.Errorf("case-insensitive search mismatch: %+v", got)
	}
}

func TestCountAuthEvents_HonorsFilter(t *testing.T) {
	store := openAuthTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	events := []AuthEvent{
		{Ts: now, Kind: AuthEventKindLoginFailure, SrcIP: "1.1.1.1"},
		{Ts: now.Add(time.Second), Kind: AuthEventKindLoginFailure, SrcIP: "1.1.1.1"},
		{Ts: now.Add(2 * time.Second), Kind: AuthEventKindForbidden, SrcIP: "2.2.2.2"},
	}
	if err := store.InsertAuthEventBatch(ctx, events); err != nil {
		t.Fatalf("seed: %v", err)
	}

	n, err := store.CountAuthEvents(ctx, AuthEventFilter{SrcIP: "1.1.1.1"})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Errorf("count = %d, want 2", n)
	}

	total, err := store.CountAuthEvents(ctx, AuthEventFilter{})
	if err != nil {
		t.Fatalf("count all: %v", err)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
}

func TestPruneAuthEventsOlderThan(t *testing.T) {
	store := openAuthTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	old := AuthEvent{Ts: now.Add(-40 * 24 * time.Hour), Kind: AuthEventKindLoginFailure, SrcIP: "1.1.1.1"}
	fresh := AuthEvent{Ts: now, Kind: AuthEventKindLoginFailure, SrcIP: "2.2.2.2"}
	if err := store.InsertAuthEventBatch(ctx, []AuthEvent{old, fresh}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cutoff := now.Add(-RetainAuthEvents)
	deleted, err := store.PruneAuthEventsOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1", deleted)
	}
	remaining, _ := store.QueryAuthEvents(ctx, AuthEventFilter{Limit: 10})
	if len(remaining) != 1 || remaining[0].SrcIP != "2.2.2.2" {
		t.Errorf("remaining = %+v, want only fresh", remaining)
	}
}

func TestParseAuthEventKind(t *testing.T) {
	cases := []struct {
		in   string
		want AuthEventKind
	}{
		{"login_failure", AuthEventKindLoginFailure},
		{"session_expired", AuthEventKindSessionExpired},
		{"oidc_callback_rejected", AuthEventKindOIDCCallbackRejected},
		{"forbidden", AuthEventKindForbidden},
		{"unknown", AuthEventKindLoginFailure}, // defensive default
		{"", AuthEventKindLoginFailure},        // defensive default
		{"garbage", AuthEventKindLoginFailure}, // defensive default
	}
	for _, c := range cases {
		if got := ParseAuthEventKind(c.in); got != c.want {
			t.Errorf("Parse(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestAuthEventKind_String(t *testing.T) {
	cases := []struct {
		in   AuthEventKind
		want string
	}{
		{AuthEventKindLoginFailure, "login_failure"},
		{AuthEventKindSessionExpired, "session_expired"},
		{AuthEventKindOIDCCallbackRejected, "oidc_callback_rejected"},
		{AuthEventKindForbidden, "forbidden"},
		{AuthEventKind(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.in.String(); got != c.want {
			t.Errorf("%v.String() = %q, want %q", c.in, got, c.want)
		}
	}
}
