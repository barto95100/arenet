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

package storage

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return s
}

func TestNewStore_EmptyPath(t *testing.T) {
	if _, err := NewStore(""); err == nil {
		t.Fatal("expected error for empty path, got nil")
	}
}

func TestNewStore_CreatesAllBuckets(t *testing.T) {
	s := newTestStore(t)

	want := []string{"routes", "users", "sessions", "audit"}
	err := s.DB().View(func(tx *bolt.Tx) error {
		for _, name := range want {
			if b := tx.Bucket([]byte(name)); b == nil {
				t.Errorf("bucket %q not created", name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}
}

func TestNewStore_ReopenIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arenet.db")

	s1, err := NewStore(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, err := s1.CreateRoute(context.Background(), Route{Host: "a.example.com", UpstreamURL: "http://u:1"}); err != nil {
		t.Fatalf("seed Step C bucket: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := NewStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })

	routes, err := s2.ListRoutes(context.Background())
	if err != nil {
		t.Fatalf("list after reopen: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("Step C data lost on reopen: want 1 route, got %d", len(routes))
	}

	err = s2.DB().View(func(tx *bolt.Tx) error {
		for _, name := range []string{"users", "sessions", "audit"} {
			if b := tx.Bucket([]byte(name)); b == nil {
				t.Errorf("bucket %q missing after reopen", name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}
}

// TestStore_DB ensures the DB accessor remains exported (regression-safe
// for the auth/audit packages that depend on it).
func TestStore_DB(t *testing.T) {
	s := newTestStore(t)
	if s.DB() == nil {
		t.Fatal("DB() returned nil")
	}
}

func TestCreateRoute(t *testing.T) {
	tests := []struct {
		name    string
		in      Route
		wantErr bool
	}{
		{
			name: "valid",
			in:   Route{Host: "a.example.com", UpstreamURL: "http://127.0.0.1:9000"},
		},
		{
			name:    "missing host",
			in:      Route{UpstreamURL: "http://127.0.0.1:9000"},
			wantErr: true,
		},
		{
			name:    "missing upstream",
			in:      Route{Host: "a.example.com"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			ctx := context.Background()

			got, err := s.CreateRoute(ctx, tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (route=%+v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.ID == "" {
				t.Error("expected non-empty ID")
			}
			if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
				t.Error("expected non-zero timestamps")
			}
			if got.Host != tc.in.Host || got.UpstreamURL != tc.in.UpstreamURL {
				t.Errorf("fields not preserved: %+v", got)
			}
		})
	}
}

func TestGetRoute(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateRoute(ctx, Route{Host: "a.example.com", UpstreamURL: "http://u:1"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	tests := []struct {
		name    string
		id      string
		wantErr error
	}{
		{name: "existing", id: created.ID},
		{name: "missing id", id: "", wantErr: errors.New("non-nil")},
		{name: "not found", id: "00000000-0000-0000-0000-000000000000", wantErr: ErrNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.GetRoute(ctx, tc.id)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error, got nil (route=%+v)", got)
				}
				if errors.Is(tc.wantErr, ErrNotFound) && !errors.Is(err, ErrNotFound) {
					t.Fatalf("want ErrNotFound, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.ID != created.ID {
				t.Errorf("got id=%q, want %q", got.ID, created.ID)
			}
		})
	}
}

func TestListRoutes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	got, err := s.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty list, got %d", len(got))
	}

	for _, h := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if _, err := s.CreateRoute(ctx, Route{Host: h, UpstreamURL: "http://u:1"}); err != nil {
			t.Fatalf("seed %s: %v", h, err)
		}
	}

	got, err = s.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 routes, got %d", len(got))
	}
	// Sorted by CreatedAt ascending.
	for i := 1; i < len(got); i++ {
		if got[i-1].CreatedAt.After(got[i].CreatedAt) {
			t.Errorf("list not sorted by created_at asc: %v vs %v", got[i-1].CreatedAt, got[i].CreatedAt)
		}
	}
}

func TestUpdateRoute(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateRoute(ctx, Route{Host: "a.example.com", UpstreamURL: "http://u:1"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	tests := []struct {
		name    string
		mut     func(Route) Route
		wantErr bool
	}{
		{
			name: "valid update",
			mut: func(r Route) Route {
				r.UpstreamURL = "http://u:2"
				r.TLSEnabled = true
				r.WAFMode = "block"
				return r
			},
		},
		{
			name:    "missing id",
			mut:     func(r Route) Route { r.ID = ""; return r },
			wantErr: true,
		},
		{
			name:    "invalid host",
			mut:     func(r Route) Route { r.Host = ""; return r },
			wantErr: true,
		},
		{
			name: "not found",
			mut: func(r Route) Route {
				r.ID = "00000000-0000-0000-0000-000000000000"
				return r
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			updated, err := s.UpdateRoute(ctx, tc.mut(created))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (route=%+v)", updated)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !updated.UpdatedAt.After(created.UpdatedAt) && !updated.UpdatedAt.Equal(created.UpdatedAt) {
				t.Errorf("UpdatedAt not refreshed: %v vs %v", updated.UpdatedAt, created.UpdatedAt)
			}
			if !updated.CreatedAt.Equal(created.CreatedAt) {
				t.Errorf("CreatedAt was modified: %v vs %v", updated.CreatedAt, created.CreatedAt)
			}
		})
	}
}

func TestDeleteRoute(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateRoute(ctx, Route{Host: "a.example.com", UpstreamURL: "http://u:1"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	tests := []struct {
		name    string
		id      string
		wantErr error
	}{
		{name: "existing", id: created.ID},
		{name: "missing id", id: "", wantErr: errors.New("non-nil")},
		{name: "not found", id: "00000000-0000-0000-0000-000000000000", wantErr: ErrNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := s.DeleteRoute(ctx, tc.id)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if errors.Is(tc.wantErr, ErrNotFound) && !errors.Is(err, ErrNotFound) {
					t.Fatalf("want ErrNotFound, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if _, err := s.GetRoute(ctx, created.ID); !errors.Is(err, ErrNotFound) {
				t.Errorf("route still present after delete, err=%v", err)
			}
		})
	}
}

func TestRestoreRoute(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	original := Route{
		ID:          "fixed-uuid-for-test",
		Host:        "restore.example",
		UpstreamURL: "http://127.0.0.1:7000",
		TLSEnabled:  true,
		WAFMode:     "off",
		CreatedAt:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	if err := s.RestoreRoute(ctx, original); err != nil {
		t.Fatalf("RestoreRoute: %v", err)
	}

	got, err := s.GetRoute(ctx, original.ID)
	if err != nil {
		t.Fatalf("GetRoute: %v", err)
	}
	if !reflect.DeepEqual(got, original) {
		t.Errorf("restored route differs: got=%+v want=%+v", got, original)
	}

	t.Run("empty id rejected", func(t *testing.T) {
		err := s.RestoreRoute(ctx, Route{Host: "x", UpstreamURL: "http://x:1"})
		if err == nil {
			t.Fatal("expected error for empty ID")
		}
	})
}

// --- Step I.3 — Alias hostnames -------------------------------------------

func TestRoute_AllHosts_ReturnsHostThenAliases(t *testing.T) {
	r := Route{Host: "primary.com", Aliases: []string{"alt1.com", "alt2.com"}}
	got := r.AllHosts()
	want := []string{"primary.com", "alt1.com", "alt2.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AllHosts() = %v; want %v (primary first)", got, want)
	}

	// No aliases → singleton slice with just the host.
	rNoAlias := Route{Host: "only.com"}
	if !reflect.DeepEqual(rNoAlias.AllHosts(), []string{"only.com"}) {
		t.Errorf("AllHosts() with nil aliases = %v; want [only.com]", rNoAlias.AllHosts())
	}
}

func TestRoute_Validate_RejectsAliasDuplicateOfHost(t *testing.T) {
	r := Route{
		Host: "x.com", UpstreamURL: "http://127.0.0.1:9000",
		Aliases: []string{"y.com", "x.com"}, // x.com == Host
	}
	err := r.validate()
	if err == nil {
		t.Fatal("validate() = nil; want duplicate-of-host error")
	}
	if !strings.Contains(err.Error(), `duplicates the primary host`) {
		t.Errorf("err = %v; want duplicates-the-primary-host message", err)
	}
}

func TestRoute_Validate_RejectsAliasesNotUnique(t *testing.T) {
	r := Route{
		Host: "x.com", UpstreamURL: "http://127.0.0.1:9000",
		Aliases: []string{"dup.com", "dup.com"}, // intra-alias duplicate
	}
	err := r.validate()
	if err == nil {
		t.Fatal("validate() = nil; want intra-alias duplicate error")
	}
	if !strings.Contains(err.Error(), `duplicates within the same route`) {
		t.Errorf("err = %v; want duplicates-within-same-route message", err)
	}
}

func TestRoute_Validate_RejectsEmptyAlias(t *testing.T) {
	r := Route{
		Host: "x.com", UpstreamURL: "http://127.0.0.1:9000",
		Aliases: []string{""},
	}
	err := r.validate()
	if err == nil {
		t.Fatal("validate() = nil; want empty-alias error")
	}
	if !strings.Contains(err.Error(), `alias must not be empty`) {
		t.Errorf("err = %v; want alias-must-not-be-empty message", err)
	}
}

// --- Step I.5 — Basic Auth invariants -------------------------------------

func TestRoute_Validate_BasicAuthEnabledRequiresUsername(t *testing.T) {
	r := Route{
		Host: "x.com", UpstreamURL: "http://127.0.0.1:9000",
		BasicAuthEnabled:      true,
		BasicAuthUsername:     "",
		BasicAuthPasswordHash: "$argon2id$..fake..",
	}
	err := r.validate()
	if err == nil || !strings.Contains(err.Error(), "basic_auth_username") {
		t.Errorf("validate() = %v; want basic_auth_username error", err)
	}
}

func TestRoute_Validate_BasicAuthEnabledRequiresHash(t *testing.T) {
	r := Route{
		Host: "x.com", UpstreamURL: "http://127.0.0.1:9000",
		BasicAuthEnabled:      true,
		BasicAuthUsername:     "admin",
		BasicAuthPasswordHash: "",
	}
	err := r.validate()
	if err == nil || !strings.Contains(err.Error(), "basic_auth_password_hash") {
		t.Errorf("validate() = %v; want basic_auth_password_hash error", err)
	}
}

func TestRoute_Validate_BasicAuthDisabledIgnoresFields(t *testing.T) {
	// Disabled basic auth: even with empty username + hash, validate
	// must pass (the API layer clears these fields when toggling off).
	r := Route{
		Host: "x.com", UpstreamURL: "http://127.0.0.1:9000",
		BasicAuthEnabled: false,
	}
	if err := r.validate(); err != nil {
		t.Errorf("validate() = %v; want nil (disabled basic auth ignores other fields)", err)
	}
}

// --- Step I.6 — Custom headers --------------------------------------------

// TestRoute_Validate_HeadersAreNotInspected is a sanity test: the
// storage layer trusts the API to have run validateHeaders on the
// maps, so it accepts any content (including what a unit test might
// inject). The line of defense for header injection is in the API
// layer; storage just persists.
func TestRoute_Validate_HeadersAreNotInspected(t *testing.T) {
	r := Route{
		Host: "x.com", UpstreamURL: "http://127.0.0.1:9000",
		RequestHeaders:  map[string]string{"X-Anything": "value with whatever the API allowed"},
		ResponseHeaders: map[string]string{"X-Another": ""},
	}
	if err := r.validate(); err != nil {
		t.Errorf("validate() = %v; storage must trust the API on header content", err)
	}
}
