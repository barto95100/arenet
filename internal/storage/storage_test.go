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

// minimalRoute returns a Route with the bare minimum Step J.1 fields
// populated to pass validate(): a Host, a one-element upstream pool,
// and the round_robin LB policy default. Other Step I fields stay at
// zero value. Centralised so the dozen+ pre-J.1 test fixtures that
// used to inline a single upstream string share one shape and the
// Upstream struct churn lives in one place.
func minimalRoute(host, upstream string) Route {
	return Route{
		Host:      host,
		Upstreams: []Upstream{{URL: upstream, Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
	}
}

func TestNewStore_EmptyPath(t *testing.T) {
	if _, err := NewStore(""); err == nil {
		t.Fatal("expected error for empty path, got nil")
	}
}

func TestNewStore_CreatesAllBuckets(t *testing.T) {
	s := newTestStore(t)

	want := []string{"routes", "users", "sessions", "audit", "managed_domains"}
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
	if _, err := s1.CreateRoute(context.Background(), Route{
		Host:      "a.example.com",
		Upstreams: []Upstream{{URL: "http://u:1", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
	}); err != nil {
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
			in: Route{
				Host:      "a.example.com",
				Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
				LBPolicy:  LBPolicyRoundRobin,
			},
		},
		{
			name: "missing host",
			in: Route{
				Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
				LBPolicy:  LBPolicyRoundRobin,
			},
			wantErr: true,
		},
		{
			name:    "missing upstream pool",
			in:      Route{Host: "a.example.com", LBPolicy: LBPolicyRoundRobin},
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
			if got.Host != tc.in.Host {
				t.Errorf("host not preserved: got %q, want %q", got.Host, tc.in.Host)
			}
			if len(got.Upstreams) != len(tc.in.Upstreams) {
				t.Fatalf("upstream pool size: got %d, want %d", len(got.Upstreams), len(tc.in.Upstreams))
			}
			for i := range tc.in.Upstreams {
				if got.Upstreams[i] != tc.in.Upstreams[i] {
					t.Errorf("upstreams[%d] not preserved: got %+v, want %+v",
						i, got.Upstreams[i], tc.in.Upstreams[i])
				}
			}
			if got.LBPolicy != tc.in.LBPolicy {
				t.Errorf("lb_policy not preserved: got %q, want %q", got.LBPolicy, tc.in.LBPolicy)
			}
		})
	}
}

func TestGetRoute(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateRoute(ctx, minimalRoute("a.example.com", "http://u:1"))
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
		if _, err := s.CreateRoute(ctx, minimalRoute(h, "http://u:1")); err != nil {
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

	created, err := s.CreateRoute(ctx, minimalRoute("a.example.com", "http://u:1"))
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
				r.Upstreams = []Upstream{{URL: "http://u:2", Weight: 1}}
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

	created, err := s.CreateRoute(ctx, minimalRoute("a.example.com", "http://u:1"))
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
		ID:         "fixed-uuid-for-test",
		Host:       "restore.example",
		Upstreams:  []Upstream{{URL: "http://127.0.0.1:7000", Weight: 1}},
		LBPolicy:   LBPolicyRoundRobin,
		TLSEnabled: true,
		WAFMode:    "off",
		CreatedAt:  time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		UpdatedAt:  time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
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
		err := s.RestoreRoute(ctx, minimalRoute("x", "http://x:1"))
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
		Host:      "x.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		Aliases:   []string{"y.com", "x.com"}, // x.com == Host
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
		Host:      "x.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		Aliases:   []string{"dup.com", "dup.com"}, // intra-alias duplicate
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
		Host:      "x.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		Aliases:   []string{""},
	}
	err := r.validate()
	if err == nil {
		t.Fatal("validate() = nil; want empty-alias error")
	}
	if !strings.Contains(err.Error(), `alias must not be empty`) {
		t.Errorf("err = %v; want alias-must-not-be-empty message", err)
	}
}

// --- Step J.1 — Upstream pool & LB policy invariants ----------------------

func TestRoute_Validate_RejectsEmptyUpstreamURL(t *testing.T) {
	r := Route{
		Host:      "x.com",
		Upstreams: []Upstream{{URL: "", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
	}
	err := r.validate()
	if err == nil {
		t.Fatal("validate() = nil; want empty-upstream-url error")
	}
	if !strings.Contains(err.Error(), "upstreams[0].url must not be empty") {
		t.Errorf("err = %v; want upstreams[0].url-must-not-be-empty message", err)
	}
}

func TestRoute_Validate_RejectsNonPositiveWeight(t *testing.T) {
	tests := []struct {
		name   string
		weight int
	}{
		{name: "zero", weight: 0},
		{name: "negative", weight: -3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := Route{
				Host:      "x.com",
				Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: tc.weight}},
				LBPolicy:  LBPolicyRoundRobin,
			}
			err := r.validate()
			if err == nil {
				t.Fatalf("validate() = nil; want weight >= 1 error (weight=%d)", tc.weight)
			}
			if !strings.Contains(err.Error(), "upstreams[0].weight must be >= 1") {
				t.Errorf("err = %v; want upstreams[0].weight-must-be->=1 message", err)
			}
		})
	}
}

func TestRoute_Validate_RejectsUnknownLBPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy string
	}{
		{name: "empty", policy: ""},
		{name: "bogus", policy: "magic_sauce"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := Route{
				Host:      "x.com",
				Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
				LBPolicy:  tc.policy,
			}
			err := r.validate()
			if err == nil {
				t.Fatalf("validate() = nil; want unknown-lb-policy error (policy=%q)", tc.policy)
			}
			if !strings.Contains(err.Error(), "is not a valid policy") {
				t.Errorf("err = %v; want is-not-a-valid-policy message", err)
			}
		})
	}
}

// --- Step I.5 — Basic Auth invariants -------------------------------------

func TestRoute_Validate_BasicAuthEnabledRequiresUsername(t *testing.T) {
	r := Route{
		Host:      "x.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		AuthMode:  RouteAuthBasic,
		BasicAuth: BasicAuthRouteConfig{
			Username:     "",
			PasswordHash: "$argon2id$..fake..",
		},
	}
	err := r.validate()
	if err == nil || !strings.Contains(err.Error(), "basic_auth.username") {
		t.Errorf("validate() = %v; want basic_auth.username error", err)
	}
}

func TestRoute_Validate_BasicAuthEnabledRequiresHash(t *testing.T) {
	r := Route{
		Host:      "x.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		AuthMode:  RouteAuthBasic,
		BasicAuth: BasicAuthRouteConfig{
			Username:     "admin",
			PasswordHash: "",
		},
	}
	err := r.validate()
	if err == nil || !strings.Contains(err.Error(), "basic_auth.password_hash") {
		t.Errorf("validate() = %v; want basic_auth.password_hash error", err)
	}
}

func TestRoute_Validate_BasicAuthDisabledIgnoresFields(t *testing.T) {
	// AuthMode "none" (the K.1 default for routes that don't pick
	// basic / forward_auth): even with empty BasicAuth fields,
	// validate must pass (the API layer clears these fields when
	// toggling away from "basic").
	r := Route{
		Host:      "x.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		AuthMode:  RouteAuthNone,
	}
	if err := r.validate(); err != nil {
		t.Errorf("validate() = %v; want nil (none auth mode ignores basic-auth fields)", err)
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
		Host:            "x.com",
		Upstreams:       []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:        LBPolicyRoundRobin,
		RequestHeaders:  map[string]string{"X-Anything": "value with whatever the API allowed"},
		ResponseHeaders: map[string]string{"X-Another": ""},
	}
	if err := r.validate(); err != nil {
		t.Errorf("validate() = %v; storage must trust the API on header content", err)
	}
}

// --- Step J.2 — HealthCheck zero-value & decode-from-J.1-era ---------------

// TestRoute_DecodeJ1EraRow_HasZeroHealthCheck — J.2 adds Route.
// HealthCheck without a migration. A row persisted by J.1 (before
// the HealthCheck field existed) has no `health_check` key in its
// stored JSON; standard json.Unmarshal must decode that missing key
// to the zero value, which the rest of the J.2 codebase treats as
// "no probe runs". This test seeds a J.1-era JSON literal directly
// into the bucket (bypassing CreateRoute, which would force a
// post-J.2 marshal) and then reads it back through the public API
// to prove the decode path is silent and correct.
func TestRoute_DecodeJ1EraRow_HasZeroHealthCheck(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Hand-crafted JSON without a `health_check` key — exactly the
	// shape a J.1 binary would have written for a route created
	// before Step J.2 landed.
	j1Row := []byte(`{` +
		`"id":"r-j1era",` +
		`"host":"j1era.example.com",` +
		`"upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],` +
		`"lb_policy":"round_robin",` +
		`"tls_enabled":false,` +
		`"redirect_to_https":false,` +
		`"aliases":null,` +
		`"basic_auth_enabled":false,` +
		`"basic_auth_username":"",` +
		`"basic_auth_password_hash":"",` +
		`"request_headers":null,` +
		`"response_headers":null,` +
		`"waf_mode":"off",` +
		`"created_at":"2026-05-25T00:00:00Z",` +
		`"updated_at":"2026-05-25T00:00:00Z"` +
		`}`)
	if err := s.DB().Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("routes")).Put([]byte("r-j1era"), j1Row)
	}); err != nil {
		t.Fatalf("seed J.1-era row: %v", err)
	}

	got, err := s.GetRoute(ctx, "r-j1era")
	if err != nil {
		t.Fatalf("GetRoute: %v", err)
	}

	// The whole point: a missing health_check key decodes to the
	// zero-value HealthCheck — Enabled false, every other field at
	// its Go zero. The generator (caddymgr) treats this as "omit
	// the health_checks Caddy block entirely"; no probe ever runs.
	if got.HealthCheck.Enabled {
		t.Errorf("HealthCheck.Enabled = true; want false (zero-value from absent key)")
	}
	if got.HealthCheck.URI != "" {
		t.Errorf("HealthCheck.URI = %q; want \"\"", got.HealthCheck.URI)
	}
	if got.HealthCheck.Passes != 0 {
		t.Errorf("HealthCheck.Passes = %d; want 0", got.HealthCheck.Passes)
	}
	if got.HealthCheck.Fails != 0 {
		t.Errorf("HealthCheck.Fails = %d; want 0", got.HealthCheck.Fails)
	}
}

// TestRoute_Validate_HealthCheckDisabledIgnoresSubFields — when
// HealthCheck.Enabled is false, the rest of the struct is inert and
// validate() must pass even if every sub-field would normally fail
// the strict checks. Mirrors the BasicAuth-disabled test above.
func TestRoute_Validate_HealthCheckDisabledIgnoresSubFields(t *testing.T) {
	r := Route{
		Host:      "x.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		HealthCheck: HealthCheck{
			Enabled:  false,
			URI:      "",        // would fail when Enabled
			Method:   "POST",    // would fail when Enabled
			Interval: "garbage", // would fail when Enabled
		},
	}
	if err := r.validate(); err != nil {
		t.Errorf("validate() = %v; want nil (disabled health check ignores other fields)", err)
	}
}

// TestRoute_Validate_HealthCheckEnabledRequiresURI — the one
// non-defaultable field. validate() must reject Enabled=true with
// URI="" because the API materialises everything except URI before
// the storage write. This is the strict last-line-of-defence check
// (§5.2 "URI is the one field operators must always supply").
func TestRoute_Validate_HealthCheckEnabledRequiresURI(t *testing.T) {
	r := Route{
		Host:      "x.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		HealthCheck: HealthCheck{
			Enabled:  true,
			URI:      "",
			Method:   "GET",
			Interval: "30s",
			Timeout:  "5s",
			Passes:   1,
			Fails:    1,
		},
	}
	err := r.validate()
	if err == nil {
		t.Fatal("validate() = nil; want health_check.uri error")
	}
	if !strings.Contains(err.Error(), "health_check.uri") {
		t.Errorf("err = %v; want health_check.uri error message", err)
	}
}

// TestRoute_Validate_HealthCheckEnabledRejectsBlankMethod — once
// Enabled is true, an empty Method reaching storage is a programming
// error (the API layer materialises Method "" → "GET" before
// validate). Storage's job is to fail closed.
func TestRoute_Validate_HealthCheckEnabledRejectsBlankMethod(t *testing.T) {
	r := Route{
		Host:      "x.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		HealthCheck: HealthCheck{
			Enabled:  true,
			URI:      "/healthz",
			Method:   "", // unmaterialised — programming error
			Interval: "30s",
			Timeout:  "5s",
			Passes:   1,
			Fails:    1,
		},
	}
	err := r.validate()
	if err == nil {
		t.Fatal("validate() = nil; want health_check.method error")
	}
	if !strings.Contains(err.Error(), "health_check.method") {
		t.Errorf("err = %v; want health_check.method error message", err)
	}
}

// TestRoute_Validate_HealthCheckMethod — storage validate() is a
// pure grid: it accepts canonical "GET" / "HEAD" and rejects any
// other value (including non-canonical "head" / "Get"). The API
// layer is responsible for uppercase normalisation before reaching
// storage; the end-to-end "POST method:head → stored Method:HEAD"
// contract is verified by the handler-level test in the api package.
func TestRoute_Validate_HealthCheckMethod(t *testing.T) {
	mkRoute := func(method string) *Route {
		return &Route{
			Host:      "x.com",
			Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  LBPolicyRoundRobin,
			HealthCheck: HealthCheck{
				Enabled:  true,
				URI:      "/healthz",
				Method:   method,
				Interval: "30s",
				Timeout:  "5s",
				Passes:   1,
				Fails:    1,
			},
		}
	}

	for _, m := range []string{"GET", "HEAD"} {
		t.Run("accepts/"+m, func(t *testing.T) {
			r := mkRoute(m)
			if err := r.validate(); err != nil {
				t.Errorf("validate() = %v; want nil (canonical %q)", err, m)
			}
			// Pure grid: Method MUST NOT be rewritten by validate().
			if r.HealthCheck.Method != m {
				t.Errorf("Method mutated by validate: got %q, want %q (pure-grid contract)",
					r.HealthCheck.Method, m)
			}
		})
	}

	for _, m := range []string{"head", "Get", "POST"} {
		t.Run("rejects/"+m, func(t *testing.T) {
			r := mkRoute(m)
			err := r.validate()
			if err == nil {
				t.Fatalf("validate() = nil; want method-error for %q", m)
			}
			if !strings.Contains(err.Error(), "health_check.method") {
				t.Errorf("err = %v; want health_check.method error", err)
			}
		})
	}
}

// TestRoute_Validate_HealthCheckTimeoutMustBeLessThanInterval —
// the §5.2 ordering rule. A probe whose timeout is >= the interval
// would let consecutive probes pile up; storage rejects it.
func TestRoute_Validate_HealthCheckTimeoutMustBeLessThanInterval(t *testing.T) {
	r := Route{
		Host:      "x.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		HealthCheck: HealthCheck{
			Enabled:  true,
			URI:      "/healthz",
			Method:   "GET",
			Interval: "5s",
			Timeout:  "5s", // == interval — must reject
			Passes:   1,
			Fails:    1,
		},
	}
	err := r.validate()
	if err == nil {
		t.Fatal("validate() = nil; want timeout-not-less-than-interval error")
	}
	if !strings.Contains(err.Error(), "timeout must be strictly less than interval") {
		t.Errorf("err = %v; want timeout-less-than-interval error", err)
	}
}
