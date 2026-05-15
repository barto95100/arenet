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

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// fakeReloader records ReloadFromStore calls and can be primed to return an
// error to exercise the rollback paths.
type fakeReloader struct {
	mu      sync.Mutex
	calls   int
	nextErr error
}

func (f *fakeReloader) ReloadFromStore(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.nextErr
}

func (f *fakeReloader) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type testEnv struct {
	router http.Handler
	store  *storage.Store
	caddy  *fakeReloader
}

func newTestEnv(t *testing.T, dev bool) *testEnv {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	caddy := &fakeReloader{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewHandler(store, caddy, logger)
	return &testEnv{router: NewRouter(h, dev), store: store, caddy: caddy}
}

func TestListRoutes_Empty(t *testing.T) {
	env := newTestEnv(t, false)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var got []routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rec.Body)
	}
	if len(got) != 0 {
		t.Errorf("want empty list, got %d items", len(got))
	}
}

func TestListRoutes_Multiple(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()
	for _, h := range []string{"a.local", "b.local", "c.local"} {
		if _, err := env.store.CreateRoute(ctx, storage.Route{Host: h, UpstreamURL: "http://u:1"}); err != nil {
			t.Fatalf("seed %s: %v", h, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var got []routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rec.Body)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 routes, got %d", len(got))
	}
	hosts := []string{got[0].Host, got[1].Host, got[2].Host}
	want := []string{"a.local", "b.local", "c.local"}
	for i := range want {
		if hosts[i] != want[i] {
			t.Errorf("got hosts=%v want=%v", hosts, want)
			break
		}
	}
}

func TestGetRoute_Found(t *testing.T) {
	env := newTestEnv(t, false)
	created, err := env.store.CreateRoute(context.Background(), storage.Route{Host: "g.local", UpstreamURL: "http://u:1"})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes/"+created.ID, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var got routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rec.Body)
	}
	if got.ID != created.ID || got.Host != "g.local" {
		t.Errorf("got=%+v", got)
	}
}

func TestGetRoute_NotFound(t *testing.T) {
	env := newTestEnv(t, false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes/00000000-0000-0000-0000-000000000000", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "error") {
		t.Errorf("body missing error key: %s", rec.Body)
	}
}

func TestCreateRoute_Success(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"host":"new.local","upstreamUrl":"http://127.0.0.1:9000","tlsEnabled":false,"wafEnabled":false}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if env.caddy.CallCount() != 1 {
		t.Errorf("reload calls = %d, want 1", env.caddy.CallCount())
	}
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 || got[0].Host != "new.local" {
		t.Errorf("store state: %+v", got)
	}
}

func TestCreateRoute_InvalidJSON(t *testing.T) {
	env := newTestEnv(t, false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestCreateRoute_ValidationErrors(t *testing.T) {
	tests := []struct {
		name, body, wantSub string
	}{
		{"empty host", `{"host":"","upstreamUrl":"http://x:1"}`, "host must not be empty"},
		{"whitespace host", `{"host":"a b","upstreamUrl":"http://x:1"}`, "must not contain whitespace"},
		{"bad scheme", `{"host":"a.local","upstreamUrl":"ftp://x"}`, "http or https"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, false)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			env.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), tc.wantSub) {
				t.Errorf("body %q missing %q", rec.Body.String(), tc.wantSub)
			}
			if env.caddy.CallCount() != 0 {
				t.Errorf("reload should not have been called")
			}
		})
	}
}

func TestCreateRoute_DuplicateHost(t *testing.T) {
	env := newTestEnv(t, false)
	_, _ = env.store.CreateRoute(context.Background(), storage.Route{Host: "dup.local", UpstreamURL: "http://x:1"})

	body := `{"host":"dup.local","upstreamUrl":"http://x:2"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "host already configured") {
		t.Errorf("body=%s", rec.Body)
	}
}

func TestCreateRoute_ReloadFails_Rollback(t *testing.T) {
	env := newTestEnv(t, false)
	env.caddy.nextErr = errors.New("simulated reload failure")

	body := `{"host":"rb.local","upstreamUrl":"http://x:1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 0 {
		t.Errorf("rollback failed: %d routes left", len(got))
	}
}

// Used by later tasks; defined here so it's available to subsequent tests
// in this file. Required so the test file compiles incrementally.
var _ = errors.New
