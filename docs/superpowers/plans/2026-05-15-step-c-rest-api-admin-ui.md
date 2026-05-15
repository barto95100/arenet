# Step C — REST API + Admin UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a REST API on `:8001` and a SOC-styled SvelteKit admin UI that together allow CRUD of Arenet proxy routes, with live Caddy reload after every mutation.

**Architecture:** Go binary embeds Caddy v2 (existing), BoltDB (existing), and now a chi-based admin server + embedded SvelteKit SPA. Handler depends on `CaddyReloader` interface for testability. Frontend is dark-mode dashboard with 13 reusable components, dev-served by Vite or production-served via `//go:embed`.

**Tech Stack:** Go 1.25, `github.com/go-chi/chi/v5`, `go.etcd.io/bbolt`, `github.com/caddyserver/caddy/v2`. SvelteKit 2 / Svelte 5 (TypeScript strict), Tailwind, `@sveltejs/adapter-static`, self-hosted Inter + JetBrains Mono fonts.

**Spec:** `docs/superpowers/specs/2026-05-15-step-c-rest-api-admin-ui-design.md` (commit `26bc7e1`).

**AGPL header conventions:**
- `.go` files: `// Arenet ...` block, same as Step A/B (12 lines).
- `.ts` files: `//` line comments at top of file, identical text.
- `.svelte` files: `<!-- ... -->` HTML comment ABOVE the `<script>` tag (SvelteKit's own pattern).
- `package.json`, `tsconfig.json`, etc. (no comments allowed): no header — license is repo-wide via `LICENSE`.

---

## Chunk 1 — Backend: `storage.RestoreRoute` + API validation

Pure TDD, no HTTP yet. Two units of work: extend `storage` with a single rollback-only method, and create the API package with the two validation functions. Both are deterministic and have zero external dependencies.

### Task 1.1: Add `RestoreRoute` to storage (test first)

**Files:**
- Modify: `internal/storage/storage_test.go` (append test)
- Modify: `internal/storage/routes.go` (append method)

- [ ] **Step 1: Write the failing test**

Append to `internal/storage/storage_test.go`:

```go
func TestRestoreRoute(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	original := Route{
		ID:          "fixed-uuid-for-test",
		Host:        "restore.example",
		UpstreamURL: "http://127.0.0.1:7000",
		TLSEnabled:  true,
		WAFEnabled:  false,
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
	if got.ID != original.ID || got.Host != original.Host ||
		!got.CreatedAt.Equal(original.CreatedAt) ||
		!got.UpdatedAt.Equal(original.UpdatedAt) {
		t.Errorf("restored route differs: got=%+v want=%+v", got, original)
	}

	t.Run("empty id rejected", func(t *testing.T) {
		err := s.RestoreRoute(ctx, Route{Host: "x", UpstreamURL: "http://x:1"})
		if err == nil {
			t.Fatal("expected error for empty ID")
		}
	})
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test -run TestRestoreRoute ./internal/storage/
```
Expected: FAIL — `s.RestoreRoute undefined`.

- [ ] **Step 3: Implement `RestoreRoute`**

Append to `internal/storage/routes.go`:

```go
// RestoreRoute re-inserts an existing Route exactly as supplied, preserving
// the provided ID, CreatedAt and UpdatedAt timestamps.
//
// This method exists ONLY for the rollback path of internal/api when a Caddy
// reload fails after a DELETE. It bypasses the normal CreateRoute lifecycle
// (no UUID generation, no timestamp refresh) precisely to make rollback
// fidelity possible. Do NOT use it for business logic — use CreateRoute or
// UpdateRoute.
func (s *Store) RestoreRoute(ctx context.Context, r Route) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if r.ID == "" {
		return errors.New("route: id must not be empty")
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		buf, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal route: %w", err)
		}
		return tx.Bucket([]byte(bucketRoutes)).Put([]byte(r.ID), buf)
	})
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
go test -race -run TestRestoreRoute ./internal/storage/
```
Expected: PASS.

- [ ] **Step 5: Run the full storage test suite to ensure no regression**

```bash
go test -race -count=1 ./internal/storage/
```
Expected: `ok   github.com/barto95100/arenet/internal/storage`.

- [ ] **Step 6: Commit**

```bash
git add internal/storage/routes.go internal/storage/storage_test.go
git commit -m "$(cat <<'EOF'
Add storage.RestoreRoute for API rollback path

Re-inserts a Route preserving ID, CreatedAt, UpdatedAt for fidelity. Used
only by internal/api when a Caddy reload fails after a DELETE.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

### Task 1.2: Create `internal/api/validation.go` and `validation_test.go`

**Files:**
- Create: `internal/api/validation.go`
- Create: `internal/api/validation_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/api/validation_test.go`:

```go
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
	"strings"
	"testing"
)

func TestValidateHost(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantSub string // expected error substring; empty = expect nil
	}{
		{"valid simple", "test.local", ""},
		{"valid localhost", "localhost", ""},
		{"valid deep", "a.b.c.d.example.com", ""},
		{"empty", "", "must not be empty"},
		{"whitespace only", "   ", "must not be empty"},
		{"internal whitespace", "foo bar.com", "must not contain whitespace"},
		{"leading dash", "-foo.com", "must be a valid hostname"},
		{"underscore", "foo_bar.com", "must be a valid hostname"},
		{"double dot", "foo..bar.com", "must be a valid hostname"},
		{"too long", strings.Repeat("a", 254), "must be a valid hostname"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHost(tc.in)
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q missing substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestValidateUpstreamURL(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantSub string
	}{
		{"valid http", "http://127.0.0.1:9999", ""},
		{"valid https", "https://example.com", ""},
		{"valid https with port", "https://example.com:8443/path", ""},
		{"empty", "", "must not be empty"},
		{"garbage", "not-a-url", "is not a valid URL"},
		{"ftp scheme", "ftp://example.com", "must use http or https scheme"},
		{"file scheme", "file:///etc/passwd", "must use http or https scheme"},
		{"no host", "http:///foo", "must include a host"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUpstreamURL(tc.in)
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q missing substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test ./internal/api/
```
Expected: FAIL — package `api` has no `validateHost` / `validateUpstreamURL`.

- [ ] **Step 3: Implement validation**

Create `internal/api/validation.go`:

```go
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

// Package api exposes the REST admin API for Arenet.
package api

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// hostnameRE is a pragmatic RFC 1123 hostname check: dot-separated labels,
// each label 1-63 chars of alnum + dash, must start and end with alnum.
var hostnameRE = regexp.MustCompile(
	`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`,
)

// validateHost checks that s is non-empty, contains no whitespace, and matches
// a basic hostname grammar. Returns the first failure with a user-facing
// English message.
func validateHost(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("host must not be empty")
	}
	if strings.ContainsFunc(s, unicode.IsSpace) {
		return errors.New("host must not contain whitespace")
	}
	if len(s) > 253 || !hostnameRE.MatchString(s) {
		return errors.New("host must be a valid hostname")
	}
	return nil
}

// validateUpstreamURL checks that s is a parsable absolute URL using the http
// or https scheme and that it carries a host component.
func validateUpstreamURL(s string) error {
	if s == "" {
		return errors.New("upstreamUrl must not be empty")
	}
	u, err := url.ParseRequestURI(s)
	if err != nil {
		return errors.New("upstreamUrl is not a valid URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return errors.New("upstreamUrl must use http or https scheme")
	}
	if u.Host == "" {
		return errors.New("upstreamUrl must include a host")
	}
	return nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
go test -race -count=1 ./internal/api/
```
Expected: PASS for both `TestValidateHost` and `TestValidateUpstreamURL`.

- [ ] **Step 5: Commit**

```bash
git add internal/api/validation.go internal/api/validation_test.go
git commit -m "$(cat <<'EOF'
Add API validation for host and upstream URL

Pragmatic RFC 1123 hostname check (labels 1-63 chars alnum + dash, total
<= 253). UpstreamURL must parse via url.ParseRequestURI, use http or
https, and carry a host.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Chunk 2 — Backend: API handlers + middleware + chi router

This chunk builds `internal/api/` to its full functional surface: error helper, handlers, middleware, router. Uses TDD throughout via `httptest`. CaddyReloader is injected as an interface so a fake reloader can drive the rollback paths.

### Task 2.1: Promote `chi/v5` to a direct dependency

**Files:**
- Modify: `go.mod`

- [ ] **Step 1: Add chi as a direct require**

```bash
go get github.com/go-chi/chi/v5
go mod tidy
```

- [ ] **Step 2: Verify chi appears in the direct `require` block of `go.mod`**

```bash
grep -A1 'require (' go.mod | head -10
```
Expected: `github.com/go-chi/chi/v5 vX.Y.Z` listed without `// indirect`.

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "$(cat <<'EOF'
Promote go-chi/chi/v5 to a direct dependency for the admin API

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

### Task 2.2: Create error helper and `Handler` struct skeleton

**Files:**
- Create: `internal/api/errors.go`
- Create: `internal/api/handler.go`

- [ ] **Step 1: Create `internal/api/errors.go`**

```go
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
	"encoding/json"
	"net/http"
)

// writeError sends an HTTP error response in the canonical Arenet shape:
//
//	{"error": "<message>"}
//
// It also sets Content-Type and the appropriate status code.
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// writeJSON serializes v as JSON with the given status. On marshal failure it
// downgrades to 500 with a fixed message — this is a programmer error, not a
// runtime case the client should reason about.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
```

- [ ] **Step 2: Create `internal/api/handler.go`**

```go
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
	"log/slog"

	"github.com/barto95100/arenet/internal/storage"
)

// CaddyReloader is the subset of internal/caddymgr the API depends on. Defined
// here (consumer side) so tests can inject a fake without booting Caddy.
type CaddyReloader interface {
	ReloadFromStore(ctx context.Context) error
}

// Handler owns the storage + caddy reloader + logger and exposes the HTTP
// handlers for the admin API.
type Handler struct {
	store  *storage.Store
	caddy  CaddyReloader
	logger *slog.Logger
}

// NewHandler constructs a Handler. All arguments must be non-nil.
func NewHandler(store *storage.Store, caddy CaddyReloader, logger *slog.Logger) *Handler {
	if store == nil || caddy == nil || logger == nil {
		panic("api.NewHandler: nil dependency")
	}
	return &Handler{store: store, caddy: caddy, logger: logger}
}

// routeRequest is the wire shape accepted by POST and PUT /routes. JSON tags
// are camelCase per the spec.
type routeRequest struct {
	Host        string `json:"host"`
	UpstreamURL string `json:"upstreamUrl"`
	TLSEnabled  bool   `json:"tlsEnabled"`
	WAFEnabled  bool   `json:"wafEnabled"`
}

// routeResponse is the wire shape returned by GET / POST / PUT /routes. The
// JSON tags must match routeRequest's camelCase scheme.
type routeResponse struct {
	ID          string `json:"id"`
	Host        string `json:"host"`
	UpstreamURL string `json:"upstreamUrl"`
	TLSEnabled  bool   `json:"tlsEnabled"`
	WAFEnabled  bool   `json:"wafEnabled"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

// toResponse converts a storage.Route to its API wire form (RFC 3339
// timestamps).
func toResponse(r storage.Route) routeResponse {
	return routeResponse{
		ID:          r.ID,
		Host:        r.Host,
		UpstreamURL: r.UpstreamURL,
		TLSEnabled:  r.TLSEnabled,
		WAFEnabled:  r.WAFEnabled,
		CreatedAt:   r.CreatedAt.UTC().Format("2006-01-02T15:04:05.999Z07:00"),
		UpdatedAt:   r.UpdatedAt.UTC().Format("2006-01-02T15:04:05.999Z07:00"),
	}
}
```

Note: `panic` in `NewHandler` on nil deps is a programmer-error guard at startup; it is unreachable in production paths and is documented in CLAUDE.md's exception ("never panic outside `main`" — `NewHandler` is called by `main.go`, so this lives in the main-init bubble).

- [ ] **Step 3: Verify it builds**

```bash
go build ./internal/api/
```
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add internal/api/errors.go internal/api/handler.go
git commit -m "$(cat <<'EOF'
Add API Handler skeleton with CaddyReloader interface

Defines the consumer-side CaddyReloader interface for handler injection
in tests. Establishes route wire shape with camelCase JSON tags and the
error helper.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

### Task 2.3: Implement GET handlers (list + get one) — test first

**Files:**
- Create: `internal/api/handler_test.go`
- Create: `internal/api/routes.go` (router + handler methods, growing across tasks)

- [ ] **Step 1: Write the failing test**

Create `internal/api/handler_test.go`:

```go
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
	mu       sync.Mutex
	calls    int
	nextErr  error
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
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
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
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
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

// Used by later tasks; defined here so it's available to subsequent tests
// in this file. Required so the test file compiles incrementally.
var _ = errors.New
```

- [ ] **Step 2: Run — should fail at compile time**

```bash
go test ./internal/api/
```
Expected: compile error — `NewRouter` undefined.

- [ ] **Step 3: Create `internal/api/routes.go` with GET handlers and router skeleton**

```go
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
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/barto95100/arenet/internal/storage"
)

// NewRouter builds the chi router for the admin API. When dev is true a
// permissive CORS middleware is mounted for http://localhost:5173.
func NewRouter(h *Handler, dev bool) chi.Router {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(slogLogger(h.logger))
	r.Use(chimw.Recoverer)
	if dev {
		r.Use(devCORS("http://localhost:5173"))
	}
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/routes", h.listRoutes)
		r.Post("/routes", h.createRoute)
		r.Get("/routes/{id}", h.getRoute)
		r.Put("/routes/{id}", h.updateRoute)
		r.Delete("/routes/{id}", h.deleteRoute)
	})
	return r
}

func (h *Handler) listRoutes(w http.ResponseWriter, r *http.Request) {
	routes, err := h.store.ListRoutes(r.Context())
	if err != nil {
		h.logger.Error("list routes", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list routes")
		return
	}
	out := make([]routeResponse, 0, len(routes))
	for _, rt := range routes {
		out = append(out, toResponse(rt))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) getRoute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rt, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("get route", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to get route")
		return
	}
	writeJSON(w, http.StatusOK, toResponse(rt))
}

// Placeholders so the router compiles. Implemented in later tasks of this
// chunk.
func (h *Handler) createRoute(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "not implemented yet")
}
func (h *Handler) updateRoute(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "not implemented yet")
}
func (h *Handler) deleteRoute(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "not implemented yet")
}
```

- [ ] **Step 4: Create stubbed middleware so the router compiles**

Create `internal/api/middleware.go` with stubs that we'll flesh out in Task 2.7:

```go
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
	"log/slog"
	"net/http"
)

// slogLogger is a placeholder; replaced in Task 2.7 with a proper request
// logger.
func slogLogger(_ *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}

// devCORS is a placeholder; replaced in Task 2.7 with the real CORS impl.
func devCORS(_ string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}
```

- [ ] **Step 5: Run the tests for the GET paths**

```bash
go test -race -run 'TestListRoutes_|TestGetRoute_' ./internal/api/
```
Expected: PASS for the 4 subtests defined here.

- [ ] **Step 6: Commit**

```bash
git add internal/api/handler_test.go internal/api/routes.go internal/api/middleware.go
git commit -m "$(cat <<'EOF'
Wire chi router and implement GET /routes and GET /routes/{id}

CaddyReloader fake supports recording reload calls; middleware stubs are
placeholders for Task 2.7. POST/PUT/DELETE return 501 until later tasks.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

### Task 2.4: Implement POST `/routes` (create) with rollback

**Files:**
- Modify: `internal/api/handler_test.go` (append tests)
- Modify: `internal/api/routes.go` (replace `createRoute`)

- [ ] **Step 1: Write the failing tests**

Append to `internal/api/handler_test.go`:

```go
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
```

- [ ] **Step 2: Run — verify the new tests fail**

```bash
go test -race -run TestCreateRoute_ ./internal/api/
```
Expected: FAIL (handler returns 501).

- [ ] **Step 3: Replace `createRoute` in `internal/api/routes.go`**

```go
func (h *Handler) createRoute(w http.ResponseWriter, r *http.Request) {
	var req routeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := validateHost(req.Host); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateUpstreamURL(req.UpstreamURL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Uniqueness check.
	existing, err := h.store.ListRoutes(r.Context())
	if err != nil {
		h.logger.Error("uniqueness list", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to verify uniqueness")
		return
	}
	for _, rt := range existing {
		if rt.Host == req.Host {
			writeError(w, http.StatusConflict, "host already configured")
			return
		}
	}

	created, err := h.store.CreateRoute(r.Context(), storage.Route{
		Host:        req.Host,
		UpstreamURL: req.UpstreamURL,
		TLSEnabled:  req.TLSEnabled,
		WAFEnabled:  req.WAFEnabled,
	})
	if err != nil {
		h.logger.Error("create route", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create route")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after create — rolling back", "err", err, "id", created.ID)
		if delErr := h.store.DeleteRoute(r.Context(), created.ID); delErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", delErr, "id", created.ID)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, toResponse(created))
}
```

Add `encoding/json` to the imports of `routes.go`.

- [ ] **Step 4: Run the new tests**

```bash
go test -race -run TestCreateRoute_ ./internal/api/
```
Expected: PASS for all five subtests.

- [ ] **Step 5: Run the full API test suite**

```bash
go test -race -count=1 ./internal/api/
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/api/routes.go internal/api/handler_test.go
git commit -m "$(cat <<'EOF'
Implement POST /api/v1/routes with uniqueness check and rollback

Rejects duplicate host (409). Rolls back the DB insert if Caddy reload
fails (500). Validation errors return 400 with the first failing message.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

### Task 2.5: Implement PUT `/routes/{id}` with rollback

**Files:**
- Modify: `internal/api/handler_test.go`
- Modify: `internal/api/routes.go`

- [ ] **Step 1: Write the failing tests**

Append to `handler_test.go`:

```go
func TestUpdateRoute_Success(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{Host: "u.local", UpstreamURL: "http://u:1"})

	body := `{"host":"u.local","upstreamUrl":"http://u:2","tlsEnabled":true,"wafEnabled":false}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if env.caddy.CallCount() != 1 {
		t.Errorf("reload calls = %d", env.caddy.CallCount())
	}
	got, _ := env.store.GetRoute(context.Background(), created.ID)
	if got.UpstreamURL != "http://u:2" || !got.TLSEnabled {
		t.Errorf("not updated: %+v", got)
	}
}

func TestUpdateRoute_NotFound(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"x.local","upstreamUrl":"http://x:1"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/00000000-0000-0000-0000-000000000000", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestUpdateRoute_HostCollision(t *testing.T) {
	env := newTestEnv(t, false)
	_, _ = env.store.CreateRoute(context.Background(), storage.Route{Host: "a.local", UpstreamURL: "http://x:1"})
	target, _ := env.store.CreateRoute(context.Background(), storage.Route{Host: "b.local", UpstreamURL: "http://x:2"})

	// Try to rename b.local → a.local (already taken).
	body := `{"host":"a.local","upstreamUrl":"http://x:2"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+target.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d", rec.Code)
	}
	got, _ := env.store.GetRoute(context.Background(), target.ID)
	if got.Host != "b.local" {
		t.Errorf("target was mutated: %+v", got)
	}
}

func TestUpdateRoute_ReloadFails_Rollback(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{Host: "rb.local", UpstreamURL: "http://old:1"})

	env.caddy.nextErr = errors.New("simulated")
	body := `{"host":"rb.local","upstreamUrl":"http://new:1"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", rec.Code)
	}
	got, _ := env.store.GetRoute(context.Background(), created.ID)
	if got.UpstreamURL != "http://old:1" {
		t.Errorf("rollback failed: upstream=%q", got.UpstreamURL)
	}
}
```

- [ ] **Step 2: Run the tests — they should fail**

```bash
go test -race -run TestUpdateRoute_ ./internal/api/
```
Expected: FAIL.

- [ ] **Step 3: Replace `updateRoute` in `routes.go`**

```go
func (h *Handler) updateRoute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req routeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := validateHost(req.Host); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateUpstreamURL(req.UpstreamURL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	previous, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("get route for update", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load route")
		return
	}

	// Host change must not collide with another route.
	if req.Host != previous.Host {
		existing, err := h.store.ListRoutes(r.Context())
		if err != nil {
			h.logger.Error("uniqueness list (update)", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to verify uniqueness")
			return
		}
		for _, rt := range existing {
			if rt.ID != id && rt.Host == req.Host {
				writeError(w, http.StatusConflict, "host already configured")
				return
			}
		}
	}

	updated, err := h.store.UpdateRoute(r.Context(), storage.Route{
		ID:          id,
		Host:        req.Host,
		UpstreamURL: req.UpstreamURL,
		TLSEnabled:  req.TLSEnabled,
		WAFEnabled:  req.WAFEnabled,
	})
	if err != nil {
		h.logger.Error("update route", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to update route")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after update — rolling back", "err", err, "id", id)
		if _, rbErr := h.store.UpdateRoute(r.Context(), previous); rbErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", rbErr, "id", id)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, toResponse(updated))
}
```

- [ ] **Step 4: Run the tests**

```bash
go test -race -run TestUpdateRoute_ ./internal/api/
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/routes.go internal/api/handler_test.go
git commit -m "$(cat <<'EOF'
Implement PUT /api/v1/routes/{id} with rollback on reload failure

Cross-route host collision detected via ListRoutes. Reload failure
restores the previous Route state via UpdateRoute.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

### Task 2.6: Implement DELETE `/routes/{id}` with `RestoreRoute` rollback

**Files:**
- Modify: `internal/api/handler_test.go`
- Modify: `internal/api/routes.go`

- [ ] **Step 1: Write the failing tests**

Append to `handler_test.go`:

```go
func TestDeleteRoute_Success(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{Host: "d.local", UpstreamURL: "http://u:1"})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/routes/"+created.ID, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if env.caddy.CallCount() != 1 {
		t.Errorf("reload calls = %d", env.caddy.CallCount())
	}
	if _, err := env.store.GetRoute(context.Background(), created.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestDeleteRoute_NotFound(t *testing.T) {
	env := newTestEnv(t, false)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/routes/00000000-0000-0000-0000-000000000000", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestDeleteRoute_ReloadFails_Rollback(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{Host: "rb.local", UpstreamURL: "http://u:1"})

	env.caddy.nextErr = errors.New("simulated")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/routes/"+created.ID, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", rec.Code)
	}
	got, err := env.store.GetRoute(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("rollback failed, GetRoute err=%v", err)
	}
	if !got.CreatedAt.Equal(created.CreatedAt) || !got.UpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("RestoreRoute didn't preserve timestamps: got=%v want=%v", got, created)
	}
}
```

- [ ] **Step 2: Run — verify failures**

```bash
go test -race -run TestDeleteRoute_ ./internal/api/
```
Expected: FAIL.

- [ ] **Step 3: Replace `deleteRoute`**

```go
func (h *Handler) deleteRoute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	previous, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("get route for delete", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load route")
		return
	}

	if err := h.store.DeleteRoute(r.Context(), id); err != nil {
		h.logger.Error("delete route", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to delete route")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after delete — rolling back", "err", err, "id", id)
		if rbErr := h.store.RestoreRoute(r.Context(), previous); rbErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", rbErr, "id", id)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
```

- [ ] **Step 4: Run the tests**

```bash
go test -race -run TestDeleteRoute_ ./internal/api/
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/routes.go internal/api/handler_test.go
git commit -m "$(cat <<'EOF'
Implement DELETE /api/v1/routes/{id} with RestoreRoute rollback

Reload failure restores the Route bit-for-bit (incl. original timestamps)
via storage.RestoreRoute. Returns 204 on success.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

### Task 2.7: Replace stub middlewares with real `slogLogger` and `devCORS`

**Files:**
- Modify: `internal/api/middleware.go`
- Modify: `internal/api/handler_test.go`

- [ ] **Step 1: Write the failing CORS tests**

Append to `handler_test.go`:

```go
func TestCORS_DevMode_Preflight(t *testing.T) {
	env := newTestEnv(t, true) // dev=true

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/routes", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Allow-Origin=%q", got)
	}
	if got := rec.Header().Get("Access-Control-Max-Age"); got != "3600" {
		t.Errorf("Max-Age=%q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "POST") {
		t.Errorf("Allow-Methods=%q", got)
	}
}

func TestCORS_ProdMode_NoHeader(t *testing.T) {
	env := newTestEnv(t, false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin should be empty in prod, got %q", got)
	}
}
```

- [ ] **Step 2: Run — verify the preflight test fails**

```bash
go test -race -run TestCORS_ ./internal/api/
```
Expected: FAIL on `TestCORS_DevMode_Preflight` (current stub returns 404 / no headers).

- [ ] **Step 3: Replace `internal/api/middleware.go`**

```go
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
	"log/slog"
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// slogLogger logs one structured line per request when the handler returns.
func slogLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			dur := time.Since(start)
			level := slog.LevelInfo
			switch {
			case ww.Status() >= 500:
				level = slog.LevelError
			case ww.Status() >= 400:
				level = slog.LevelWarn
			}
			logger.LogAttrs(r.Context(), level, "http request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", ww.Status()),
				slog.Int64("duration_ms", dur.Milliseconds()),
				slog.String("request_id", chimw.GetReqID(r.Context())),
				slog.String("remote_addr", r.RemoteAddr),
			)
		})
	}
}

// devCORS allows preflight + simple requests from allowOrigin. Only mounted
// in dev mode by NewRouter.
func devCORS(allowOrigin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Max-Age", "3600")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
```

- [ ] **Step 4: Run the full API test suite**

```bash
go test -race -count=1 ./internal/api/
```
Expected: PASS for all tests (`TestList*`, `TestGet*`, `TestCreate*`, `TestUpdate*`, `TestDelete*`, `TestCORS_*`, `TestValidate*`).

- [ ] **Step 5: Run `go vet`**

```bash
go vet ./...
```
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add internal/api/middleware.go internal/api/handler_test.go
git commit -m "$(cat <<'EOF'
Implement slogLogger and devCORS middleware

Logger reports method/path/status/duration/request_id/remote_addr with
INFO/WARN/ERROR by status class. devCORS allows http://localhost:5173 in
dev mode only, with Max-Age=3600 to dedupe preflights.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Chunk 3 — Backend: `main.go` wiring + admin server + dev landing

The API package is complete and tested. This chunk plugs it into `main.go`: builds the router, starts an HTTP server on `cfg.adminPort` in a goroutine, orchestrates the ordered shutdown (admin → caddy → store), drains the server error channel, and adds the dev landing page at `GET /` when `--dev` is set.

Verification at this chunk is partly behavioral (smoke test with `curl`), not just unit tests, because `main.go` has no test file.

### Task 3.1: Wire admin HTTP server with graceful shutdown

**Files:**
- Modify: `cmd/arenet/main.go`

- [ ] **Step 1: Read the current `cmd/arenet/main.go`**

Reread to remind yourself of the existing structure (Step B `run()` function).

- [ ] **Step 2: Replace the relevant region of `run()`**

Replace the block between `mgr.Start(ctx)` and the final `<-ctx.Done()` with:

```go
	if err := mgr.Start(ctx); err != nil {
		return err
	}
	defer func() {
		if cerr := mgr.Stop(); cerr != nil {
			logger.Error("caddy stop error", "err", cerr)
			if retErr == nil {
				retErr = cerr
			}
		}
	}()

	apiHandler := api.NewHandler(store, mgr, logger)
	router := api.NewRouter(apiHandler, cfg.dev)

	if cfg.dev {
		router.Get("/", devLandingHandler(cfg.adminPort))
	} else {
		staticFS, ferr := web.StaticFS()
		if ferr != nil {
			return fmt.Errorf("embed: %w", ferr)
		}
		router.Handle("/*", http.FileServer(http.FS(staticFS)))
	}

	adminSrv := &http.Server{
		Addr:              cfg.adminPort,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serverErr := make(chan error, 1)
	go func() {
		if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	httpsActive, err := mgr.HasHTTPSServer(ctx)
	if err != nil {
		return err
	}
	listenAttrs := []any{"http", ":8080", "admin_api", cfg.adminPort}
	if httpsActive {
		listenAttrs = append(listenAttrs, "https", ":8443")
	}
	logger.Info("Arenet listening", listenAttrs...)

	select {
	case <-ctx.Done():
	case err := <-serverErr:
		return fmt.Errorf("admin server: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := adminSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("admin server shutdown error", "err", err)
	}
	if err, ok := <-serverErr; ok && err != nil {
		logger.Error("admin server post-shutdown error", "err", err)
	}
	logger.Info("Arenet shutting down")
	return nil
```

- [ ] **Step 3: Add `devLandingHandler` at the bottom of `main.go`**

```go
// devLandingHandler returns a tiny HTML page guiding the developer to the
// Vite dev server. Only mounted at GET / when --dev is true.
func devLandingHandler(adminPort string) http.HandlerFunc {
	const tmpl = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><title>Arenet (dev)</title>
<style>body{font-family:system-ui;padding:2rem;max-width:40rem;margin:auto;background:#0a0e14;color:#e6edf3}
a{color:#00d9ff}code{background:#1a212b;padding:0.1rem 0.3rem;border-radius:0.2rem}</style>
</head><body>
<h1>Arenet — dev mode</h1>
<p>The admin API is running on <code>%s</code>.</p>
<p>The frontend is served separately by Vite. Open <a href="http://localhost:5173">http://localhost:5173</a>.</p>
</body></html>`
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, tmpl, adminPort)
	}
}
```

- [ ] **Step 4: Update the imports in `main.go`**

Add (or merge) the following imports:

```go
import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/barto95100/arenet/internal/api"
	"github.com/barto95100/arenet/internal/caddymgr"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/barto95100/arenet/web"
)
```

Note: `web` doesn't exist yet — Task 3.2 creates it. So this step **will not compile**; we accept that and complete Task 3.2 before building.

- [ ] **Step 5: Skip build until Task 3.2 is done**

Move on. The repo is temporarily not buildable; this is acceptable inside a single chunk because the two tasks ship in a single logical change.

### Task 3.2: Create the `web` package stub with `//go:embed`

**Files:**
- Create: `web/embed.go`
- Create: `web/frontend/build/.gitkeep`
- Modify: `.gitignore`

- [ ] **Step 1: Create `web/frontend/build/.gitkeep`**

```bash
mkdir -p web/frontend/build
touch web/frontend/build/.gitkeep
```

- [ ] **Step 2: Create `web/embed.go`**

```go
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

// Package web bundles the SvelteKit production build into the Arenet
// binary via go:embed.
package web

import (
	"embed"
	"io/fs"
)

// The "all:" prefix is required because SvelteKit emits files starting with
// "_" (e.g. _app/) which the default //go:embed rules skip. The
// build/.gitkeep file guarantees this directory exists at compile time even
// before the first `npm run build`.
//
//go:embed all:frontend/build
var staticFS embed.FS

// StaticFS returns the embedded SvelteKit build directory rooted at
// frontend/build so that http.FileServer serves it from /.
func StaticFS() (fs.FS, error) {
	return fs.Sub(staticFS, "frontend/build")
}
```

- [ ] **Step 3: Update `.gitignore`**

Append (or replace the existing frontend section):

```
# Frontend
/web/frontend/node_modules/
/web/frontend/.svelte-kit/
/web/frontend/build/
!/web/frontend/build/.gitkeep
/web/frontend/.env
```

- [ ] **Step 4: Verify build now compiles**

```bash
go build ./...
```
Expected: no output.

- [ ] **Step 5: Smoke test the admin API**

Build and run:

```bash
mkdir -p bin && go build -o bin/arenet ./cmd/arenet
./bin/arenet --dev --data-dir ./data &
sleep 1
curl -s http://localhost:8001/api/v1/routes
curl -s -i http://localhost:8001/ | head -5
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"host":"smoke.local","upstreamUrl":"http://127.0.0.1:9000"}' \
  http://localhost:8001/api/v1/routes
curl -s http://localhost:8001/api/v1/routes
kill %1
wait 2>/dev/null
```

Expected:
- First `GET /api/v1/routes` → `[]`
- `GET /` → `200` + HTML containing `Arenet — dev mode`
- `POST` → `201` + JSON of the new route
- Second `GET` → array with the newly created route

- [ ] **Step 6: Run full test suite + vet**

```bash
go test -race -count=1 ./... && go vet ./...
```
Expected: all green.

- [ ] **Step 7: Commit the whole Chunk 3**

```bash
git add cmd/arenet/main.go web/embed.go web/frontend/build/.gitkeep .gitignore
git commit -m "$(cat <<'EOF'
Wire admin HTTP server into main with ordered shutdown

API on cfg.adminPort, dev landing at GET / when --dev is set, otherwise
serve //go:embed all:frontend/build via http.FileServer. Shutdown order:
admin server (with 10s timeout) → caddy → store. serverErr channel is
drained post-Shutdown so late errors are logged. .gitkeep keeps //go:embed
matching before the first npm run build.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Chunk 4 — Frontend: design system foundations

Scaffolds the SvelteKit project, configures Tailwind with the SOC color tokens, installs and self-hosts Inter + JetBrains Mono, sets the root prerender/SSR flags, and verifies the dev server renders **a throwaway smoke page** with the design tokens applied. No components yet.

### Task 4.1: Scaffold the SvelteKit project

**Files:**
- Create: `web/frontend/package.json`, `web/frontend/svelte.config.js`, `web/frontend/vite.config.ts`, `web/frontend/tsconfig.json`, `web/frontend/src/app.html`, `web/frontend/src/app.d.ts`, `web/frontend/src/routes/+layout.ts`, `web/frontend/src/routes/+page.svelte`, etc.

- [ ] **Step 1: Initialize with the official SvelteKit CLI**

The current SvelteKit init command is `npx sv create`. Run from `web/frontend`:

```bash
cd web/frontend
npx --yes sv create . --template minimal --types ts --no-add-ons
```

If the directory contains the `build/.gitkeep` file from Chunk 3, the CLI will refuse. Move it temporarily:

```bash
mv build/.gitkeep ../.gitkeep.tmp
rmdir build
npx --yes sv create . --template minimal --types ts --no-add-ons
mkdir -p build && mv ../.gitkeep.tmp build/.gitkeep
```

- [ ] **Step 2: Install dependencies**

```bash
npm install
```

- [ ] **Step 3: Install adapter-static, Tailwind, PostCSS, autoprefixer**

```bash
npm install --save-dev @sveltejs/adapter-static tailwindcss postcss autoprefixer
```

- [ ] **Step 4: Replace `svelte.config.js`**

```js
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter({
      fallback: '200.html'
    })
  }
};

export default config;
```

- [ ] **Step 5: Replace `vite.config.ts`**

```ts
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  server: {
    port: 5173,
    strictPort: true
  }
});
```

- [ ] **Step 6: Replace `src/routes/+layout.ts`**

```ts
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

export const prerender = true;
export const ssr = false;
```

- [ ] **Step 7: Verify `tsconfig.json` has `"strict": true`**

Inspect `tsconfig.json` — SvelteKit's minimal template extends `.svelte-kit/tsconfig.json`. If `"strict": true` is not already in `compilerOptions`, add it.

- [ ] **Step 8: Verify the dev server starts**

```bash
npm run dev -- --port 5173 &
sleep 3
curl -s http://localhost:5173 | head -5
kill %1
wait 2>/dev/null
```
Expected: HTML output (SvelteKit shell with the default `+page.svelte`).

- [ ] **Step 9: Commit (without committing build/, node_modules/)**

```bash
cd ../..
git add web/frontend/package.json web/frontend/package-lock.json web/frontend/svelte.config.js web/frontend/vite.config.ts web/frontend/tsconfig.json web/frontend/src
git commit -m "$(cat <<'EOF'
Scaffold SvelteKit project (TS strict, adapter-static, SSR off)

prerender=true + ssr=false produces a single hydrated SPA shell suitable
for go:embed serving via http.FileServer.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

### Task 4.2: Configure Tailwind with the SOC token palette

**Files:**
- Create: `web/frontend/tailwind.config.ts`, `web/frontend/postcss.config.js`
- Modify: `web/frontend/src/app.css` (or create if missing), `web/frontend/src/routes/+layout.svelte`

- [ ] **Step 1: Create `tailwind.config.ts`**

```ts
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./src/**/*.{html,js,ts,svelte}'],
  theme: {
    extend: {
      colors: {
        base: 'var(--bg-base)',
        sidebar: 'var(--bg-sidebar)',
        elevated: 'var(--bg-elevated)',
        surface: 'var(--bg-surface)',
        hover: 'var(--bg-hover)',
        'border-subtle': 'var(--border-subtle)',
        'border-default': 'var(--border-default)',
        'border-strong': 'var(--border-strong)',
        primary: 'var(--text-primary)',
        secondary: 'var(--text-secondary)',
        muted: 'var(--text-muted)',
        inverse: 'var(--text-inverse)',
        cyan: 'var(--accent-cyan)',
        'cyan-dark': 'var(--accent-cyan-d)',
        up: 'var(--status-up)',
        warn: 'var(--status-warn)',
        down: 'var(--status-down)',
        info: 'var(--status-info)'
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace']
      },
      fontSize: {
        xs: '12px',
        sm: '14px',
        base: '16px',
        lg: '20px',
        '2xl': '28px',
        '4xl': '36px'
      },
      boxShadow: {
        'glow-cyan': '0 0 16px rgba(0, 217, 255, 0.4)',
        'glow-green': '0 0 12px rgba(0, 255, 136, 0.4)',
        'glow-red': '0 0 12px rgba(255, 71, 87, 0.4)'
      }
    }
  },
  plugins: []
};

export default config;
```

- [ ] **Step 2: Create `postcss.config.js`**

```js
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {}
  }
};
```

- [ ] **Step 3: Create `src/app.css`**

```css
/*
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
*/

@tailwind base;
@tailwind components;
@tailwind utilities;

:root {
  /* Backgrounds */
  --bg-base:        #0a0e14;
  --bg-sidebar:     #060a10;
  --bg-elevated:    #11161f;
  --bg-surface:     #1a212b;
  --bg-hover:       #1f2733;

  /* Borders */
  --border-subtle:  #1f2733;
  --border-default: #2a3441;
  --border-strong:  #3a4554;

  /* Text */
  --text-primary:   #e6edf3;
  --text-secondary: #8b949e;
  --text-muted:     #4a5568;
  --text-inverse:   #0a0e14;

  /* Signature */
  --accent-cyan:    #00d9ff;
  --accent-cyan-d:  #00a8c7;

  /* Status */
  --status-up:      #00ff88;
  --status-warn:    #ffaa00;
  --status-down:    #ff4757;
  --status-info:    #a78bfa;
}

html, body {
  background: var(--bg-base);
  color: var(--text-primary);
  font-family: 'Inter', system-ui, sans-serif;
  min-height: 100vh;
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0s !important;
    transition-duration: 0s !important;
  }
}
```

- [ ] **Step 4: Create `src/routes/+layout.svelte` (imports app.css)**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  import '../app.css';
  let { children } = $props();
</script>

{@render children?.()}
```

- [ ] **Step 5: Replace `src/routes/+page.svelte` with a throwaway smoke page**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.

THROWAWAY SMOKE PAGE — replaced in Chunk 7 with the / → /routes redirect.
-->
<div class="p-8 space-y-4">
  <h1 class="text-4xl font-semibold">Arenet design system smoke</h1>
  <p class="text-secondary text-sm">If you can read this, tokens are wired.</p>

  <div class="grid grid-cols-4 gap-3">
    <div class="p-4 bg-base border border-border-subtle rounded-lg">bg-base</div>
    <div class="p-4 bg-elevated border border-border-subtle rounded-lg">bg-elevated</div>
    <div class="p-4 bg-surface border border-border-default rounded-lg">bg-surface</div>
    <div class="p-4 bg-hover border border-border-strong rounded-lg">bg-hover</div>
  </div>

  <div class="flex gap-2">
    <span class="px-3 py-1 rounded bg-cyan text-inverse">cyan</span>
    <span class="px-3 py-1 rounded bg-up text-inverse">up</span>
    <span class="px-3 py-1 rounded bg-warn text-inverse">warn</span>
    <span class="px-3 py-1 rounded bg-down text-inverse">down</span>
    <span class="px-3 py-1 rounded bg-info text-inverse">info</span>
  </div>

  <div class="shadow-glow-cyan p-4 bg-elevated border border-cyan rounded-lg w-fit">
    shadow-glow-cyan
  </div>

  <p class="font-mono text-sm text-secondary">font-mono test: 192.0.2.1:443</p>
</div>
```

- [ ] **Step 6: Run the dev server and visually verify**

```bash
cd web/frontend
npm run dev &
sleep 3
```

Open `http://localhost:5173` in a browser and confirm:
- Dark background applied (`#0a0e14`).
- 4 color swatches show distinct shades.
- Cyan / up / warn / down / info pills render with the expected hues.
- The cyan-glow box has a visible cyan halo.
- Mono line uses a monospace fallback (Inter and JetBrains Mono come in Task 4.3).

Then kill the dev server: `kill %1; wait 2>/dev/null`.

- [ ] **Step 7: Commit**

```bash
cd ../..
git add web/frontend/tailwind.config.ts web/frontend/postcss.config.js web/frontend/src/app.css web/frontend/src/routes/+layout.svelte web/frontend/src/routes/+page.svelte
git commit -m "$(cat <<'EOF'
Configure Tailwind with SOC color tokens

CSS variables in :root, Tailwind utilities mapped via var() in
tailwind.config.ts. Smoke page in / is throwaway and removed in Chunk 7.
prefers-reduced-motion suppresses all animations globally.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

### Task 4.3: Self-host Inter and JetBrains Mono

**Files:**
- Add: `web/frontend/static/fonts/Inter-{Regular,Medium,SemiBold,Bold}.woff2`, `web/frontend/static/fonts/JetBrainsMono-{Regular,Medium}.woff2`
- Modify: `web/frontend/src/app.css`

- [ ] **Step 1: Download the font files**

Source the official woff2 files from the foundries (rsms / JetBrains). Concrete URLs:

```bash
mkdir -p web/frontend/static/fonts
cd web/frontend/static/fonts

curl -fLO https://rsms.me/inter/font-files/Inter-Regular.woff2
curl -fLO https://rsms.me/inter/font-files/Inter-Medium.woff2
curl -fLO https://rsms.me/inter/font-files/Inter-SemiBold.woff2
curl -fLO https://rsms.me/inter/font-files/Inter-Bold.woff2

curl -fL -o JetBrainsMono-Regular.woff2 \
  https://github.com/JetBrains/JetBrainsMono/raw/master/fonts/webfonts/JetBrainsMono-Regular.woff2
curl -fL -o JetBrainsMono-Medium.woff2 \
  https://github.com/JetBrains/JetBrainsMono/raw/master/fonts/webfonts/JetBrainsMono-Medium.woff2

cd -
ls web/frontend/static/fonts/
```

Expected: 6 woff2 files, all > 10 KB.

- [ ] **Step 2: Add `@font-face` declarations to `src/app.css`**

Prepend (before `@tailwind base`):

```css
@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 400;
  font-display: swap;
  src: url('/fonts/Inter-Regular.woff2') format('woff2');
}
@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 500;
  font-display: swap;
  src: url('/fonts/Inter-Medium.woff2') format('woff2');
}
@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 600;
  font-display: swap;
  src: url('/fonts/Inter-SemiBold.woff2') format('woff2');
}
@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 700;
  font-display: swap;
  src: url('/fonts/Inter-Bold.woff2') format('woff2');
}
@font-face {
  font-family: 'JetBrains Mono';
  font-style: normal;
  font-weight: 400;
  font-display: swap;
  src: url('/fonts/JetBrainsMono-Regular.woff2') format('woff2');
}
@font-face {
  font-family: 'JetBrains Mono';
  font-style: normal;
  font-weight: 500;
  font-display: swap;
  src: url('/fonts/JetBrainsMono-Medium.woff2') format('woff2');
}
```

- [ ] **Step 3: Visually verify in the dev server**

```bash
cd web/frontend
npm run dev &
sleep 3
```

Open `http://localhost:5173`. Smoke page text must now render with Inter (notice the rounded, geometric forms). The mono line `192.0.2.1:443` must render with JetBrains Mono (square zero, distinctive zeros and ones).

Kill: `kill %1; wait 2>/dev/null`.

- [ ] **Step 4: Commit**

```bash
cd ../..
git add web/frontend/static/fonts web/frontend/src/app.css
git commit -m "$(cat <<'EOF'
Self-host Inter and JetBrains Mono webfonts

Six woff2 files served from /fonts/ via SvelteKit static assets.
font-display: swap to avoid invisible text during fetch.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

### Task 4.4: Create the API client and types files

**Files:**
- Create: `web/frontend/src/lib/api/types.ts`, `web/frontend/src/lib/api/client.ts`
- Create: `web/frontend/.env.example`

- [ ] **Step 1: Create `src/lib/api/types.ts`**

```ts
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

export interface Route {
  id: string;
  host: string;
  upstreamUrl: string;
  tlsEnabled: boolean;
  wafEnabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface RouteRequest {
  host: string;
  upstreamUrl: string;
  tlsEnabled: boolean;
  wafEnabled: boolean;
}

/**
 * Discriminated kind of an ApiError so the UI can decide between inline
 * (validation) and toast (system) presentation.
 */
export type ErrorKind = 'validation' | 'system';

export class ApiError extends Error {
  status: number;
  kind: ErrorKind;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
    this.kind = status === 400 || status === 409 ? 'validation' : 'system';
  }
}
```

- [ ] **Step 2: Create `src/lib/api/client.ts`**

```ts
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import type { Route, RouteRequest } from './types';
import { ApiError } from './types';

const BASE: string = (import.meta.env.VITE_API_BASE_URL ?? '') as string;

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method };
  if (body !== undefined) {
    init.headers = { 'Content-Type': 'application/json' };
    init.body = JSON.stringify(body);
  }
  let res: Response;
  try {
    res = await fetch(`${BASE}/api/v1${path}`, init);
  } catch (err) {
    throw new ApiError(`network error: ${(err as Error).message}`, 0);
  }
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const payload = await res.json();
      if (payload && typeof payload.error === 'string') msg = payload.error;
    } catch {
      /* leave default msg */
    }
    throw new ApiError(msg, res.status);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const listRoutes = (): Promise<Route[]> => request<Route[]>('GET', '/routes');
export const getRoute = (id: string): Promise<Route> => request<Route>('GET', `/routes/${id}`);
export const createRoute = (r: RouteRequest): Promise<Route> => request<Route>('POST', '/routes', r);
export const updateRoute = (id: string, r: RouteRequest): Promise<Route> =>
  request<Route>('PUT', `/routes/${id}`, r);
export const deleteRoute = (id: string): Promise<void> => request<void>('DELETE', `/routes/${id}`);
```

- [ ] **Step 3: Create `web/frontend/.env.example`**

```
# Copy to .env for local development.
VITE_API_BASE_URL=http://localhost:8001
```

- [ ] **Step 4: Append a quick smoke test to the throwaway page**

Append to `src/routes/+page.svelte` (inside the same `<div>`):

```svelte
<script lang="ts">
  import { listRoutes } from '$lib/api/client';
  let status = $state('loading...');
  listRoutes()
    .then((rs) => (status = `${rs.length} routes`))
    .catch((e) => (status = `error: ${e.message}`));
</script>

<p class="text-secondary text-sm">API smoke: {status}</p>
```

- [ ] **Step 5: Manual integration test**

Terminal A:
```bash
./bin/arenet --dev --data-dir ./data
```

Terminal B:
```bash
cd web/frontend
cp .env.example .env
npm run dev &
```

Open `http://localhost:5173`. The smoke page should now show `API smoke: 0 routes` (or whatever the current DB state is).

Kill both processes.

- [ ] **Step 6: Commit**

```bash
git add web/frontend/src/lib web/frontend/.env.example
git commit -m "$(cat <<'EOF'
Add typed API client and shared types

ApiError carries a 'kind' discriminant (validation | system) so the page
can decide between inline error and toast presentation per spec §10.5
notification rule.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Chunk 5 — Frontend: atomic components

Seven atomic components: `Button`, `Input`, `Checkbox`, `Badge`, `Spinner`, `StatusDot`, `Card`. Each is mounted on the throwaway smoke page so you can eyeball it before moving on.

### Task 5.1: `Spinner.svelte` and `StatusDot.svelte`

**Files:**
- Create: `web/frontend/src/lib/components/Spinner.svelte`, `StatusDot.svelte`

- [ ] **Step 1: Create `Spinner.svelte`**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  type Size = 'sm' | 'md' | 'lg';
  let { size = 'md' }: { size?: Size } = $props();
  const sizePx = { sm: 14, md: 20, lg: 32 }[size];
</script>

<svg
  width={sizePx}
  height={sizePx}
  viewBox="0 0 24 24"
  fill="none"
  role="status"
  aria-label="Loading"
>
  <circle cx="12" cy="12" r="10" stroke="var(--border-default)" stroke-width="3" />
  <path
    d="M22 12a10 10 0 0 1-10 10"
    stroke="var(--accent-cyan)"
    stroke-width="3"
    stroke-linecap="round"
  >
    <animateTransform
      attributeName="transform"
      type="rotate"
      from="0 12 12"
      to="360 12 12"
      dur="0.9s"
      repeatCount="indefinite"
    />
  </path>
</svg>
```

- [ ] **Step 2: Create `StatusDot.svelte`**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  type Status = 'up' | 'warn' | 'down' | 'info' | 'idle';
  let { status = 'idle' }: { status?: Status } = $props();
  const colorMap: Record<Status, string> = {
    up: 'var(--status-up)',
    warn: 'var(--status-warn)',
    down: 'var(--status-down)',
    info: 'var(--status-info)',
    idle: 'var(--text-muted)'
  };
  const pulse = status !== 'idle';
</script>

<span
  class="inline-block w-2 h-2 rounded-full"
  class:pulse-dot={pulse}
  style:background-color={colorMap[status]}
  aria-label={`Status: ${status}`}
></span>

<style>
  .pulse-dot {
    animation: pulse-status 2s ease-in-out infinite;
  }
  @keyframes pulse-status {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
</style>
```

- [ ] **Step 3: Mount on the smoke page**

Append to `src/routes/+page.svelte`:

```svelte
<script lang="ts">
  import Spinner from '$lib/components/Spinner.svelte';
  import StatusDot from '$lib/components/StatusDot.svelte';
</script>

<div class="flex items-center gap-4">
  <Spinner size="sm" />
  <Spinner size="md" />
  <Spinner size="lg" />
  <StatusDot status="up" />
  <StatusDot status="warn" />
  <StatusDot status="down" />
  <StatusDot status="info" />
  <StatusDot status="idle" />
</div>
```

(Adapt: the page already has a `<script>` — add only the missing imports and the new block.)

- [ ] **Step 4: Visually verify**

`npm run dev`, open `localhost:5173`, confirm 3 spinning circles + 4 pulsing dots + 1 static muted dot.

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/lib/components/Spinner.svelte web/frontend/src/lib/components/StatusDot.svelte web/frontend/src/routes/+page.svelte
git commit -m "Add Spinner and StatusDot atomic components"
```

### Task 5.2: `Button.svelte`

**Files:**
- Create: `web/frontend/src/lib/components/Button.svelte`

- [ ] **Step 1: Create the component**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  import Spinner from './Spinner.svelte';

  type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';
  type Size = 'sm' | 'md' | 'lg';

  let {
    variant = 'primary',
    size = 'md',
    loading = false,
    disabled = false,
    type = 'button',
    onclick,
    children,
    ...rest
  }: {
    variant?: Variant;
    size?: Size;
    loading?: boolean;
    disabled?: boolean;
    type?: 'button' | 'submit' | 'reset';
    onclick?: (e: MouseEvent) => void;
    children?: import('svelte').Snippet;
  } = $props();

  const variantClass: Record<Variant, string> = {
    primary:
      'bg-cyan text-inverse hover:shadow-glow-cyan active:scale-[0.98] focus-visible:ring-cyan',
    secondary:
      'bg-elevated text-primary border border-border-default hover:bg-hover focus-visible:ring-cyan',
    ghost:
      'bg-transparent text-secondary hover:text-primary hover:bg-hover focus-visible:ring-cyan',
    danger:
      'bg-down text-inverse hover:shadow-glow-red active:scale-[0.98] focus-visible:ring-down'
  };
  const sizeClass: Record<Size, string> = {
    sm: 'px-2.5 py-1 text-xs',
    md: 'px-3.5 py-1.5 text-sm',
    lg: 'px-5 py-2 text-base'
  };
</script>

<button
  {type}
  disabled={disabled || loading}
  class="inline-flex items-center justify-center gap-2 rounded-md font-medium transition-all duration-200 ease-out focus-visible:outline-none focus-visible:ring-2 disabled:opacity-50 disabled:cursor-not-allowed {variantClass[variant]} {sizeClass[size]}"
  {onclick}
  {...rest}
>
  {#if loading}
    <Spinner size="sm" />
  {/if}
  {@render children?.()}
</button>
```

- [ ] **Step 2: Mount on the smoke page**

```svelte
<div class="flex flex-wrap gap-3">
  <Button>Primary</Button>
  <Button variant="secondary">Secondary</Button>
  <Button variant="ghost">Ghost</Button>
  <Button variant="danger">Danger</Button>
  <Button loading>Loading</Button>
  <Button disabled>Disabled</Button>
  <Button size="sm">Small</Button>
  <Button size="lg">Large</Button>
</div>
```

(Add `import Button from '$lib/components/Button.svelte';` in the page's script.)

- [ ] **Step 3: Verify**

Dev server up. Confirm: hover on primary shows cyan glow, click momentarily shrinks, danger glows red on hover, loading shows spinner + disabled state.

- [ ] **Step 4: Commit**

```bash
git add web/frontend/src/lib/components/Button.svelte web/frontend/src/routes/+page.svelte
git commit -m "Add Button atomic component (4 variants, 3 sizes, loading)"
```

### Task 5.3: `Input.svelte` and `Checkbox.svelte`

**Files:**
- Create: `web/frontend/src/lib/components/Input.svelte`, `Checkbox.svelte`

- [ ] **Step 1: Create `Input.svelte`**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  let {
    label,
    error,
    value = $bindable(''),
    type = 'text',
    id = `input-${Math.random().toString(36).slice(2, 9)}`,
    placeholder = '',
    ...rest
  }: {
    label?: string;
    error?: string;
    value?: string;
    type?: string;
    id?: string;
    placeholder?: string;
  } = $props();
</script>

<div class="flex flex-col gap-1.5">
  {#if label}
    <label for={id} class="text-sm font-medium text-secondary">{label}</label>
  {/if}
  <input
    {id}
    {type}
    {placeholder}
    bind:value
    class="bg-surface border rounded-md px-3 py-2 text-sm text-primary placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-cyan focus:shadow-glow-cyan transition-shadow"
    class:border-down={error}
    class:border-border-default={!error}
    aria-invalid={error ? 'true' : undefined}
    aria-describedby={error ? `${id}-err` : undefined}
    {...rest}
  />
  {#if error}
    <p id={`${id}-err`} class="text-xs text-down">{error}</p>
  {/if}
</div>
```

- [ ] **Step 2: Create `Checkbox.svelte`**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  let {
    label,
    checked = $bindable(false),
    disabled = false,
    title = '',
    id = `cb-${Math.random().toString(36).slice(2, 9)}`
  }: {
    label?: string;
    checked?: boolean;
    disabled?: boolean;
    title?: string;
    id?: string;
  } = $props();
</script>

<label for={id} class="inline-flex items-center gap-2 cursor-pointer select-none" class:cursor-not-allowed={disabled} {title}>
  <span class="relative inline-block w-4 h-4">
    <input
      {id}
      type="checkbox"
      bind:checked
      {disabled}
      class="absolute inset-0 opacity-0 cursor-pointer disabled:cursor-not-allowed"
    />
    <span
      class="absolute inset-0 rounded border transition-all duration-100"
      class:bg-cyan={checked}
      class:border-cyan={checked}
      class:bg-transparent={!checked}
      class:border-border-default={!checked}
      class:opacity-50={disabled}
    >
      {#if checked}
        <svg viewBox="0 0 16 16" class="w-4 h-4 text-inverse" fill="none">
          <path d="M3 8.5l3 3 7-7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      {/if}
    </span>
  </span>
  {#if label}<span class="text-sm text-primary" class:text-muted={disabled}>{label}</span>{/if}
</label>
```

- [ ] **Step 3: Mount on the smoke page**

```svelte
<div class="flex flex-col gap-3 max-w-sm">
  <Input label="Host" placeholder="example.com" />
  <Input label="Erroring" error="host must not be empty" value="bad input" />
  <Checkbox label="Enable TLS" />
  <Checkbox label="Enable WAF (coming soon)" disabled title="Available in Step F" />
</div>
```

(Add imports.)

- [ ] **Step 4: Verify**

Dev server up. Confirm: input focus shows cyan ring + glow, error input has red border + red message below, checkbox click flips state with smooth transition, disabled checkbox shows muted color + tooltip on hover.

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/lib/components/Input.svelte web/frontend/src/lib/components/Checkbox.svelte web/frontend/src/routes/+page.svelte
git commit -m "Add Input and Checkbox atomic components"
```

### Task 5.4: `Badge.svelte` and `Card.svelte`

**Files:**
- Create: `web/frontend/src/lib/components/Badge.svelte`, `Card.svelte`

- [ ] **Step 1: Create `Badge.svelte`**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  type Variant = 'tls' | 'waf' | 'status-up' | 'status-warn' | 'status-down' | 'neutral';
  let {
    variant = 'neutral',
    children
  }: { variant?: Variant; children?: import('svelte').Snippet } = $props();

  const classes: Record<Variant, string> = {
    tls: 'bg-cyan/15 text-cyan border-cyan/40',
    waf: 'bg-info/15 text-info border-info/40',
    'status-up': 'bg-up/15 text-up border-up/40',
    'status-warn': 'bg-warn/15 text-warn border-warn/40',
    'status-down': 'bg-down/15 text-down border-down/40',
    neutral: 'bg-elevated text-secondary border-border-default'
  };
</script>

<span
  class="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-full border {classes[variant]}"
>
  {@render children?.()}
</span>
```

- [ ] **Step 2: Create `Card.svelte`**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  let {
    padding = 'p-6',
    class: cls = '',
    children
  }: { padding?: string; class?: string; children?: import('svelte').Snippet } = $props();
</script>

<div class="bg-elevated border border-border-subtle rounded-lg {padding} {cls}">
  {@render children?.()}
</div>
```

- [ ] **Step 3: Mount on the smoke page**

```svelte
<div class="flex flex-wrap gap-2">
  <Badge variant="tls">TLS</Badge>
  <Badge variant="waf">WAF</Badge>
  <Badge variant="status-up">Up</Badge>
  <Badge variant="status-warn">Warn</Badge>
  <Badge variant="status-down">Down</Badge>
  <Badge>neutral</Badge>
</div>

<Card class="max-w-md">
  <h2 class="text-lg font-semibold">Card title</h2>
  <p class="text-sm text-secondary">Body text inside a Card.</p>
</Card>
```

- [ ] **Step 4: Verify visually, then commit**

```bash
git add web/frontend/src/lib/components/Badge.svelte web/frontend/src/lib/components/Card.svelte web/frontend/src/routes/+page.svelte
git commit -m "Add Badge and Card atomic components"
```

---

## Chunk 6 — Frontend: composed components

Five composed components, all built on top of Chunk 5 atomics: `StatCard`, `DataTable`, `Modal`, `Toast` (+ `ToastContainer` + `toast.ts` store).

### Task 6.1: `StatCard.svelte`

**Files:**
- Create: `web/frontend/src/lib/components/StatCard.svelte`

- [ ] **Step 1: Create the component**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  import Card from './Card.svelte';

  let {
    label,
    value,
    trend = 0
  }: { label: string; value: string | number; trend?: number } = $props();

  const trendColor =
    trend > 0 ? 'text-up' : trend < 0 ? 'text-down' : 'text-muted';
  const trendArrow = trend > 0 ? '↗' : trend < 0 ? '↘' : '·';
</script>

<Card padding="p-5">
  <p class="text-xs uppercase tracking-wide text-secondary">{label}</p>
  <div class="mt-2 flex items-baseline gap-2">
    <span class="text-4xl font-bold text-primary tabular-nums">{value}</span>
    {#if trend !== 0}
      <span class="text-sm {trendColor}">{trendArrow} {Math.abs(trend)}</span>
    {/if}
  </div>
</Card>
```

- [ ] **Step 2: Mount on the smoke page**

```svelte
<div class="grid grid-cols-4 gap-3 max-w-3xl">
  <StatCard label="Total" value={12} />
  <StatCard label="Active" value={9} trend={2} />
  <StatCard label="TLS" value={4} trend={-1} />
  <StatCard label="WAF" value={0} />
</div>
```

- [ ] **Step 3: Visually verify and commit**

```bash
git add web/frontend/src/lib/components/StatCard.svelte web/frontend/src/routes/+page.svelte
git commit -m "Add StatCard component for the Routes header stats row"
```

### Task 6.2: `DataTable.svelte`

**Files:**
- Create: `web/frontend/src/lib/components/DataTable.svelte`

- [ ] **Step 1: Create the component**

`DataTable` is generic over an item type `T`. It accepts a `headers` array, an `items` array, a `row` snippet that receives one item, and an optional `expanded` snippet that receives the active item when a row is clicked.

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts" generics="T extends { id: string }">
  import type { Snippet } from 'svelte';

  let {
    headers,
    items,
    row,
    expanded
  }: {
    headers: string[];
    items: T[];
    row: Snippet<[T]>;
    expanded?: Snippet<[T]>;
  } = $props();

  let activeId = $state<string | null>(null);
  const toggle = (id: string) => (activeId = activeId === id ? null : id);
</script>

<div class="overflow-hidden border border-border-subtle rounded-lg">
  <table class="w-full text-sm">
    <thead class="bg-sidebar sticky top-0">
      <tr>
        {#each headers as h}
          <th class="px-4 py-3 text-left text-xs uppercase tracking-wide text-secondary font-medium">
            {h}
          </th>
        {/each}
      </tr>
    </thead>
    <tbody>
      {#each items as item (item.id)}
        <tr
          class="border-t border-border-subtle transition-all duration-150 ease-out hover:bg-hover cursor-pointer relative"
          class:bg-hover={activeId === item.id}
          onclick={() => toggle(item.id)}
        >
          <td
            class="absolute left-0 top-0 bottom-0 w-0.5 transition-all duration-150"
            class:bg-cyan={activeId === item.id}
          ></td>
          {@render row(item)}
        </tr>
        {#if activeId === item.id && expanded}
          <tr class="bg-surface">
            <td colspan={headers.length} class="px-6 py-4">
              {@render expanded(item)}
            </td>
          </tr>
        {/if}
      {/each}
    </tbody>
  </table>
</div>
```

- [ ] **Step 2: Mount a smoke instance on the page**

```svelte
<script lang="ts">
  import DataTable from '$lib/components/DataTable.svelte';
  const sampleItems = [
    { id: '1', name: 'first', value: 'foo' },
    { id: '2', name: 'second', value: 'bar' }
  ];
</script>

<DataTable headers={['Name', 'Value']} items={sampleItems}>
  {#snippet row(item)}
    <td class="px-4 py-3 font-medium">{item.name}</td>
    <td class="px-4 py-3 font-mono text-secondary">{item.value}</td>
  {/snippet}
  {#snippet expanded(item)}
    <p class="text-secondary">expanded: {item.name}</p>
  {/snippet}
</DataTable>
```

- [ ] **Step 3: Verify and commit**

Confirm: hover row → bg lights up, click → cyan left bar appears + bg sticks + expanded row renders below; click again → collapses.

```bash
git add web/frontend/src/lib/components/DataTable.svelte web/frontend/src/routes/+page.svelte
git commit -m "Add DataTable composed component (generic, click-to-expand)"
```

### Task 6.3: `Modal.svelte`

**Files:**
- Create: `web/frontend/src/lib/components/Modal.svelte`

- [ ] **Step 1: Create the component**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    open = false,
    title,
    onClose,
    children,
    footer
  }: {
    open?: boolean;
    title: string;
    onClose: () => void;
    children?: Snippet;
    footer?: Snippet;
  } = $props();

  let dialog: HTMLDivElement;

  $effect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    const prev = document.activeElement as HTMLElement | null;
    queueMicrotask(() => dialog?.focus());
    return () => {
      document.removeEventListener('keydown', onKey);
      prev?.focus();
    };
  });
</script>

{#if open}
  <div
    role="presentation"
    class="fixed inset-0 z-50 bg-base/80 backdrop-blur-sm flex items-center justify-center p-4 modal-fade"
    onclick={(e) => {
      if (e.target === e.currentTarget) onClose();
    }}
  >
    <div
      bind:this={dialog}
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
      tabindex="-1"
      class="bg-elevated border border-border-default rounded-lg shadow-2xl w-full max-w-md modal-slide-up focus:outline-none"
    >
      <header class="px-5 py-4 border-b border-border-subtle">
        <h2 id="modal-title" class="text-lg font-semibold">{title}</h2>
      </header>
      <div class="px-5 py-4">{@render children?.()}</div>
      {#if footer}
        <footer class="px-5 py-3 border-t border-border-subtle flex justify-end gap-2">
          {@render footer()}
        </footer>
      {/if}
    </div>
  </div>
{/if}

<style>
  .modal-fade { animation: fade-in 200ms ease-out; }
  .modal-slide-up { animation: slide-up 200ms ease-out; }
  @keyframes fade-in {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  @keyframes slide-up {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
  }
</style>
```

- [ ] **Step 2: Mount a smoke instance**

```svelte
<script lang="ts">
  import Modal from '$lib/components/Modal.svelte';
  let modalOpen = $state(false);
</script>

<Button onclick={() => (modalOpen = true)}>Open modal</Button>
<Modal open={modalOpen} title="Demo modal" onClose={() => (modalOpen = false)}>
  <p>Hello from a modal.</p>
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (modalOpen = false)}>Cancel</Button>
    <Button onclick={() => (modalOpen = false)}>Confirm</Button>
  {/snippet}
</Modal>
```

- [ ] **Step 3: Verify and commit**

Confirm: click "Open modal" → backdrop + dialog slides up from below + fades in over ~200ms. Press Escape → closes. Click outside the dialog → closes. Tab focus stays in the dialog.

```bash
git add web/frontend/src/lib/components/Modal.svelte web/frontend/src/routes/+page.svelte
git commit -m "Add Modal composed component (Escape, click-outside, focus restore)"
```

### Task 6.4: Toast store + `Toast.svelte` + `ToastContainer.svelte`

**Files:**
- Create: `web/frontend/src/lib/stores/toast.ts`, `Toast.svelte`, `ToastContainer.svelte`

- [ ] **Step 1: Create the store**

```ts
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { writable } from 'svelte/store';

export type ToastVariant = 'success' | 'danger' | 'info';
export interface ToastEntry {
  id: number;
  message: string;
  variant: ToastVariant;
}

const TOAST_TTL_MS = 4000;
let nextId = 1;

export const toasts = writable<ToastEntry[]>([]);

export function pushToast(message: string, variant: ToastVariant = 'info'): void {
  const id = nextId++;
  toasts.update((list) => [...list, { id, message, variant }]);
  setTimeout(() => dismissToast(id), TOAST_TTL_MS);
}

export function dismissToast(id: number): void {
  toasts.update((list) => list.filter((t) => t.id !== id));
}
```

- [ ] **Step 2: Create `Toast.svelte`**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  import type { ToastEntry } from '$lib/stores/toast';
  import { dismissToast } from '$lib/stores/toast';

  let { entry }: { entry: ToastEntry } = $props();

  const styles: Record<ToastEntry['variant'], string> = {
    success: 'border-up/40 bg-up/10 text-primary shadow-glow-green',
    danger: 'border-down/40 bg-down/10 text-primary shadow-glow-red',
    info: 'border-cyan/40 bg-cyan/10 text-primary shadow-glow-cyan'
  };
</script>

<div
  role="status"
  class="pointer-events-auto px-4 py-3 rounded-md border bg-elevated min-w-[16rem] max-w-sm toast-slide-in flex items-start gap-3 {styles[entry.variant]}"
>
  <p class="text-sm flex-1">{entry.message}</p>
  <button
    class="text-secondary hover:text-primary text-xs"
    aria-label="Dismiss notification"
    onclick={() => dismissToast(entry.id)}
  >×</button>
</div>

<style>
  .toast-slide-in {
    animation: slide-in 200ms ease-out;
  }
  @keyframes slide-in {
    from { opacity: 0; transform: translateX(20px); }
    to { opacity: 1; transform: translateX(0); }
  }
</style>
```

- [ ] **Step 3: Create `ToastContainer.svelte`**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  import { toasts } from '$lib/stores/toast';
  import Toast from './Toast.svelte';
</script>

<div
  class="pointer-events-none fixed bottom-4 right-4 z-50 flex flex-col gap-2"
  aria-live="polite"
>
  {#each $toasts as entry (entry.id)}
    <Toast {entry} />
  {/each}
</div>
```

- [ ] **Step 4: Wire `ToastContainer` into the layout**

Edit `src/routes/+layout.svelte` to render `ToastContainer` after the children slot:

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  import '../app.css';
  import ToastContainer from '$lib/components/ToastContainer.svelte';
  let { children } = $props();
</script>

{@render children?.()}
<ToastContainer />
```

- [ ] **Step 5: Mount smoke buttons on the page**

```svelte
<div class="flex gap-2">
  <Button variant="secondary" onclick={() => pushToast('Saved successfully', 'success')}>Push success</Button>
  <Button variant="secondary" onclick={() => pushToast('Network error', 'danger')}>Push danger</Button>
  <Button variant="secondary" onclick={() => pushToast('Heads up', 'info')}>Push info</Button>
</div>
```

(Add `import { pushToast } from '$lib/stores/toast';`.)

- [ ] **Step 6: Verify**

Click each button → toast slides in from the right, stacks vertically, auto-dismisses after 4s, can be dismissed manually with ×, the appropriate glow color is applied.

- [ ] **Step 7: Commit**

```bash
git add web/frontend/src/lib/stores web/frontend/src/lib/components/Toast.svelte web/frontend/src/lib/components/ToastContainer.svelte web/frontend/src/routes/+layout.svelte web/frontend/src/routes/+page.svelte
git commit -m "$(cat <<'EOF'
Add toast store + Toast + ToastContainer

ToastContainer is mounted globally in +layout.svelte. pushToast(msg, variant)
queues a notification; auto-dismiss after 4s.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Chunk 7 — Frontend: layout shell + placeholder pages

Builds `Sidebar.svelte` and the real `+layout.svelte` shell, creates the three placeholder pages (`/topology`, `/security`, `/settings`), implements the `/` → `/routes` redirect, persists the sidebar collapse state in `localStorage`, and **removes the throwaway smoke page**.

### Task 7.1: `Sidebar.svelte`

**Files:**
- Create: `web/frontend/src/lib/components/Sidebar.svelte`

- [ ] **Step 1: Create the component**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  import { page } from '$app/state';
  import StatusDot from './StatusDot.svelte';

  let { collapsed = $bindable(false) }: { collapsed?: boolean } = $props();

  type Item = { href: string; label: string; icon: string; disabled?: boolean; tooltip?: string };
  const items: Item[] = [
    { href: '/routes', label: 'Routes', icon: '◉' },
    { href: '/topology', label: 'Topology', icon: '▲', disabled: true, tooltip: 'Coming soon' },
    { href: '/security', label: 'Security', icon: '🛡', disabled: true, tooltip: 'Coming soon' },
    { href: '/settings', label: 'Settings', icon: '⚙', disabled: true, tooltip: 'Coming soon' }
  ];

  const isActive = (href: string) => page.url.pathname === href;
</script>

<aside
  class="flex flex-col bg-sidebar border-r border-border-subtle h-screen sticky top-0 transition-[width] duration-200"
  style:width={collapsed ? '64px' : '256px'}
  aria-label="Primary"
>
  <div class="px-4 py-5 border-b border-border-subtle">
    <span class="font-mono text-base font-bold tracking-widest">
      <span class="text-cyan">A</span><span class:hidden={collapsed}>RENET</span>
    </span>
  </div>

  <nav class="flex-1 py-3 flex flex-col gap-1">
    {#each items as item}
      <a
        href={item.disabled ? undefined : item.href}
        title={item.tooltip ?? item.label}
        class="relative flex items-center gap-3 mx-2 px-3 py-2 rounded-md text-sm transition-colors"
        class:text-primary={isActive(item.href)}
        class:bg-hover={isActive(item.href)}
        class:shadow-glow-cyan={isActive(item.href)}
        class:text-secondary={!isActive(item.href) && !item.disabled}
        class:text-muted={item.disabled}
        class:cursor-not-allowed={item.disabled}
        class:pointer-events-none={item.disabled}
        aria-current={isActive(item.href) ? 'page' : undefined}
      >
        {#if isActive(item.href)}
          <span class="absolute left-0 top-1.5 bottom-1.5 w-1 bg-cyan rounded-r"></span>
        {/if}
        <span class="w-5 text-center text-base" aria-hidden="true">{item.icon}</span>
        <span class:hidden={collapsed}>{item.label}</span>
      </a>
    {/each}
  </nav>

  <div class="px-4 py-3 border-t border-border-subtle flex flex-col gap-2">
    <div class="flex items-center gap-2 text-xs" class:justify-center={collapsed}>
      <StatusDot status="up" />
      <span class:hidden={collapsed} class="text-secondary">Connected</span>
    </div>
    <div class="flex items-center gap-2 text-sm" class:justify-center={collapsed}>
      <span class="inline-block w-6 h-6 rounded-full bg-elevated border border-border-default text-center leading-6">a</span>
      <span class:hidden={collapsed} class="text-primary">admin</span>
    </div>
    <button
      class="text-xs text-secondary hover:text-primary self-start"
      class:self-center={collapsed}
      aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      onclick={() => (collapsed = !collapsed)}
    >{collapsed ? '»' : '« Collapse'}</button>
  </div>
</aside>
```

- [ ] **Step 2: Smoke test**

In `+page.svelte` (still smoke page), render the sidebar alongside the smoke content temporarily:

```svelte
<script lang="ts">
  import Sidebar from '$lib/components/Sidebar.svelte';
  let sbCollapsed = $state(false);
</script>

<div class="flex">
  <Sidebar bind:collapsed={sbCollapsed} />
  <div class="p-6 flex-1">existing smoke content here…</div>
</div>
```

Visually verify: 256px wide, items rendered, Routes is unstyled-active (because we're on /), 3 other items are muted with `cursor-not-allowed`. Click `« Collapse` → width animates to 64px, labels hide.

- [ ] **Step 3: Commit**

```bash
git add web/frontend/src/lib/components/Sidebar.svelte web/frontend/src/routes/+page.svelte
git commit -m "Add Sidebar component (collapse, active highlight, disabled items)"
```

### Task 7.2: Real layout shell + placeholder pages + redirect

**Files:**
- Modify: `web/frontend/src/routes/+layout.svelte`
- Create: `web/frontend/src/routes/routes/+page.svelte`, `topology/+page.svelte`, `security/+page.svelte`, `settings/+page.svelte`
- Replace: `web/frontend/src/routes/+page.svelte` (was smoke page)

- [ ] **Step 1: Replace `+layout.svelte` with the real shell**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import Sidebar from '$lib/components/Sidebar.svelte';
  import ToastContainer from '$lib/components/ToastContainer.svelte';

  let { children } = $props();
  let collapsed = $state(false);

  onMount(() => {
    const stored = localStorage.getItem('arenet.sidebar.collapsed');
    if (stored === 'true') collapsed = true;
  });

  $effect(() => {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('arenet.sidebar.collapsed', String(collapsed));
    }
  });
</script>

<div class="flex min-h-screen">
  <Sidebar bind:collapsed />
  <main class="flex-1 p-6">
    {@render children?.()}
  </main>
</div>
<ToastContainer />
```

- [ ] **Step 2: Replace `src/routes/+page.svelte` with a `/` → `/routes` redirect**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  onMount(() => goto('/routes', { replaceState: true }));
</script>
<p class="text-secondary">Redirecting to /routes…</p>
```

- [ ] **Step 3: Create the Routes placeholder**

Create `src/routes/routes/+page.svelte`:

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<h1 class="text-4xl font-semibold">Routes</h1>
<p class="text-secondary text-sm mt-1">Manage reverse proxy routes.</p>
<p class="mt-8 text-muted">Page content arrives in Chunk 8.</p>
```

- [ ] **Step 4: Create the three other placeholder pages**

`src/routes/topology/+page.svelte`:

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<h1 class="text-4xl font-semibold">Topology</h1>
<p class="text-secondary text-sm mt-1">Live network visualization.</p>
<p class="mt-8 text-muted">Available in Step E.</p>
```

`src/routes/security/+page.svelte`:

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<h1 class="text-4xl font-semibold">Security</h1>
<p class="text-secondary text-sm mt-1">WAF, IP reputation, threats.</p>
<p class="mt-8 text-muted">Coming in a later step.</p>
```

`src/routes/settings/+page.svelte`:

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<h1 class="text-4xl font-semibold">Settings</h1>
<p class="text-secondary text-sm mt-1">Application preferences.</p>
<p class="mt-8 text-muted">Coming in a later step.</p>
```

- [ ] **Step 5: Verify visually**

`npm run dev`. Open `http://localhost:5173/`. Confirm:
- `/` redirects to `/routes`.
- Sidebar shows Routes as active (cyan bar + glow), the 3 others as disabled.
- Clicking disabled items does nothing.
- Manually visiting `/topology`, `/security`, `/settings` renders the placeholders with the sidebar still showing them as disabled (visible but not clickable from the sidebar).
- Collapse toggle persists across reloads.

- [ ] **Step 6: Commit**

```bash
git add web/frontend/src/routes
git commit -m "$(cat <<'EOF'
Wire layout shell + placeholder pages + / -> /routes redirect

Sidebar collapse state persisted via localStorage. Topology, Security,
Settings render placeholders so client-side nav doesn't 404, but sidebar
items remain disabled per spec.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Chunk 8 — Frontend: full Routes page

This is the largest chunk. We split it into 8a (statics + form) and 8b (API wiring + toasts) only if needed; given the size below it is decomposed into 5 sub-tasks already.

### Task 8.1: Routes page skeleton with state + load

**Files:**
- Replace: `web/frontend/src/routes/routes/+page.svelte`

- [ ] **Step 1: Implement the load + empty state**

```svelte
<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import { listRoutes } from '$lib/api/client';
  import type { Route } from '$lib/api/types';
  import { ApiError } from '$lib/api/types';
  import { pushToast } from '$lib/stores/toast';
  import Button from '$lib/components/Button.svelte';
  import Spinner from '$lib/components/Spinner.svelte';

  let routes = $state<Route[]>([]);
  let loading = $state(true);
  let loadError = $state<string | null>(null);

  async function loadRoutes() {
    loading = true;
    loadError = null;
    try {
      routes = await listRoutes();
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : String(err);
      loadError = msg;
      pushToast(msg, 'danger');
    } finally {
      loading = false;
    }
  }

  onMount(loadRoutes);
</script>

<div class="flex items-start justify-between">
  <div>
    <h1 class="text-4xl font-semibold">Routes</h1>
    <p class="text-secondary text-sm mt-1">Manage reverse proxy routes.</p>
  </div>
  <Button onclick={() => alert('form coming in Task 8.3')}>+ Add route</Button>
</div>

{#if loading}
  <div class="flex items-center gap-2 mt-12 text-secondary">
    <Spinner /> Loading routes…
  </div>
{:else if loadError}
  <div class="mt-12 text-down">Failed to load routes: {loadError}</div>
{:else if routes.length === 0}
  <div class="mt-16 flex flex-col items-center text-center gap-4">
    <div class="text-6xl text-muted">◉</div>
    <p class="text-secondary">No routes configured yet.</p>
    <Button onclick={() => alert('form coming in Task 8.3')}>+ Add your first route</Button>
  </div>
{:else}
  <p class="mt-8 text-secondary">{routes.length} routes (stats + table arrive in Task 8.2).</p>
{/if}
```

- [ ] **Step 2: Verify**

Start backend with `--insert-test-route`, start Vite. Open `/routes`. With one test route in the DB, you should see "1 routes (stats + table arrive in Task 8.2)." Stop backend, reload page → "Failed to load routes" + red toast.

- [ ] **Step 3: Commit**

```bash
git add web/frontend/src/routes/routes/+page.svelte
git commit -m "Add Routes page skeleton: load, loading, empty, error states"
```

### Task 8.2: Stats row + DataTable

**Files:**
- Modify: `web/frontend/src/routes/routes/+page.svelte`

- [ ] **Step 1: Compute derived stats and render the table**

Replace the conditional block (`{#if loading}`...`{/if}`) with the version including stats + table:

```svelte
<script lang="ts">
  // ...previous imports
  import StatCard from '$lib/components/StatCard.svelte';
  import DataTable from '$lib/components/DataTable.svelte';
  import StatusDot from '$lib/components/StatusDot.svelte';
  import Badge from '$lib/components/Badge.svelte';

  // ... existing state and loadRoutes()

  const stats = $derived({
    total: routes.length,
    active: routes.length,
    tls: routes.filter((r) => r.tlsEnabled).length,
    waf: routes.filter((r) => r.wafEnabled).length
  });

  function fmtDate(iso: string): string {
    return new Date(iso).toLocaleString();
  }
</script>

<!-- header block unchanged -->

{#if loading}
  ...same as before
{:else if loadError}
  ...same as before
{:else if routes.length === 0}
  ...same as before
{:else}
  <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mt-6">
    <StatCard label="Total Routes" value={stats.total} />
    <StatCard label="Active" value={stats.active} />
    <StatCard label="With TLS" value={stats.tls} />
    <StatCard label="With WAF" value={stats.waf} />
  </div>

  <div class="mt-6">
    <DataTable headers={['Status', 'Host', 'Upstream', 'TLS', 'WAF', 'Actions']} items={routes}>
      {#snippet row(r)}
        <td class="px-4 py-3"><StatusDot status="up" /></td>
        <td class="px-4 py-3 font-mono">{r.host}</td>
        <td class="px-4 py-3 font-mono text-secondary truncate max-w-[16rem]" title={r.upstreamUrl}>{r.upstreamUrl}</td>
        <td class="px-4 py-3">{#if r.tlsEnabled}<Badge variant="tls">TLS</Badge>{:else}<span class="text-muted">—</span>{/if}</td>
        <td class="px-4 py-3">{#if r.wafEnabled}<Badge variant="waf">WAF</Badge>{:else}<span class="text-muted">—</span>{/if}</td>
        <td class="px-4 py-3">
          <div class="flex gap-1">
            <Button variant="ghost" size="sm" onclick={() => alert('edit in 8.3')}>Edit</Button>
            <Button variant="ghost" size="sm" onclick={() => alert('delete in 8.4')}>Delete</Button>
          </div>
        </td>
      {/snippet}
      {#snippet expanded(r)}
        <dl class="grid grid-cols-2 gap-x-6 gap-y-1 text-xs">
          <dt class="text-secondary">ID</dt><dd class="font-mono">{r.id}</dd>
          <dt class="text-secondary">Created</dt><dd class="font-mono">{fmtDate(r.createdAt)}</dd>
          <dt class="text-secondary">Updated</dt><dd class="font-mono">{fmtDate(r.updatedAt)}</dd>
          <dt class="text-secondary">Live traffic</dt><dd class="text-muted">— (coming soon)</dd>
        </dl>
      {/snippet}
    </DataTable>
  </div>
{/if}
```

- [ ] **Step 2: Verify**

With at least one test route in DB, open `/routes`. Confirm: 4 stats cards (Total/Active/TLS/WAF), table with all columns, click row → expanded panel shows ID + timestamps + "Live traffic: — (coming soon)".

- [ ] **Step 3: Commit**

```bash
git add web/frontend/src/routes/routes/+page.svelte
git commit -m "Add stats row and DataTable to Routes page"
```

### Task 8.3: Add/Edit modal with create/update wiring

**Files:**
- Modify: `web/frontend/src/routes/routes/+page.svelte`

- [ ] **Step 1: Add state and handler functions**

In the script block, add:

```ts
import { createRoute, updateRoute } from '$lib/api/client';
import type { RouteRequest } from '$lib/api/types';
import Modal from '$lib/components/Modal.svelte';
import Input from '$lib/components/Input.svelte';
import Checkbox from '$lib/components/Checkbox.svelte';

type FormMode = 'create' | 'edit';
let formOpen = $state(false);
let formMode = $state<FormMode>('create');
let editingId = $state<string | null>(null);
let submitting = $state(false);
let formError = $state<string | null>(null);
let hostError = $state<string | null>(null);
let upstreamError = $state<string | null>(null);

let formData = $state<RouteRequest>({
  host: '',
  upstreamUrl: '',
  tlsEnabled: false,
  wafEnabled: false
});

function openCreate() {
  formMode = 'create';
  editingId = null;
  formData = { host: '', upstreamUrl: '', tlsEnabled: false, wafEnabled: false };
  formError = null;
  hostError = null;
  upstreamError = null;
  formOpen = true;
}

function openEdit(r: Route) {
  formMode = 'edit';
  editingId = r.id;
  formData = {
    host: r.host,
    upstreamUrl: r.upstreamUrl,
    tlsEnabled: r.tlsEnabled,
    wafEnabled: r.wafEnabled
  };
  formError = null;
  hostError = null;
  upstreamError = null;
  formOpen = true;
}

/** Map a server validation message to a specific field, or null if unattributable. */
function fieldFromMessage(msg: string): 'host' | 'upstreamUrl' | null {
  const lower = msg.toLowerCase();
  if (lower.startsWith('host ')) return 'host';
  if (lower.startsWith('upstreamurl ')) return 'upstreamUrl';
  return null;
}

async function submitForm(e: SubmitEvent) {
  e.preventDefault();
  submitting = true;
  formError = null;
  hostError = null;
  upstreamError = null;
  try {
    if (formMode === 'create') {
      await createRoute(formData);
      pushToast('Route created', 'success');
    } else if (editingId) {
      await updateRoute(editingId, formData);
      pushToast('Route updated', 'success');
    }
    formOpen = false;
    await loadRoutes();
  } catch (err) {
    if (err instanceof ApiError && err.kind === 'validation') {
      const field = fieldFromMessage(err.message);
      if (field === 'host') hostError = err.message;
      else if (field === 'upstreamUrl') upstreamError = err.message;
      else formError = err.message;
    } else {
      const msg = err instanceof ApiError ? err.message : String(err);
      pushToast(msg, 'danger');
    }
  } finally {
    submitting = false;
  }
}
```

- [ ] **Step 2: Wire the buttons to call `openCreate` / `openEdit`**

Replace the `alert(...)` placeholders in the page-header `+ Add route` button, the empty-state button, and the row Edit button with the appropriate handlers (`openCreate()`, `openEdit(r)`).

- [ ] **Step 3: Render the modal**

Append after the main `{#if loading}` block:

```svelte
<Modal
  open={formOpen}
  title={formMode === 'create' ? 'Add route' : 'Edit route'}
  onClose={() => (formOpen = false)}
>
  <form onsubmit={submitForm} class="flex flex-col gap-4">
    {#if formError}
      <p class="px-3 py-2 rounded bg-down/10 border border-down/40 text-sm text-down">{formError}</p>
    {/if}
    <Input
      label="Host"
      bind:value={formData.host}
      placeholder="example.local"
      error={hostError ?? undefined}
    />
    <Input
      label="Upstream URL"
      bind:value={formData.upstreamUrl}
      placeholder="http://127.0.0.1:8080"
      error={upstreamError ?? undefined}
    />
    <Checkbox label="Enable TLS" bind:checked={formData.tlsEnabled} />
    <Checkbox
      label="Enable WAF (coming in Step F)"
      bind:checked={formData.wafEnabled}
      disabled
      title="WAF support arrives in Step F"
    />
  </form>
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (formOpen = false)}>Cancel</Button>
    <Button onclick={(e) => submitForm(e as unknown as SubmitEvent)} loading={submitting}>
      {formMode === 'create' ? 'Create' : 'Save'}
    </Button>
  {/snippet}
</Modal>
```

Note: the footer's Submit button replicates the form `onsubmit` because the modal's footer is rendered outside the `<form>`. The Submit button manually triggers `submitForm`.

- [ ] **Step 4: Manual integration test**

With backend up:
1. Click `+ Add route`, leave host empty, click Create → inline red error under Host. No toast.
2. Set host to a valid value with bad upstreamUrl → red error under Upstream URL.
3. Set both valid → modal closes, table refreshes with the new route, green toast "Route created".
4. Create another route with the same host → 409, inline red error on Host saying "host already configured".
5. Stop the backend, try Create → red toast "network error: ...".
6. Restart backend. Click Edit on a row → form opens prefilled, change upstreamUrl, Save → green toast, table refreshes.

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/routes/routes/+page.svelte
git commit -m "$(cat <<'EOF'
Wire Add/Edit modal with field-level errors and toasts

Validation errors (400/409) render inline; system errors (500/network)
surface as red toasts. Success mutations show a green toast and trigger
a list refetch.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

### Task 8.4: Delete confirmation modal

**Files:**
- Modify: `web/frontend/src/routes/routes/+page.svelte`

- [ ] **Step 1: Add state and handler**

In the script block:

```ts
import { deleteRoute } from '$lib/api/client';

let confirmTarget = $state<Route | null>(null);
let deleting = $state(false);

async function confirmDelete() {
  if (!confirmTarget) return;
  deleting = true;
  try {
    await deleteRoute(confirmTarget.id);
    pushToast('Route deleted', 'success');
    confirmTarget = null;
    await loadRoutes();
  } catch (err) {
    const msg = err instanceof ApiError ? err.message : String(err);
    pushToast(msg, 'danger');
  } finally {
    deleting = false;
  }
}
```

- [ ] **Step 2: Replace the row Delete `onclick`**

```svelte
<Button variant="ghost" size="sm" onclick={() => (confirmTarget = r)}>Delete</Button>
```

- [ ] **Step 3: Render the confirmation modal**

```svelte
<Modal
  open={confirmTarget !== null}
  title="Delete route"
  onClose={() => (confirmTarget = null)}
>
  {#if confirmTarget}
    <p class="text-sm">
      Are you sure you want to delete the route for
      <code class="font-mono text-cyan">{confirmTarget.host}</code>?
    </p>
    <p class="text-xs text-secondary mt-2">
      Caddy will be reloaded immediately. This action cannot be undone.
    </p>
  {/if}
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (confirmTarget = null)}>Cancel</Button>
    <Button variant="danger" loading={deleting} onclick={confirmDelete}>Delete</Button>
  {/snippet}
</Modal>
```

- [ ] **Step 4: Manual integration test**

With backend up: click Delete on a row → modal pops with the host name → Cancel closes without action; Delete shows spinner, then green toast "Route deleted", table refreshes.

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/routes/routes/+page.svelte
git commit -m "Add delete confirmation modal for Routes page"
```

### Task 8.5: Global loading bar

**Files:**
- Create: `web/frontend/src/lib/stores/loading.ts`
- Modify: `web/frontend/src/lib/api/client.ts`
- Modify: `web/frontend/src/routes/+layout.svelte`

- [ ] **Step 1: Create the loading counter store**

```ts
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { writable, derived } from 'svelte/store';

const counter = writable(0);

export const loading = derived(counter, ($c) => $c > 0);

export function beginRequest(): void {
  counter.update((c) => c + 1);
}
export function endRequest(): void {
  counter.update((c) => Math.max(0, c - 1));
}
```

- [ ] **Step 2: Instrument the API client**

Wrap the `request` function in `client.ts`:

```ts
import { beginRequest, endRequest } from '$lib/stores/loading';

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  beginRequest();
  try {
    // ...existing body unchanged
  } finally {
    endRequest();
  }
}
```

- [ ] **Step 3: Render the bar in the layout**

In `src/routes/+layout.svelte`, add inside `<main>` at the top:

```svelte
<script lang="ts">
  // ...existing imports
  import { loading } from '$lib/stores/loading';
</script>

<div class="flex min-h-screen">
  <Sidebar bind:collapsed />
  <main class="flex-1 p-6 relative">
    {#if $loading}
      <div class="absolute left-0 right-0 top-0 h-0.5 overflow-hidden">
        <div class="h-full w-1/3 bg-cyan loading-shimmer"></div>
      </div>
    {/if}
    {@render children?.()}
  </main>
</div>
<ToastContainer />

<style>
  .loading-shimmer {
    animation: shimmer 1.5s ease-in-out infinite;
  }
  @keyframes shimmer {
    0% { transform: translateX(-100%); }
    100% { transform: translateX(400%); }
  }
</style>
```

- [ ] **Step 4: Verify**

Throttle the network in DevTools to Slow 3G. Trigger Create → cyan shimmer slides across the top during the request. Stop throttling.

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/lib/stores/loading.ts web/frontend/src/lib/api/client.ts web/frontend/src/routes/+layout.svelte
git commit -m "Add global loading shimmer driven by in-flight API request counter"
```

---

## Chunk 9 — Integration, embed, screenshots, acceptance

Final chunk. Update the Makefile, write the frontend README, do a clean build, and verify each acceptance criterion from §17.

### Task 9.1: Update Makefile

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: Replace the existing Makefile**

```makefile
# Arenet - Homelab-friendly reverse proxy with integrated security
# Copyright (C) 2026  Ludovic Ramos
# Licensed under the GNU AGPLv3. See LICENSE for details.

BINARY      := arenet
CMD_PKG     := ./cmd/arenet
BUILD_DIR   := bin
DATA_DIR    := ./data
FRONTEND    := web/frontend

GOFLAGS     ?=
LDFLAGS     ?=

.PHONY: all build frontend run dev-frontend test clean fmt vet help

all: build

## frontend: Build the SvelteKit static bundle into web/frontend/build/
frontend:
	cd $(FRONTEND) && npm install && npm run build

## build: Build frontend then the arenet binary into $(BUILD_DIR)/
build: frontend
	@mkdir -p $(BUILD_DIR)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) $(CMD_PKG)

## run: Build and run arenet in dev mode (does NOT start Vite)
run: build
	@mkdir -p $(DATA_DIR)
	$(BUILD_DIR)/$(BINARY) --dev --data-dir $(DATA_DIR)

## dev-frontend: Start Vite dev server on :5173 (run alongside `make run`)
dev-frontend:
	cd $(FRONTEND) && npm run dev

## test: Run all unit tests with race detector
test:
	go test -race -count=1 ./...

## clean: Remove Go and frontend build artifacts (keeps build/.gitkeep)
clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(FRONTEND)/.svelte-kit
	find $(FRONTEND)/build -mindepth 1 -not -name '.gitkeep' -delete 2>/dev/null || true
	go clean -cache -testcache

## fmt: Format all Go source files
fmt:
	gofmt -s -w .

## vet: Run go vet on all Go packages
vet:
	go vet ./...

## help: Print this help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed -e 's/## //'
```

- [ ] **Step 2: Verify `make build` runs end-to-end**

```bash
make clean
make build
ls bin/arenet
ls web/frontend/build/_app
```
Expected: binary exists, `_app/` directory exists in the build output (proves the `all:` embed prefix is needed).

- [ ] **Step 3: Verify the embed actually contains the build**

```bash
./bin/arenet --data-dir ./data &
sleep 1
curl -s -o /tmp/index.html -w '%{http_code}\n' http://localhost:8001/
grep -c '<html' /tmp/index.html
kill %1
wait 2>/dev/null
```
Expected: HTTP `200`, at least 1 `<html` match.

- [ ] **Step 4: Commit**

```bash
git add Makefile
git commit -m "Update Makefile: frontend, dev-frontend, build chains, safe clean"
```

### Task 9.2: Write the frontend README

**Files:**
- Create: `web/frontend/README.md`

- [ ] **Step 1: Create the README**

```markdown
# Arenet Admin UI

SvelteKit frontend for the Arenet admin API.

## Prerequisites

- Node.js ≥ 20
- The Go binary running on `:8001` (see top-level `make run`)

## Local development

```bash
cd web/frontend
cp .env.example .env       # VITE_API_BASE_URL=http://localhost:8001
npm install
npm run dev
```

In a separate terminal:

```bash
make run                   # starts Arenet with --dev on :8001
```

Open `http://localhost:5173`. Vite serves the UI; the API calls go to
`:8001` and CORS allows the cross-origin requests because the binary is
in `--dev` mode.

## Production build

```bash
npm run build
```

This emits a static SPA into `web/frontend/build/`. The Go binary embeds
that directory via `//go:embed all:frontend/build` (see `web/embed.go`).
Run `make build` from the repository root for the full end-to-end build.

## Stack

- SvelteKit 2 / Svelte 5, TypeScript strict
- Tailwind CSS (tokens defined as CSS variables in `src/app.css`)
- `@sveltejs/adapter-static` with `fallback: '200.html'` (SPA mode)
- Self-hosted Inter + JetBrains Mono fonts under `static/fonts/`
- No automated tests yet — visual validation only this step. Vitest is
  planned for Step E together with D3 / WebSocket work.

## Layout

```
src/
├── app.css                 Tailwind + CSS variables + @font-face
├── routes/
│   ├── +layout.svelte      Sidebar shell + ToastContainer + loading bar
│   ├── +page.svelte        / → /routes redirect
│   ├── routes/+page.svelte The Routes management page
│   ├── topology/+page.svelte
│   ├── security/+page.svelte
│   └── settings/+page.svelte
└── lib/
    ├── api/                client.ts, types.ts
    ├── stores/             toast.ts, loading.ts
    └── components/         Sidebar, Button, Modal, Input, …
```
```

- [ ] **Step 2: Commit**

```bash
git add web/frontend/README.md
git commit -m "Add web/frontend/README"
```

### Task 9.3: Final acceptance verification

This is not a code task; it's a checklist tied to spec §17. Walk it end-to-end on a clean clone-like state.

- [ ] **Step 1: Acceptance 1 — `make build` produces a single binary**

```bash
make clean && make build
file bin/arenet
```
Expected: `bin/arenet: Mach-O 64-bit executable` (or platform equivalent).

- [ ] **Step 2: Acceptance 2 — `--insert-test-route` boots cleanly**

```bash
./bin/arenet --dev --insert-test-route --data-dir ./data &
sleep 1
```
Expected log lines contain `Arenet listening http=:8080 admin_api=:8001 https=:8443` (https only if TLS-enabled route).

- [ ] **Step 3: Acceptance 3 — UI in dev mode**

```bash
cd web/frontend && npm run dev &
sleep 3
```
Open `http://localhost:5173`. Verify visually:
- Sidebar present, Routes active with cyan bar + glow.
- Stats row, table with the test route, click expands.
- `+ Add route` opens modal, validation errors render inline, success pushes green toast and refreshes.
- Delete shows confirmation modal, success pushes toast.

- [ ] **Step 4: Acceptance 4 — placeholder pages reachable**

Manually visit `/topology`, `/security`, `/settings` in the browser. Each renders a placeholder heading + "Available in …" text. No 404s.

- [ ] **Step 5: Acceptance 5 — proxy works**

```bash
echo '127.0.0.1 test.local' | sudo tee -a /etc/hosts
python3 -m http.server 9999 &
sleep 1
curl -s -o /dev/null -w '%{http_code}\n' http://test.local:8080/
```
Expected: `200` (or whatever the upstream serves).

- [ ] **Step 6: Acceptance 6 + 7 — curls against the API**

```bash
curl -s -i http://localhost:8001/api/v1/routes | head -5
curl -s -i -X POST -H 'Content-Type: application/json' \
  -d '{"host":"","upstreamUrl":"http://x"}' \
  http://localhost:8001/api/v1/routes
```
Expected: JSON list + `HTTP/1.1 400` body `{"error":"host must not be empty"}`.

- [ ] **Step 7: Acceptance 8 — full test suite green**

Kill running processes first, then:

```bash
go test -race -count=1 ./... && go vet ./...
```
Expected: PASS + no vet output.

- [ ] **Step 8: Acceptance 10 — ordered shutdown**

With `./bin/arenet --dev --insert-test-route` running in the foreground, press `Ctrl+C`. Expected log order (within a few ms each):

1. `Arenet shutting down`
2. (any in-flight admin requests drained)
3. `Caddy stopped`
4. (process exits cleanly with code 0)

- [ ] **Step 9: Acceptance 11 — reduced motion**

In Chrome DevTools → Rendering → "Emulate CSS media feature `prefers-reduced-motion`" set to `reduce`. Refresh. Confirm: StatusDot no longer pulses, button hover no longer animates the glow transition (it appears instantly), modal opens without slide-up. Layout remains usable.

- [ ] **Step 10: Final commit**

If any small polish fixes came out of acceptance verification, commit them now. Otherwise:

```bash
git log --oneline | head -25
```
Expected: a clean linear history with one commit per major task across Chunks 1–9.

### Task 9.4: Save manual screenshots for the spec record (optional but recommended)

**Files:**
- Add: `docs/superpowers/screenshots/2026-05-15-step-c-*.png` (your captures)

- [ ] **Step 1: Capture screenshots of:**

  - Empty Routes page (no routes configured)
  - Routes page with 3 routes + one row expanded
  - Add route modal (open)
  - Validation error on Host field
  - Delete confirmation modal
  - Sidebar collapsed (64px)
  - A red toast for a system error
  - A green toast for a successful creation

- [ ] **Step 2: Commit if the user wants screenshots tracked**

```bash
git add docs/superpowers/screenshots/
git commit -m "Add Step C UI screenshots for archival"
```

---

## End

When all chunks are complete and the §17 acceptance verification in Task 9.3 is green, Step C is done. The next session (Step D — authentication) starts from this baseline.
