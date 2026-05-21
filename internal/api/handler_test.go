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

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
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

func (f *fakeReloader) SetNextErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextErr = err
}

// fakeAuditAppender records Append calls for assertion. Safe for
// concurrent use; mirrors the interface defined in handler.go.
type fakeAuditAppender struct {
	mu      sync.Mutex
	events  []audit.Event
	nextErr error
}

func (f *fakeAuditAppender) Append(ctx context.Context, evt audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, evt)
	return f.nextErr
}

// List returns a copy of the captured events. Pagination is minimal
// (Limit honored, Cursor ignored) — sufficient for handler tests
// that don't exercise cursor behavior. Filter fields ActorUserID,
// Action, TargetType, TargetID are applied; From/To are honored.
func (f *fakeAuditAppender) List(_ context.Context, filter audit.Filter) ([]audit.Event, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]audit.Event, 0)
	for _, e := range f.events {
		if filter.ActorUserID != "" && e.ActorUserID != filter.ActorUserID {
			continue
		}
		if filter.Action != "" && e.Action != filter.Action {
			continue
		}
		if filter.TargetType != "" && e.TargetType != filter.TargetType {
			continue
		}
		if filter.TargetID != "" && e.TargetID != filter.TargetID {
			continue
		}
		if !filter.From.IsZero() && e.Timestamp.Before(filter.From) {
			continue
		}
		if !filter.To.IsZero() && !e.Timestamp.Before(filter.To) {
			continue
		}
		out = append(out, e)
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, "", nil
}

func (f *fakeAuditAppender) Events() []audit.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]audit.Event, len(f.events))
	copy(out, f.events)
	return out
}

func (f *fakeAuditAppender) SetNextErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextErr = err
}

type testEnv struct {
	router     http.Handler
	store      *storage.Store
	caddy      *fakeReloader
	audit      *fakeAuditAppender
	setupToken *SetupTokenHolder
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
	auditAppender := &fakeAuditAppender{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Step D dependencies. Tests that don't exercise auth flows
	// receive functional but defaulted instances. HIBP is disabled
	// via env var so no network calls are made; the env scope is
	// limited to this t via t.Setenv.
	t.Setenv("ARENET_HIBP_DISABLED", "true")
	userStore := auth.NewUserStore(store.DB())
	sessionStore := auth.NewSessionStore(store.DB())
	hibpClient := auth.NewHIBPClient()
	rateLimiter := auth.NewRateLimiter(logger)
	setupTokenHolder := NewSetupTokenHolder()
	ipExtractor, _ := auth.NewIPExtractor("")

	h := NewHandler(store, caddy, auditAppender, userStore, sessionStore, hibpClient, rateLimiter, setupTokenHolder, dev, logger)
	rawRouter := NewRouter(h, dev, ipExtractor, nil /* ws topology handler not exercised here */)

	// Step C tests predate hard-auth gating on /routes; they hit the
	// router without a cookie. To avoid touching every Step C test,
	// we wrap the router: if a request has no arenet_session cookie,
	// we synthesize a freshly-bootstrapped admin session and inject it.
	// Step D auth tests (e.g., TestLogin*, TestSetup_403*) make their
	// own requests directly via the raw router via env.rawRouter or
	// by setting the cookie explicitly.
	autoAuth := newAutoAuthRouter(t, rawRouter, store, sessionStore, userStore)
	return &testEnv{
		router:     autoAuth,
		store:      store,
		caddy:      caddy,
		audit:      auditAppender,
		setupToken: setupTokenHolder,
	}
}

// newAutoAuthRouter wraps the raw router so any request lacking the
// arenet_session cookie gets one synthesized. The wrapper bootstraps
// a real admin user + session on first use and reuses the same
// session for subsequent unauthenticated requests within the same
// test. This preserves the Step C contract "every test starts with
// a working router" without forcing every test to bootstrap auth.
func newAutoAuthRouter(t *testing.T, raw http.Handler, store *storage.Store, ss *auth.SessionStore, us *auth.UserStore) http.Handler {
	t.Helper()
	var (
		ready         bool
		sessionCookie string
		mu            sync.Mutex
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Step D auth subtree: do not auto-authenticate; tests there
		// drive their own flow.
		if strings.HasPrefix(r.URL.Path, "/api/v1/auth") {
			raw.ServeHTTP(w, r)
			return
		}
		if _, err := r.Cookie(sessionCookieName); err == nil {
			raw.ServeHTTP(w, r)
			return
		}
		// Lazy bootstrap on first call without cookie.
		mu.Lock()
		if !ready {
			ctx := context.Background()
			u, err := us.Create(ctx, "tester", "Tester", "test-password-15c-xx")
			if err != nil {
				mu.Unlock()
				t.Fatalf("autoAuth: bootstrap user: %v", err)
			}
			sess, err := ss.Create(ctx, u.ID, false, "127.0.0.1", "test/1")
			if err != nil {
				mu.Unlock()
				t.Fatalf("autoAuth: bootstrap session: %v", err)
			}
			sessionCookie = sess.ID
			ready = true
		}
		mu.Unlock()
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
		raw.ServeHTTP(w, r)
	})
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

// Step I.1: redirectToHttps is a new wire field added with the
// ACME work. The default zero value (false) keeps the pre-Step-I.1
// behavior; explicit true must round-trip through create → store →
// response.
func TestCreateRoute_AcceptsRedirectToHTTPS(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"host":"redir.local","upstreamUrl":"http://127.0.0.1:9000","tlsEnabled":true,"redirectToHttps":true,"wafEnabled":false}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	// Store persists the field.
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 || !got[0].RedirectToHTTPS {
		t.Errorf("store RedirectToHTTPS = %v; want true. routes=%+v", got[0].RedirectToHTTPS, got)
	}
	// Response includes the field.
	if !strings.Contains(rec.Body.String(), `"redirectToHttps":true`) {
		t.Errorf("response body missing redirectToHttps=true: %s", rec.Body)
	}
}

// --- Step I.3 — Alias hostnames -------------------------------------------

func TestCreateRoute_AcceptsAliases(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"primary.local","upstreamUrl":"http://127.0.0.1:9000","tlsEnabled":false,"redirectToHttps":false,"aliases":["alt1.local","alt2.local"],"wafEnabled":false}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 || len(got[0].Aliases) != 2 {
		t.Fatalf("aliases not persisted: routes=%+v", got)
	}
	if got[0].Aliases[0] != "alt1.local" || got[0].Aliases[1] != "alt2.local" {
		t.Errorf("aliases ordering wrong: %v", got[0].Aliases)
	}
	// Response wire shape: aliases must be present as an array.
	if !strings.Contains(rec.Body.String(), `"aliases":["alt1.local","alt2.local"]`) {
		t.Errorf("response missing aliases array: %s", rec.Body)
	}
}

func TestCreateRoute_RejectsInvalidAlias(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"primary.local","upstreamUrl":"http://127.0.0.1:9000","tlsEnabled":false,"redirectToHttps":false,"aliases":["not a hostname"],"wafEnabled":false}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `not a hostname`) {
		t.Errorf("body should quote the offending alias: %s", rec.Body)
	}
}

func TestCreateRoute_RejectsIntraRouteDuplicate(t *testing.T) {
	env := newTestEnv(t, false)
	// Two identical aliases in the same request — defense-in-depth
	// before storage sees the route.
	body := `{"host":"primary.local","upstreamUrl":"http://127.0.0.1:9000","tlsEnabled":false,"redirectToHttps":false,"aliases":["dup.local","dup.local"],"wafEnabled":false}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `duplicates within the same route`) {
		t.Errorf("body=%s", rec.Body)
	}
}

func TestCreateRoute_RejectsCrossRouteDuplicate(t *testing.T) {
	env := newTestEnv(t, false)
	// Seed an existing route with Host=x.com; a new route trying to
	// claim it as an alias must fail with a 409.
	seeded, err := env.store.CreateRoute(context.Background(), storage.Route{Host: "x.local", UpstreamURL: "http://127.0.0.1:9000"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := `{"host":"other.local","upstreamUrl":"http://127.0.0.1:9001","tlsEnabled":false,"redirectToHttps":false,"aliases":["x.local"],"wafEnabled":false}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s; want 409", rec.Code, rec.Body)
	}
	// Conflict message names BOTH the host and the owning route ID.
	if !strings.Contains(rec.Body.String(), `x.local`) || !strings.Contains(rec.Body.String(), seeded.ID) {
		t.Errorf("body should cite host + owner: %s", rec.Body)
	}
}

func TestUpdateRoute_AllowsKeepingSameAliases(t *testing.T) {
	env := newTestEnv(t, false)
	created, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "primary.local", UpstreamURL: "http://127.0.0.1:9000",
		Aliases: []string{"alt.local"},
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	// PUT with the exact same (Host + Aliases) must NOT trigger a
	// false-positive duplicate error — the hostnamesEqual short-circuit
	// is the guard against the obvious bug of "comparing to self".
	body := `{"host":"primary.local","upstreamUrl":"http://127.0.0.1:9001","tlsEnabled":false,"redirectToHttps":false,"aliases":["alt.local"],"wafEnabled":false}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200 (no duplicate on self)", rec.Code, rec.Body)
	}
}

// Step I.1: an update flipping redirectToHttps back to false must
// persist the change (catches the bug of forgetting the field in
// updateRoute's storage.Route construction).
func TestUpdateRoute_PreservesRedirectToHTTPS(t *testing.T) {
	env := newTestEnv(t, false)
	// Seed: a route with redirect on.
	created, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "flip.local", UpstreamURL: "http://127.0.0.1:9000",
		TLSEnabled: true, RedirectToHTTPS: true,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := `{"host":"flip.local","upstreamUrl":"http://127.0.0.1:9000","tlsEnabled":true,"redirectToHttps":false,"wafEnabled":false}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	got, err := env.store.GetRoute(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.RedirectToHTTPS {
		t.Errorf("RedirectToHTTPS not flipped to false; got route = %+v", got)
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
	// Step I.3: the conflict message now identifies BOTH the conflicting
	// hostname and the owning route ID (the wider check covers aliases too,
	// so the message must disambiguate which host triggered the collision).
	// The body is JSON, so the quotes around dup.local are backslash-
	// escaped — match the substring without the surrounding quotes.
	if !strings.Contains(rec.Body.String(), `dup.local`) || !strings.Contains(rec.Body.String(), `already configured`) {
		t.Errorf("body=%s", rec.Body)
	}
}

func TestCreateRoute_ReloadFails_Rollback(t *testing.T) {
	env := newTestEnv(t, false)
	env.caddy.SetNextErr(errors.New("simulated reload failure"))

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
	if env.caddy.CallCount() != 0 {
		t.Errorf("reload should not have been called on 404, got %d", env.caddy.CallCount())
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

	env.caddy.SetNextErr(errors.New("simulated"))
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
	if env.caddy.CallCount() != 0 {
		t.Errorf("reload should not have been called on 404, got %d", env.caddy.CallCount())
	}
}

func TestDeleteRoute_ReloadFails_Rollback(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{Host: "rb.local", UpstreamURL: "http://u:1"})

	env.caddy.SetNextErr(errors.New("simulated"))
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
	// Allow-Credentials must be "true" so the Vite dev server at :5173
	// can send the arenet_session cookie via fetch credentials:'include'.
	// Wildcard origins are incompatible with credentials, hence the
	// explicit allowOrigin in devCORS (verified above).
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Allow-Credentials=%q want %q", got, "true")
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

func TestCORS_DevMode_ActualRequest(t *testing.T) {
	env := newTestEnv(t, true) // dev=true

	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Allow-Origin on GET in dev mode=%q, want http://localhost:5173", got)
	}
	if got := rec.Header().Get("Access-Control-Max-Age"); got != "3600" {
		t.Errorf("Max-Age=%q on actual response, want 3600", got)
	}
	// Allow-Credentials must also be set on simple requests, not just
	// preflight, otherwise the browser rejects the response when fetch
	// uses credentials:'include'.
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Allow-Credentials=%q want %q", got, "true")
	}
}

// TestCORS_DevMode_AuthMe_Preflight covers the exact path that surfaced
// the Allow-Credentials regression: the SvelteKit dev server at :5173
// polls /api/v1/auth/me with fetch credentials:'include' on every page
// load to bootstrap auth state. Without Allow-Credentials, the browser
// drops the response.
func TestCORS_DevMode_AuthMe_Preflight(t *testing.T) {
	env := newTestEnv(t, true)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/auth/me", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Allow-Origin=%q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Allow-Credentials=%q want %q", got, "true")
	}
}

// --- Audit emission on /routes mutations (spec §4 + D7 + Plan §4.4) -------
//
// The autoAuth wrapper bootstraps a `tester` user and adds a logout to
// the audit log for any subsequent /auth/logout call. Mutation tests
// below filter env.audit.Events() by Action prefix "route_" so they
// don't accidentally match other events emitted by middleware or by
// other handlers.

// routeEvents returns the subset of recorded audit events whose Action
// is one of route_created / route_updated / route_deleted.
func routeEvents(events []audit.Event) []audit.Event {
	out := make([]audit.Event, 0)
	for _, e := range events {
		switch e.Action {
		case audit.ActionRouteCreated, audit.ActionRouteUpdated, audit.ActionRouteDeleted:
			out = append(out, e)
		}
	}
	return out
}

func TestCreateRoute_EmitsAuditEvent(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"host":"audit-create.local","upstreamUrl":"http://127.0.0.1:9000","tlsEnabled":false,"wafEnabled":false}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	events := routeEvents(env.audit.Events())
	if len(events) != 1 {
		t.Fatalf("route audit events = %d, want 1: %+v", len(events), events)
	}
	ev := events[0]
	if ev.Action != audit.ActionRouteCreated {
		t.Errorf("Action=%q want %q", ev.Action, audit.ActionRouteCreated)
	}
	if ev.TargetType != "route" {
		t.Errorf("TargetType=%q want %q", ev.TargetType, "route")
	}
	// Read back the stored route to compare TargetID with the persisted id.
	stored, _ := env.store.ListRoutes(context.Background())
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored route, got %d", len(stored))
	}
	if ev.TargetID != stored[0].ID {
		t.Errorf("TargetID=%q want %q", ev.TargetID, stored[0].ID)
	}
	if ev.BeforeJSON != nil {
		t.Errorf("BeforeJSON should be nil on create, got %s", ev.BeforeJSON)
	}
	if len(ev.AfterJSON) == 0 {
		t.Fatalf("AfterJSON should be populated on create")
	}
	if !strings.Contains(string(ev.AfterJSON), "audit-create.local") {
		t.Errorf("AfterJSON missing host: %s", ev.AfterJSON)
	}
}

func TestUpdateRoute_EmitsAuditEvent(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "audit-update.local", UpstreamURL: "http://old:1",
	})

	body := `{"host":"audit-update.local","upstreamUrl":"http://new:1","tlsEnabled":true,"wafEnabled":false}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	events := routeEvents(env.audit.Events())
	if len(events) != 1 {
		t.Fatalf("route audit events = %d, want 1: %+v", len(events), events)
	}
	ev := events[0]
	if ev.Action != audit.ActionRouteUpdated {
		t.Errorf("Action=%q want %q", ev.Action, audit.ActionRouteUpdated)
	}
	if ev.TargetID != created.ID {
		t.Errorf("TargetID=%q want %q", ev.TargetID, created.ID)
	}
	if len(ev.BeforeJSON) == 0 || !strings.Contains(string(ev.BeforeJSON), "http://old:1") {
		t.Errorf("BeforeJSON missing previous upstream: %s", ev.BeforeJSON)
	}
	if len(ev.AfterJSON) == 0 || !strings.Contains(string(ev.AfterJSON), "http://new:1") {
		t.Errorf("AfterJSON missing new upstream: %s", ev.AfterJSON)
	}
}

func TestDeleteRoute_EmitsAuditEvent(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "audit-delete.local", UpstreamURL: "http://u:1",
	})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/routes/"+created.ID, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	events := routeEvents(env.audit.Events())
	if len(events) != 1 {
		t.Fatalf("route audit events = %d, want 1: %+v", len(events), events)
	}
	ev := events[0]
	if ev.Action != audit.ActionRouteDeleted {
		t.Errorf("Action=%q want %q", ev.Action, audit.ActionRouteDeleted)
	}
	if ev.TargetID != created.ID {
		t.Errorf("TargetID=%q want %q", ev.TargetID, created.ID)
	}
	if len(ev.BeforeJSON) == 0 || !strings.Contains(string(ev.BeforeJSON), "audit-delete.local") {
		t.Errorf("BeforeJSON missing deleted host: %s", ev.BeforeJSON)
	}
	if ev.AfterJSON != nil {
		t.Errorf("AfterJSON should be nil on delete, got %s", ev.AfterJSON)
	}
}

// The next three tests guard the D2 / Plan §4.4 invariant: when a
// Caddy reload fails, the storage rollback runs AND no audit event is
// emitted. The structural placement of appendAudit AFTER the reload
// branch is what makes this hold; this test catches any regression
// that moves the emission above the reload check.

func TestCreateRoute_ReloadFails_NoAudit(t *testing.T) {
	env := newTestEnv(t, false)
	env.caddy.SetNextErr(errors.New("simulated reload failure"))

	body := `{"host":"noaudit-create.local","upstreamUrl":"http://x:1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if events := routeEvents(env.audit.Events()); len(events) != 0 {
		t.Errorf("expected 0 route audit events on reload failure, got %d: %+v", len(events), events)
	}
}

func TestUpdateRoute_ReloadFails_NoAudit(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "noaudit-update.local", UpstreamURL: "http://old:1",
	})

	env.caddy.SetNextErr(errors.New("simulated reload failure"))
	body := `{"host":"noaudit-update.local","upstreamUrl":"http://new:1"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if events := routeEvents(env.audit.Events()); len(events) != 0 {
		t.Errorf("expected 0 route audit events on reload failure, got %d: %+v", len(events), events)
	}
}

func TestDeleteRoute_ReloadFails_NoAudit(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "noaudit-delete.local", UpstreamURL: "http://u:1",
	})

	env.caddy.SetNextErr(errors.New("simulated reload failure"))
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/routes/"+created.ID, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if events := routeEvents(env.audit.Events()); len(events) != 0 {
		t.Errorf("expected 0 route audit events on reload failure, got %d: %+v", len(events), events)
	}
}
