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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// OIDC concurrent test — V3 backlog item (b) from
// oidc_v3_backlog.md (2026-06-23). Pure CI hygiene : pins the
// sync.RWMutex invariant in OIDCManager (oidc.go:91, 119, 143)
// so a future refactor that removes the lock (typical "why is
// there a mutex here?" PR) trips the race detector immediately.
//
// Architecture under test :
//   - Many concurrent goroutines call GET /api/v1/auth/oidc/login
//     which reads cfg from storage + calls OIDCManager.EnsureBuilt
//     + reads {provider, verifier, oauth} from OIDCManager.snapshot
//   - One goroutine calls PUT /api/v1/settings/oidc which writes
//     a new config to storage + calls OIDCManager.EnsureBuilt to
//     rebuild the cache (oidc.go:339-348)
//   - The OIDCManager.mu protects cfgHash + provider + verifier +
//     oauth. Login takes RLock (oidc.go:119) ; rebuild takes Lock
//     (oidc.go:143). Without the lock, the read and write race.
//
// Empirically the test :
//   1. Spawns 100 Login goroutines hammering the endpoint
//   2. Concurrently performs an authenticated PUT that flips the
//      OIDC config to point at a SECOND fakeIdP (different URL)
//   3. Asserts no Login panics, no Go race detector reports, all
//      responses are either 200/302 (cache hit) or 503 (transient
//      rebuild-in-flight) — never 500
//   4. After the workers drain, asserts the final cache reflects
//      the new config (eventual consistency)
//
// Run with `go test ./internal/api/ -race -run OIDCConcurrent` to
// exercise the race detector. Without -race the test still pins
// the panic-free + eventual-consistency contract.

const (
	oidcConcurrentLoginGoroutines = 100
	// Each goroutine fires this many login requests so the
	// observation window covers a meaningful slice of the rebuild
	// transition (not a single race-free snapshot before PUT).
	oidcConcurrentLoginsPerGoroutine = 5
)

func TestOIDCConcurrent_LoginUnderConfigUpdate_NoRaceNoPanic(t *testing.T) {
	env := newTestEnv(t, false)
	idpA := newFakeIdP(t)
	idpB := newFakeIdP(t)
	idpA.clientID = "arenet-test-A"
	idpB.clientID = "arenet-test-B"

	// Seed initial config pointing at IdP A.
	initialCfg := storage.OIDCConfig{
		Enabled:      true,
		IssuerURL:    idpA.srv.URL,
		ClientID:     "arenet-test-A",
		ClientSecret: "test-secret-A-1234567890",
		RedirectURL:  "http://localhost:8080/api/v1/auth/oidc/callback",
		Scopes:       []string{"openid", "profile", "email"},
		Kind:         "authentik",
	}
	if err := env.store.PutOIDCConfig(context.Background(), initialCfg); err != nil {
		t.Fatalf("seed initial oidc config: %v", err)
	}
	// Prime the OIDCManager cache before the workers start — we
	// want to observe the cache CHURNING under load, not the
	// cold-start cost.
	if err := env.handler.oidc.EnsureBuilt(context.Background(), initialCfg); err != nil {
		t.Fatalf("prime EnsureBuilt: %v", err)
	}

	// Need an admin session to PUT /settings/oidc — provision via
	// the helper that seeds an admin + extracts the cookie jar.
	adminCookies := mustAuthenticateAsAdmin(t, env)

	// Worker stats — atomic so the writer goroutine doesn't race
	// the reader on Wait. We count category buckets rather than
	// asserting per-call so a transient 503 during the rebuild
	// window doesn't fail the test (acceptable per oidc.go:602
	// "snapshot races with config edit. Recoverable on retry").
	var (
		gotOK     uint64 // 302 redirect — happy path
		gotSU     uint64 // 503 service unavailable — transient
		gotOther  uint64 // anything unexpected → test failure
		gotPanics uint64 // recovered panics (must stay 0)
	)

	var wg sync.WaitGroup
	wg.Add(oidcConcurrentLoginGoroutines)
	for i := 0; i < oidcConcurrentLoginGoroutines; i++ {
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					atomic.AddUint64(&gotPanics, 1)
				}
			}()
			for j := 0; j < oidcConcurrentLoginsPerGoroutine; j++ {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil)
				rec := httptest.NewRecorder()
				env.router.ServeHTTP(rec, req)
				switch rec.Code {
				case http.StatusFound, http.StatusOK:
					atomic.AddUint64(&gotOK, 1)
				case http.StatusServiceUnavailable:
					atomic.AddUint64(&gotSU, 1)
				default:
					atomic.AddUint64(&gotOther, 1)
				}
			}
		}()
	}

	// Fire the PUT that flips the config to IdP B while the
	// Login workers are hammering. The PUT path itself calls
	// EnsureBuilt(merged) (oidc.go:344) which contends with the
	// Login workers' EnsureBuilt(cfg) — exactly the race surface
	// we want the detector to scrutinise.
	flippedCfg := storage.OIDCConfig{
		Enabled:      true,
		IssuerURL:    idpB.srv.URL,
		ClientID:     "arenet-test-B",
		ClientSecret: "test-secret-B-0987654321",
		RedirectURL:  "http://localhost:8080/api/v1/auth/oidc/callback",
		Scopes:       []string{"openid", "profile", "email"},
		Kind:         "authentik",
	}
	putPayload := map[string]any{
		"enabled":      flippedCfg.Enabled,
		"issuerUrl":    flippedCfg.IssuerURL,
		"clientId":     flippedCfg.ClientID,
		"clientSecret": flippedCfg.ClientSecret,
		"scopes":       flippedCfg.Scopes,
		"redirectUrl":  flippedCfg.RedirectURL,
		"kind":         flippedCfg.Kind,
	}
	putBody, _ := json.Marshal(putPayload)
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", bytes.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	for _, c := range adminCookies {
		putReq.AddCookie(c)
	}
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Errorf("PUT /settings/oidc status = %d body=%s", putRec.Code, putRec.Body.String())
	}

	wg.Wait()

	// --- Assertions -------------------------------------------

	if atomic.LoadUint64(&gotPanics) != 0 {
		t.Fatalf("OIDC concurrent : %d Login goroutine(s) panicked under config update",
			atomic.LoadUint64(&gotPanics))
	}
	if atomic.LoadUint64(&gotOther) != 0 {
		t.Errorf("OIDC concurrent : %d Login response(s) had unexpected status (want 302 / 503 only) ; %d ok %d service-unavailable",
			atomic.LoadUint64(&gotOther),
			atomic.LoadUint64(&gotOK),
			atomic.LoadUint64(&gotSU))
	}
	totalCalls := uint64(oidcConcurrentLoginGoroutines * oidcConcurrentLoginsPerGoroutine)
	settled := atomic.LoadUint64(&gotOK) + atomic.LoadUint64(&gotSU) + atomic.LoadUint64(&gotOther)
	if settled != totalCalls {
		t.Errorf("OIDC concurrent : %d responses tallied, expected %d ; some calls dropped",
			settled, totalCalls)
	}

	// --- Eventual consistency ---------------------------------
	//
	// One more Login AFTER the workers drain : the cache MUST
	// reflect the flipped config (IdP B's authorization URL),
	// proving the rebuild propagated through the contention.

	finalReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil)
	finalRec := httptest.NewRecorder()
	env.router.ServeHTTP(finalRec, finalReq)
	if finalRec.Code != http.StatusFound {
		t.Fatalf("final Login after flip : status = %d ; want 302", finalRec.Code)
	}
	loc := finalRec.Header().Get("Location")
	if !strings.Contains(loc, idpB.srv.URL) {
		t.Errorf("final Login Location header missing the new IdP URL ; got %q want substring %q (eventual consistency broken — cache stayed on IdP A)",
			loc, idpB.srv.URL)
	}
}

// TestOIDCConcurrent_ManyReadersUnderRebuild — focused race
// detector probe. Spawns many simultaneous EnsureBuilt calls
// directly against OIDCManager (bypassing the HTTP layer) to
// concentrate the load on the lock-protected critical section.
// Complements the higher-level handler test above.
func TestOIDCConcurrent_ManyReadersUnderRebuild(t *testing.T) {
	idp := newFakeIdP(t)
	idp.clientID = "arenet-test"

	mgr := NewOIDCManager()
	cfg := storage.OIDCConfig{
		Enabled:      true,
		IssuerURL:    idp.srv.URL,
		ClientID:     "arenet-test",
		ClientSecret: "test-secret-1234567890",
		RedirectURL:  "http://localhost:8080/api/v1/auth/oidc/callback",
		Scopes:       []string{"openid", "profile", "email"},
	}

	// Prime once.
	if err := mgr.EnsureBuilt(context.Background(), cfg); err != nil {
		t.Fatalf("prime: %v", err)
	}

	const N = 200
	var wg sync.WaitGroup
	wg.Add(N)
	var panics uint64
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					atomic.AddUint64(&panics, 1)
				}
			}()
			// Cache-hit path : same cfg, no rebuild required. The
			// RLock is taken + released N times — the detector
			// would catch a write happening concurrently if the
			// shape was wrong.
			if err := mgr.EnsureBuilt(context.Background(), cfg); err != nil {
				// Network blip into idp.srv is the only thing that
				// could fail here ; treat as soft fail.
				return
			}
			provider, verifier, oauth := mgr.snapshot()
			// Touch the fields so the compiler doesn't elide the
			// read (defense — go.mod might keep the snapshot()
			// inlined, removing the read).
			_ = provider
			_ = verifier
			_ = oauth
		}()
	}

	// Concurrently force a rebuild via a config change. The
	// IssuerURL is the same but ClientID differs so configHash
	// drifts and the cache rebuilds.
	go func() {
		altered := cfg
		altered.ClientID = "arenet-test-altered"
		_ = mgr.EnsureBuilt(context.Background(), altered)
	}()

	wg.Wait()

	if atomic.LoadUint64(&panics) != 0 {
		t.Fatalf("OIDCManager concurrent readers : %d panic(s) — sync primitive integrity violated",
			atomic.LoadUint64(&panics))
	}
}

// --- helpers ----------------------------------------------------

// mustAuthenticateAsAdmin returns a cookie jar for a freshly-
// minted local admin session, suitable for attaching to PUT
// /settings/oidc requests. Mirrors the auth flow exercised by
// the oidc_test.go local-login tests.
func mustAuthenticateAsAdmin(t *testing.T, env *testEnv) []*http.Cookie {
	t.Helper()
	// Bootstrap an admin user directly via the user store.
	ctx := context.Background()
	store := newTestUserStore(t, env)
	const username = "concurrent-test-admin"
	const password = "ConcurrentTestPass!23456"
	if _, err := store.Create(ctx, username, "Concurrent Test Admin", "concurrent-admin@test.local", password); err != nil {
		t.Fatalf("create admin user: %v", err)
	}

	// Login via the public POST handler so we exercise the same
	// code path the real operator uses ; this returns a real
	// session cookie via Set-Cookie.
	loginBody, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login as admin failed : %d %s", rec.Code, rec.Body.String())
	}
	resp := http.Response{Header: rec.Header()}
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatalf("login as admin returned no cookies ; body=%s", rec.Body.String())
	}
	return cookies
}

