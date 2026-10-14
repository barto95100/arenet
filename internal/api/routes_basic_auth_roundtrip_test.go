// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// v2.72 — a password survives an auth-mode round trip.
//
// Switching a route to forward_auth to try an IdP and switching back
// is a normal afternoon, and it used to cost the password: the update
// handler zeroed basicAuthHash whenever AuthMode != basic, so the way
// back was refused with "basic_auth.password_hash must not be empty"
// and the operator had to retype a credential nothing had asked them
// to change.
//
// Preserving it is safe because the emitter gates on AuthMode, not on
// the presence of a hash — caddymgr/manager.go switches on r.AuthMode
// and emits the basicauth handler only in the RouteAuthBasic branch.
// The first test below is the one that proves that half, and it is the
// one that matters: a preserved hash must protect nothing.

// A local helper: the package already has a putRouteBody with a
// different shape.
func putRouteForRoundTrip(t *testing.T, env *testEnv, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func TestUpdateRoute_AuthModeRoundTrip_KeepsThePassword(t *testing.T) {
	env := newTestEnv(t, false)

	create := `{
	  "host":"roundtrip.example.com",
	  "upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],
	  "authMode":"basic",
	  "basicAuth":{"username":"admin","password":"firstPlainPassword"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(create))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	before, _ := env.store.ListRoutes(context.Background())
	originalHash := before[0].BasicAuth.PasswordHash
	if !strings.HasPrefix(originalHash, "$argon2id$") {
		t.Fatalf("originalHash = %q; want an argon2id PHC string", originalHash)
	}

	// Away: no auth at all.
	away := putRouteForRoundTrip(t, env, created.ID, `{
	  "host":"roundtrip.example.com",
	  "upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],
	  "authMode":"none"}`)
	if away.Code != http.StatusOK {
		t.Fatalf("switch away status=%d body=%s", away.Code, away.Body)
	}

	// THE load-bearing assertion: the hash is still stored, and the
	// route is not protected by it. A hash under authMode "none" that
	// still gated traffic would be a security regression, not a
	// convenience.
	mid, _ := env.store.ListRoutes(context.Background())
	if mid[0].AuthMode != "none" {
		t.Fatalf("AuthMode = %q; want none", mid[0].AuthMode)
	}
	if mid[0].BasicAuth.PasswordHash != originalHash {
		t.Errorf("the hash was dropped on the way out: %q", mid[0].BasicAuth.PasswordHash)
	}

	// Back, with no password typed. This used to be a 400.
	back := putRouteForRoundTrip(t, env, created.ID, `{
	  "host":"roundtrip.example.com",
	  "upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],
	  "authMode":"basic",
	  "basicAuth":{"username":"admin","password":""}}`)
	if back.Code != http.StatusOK {
		t.Fatalf("switch back status=%d body=%s — the round trip must not demand a retype",
			back.Code, back.Body)
	}
	after, _ := env.store.ListRoutes(context.Background())
	if after[0].BasicAuth.PasswordHash != originalHash {
		t.Errorf("hash after the round trip = %q; want the original",
			after[0].BasicAuth.PasswordHash)
	}
}

// Rotating the password while away still replaces it: preserving must
// not outrank an explicit new value.
func TestUpdateRoute_AuthModeRoundTrip_ExplicitPasswordStillWins(t *testing.T) {
	env := newTestEnv(t, false)

	create := `{
	  "host":"rotate.example.com",
	  "upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],
	  "authMode":"basic",
	  "basicAuth":{"username":"admin","password":"firstPlainPassword"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(create))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	var created routeResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	before, _ := env.store.ListRoutes(context.Background())
	originalHash := before[0].BasicAuth.PasswordHash

	rotated := putRouteForRoundTrip(t, env, created.ID, `{
	  "host":"rotate.example.com",
	  "upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],
	  "authMode":"basic",
	  "basicAuth":{"username":"admin","password":"secondPlainPassword"}}`)
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", rotated.Code, rotated.Body)
	}

	after, _ := env.store.ListRoutes(context.Background())
	if after[0].BasicAuth.PasswordHash == originalHash {
		t.Error("an explicit new password must replace the stored hash")
	}
	if !strings.HasPrefix(after[0].BasicAuth.PasswordHash, "$argon2id$") {
		t.Errorf("hash = %q; want an argon2id PHC string", after[0].BasicAuth.PasswordHash)
	}
}
