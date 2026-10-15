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

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// A viewer must not read the operator's upstream credentials (v2.73).
//
// GET /routes and GET /routes/{id} sit in the hard-auth group without
// RequireAdminMiddleware, so a viewer — an invited human, an
// OIDC identity auto-created with the default viewer role, or a
// viewer-scoped service-account token in a monitoring script — got
// every route's custom headers and health-check probe headers in
// cleartext. Those values authenticate against the backend directly,
// so the disclosure leaves Arenet's trust boundary entirely.
//
// The project classifies them as secrets everywhere else:
// storage.IsSensitiveHeader seals them at rest, the audit log redacts
// them, the backup exporter sentinels them. This read was the hole.
//
// Asserted on the WIRE — the parsed JSON body — not on the Go struct.
// A struct-level test would not have caught the response shape, and
// the response shape is what the viewer receives.

const (
	upstreamToken = "Bearer super-secret-upstream-token"
	probeToken    = "Bearer health-probe-secret"
)

// seedRouteWithSecrets stores a route carrying a credential in each of
// the three places a route can hold one.
func seedRouteWithSecrets(t *testing.T, env *testEnv) storage.Route {
	t.Helper()
	rt, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "secrets.example.com",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.9:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		RequestHeaders: map[string]string{
			"Authorization": upstreamToken,
			"X-Trace":       "not-a-secret",
		},
		ResponseHeaders: map[string]string{"X-Api-Key": "resp-secret"},
		HealthCheck: storage.HealthCheck{
			Enabled:      true,
			URI:          "/healthz",
			Method:       "GET",
			Interval:     "30s",
			Timeout:      "5s",
			ExpectStatus: 200,
			Passes:       1,
			Fails:        1,
			Headers:      map[string]string{"Authorization": probeToken},
		},
	})
	if err != nil {
		t.Fatalf("seed route: %v", err)
	}
	return rt
}

// cookieFor seeds a user of the given kind and returns a session
// cookie for them.
func cookieFor(t *testing.T, env *testEnv, admin bool) *http.Cookie {
	t.Helper()
	ctx := context.Background()
	users := auth.NewUserStore(env.store.DB())

	var u auth.User
	var err error
	if admin {
		// The first local user is the admin.
		u, err = users.Create(ctx, "boss", "Boss", "", "a-long-enough-password-x")
	} else {
		u, err = users.CreateOIDCUser(ctx, "watcher", "Watcher", "", "sub-watcher")
	}
	if err != nil {
		t.Fatalf("seed user (admin=%v): %v", admin, err)
	}
	wantRole := auth.UserRoleViewer
	if admin {
		wantRole = auth.UserRoleAdmin
	}
	if u.Role != wantRole {
		t.Fatalf("seeded role = %q, want %q", u.Role, wantRole)
	}

	s, serr := auth.NewSessionStore(env.store.DB()).Create(ctx, u.ID, false, "127.0.0.1", "test/1")
	if serr != nil {
		t.Fatalf("seed session: %v", serr)
	}
	return &http.Cookie{Name: sessionCookieName, Value: s.ID}
}

func getRoutesAs(t *testing.T, env *testEnv, c *http.Cookie, path string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200. body: %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func TestListRoutes_ViewerDoesNotSeeUpstreamCredentials(t *testing.T) {
	env := newTestEnv(t, false)
	seedRouteWithSecrets(t, env)
	body := getRoutesAs(t, env, cookieFor(t, env, false), "/api/v1/routes")

	for _, secret := range []string{upstreamToken, probeToken, "resp-secret"} {
		if strings.Contains(body, secret) {
			t.Errorf("a viewer received %q in the route list — that value authenticates "+
				"against the backend directly", secret)
		}
	}
	// The header NAME stays: a viewer may know the route injects an
	// Authorization without being handed its value.
	if !strings.Contains(body, "Authorization") {
		t.Error("the header name must stay, so the route's shape is still readable")
	}
	// And a non-credential header value is untouched.
	if !strings.Contains(body, "not-a-secret") {
		t.Error("only credential-bearing values are redacted, not every header")
	}
}

func TestGetRoute_ViewerDoesNotSeeUpstreamCredentials(t *testing.T) {
	env := newTestEnv(t, false)
	rt := seedRouteWithSecrets(t, env)
	body := getRoutesAs(t, env, cookieFor(t, env, false), "/api/v1/routes/"+rt.ID)

	for _, secret := range []string{upstreamToken, probeToken, "resp-secret"} {
		if strings.Contains(body, secret) {
			t.Errorf("a viewer received %q from the single-route read", secret)
		}
	}
}

// The admin keeps the plaintext, which is what makes the route form
// round-trip on edit without a sentinel the operator could type into a
// backend header by accident.
func TestListRoutes_AdminStillSeesTheValues(t *testing.T) {
	env := newTestEnv(t, false)
	seedRouteWithSecrets(t, env)
	body := getRoutesAs(t, env, cookieFor(t, env, true), "/api/v1/routes")

	for _, secret := range []string{upstreamToken, probeToken} {
		if !strings.Contains(body, secret) {
			t.Errorf("the admin must still read %q, or the edit form cannot round-trip it", secret)
		}
	}
}

// The wire shape, read as JSON rather than as a substring, so the
// redaction is asserted in the field it belongs to.
func TestListRoutes_ViewerRedactionIsInTheRightField(t *testing.T) {
	env := newTestEnv(t, false)
	seedRouteWithSecrets(t, env)
	body := getRoutesAs(t, env, cookieFor(t, env, false), "/api/v1/routes")

	var routes []struct {
		RequestHeaders  map[string]string `json:"requestHeaders"`
		ResponseHeaders map[string]string `json:"responseHeaders"`
		HealthCheck     struct {
			Headers map[string]string `json:"headers"`
		} `json:"healthCheck"`
	}
	if err := json.Unmarshal([]byte(body), &routes); err != nil {
		t.Fatalf("decode: %v — body: %s", err, body)
	}
	if len(routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(routes))
	}
	r := routes[0]
	if got := r.RequestHeaders["Authorization"]; got == upstreamToken || got == "" {
		t.Errorf("requestHeaders.Authorization = %q; want a redaction marker, "+
			"neither the secret nor an empty value that reads as 'no header set'", got)
	}
	if got := r.HealthCheck.Headers["Authorization"]; got == probeToken || got == "" {
		t.Errorf("healthCheck.headers.Authorization = %q; want a redaction marker", got)
	}
	if got := r.ResponseHeaders["X-Api-Key"]; got == "resp-secret" || got == "" {
		t.Errorf("responseHeaders.X-Api-Key = %q; want a redaction marker", got)
	}
}

// F48 — the health-check probe headers were the one credential-bearing
// map routeForAudit did not touch.
//
// The field's documented purpose is "an Authorization a health
// endpoint requires" (v2.55), so a credential there is the intended
// use, not an abuse. It was serialised verbatim into the audit event's
// before/after blob; GET /api/v1/audit is mounted outside
// RequireAdminMiddleware, so any viewer could read it back for every
// route change ever made, and the secret codec does not seal the audit
// bucket either.
func TestRouteForAudit_RedactsHealthCheckProbeHeaders(t *testing.T) {
	r := storage.Route{
		Host:      "app.example.com",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.9", Weight: 1}},
		HealthCheck: storage.HealthCheck{
			Enabled: true,
			Headers: map[string]string{
				"Authorization": probeToken,
				"X-Probe-Id":    "not-a-secret",
			},
		},
		PathRules: []storage.PathRule{{
			PathPrefix: "/api",
			HealthCheck: &storage.HealthCheck{
				Enabled: true,
				Headers: map[string]string{"X-Api-Key": "path-rule-secret"},
			},
		}},
	}

	got := routeForAudit(r)

	if v := got.HealthCheck.Headers["Authorization"]; v == probeToken {
		t.Error("the route's probe credential reached the audit payload")
	}
	if v := got.HealthCheck.Headers["X-Probe-Id"]; v != "not-a-secret" {
		t.Errorf("a non-credential probe header must survive, got %q", v)
	}
	if v := got.PathRules[0].HealthCheck.Headers["X-Api-Key"]; v == "path-rule-secret" {
		t.Error("a path rule's probe credential reached the audit payload")
	}

	// The input must not be mutated: the caller goes on to store the
	// real route, and a redaction that leaked backwards into it would
	// wipe the operator's configuration.
	if r.HealthCheck.Headers["Authorization"] != probeToken {
		t.Error("routeForAudit mutated its argument — the stored route would lose its header")
	}
	if r.PathRules[0].HealthCheck.Headers["X-Api-Key"] != "path-rule-secret" {
		t.Error("routeForAudit mutated a path rule's probe headers in place")
	}
}
