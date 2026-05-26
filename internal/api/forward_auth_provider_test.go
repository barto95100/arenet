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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// seedForwardAuthProvider primes the store with a complete
// forward-auth provider so tests that need a configured provider
// (e.g. the mutex-rejection happy-path, GET secret-redaction,
// delete-rejected-by-reference) can start from a populated row.
func seedForwardAuthProvider(t *testing.T, store *storage.Store) storage.ForwardAuthProvider {
	t.Helper()
	p := storage.ForwardAuthProvider{
		Name:           "authelia-prod",
		Kind:           "authelia",
		VerifyURL:      "http://authelia:9091",
		AuthRequestURI: "/api/authz/forward-auth",
		CopyHeaders:    []string{"Remote-User", "Remote-Email"},
		ClientSecret:   "secret-token-1234567890",
	}
	created, err := store.CreateForwardAuthProvider(context.Background(), p)
	if err != nil {
		t.Fatalf("seed forward-auth provider: %v", err)
	}
	return created
}

// TestForwardAuthProvider_CRUD_Success exercises the full CRUD
// cycle end-to-end via the HTTP handlers.
func TestForwardAuthProvider_CRUD_Success(t *testing.T) {
	env := newTestEnv(t, false)

	// POST
	body := `{"name":"authelia-prod","kind":"authelia","verifyUrl":"http://authelia:9091","authRequestUri":"/api/authz/forward-auth","copyHeaders":["Remote-User","Remote-Email"],"clientSecret":"secret"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/forward-auth/providers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST: status=%d body=%s", rec.Code, rec.Body)
	}

	// GET list (1 entry)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/settings/forward-auth/providers", nil)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET list: status=%d body=%s", rec.Code, rec.Body)
	}
	listBody := rec.Body.String()
	if !strings.Contains(listBody, `"name":"authelia-prod"`) {
		t.Errorf("list missing provider: %s", listBody)
	}

	// GET by name
	req = httptest.NewRequest(http.MethodGet, "/api/v1/settings/forward-auth/providers/authelia-prod", nil)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET single: status=%d body=%s", rec.Code, rec.Body)
	}

	// PUT (update verify URL + preserve secret via empty)
	body = `{"name":"authelia-prod","kind":"authelia","verifyUrl":"http://authelia:9092","authRequestUri":"/api/authz/forward-auth","copyHeaders":["Remote-User"],"clientSecret":""}`
	req = httptest.NewRequest(http.MethodPut, "/api/v1/settings/forward-auth/providers/authelia-prod", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: status=%d body=%s", rec.Code, rec.Body)
	}

	// Verify the secret was preserved in storage.
	got, err := env.store.GetForwardAuthProvider(context.Background(), "authelia-prod")
	if err != nil {
		t.Fatalf("GetForwardAuthProvider: %v", err)
	}
	if got.ClientSecret != "secret" {
		t.Errorf("client_secret was NOT preserved by empty PUT: got %q, want %q", got.ClientSecret, "secret")
	}
	if got.VerifyURL != "http://authelia:9092" {
		t.Errorf("verify_url not updated: %q", got.VerifyURL)
	}

	// DELETE
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/settings/forward-auth/providers/authelia-prod", nil)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE: status=%d body=%s", rec.Code, rec.Body)
	}
}

// TestForwardAuthProvider_GET_SecretRedaction pins the AC #2bis
// redaction discipline: the client_secret is NEVER echoed on the
// API GET path; a `clientSecretSet: true` boolean flag signals
// the UI whether a secret exists.
func TestForwardAuthProvider_GET_SecretRedaction(t *testing.T) {
	env := newTestEnv(t, false)
	seeded := seedForwardAuthProvider(t, env.store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/forward-auth/providers/authelia-prod", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	// The secret value MUST NOT appear in the response body.
	if strings.Contains(body, seeded.ClientSecret) {
		t.Errorf("client_secret leaked in GET body: %s", body)
	}
	// The redaction shape: clientSecret:"" + clientSecretSet:true.
	if !strings.Contains(body, `"clientSecret":""`) {
		t.Errorf("clientSecret not redacted to empty string: %s", body)
	}
	if !strings.Contains(body, `"clientSecretSet":true`) {
		t.Errorf("clientSecretSet flag missing: %s", body)
	}
}

// TestForwardAuthProvider_Audit_SecretsRedacted pins the AC #2bis
// audit emission discipline: the client_secret is NEVER in
// before/after JSON payloads of the audit event.
func TestForwardAuthProvider_Audit_SecretsRedacted(t *testing.T) {
	env := newTestEnv(t, false)
	previous := seedForwardAuthProvider(t, env.store)

	// PUT with a rotated secret so we exercise both before + after redaction.
	body := `{"name":"authelia-prod","kind":"authelia","verifyUrl":"http://authelia:9091","authRequestUri":"/api/authz/forward-auth","copyHeaders":["Remote-User"],"clientSecret":"new-rotated-secret"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/forward-auth/providers/authelia-prod", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	events := env.audit.Events()
	var evt *audit.Event
	for i := range events {
		if events[i].Action == audit.ActionForwardAuthProviderUpdated {
			evt = &events[i]
			break
		}
	}
	if evt == nil {
		t.Fatalf("forward_auth_provider_updated event not emitted; events=%+v", events)
	}
	beforeStr := string(evt.BeforeJSON)
	afterStr := string(evt.AfterJSON)
	if strings.Contains(beforeStr, previous.ClientSecret) {
		t.Errorf("audit beforeJson leaked previous secret: %s", beforeStr)
	}
	if strings.Contains(afterStr, "new-rotated-secret") {
		t.Errorf("audit afterJson leaked rotated secret: %s", afterStr)
	}
}

// TestForwardAuthProvider_DELETE_RejectedByReference pins the
// §1.3 decision 14 reference-guard: a provider referenced by ≥1
// route returns 409 + the offending route IDs in the body.
func TestForwardAuthProvider_DELETE_RejectedByReference(t *testing.T) {
	env := newTestEnv(t, false)
	seedForwardAuthProvider(t, env.store)

	// Create a route that references the provider.
	body := `{"host":"protected.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"wafMode":"off","authMode":"forward_auth","forwardAuth":{"providerName":"authelia-prod"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create route: status=%d body=%s", rec.Code, rec.Body)
	}

	// Attempt to delete the provider.
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/settings/forward-auth/providers/authelia-prod", nil)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("DELETE: status=%d (want 409) body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "referenced by") {
		t.Errorf("rejection message missing reference context: %s", rec.Body)
	}
}

// TestRouteCreate_ForwardAuth_UnknownProvider_Rejects pins the
// primary cross-rule of K.1 §5.1: a route POST with AuthMode =
// "forward_auth" referencing a provider name that doesn't exist
// is rejected with 400 at the API layer (before storage).
func TestRouteCreate_ForwardAuth_UnknownProvider_Rejects(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"host":"orphan.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"wafMode":"off","authMode":"forward_auth","forwardAuth":{"providerName":"does-not-exist"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d (want 400) body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "forward-auth provider") {
		t.Errorf("rejection does not name the cause: %s", rec.Body)
	}
}

// TestRouteCreate_AuthFieldsMutex pins the AC #5 mutual-exclusion
// guard: a request that sets both AuthMode == "basic" AND
// ForwardAuth.ProviderName (or any of the other forbidden
// combinations) is rejected at the API layer.
func TestRouteCreate_AuthFieldsMutex(t *testing.T) {
	env := newTestEnv(t, false)
	seedForwardAuthProvider(t, env.store)

	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "basic + forward_auth both set",
			body: `{"host":"mutex1.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"wafMode":"off","authMode":"basic","basicAuth":{"username":"admin","password":"pw-12345678901234567"},"forwardAuth":{"providerName":"authelia-prod"}}`,
			want: "pick one auth method",
		},
		{
			name: "none + basic_auth fields populated",
			body: `{"host":"mutex2.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"wafMode":"off","authMode":"none","basicAuth":{"username":"admin","password":"x"}}`,
			want: "clear the fields",
		},
		{
			name: "none + forward_auth populated",
			body: `{"host":"mutex3.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"wafMode":"off","authMode":"none","forwardAuth":{"providerName":"authelia-prod"}}`,
			want: "clear the field",
		},
		{
			name: "forward_auth + basic_auth fields populated",
			body: `{"host":"mutex4.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"wafMode":"off","authMode":"forward_auth","basicAuth":{"username":"admin","password":""},"forwardAuth":{"providerName":"authelia-prod"}}`,
			want: "pick one auth method",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			env.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d (want 400) body=%s", rec.Code, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Errorf("expected error containing %q, got %s", tc.want, rec.Body)
			}
		})
	}
}

// TestRouteCreate_ForwardAuth_WithProvider_Accepts is the positive
// counterpart: with a configured provider, a forward_auth route
// create succeeds. Confirms the cross-rule isn't over-eager.
func TestRouteCreate_ForwardAuth_WithProvider_Accepts(t *testing.T) {
	env := newTestEnv(t, false)
	seedForwardAuthProvider(t, env.store)

	body := `{"host":"protected.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"wafMode":"off","authMode":"forward_auth","forwardAuth":{"providerName":"authelia-prod"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"authMode":"forward_auth"`) {
		t.Errorf("response missing authMode=forward_auth: %s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"providerName":"authelia-prod"`) {
		t.Errorf("response missing providerName: %s", rec.Body)
	}
}
