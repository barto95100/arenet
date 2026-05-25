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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// seedDNSProvider primes the store with a complete OVH DNS provider
// config so tests that depend on an already-configured provider
// (e.g. the dns-01 route create success path, the GET redaction
// path, the audit redaction path) can start from a populated row.
// Returns the seeded struct so tests can compare against it.
func seedDNSProvider(t *testing.T, store *storage.Store) storage.DNSProviderConfig {
	t.Helper()
	cfg := storage.DNSProviderConfig{
		Endpoint:          "ovh-eu",
		ApplicationKey:    "AK-fixture-1234567890",
		ApplicationSecret: "AS-fixture-secret-value",
		ConsumerKey:       "CK-fixture-consumer",
	}
	if err := store.PutDNSProviderOVH(context.Background(), cfg); err != nil {
		t.Fatalf("seedDNSProvider: %v", err)
	}
	return cfg
}

// --- Step J.4 §5.4 — secret discipline (GET response body) ----------------

// TestDNSProvider_SecretsNeverInResponseBody pins the redaction
// rule on the GET path: the three secret fields are emitted as
// empty strings even when the storage row carries non-empty
// values. A regression here would leak the OVH credentials over
// HTTP to any authenticated caller.
func TestDNSProvider_SecretsNeverInResponseBody(t *testing.T) {
	env := newTestEnv(t, false)
	seeded := seedDNSProvider(t, env.store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/dns-providers/ovh", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	// Endpoint round-trips normally — non-secret.
	if !strings.Contains(body, `"endpoint":"ovh-eu"`) {
		t.Errorf("endpoint not surfaced: %s", body)
	}
	// configured: true must surface (all four fields non-empty in storage).
	if !strings.Contains(body, `"configured":true`) {
		t.Errorf("configured flag not true: %s", body)
	}
	// Each of the three secret values from storage must NEVER
	// appear in the body. One assertion per field so a regression
	// names the leaking field.
	if strings.Contains(body, seeded.ApplicationKey) {
		t.Errorf("applicationKey leaked in GET body: %s", body)
	}
	if strings.Contains(body, seeded.ApplicationSecret) {
		t.Errorf("applicationSecret leaked in GET body: %s", body)
	}
	if strings.Contains(body, seeded.ConsumerKey) {
		t.Errorf("consumerKey leaked in GET body: %s", body)
	}
	// The wire shape must emit the three secret keys as empty strings.
	if !strings.Contains(body, `"applicationKey":""`) {
		t.Errorf("applicationKey not redacted to \"\": %s", body)
	}
	if !strings.Contains(body, `"applicationSecret":""`) {
		t.Errorf("applicationSecret not redacted to \"\": %s", body)
	}
	if !strings.Contains(body, `"consumerKey":""`) {
		t.Errorf("consumerKey not redacted to \"\": %s", body)
	}
}

// TestDNSProvider_GetFreshInstall pins the no-row response shape:
// a fresh install returns 200 with configured:false + empty
// fields, NOT a 404. The UI relies on this contract to render
// the "not configured" badge without a special-case branch on
// HTTP error.
func TestDNSProvider_GetFreshInstall(t *testing.T) {
	env := newTestEnv(t, false)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/dns-providers/ovh", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"configured":false`) {
		t.Errorf("configured flag not false on fresh install: %s", body)
	}
}

// --- Step J.4 §5.4 — audit redaction --------------------------------------

// TestDNSProvider_SecretsNeverInAuditLog pins the redaction rule
// on the audit emission path: a dns_provider_updated event must
// carry the secret fields as empty strings in BOTH BeforeJSON
// and AfterJSON. A regression here would persist the OVH
// credentials in the audit bucket (a "trust boundary" violation
// per spec §1.6: audit holds no secrets).
func TestDNSProvider_SecretsNeverInAuditLog(t *testing.T) {
	env := newTestEnv(t, false)
	previous := seedDNSProvider(t, env.store)
	// Rotate to a new set of secrets so both Before and After
	// carry redactable content.
	body := `{"endpoint":"ovh-ca","applicationKey":"AK-new-rotated","applicationSecret":"AS-new-rotated","consumerKey":"CK-new-rotated"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/dns-providers/ovh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	events := env.audit.Events()
	var evt *audit.Event
	for i := range events {
		if events[i].Action == audit.ActionDNSProviderUpdated {
			evt = &events[i]
			break
		}
	}
	if evt == nil {
		t.Fatalf("dns_provider_updated event not emitted; events=%+v", events)
	}

	// BeforeJSON must carry the previous endpoint (non-secret)
	// AND blank the three secret fields. We assert via the
	// concrete previous values not appearing.
	beforeStr := string(evt.BeforeJSON)
	if !strings.Contains(beforeStr, `"endpoint":"ovh-eu"`) {
		t.Errorf("BeforeJSON missing previous endpoint: %s", beforeStr)
	}
	if strings.Contains(beforeStr, previous.ApplicationKey) ||
		strings.Contains(beforeStr, previous.ApplicationSecret) ||
		strings.Contains(beforeStr, previous.ConsumerKey) {
		t.Errorf("BeforeJSON leaked a previous secret: %s", beforeStr)
	}
	if !strings.Contains(beforeStr, `"application_key":""`) ||
		!strings.Contains(beforeStr, `"application_secret":""`) ||
		!strings.Contains(beforeStr, `"consumer_key":""`) {
		t.Errorf("BeforeJSON not blanking all three secret fields: %s", beforeStr)
	}

	// AfterJSON must carry the new endpoint AND blank the three
	// rotated secret values.
	afterStr := string(evt.AfterJSON)
	if !strings.Contains(afterStr, `"endpoint":"ovh-ca"`) {
		t.Errorf("AfterJSON missing new endpoint: %s", afterStr)
	}
	if strings.Contains(afterStr, "AK-new-rotated") ||
		strings.Contains(afterStr, "AS-new-rotated") ||
		strings.Contains(afterStr, "CK-new-rotated") {
		t.Errorf("AfterJSON leaked a rotated secret: %s", afterStr)
	}
	if !strings.Contains(afterStr, `"application_key":""`) ||
		!strings.Contains(afterStr, `"application_secret":""`) ||
		!strings.Contains(afterStr, `"consumer_key":""`) {
		t.Errorf("AfterJSON not blanking all three secret fields: %s", afterStr)
	}
}

// --- Step J.4 §5.4 — edit-time validation guard (β.α) ---------------------

// TestRouteCreate_DNS01_NoProvider_Rejects pins the primary
// guard-rail of the (β) decision: a route POST with
// acmeChallenge="dns-01" must be rejected with 400 when no OVH
// provider is configured. Without this guard the cert would be
// issued (or fail to issue) silently at the next renewal
// attempt, with no edit-time signal to the operator.
func TestRouteCreate_DNS01_NoProvider_Rejects(t *testing.T) {
	env := newTestEnv(t, false)
	// Fresh install — no provider in storage.

	body := `{"host":"wild.example.com","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":true,"acmeChallenge":"dns-01","wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d (want 400) body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "dns-01") ||
		!strings.Contains(rec.Body.String(), "DNS provider") {
		t.Errorf("rejection message does not name the cause: %s", rec.Body)
	}
	// Defense in depth: no row must have been persisted on this rejected POST.
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 0 {
		t.Errorf("store unexpectedly contains routes after rejected POST: %+v", got)
	}
	// And no Caddy reload should have been attempted.
	if env.caddy.CallCount() != 0 {
		t.Errorf("reload calls=%d, want 0 on validation reject", env.caddy.CallCount())
	}
}

// TestRouteUpdate_DNS01_NoProvider_Rejects mirrors the create
// guard on the update path. Seed a plain HTTP-01 route, then PUT
// it to dns-01 without a provider configured.
func TestRouteUpdate_DNS01_NoProvider_Rejects(t *testing.T) {
	env := newTestEnv(t, false)

	// Step 1: create a plain http-01 route the normal way.
	createBody := `{"host":"plain.example.com","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":true,"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created: %v", err)
	}

	// Step 2: PUT to dns-01 without a provider configured — must reject.
	putBody := `{"host":"plain.example.com","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":true,"acmeChallenge":"dns-01","wafMode":"off"}`
	req = httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d (want 400) body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "DNS provider") {
		t.Errorf("rejection does not name the cause: %s", rec.Body)
	}
}

// TestRouteCreate_DNS01_WithProvider_Accepts is the positive
// counterpart: with a complete OVH provider configured, a dns-01
// route create succeeds. Confirms the guard isn't over-eager
// (false positive blocking valid configs).
func TestRouteCreate_DNS01_WithProvider_Accepts(t *testing.T) {
	env := newTestEnv(t, false)
	seedDNSProvider(t, env.store)

	body := `{"host":"wild.example.com","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":true,"acmeChallenge":"dns-01","wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"acmeChallenge":"dns-01"`) {
		t.Errorf("response missing acmeChallenge=dns-01: %s", rec.Body)
	}
}

// --- Step J.4 §5.4 — partial DNS provider config rejected -----------------

// TestDNSProviderPut_PartialConfig_Rejects pins the §5.4
// "partial config rejected" rule on a fresh-install PUT. Three
// fields supplied, one blank → 400 from storage.validate. Without
// this, an operator could half-configure the provider and the
// edit-time route guard would still see "configured":false but
// the failure signal at PUT time would be missing.
func TestDNSProviderPut_PartialConfig_Rejects(t *testing.T) {
	env := newTestEnv(t, false)
	// No previous row → preserve-on-edit cannot fill the blank.

	body := `{"endpoint":"ovh-eu","applicationKey":"AK-x","applicationSecret":"","consumerKey":"CK-x"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/dns-providers/ovh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d (want 400) body=%s", rec.Code, rec.Body)
	}
}

// --- Step J.4 §5.4 — preserve-on-edit -------------------------------------

// TestDNSProviderPut_PreserveBlankSecrets pins the wire
// preserve-on-edit semantics: a PUT with a non-empty endpoint
// but blank secrets keeps the previously stored secrets in
// storage. Required so an operator can flip the OVH region
// without re-typing every secret. Mirrors the Step I.5
// BasicAuth password-blank-preserves-hash pattern.
func TestDNSProviderPut_PreserveBlankSecrets(t *testing.T) {
	env := newTestEnv(t, false)
	previous := seedDNSProvider(t, env.store)

	// Change the region only — secrets blank.
	body := `{"endpoint":"ovh-ca","applicationKey":"","applicationSecret":"","consumerKey":""}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/dns-providers/ovh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	// Storage now carries the new endpoint AND the previous secrets.
	got, err := env.store.GetDNSProviderOVH(context.Background())
	if err != nil {
		t.Fatalf("GetDNSProviderOVH: %v", err)
	}
	if got.Endpoint != "ovh-ca" {
		t.Errorf("Endpoint: got %q, want ovh-ca", got.Endpoint)
	}
	if got.ApplicationKey != previous.ApplicationKey ||
		got.ApplicationSecret != previous.ApplicationSecret ||
		got.ConsumerKey != previous.ConsumerKey {
		t.Errorf("secrets not preserved: got %+v, want previous %+v", got, previous)
	}
}

// --- Step J.4 §5.4 — erasure path (PUT all-blank ⇒ delete row) ------------

// TestDNSProviderPut_AllBlank_Erases pins the erasure semantics:
// a PUT with the endpoint AND the three secrets all blank
// removes the persisted row. Without this branch the
// preserve-on-edit merge would carry the previous secrets
// forward and an operator could never de-configure the provider
// (OVH credentials stuck in BoltDB for life, contradicting the
// §5.4 design which states `delete = PUT all blank`).
func TestDNSProviderPut_AllBlank_Erases(t *testing.T) {
	env := newTestEnv(t, false)
	seedDNSProvider(t, env.store)

	body := `{"endpoint":"","applicationKey":"","applicationSecret":"","consumerKey":""}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/dns-providers/ovh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"configured":false`) {
		t.Errorf("response after erasure not configured:false: %s", rec.Body)
	}

	// The storage row is gone — a fresh GET on the store returns
	// ErrNotFound (the public API surface translates that to
	// configured:false on the wire; the storage layer is the
	// strict truth).
	_, err := env.store.GetDNSProviderOVH(context.Background())
	if err == nil {
		t.Fatal("expected ErrNotFound after erasure, got nil")
	}

	// Re-GET via the API: still 200, configured:false (the UI
	// contract holds even post-erasure, no 404 surprise).
	req = httptest.NewRequest(http.MethodGet, "/api/v1/settings/dns-providers/ovh", nil)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET after erase: status=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"configured":false`) {
		t.Errorf("GET after erase not configured:false: %s", rec.Body)
	}
}

// TestDNSProviderPut_AllBlank_OnFreshInstall_NoOp pins the
// idempotent corner of the erasure path: PUT all-blank on a
// fresh install (no row to erase) returns 200 with the same
// "not configured" shape, no audit emission, no Caddy reload.
func TestDNSProviderPut_AllBlank_OnFreshInstall_NoOp(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"endpoint":"","applicationKey":"","applicationSecret":"","consumerKey":""}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/dns-providers/ovh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"configured":false`) {
		t.Errorf("response not configured:false: %s", rec.Body)
	}
	// No audit on a no-op — nothing changed.
	for _, e := range env.audit.Events() {
		if e.Action == audit.ActionDNSProviderUpdated {
			t.Errorf("unexpected audit event on fresh-install erase no-op: %+v", e)
		}
	}
	// And no Caddy reload on the no-op path.
	if env.caddy.CallCount() != 0 {
		t.Errorf("reload calls=%d, want 0", env.caddy.CallCount())
	}
}

// --- Step J.4 §5.4 — DELETE method not registered ------------------------

// TestDNSProvider_DELETE_NotAllowed pins the §5.4 lifecycle
// decision "no DELETE endpoint in v1.0": the chi router has no
// DELETE handler registered at /api/v1/settings/dns-providers/ovh,
// so a DELETE request lands on chi's default 405. The de-
// configuration path is the all-blank PUT covered above; this
// test exists as the regression guard against a future
// well-meaning refactor that adds a DELETE handler (which would
// bypass the all-blank erasure path's reload + audit emission).
func TestDNSProvider_DELETE_NotAllowed(t *testing.T) {
	env := newTestEnv(t, false)
	seedDNSProvider(t, env.store)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/settings/dns-providers/ovh", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d (want 405) body=%s", rec.Code, rec.Body)
	}
	// The seeded row must still be there.
	_, err := env.store.GetDNSProviderOVH(context.Background())
	if err != nil {
		t.Errorf("seeded row should still exist after DELETE 405: %v", err)
	}
}
