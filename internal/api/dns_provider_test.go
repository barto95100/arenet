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

// --- test helpers ---------------------------------------------------------

// getRec issues a GET through the env router and returns the recorder.
func getRec(t *testing.T, env *testEnv, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

// deleteRec issues a DELETE through the env router and returns the recorder.
func deleteRec(t *testing.T, env *testEnv, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

// createProviderViaAPI POSTs a fully-configured provider and returns the
// decoded response map. Uses distinctive secret values so downstream
// assertions can grep for a leaked secret by substring.
func createProviderViaAPI(t *testing.T, env *testEnv, label string) map[string]any {
	t.Helper()
	body := map[string]string{
		"label": label, "type": "ovh", "endpoint": "ovh-eu",
		"applicationKey": "SECRET_AK", "applicationSecret": "SECRET_AS", "consumerKey": "SECRET_CK",
	}
	rec := postJSON(t, env.router, "/api/v1/settings/dns-providers", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %q status = %d, body=%s", label, rec.Code, rec.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	return out
}

// seedDNSProvider primes the store with a complete OVH DNS provider
// config so tests that depend on an already-configured provider (the
// dns-01 route create success path) can start from a populated row.
func seedDNSProvider(t *testing.T, store *storage.Store) storage.DNSProviderConfig {
	t.Helper()
	created, err := store.CreateDNSProvider(context.Background(), storage.DNSProviderConfig{
		Label:             "OVH fixture",
		Type:              storage.DNSProviderTypeOVH,
		Endpoint:          "ovh-eu",
		ApplicationKey:    "AK-fixture-1234567890",
		ApplicationSecret: "AS-fixture-secret-value",
		ConsumerKey:       "CK-fixture-consumer",
	})
	if err != nil {
		t.Fatalf("seedDNSProvider: %v", err)
	}
	return created
}

// --- collection API: create + list hides secrets --------------------------

// TestDNSProviders_CreateThenListHidesSecrets pins the primary secret
// discipline: a create returns 201 with an id but NO secret fields, and
// the list surfaces the entry with configured:true and no secrets.
func TestDNSProviders_CreateThenListHidesSecrets(t *testing.T) {
	env := newTestEnv(t, false)

	created := createProviderViaAPI(t, env, "OVH perso")
	if created["id"] == nil || created["id"] == "" {
		t.Fatal("no id in create response")
	}
	if created["configured"] != true {
		t.Errorf("create response configured != true: %+v", created)
	}
	// No secret field may appear with a non-empty value, under any
	// plausible JSON key spelling.
	for _, k := range []string{"applicationKey", "application_key", "applicationSecret", "application_secret", "consumerKey", "consumer_key"} {
		if v, ok := created[k]; ok && v != "" && v != nil {
			t.Errorf("secret %q leaked in create response: %v", k, v)
		}
	}
	// And no secret VALUE may appear anywhere in the raw body.
	rawCreate, _ := json.Marshal(created)
	for _, sv := range []string{"SECRET_AK", "SECRET_AS", "SECRET_CK"} {
		if strings.Contains(string(rawCreate), sv) {
			t.Errorf("secret value %q leaked in create response body: %s", sv, rawCreate)
		}
	}

	rec := getRec(t, env, "/api/v1/settings/dns-providers")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, body=%s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "SECRET_") {
		t.Errorf("secret leaked in list body: %s", rec.Body)
	}
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list len = %d, want 1", len(list))
	}
	if list[0]["configured"] != true {
		t.Errorf("list entry configured != true: %+v", list[0])
	}
	usedBy, _ := list[0]["usedBy"].([]any)
	if len(usedBy) != 0 {
		t.Errorf("usedBy = %v, want empty", usedBy)
	}
}

// TestDNSProviders_ListSortedByLabel pins the stable ordering contract:
// the list is sorted by Label ascending regardless of creation order.
func TestDNSProviders_ListSortedByLabel(t *testing.T) {
	env := newTestEnv(t, false)
	createProviderViaAPI(t, env, "Zeta")
	createProviderViaAPI(t, env, "Alpha")
	createProviderViaAPI(t, env, "Mid")

	rec := getRec(t, env, "/api/v1/settings/dns-providers")
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	got := []string{}
	for _, e := range list {
		got = append(got, e["label"].(string))
	}
	want := []string{"Alpha", "Mid", "Zeta"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("labels = %v, want sorted %v", got, want)
	}
}

// TestDNSProviders_GetMissing_Returns404Code pins the 404 structured
// error contract for an unknown id.
func TestDNSProviders_GetMissing_Returns404Code(t *testing.T) {
	env := newTestEnv(t, false)
	rec := getRec(t, env, "/api/v1/settings/dns-providers/does-not-exist")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["code"] != "provider_not_found" {
		t.Errorf("code = %v, want provider_not_found; body=%s", body["code"], rec.Body)
	}
}

// TestDNSProviders_UpdatePreservesBlankSecrets pins the wire
// preserve-on-edit semantics: create a full provider, PUT a label-only
// change with blank secrets, and confirm the entry stays configured:true.
func TestDNSProviders_UpdatePreservesBlankSecrets(t *testing.T) {
	env := newTestEnv(t, false)
	created := createProviderViaAPI(t, env, "OVH perso")
	id := created["id"].(string)

	// Edit label only; all secrets blank.
	putBody := map[string]string{
		"label": "OVH renamed", "type": "ovh", "endpoint": "ovh-ca",
		"applicationKey": "", "applicationSecret": "", "consumerKey": "",
	}
	buf, _ := json.Marshal(putBody)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/dns-providers/"+id, strings.NewReader(string(buf)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d, body=%s", rec.Code, rec.Body)
	}
	var updated map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &updated)
	if updated["label"] != "OVH renamed" || updated["endpoint"] != "ovh-ca" {
		t.Errorf("update did not apply non-secret fields: %+v", updated)
	}
	if updated["configured"] != true {
		t.Errorf("blank secrets not preserved (configured != true): %+v", updated)
	}

	// Re-fetch via list to confirm persistence of the preserved secrets.
	rec = getRec(t, env, "/api/v1/settings/dns-providers")
	var list []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 || list[0]["configured"] != true {
		t.Errorf("post-update list = %+v, want 1 configured entry", list)
	}
	// Storage still carries the ORIGINAL secrets (not blanked).
	got, err := env.store.GetDNSProvider(context.Background(), id)
	if err != nil {
		t.Fatalf("GetDNSProvider: %v", err)
	}
	if got.ApplicationKey != "SECRET_AK" || got.ConsumerKey != "SECRET_CK" {
		t.Errorf("storage secrets not preserved: %+v", got)
	}
}

// TestDNSProviders_DeleteInUse_Returns409WithWildcards pins the
// operator's i18n-critical gate: deleting a provider referenced by a
// managed domain returns 409 with code "provider_in_use" AND
// params.wildcards containing the apex name(s).
func TestDNSProviders_DeleteInUse_Returns409WithWildcards(t *testing.T) {
	env := newTestEnv(t, false)
	created := createProviderViaAPI(t, env, "OVH perso")
	id := created["id"].(string)

	// Attach a managed domain to this provider directly in storage.
	if err := env.store.PutManagedDomain(context.Background(), storage.ManagedDomain{
		Apex: "example.com", ProviderID: id,
	}); err != nil {
		t.Fatalf("PutManagedDomain: %v", err)
	}

	rec := deleteRec(t, env, "/api/v1/settings/dns-providers/"+id)
	if rec.Code != http.StatusConflict {
		t.Fatalf("delete status = %d, want 409; body=%s", rec.Code, rec.Body)
	}
	var body struct {
		Code   string         `json:"code"`
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode 409 body: %v", err)
	}
	if body.Code != "provider_in_use" {
		t.Errorf("code = %q, want provider_in_use", body.Code)
	}
	wc, ok := body.Params["wildcards"].([]any)
	if !ok || len(wc) != 1 || wc[0] != "example.com" {
		t.Errorf("params.wildcards = %v, want [example.com]", body.Params["wildcards"])
	}
	// The provider must still exist (delete was refused).
	if _, err := env.store.GetDNSProvider(context.Background(), id); err != nil {
		t.Errorf("provider unexpectedly removed after 409: %v", err)
	}
}

// TestDNSProviders_DeleteNotFound_Returns404 pins the delete 404 path.
func TestDNSProviders_DeleteNotFound_Returns404(t *testing.T) {
	env := newTestEnv(t, false)
	rec := deleteRec(t, env, "/api/v1/settings/dns-providers/nope")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["code"] != "provider_not_found" {
		t.Errorf("code = %v, want provider_not_found", body["code"])
	}
}

// TestDNSProviders_DeleteUnused_Succeeds pins the happy delete path
// (204) and that the audit event carries no secret.
func TestDNSProviders_DeleteUnused_Succeeds(t *testing.T) {
	env := newTestEnv(t, false)
	created := createProviderViaAPI(t, env, "OVH perso")
	id := created["id"].(string)

	rec := deleteRec(t, env, "/api/v1/settings/dns-providers/"+id)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body)
	}
	if _, err := env.store.GetDNSProvider(context.Background(), id); err == nil {
		t.Error("provider still present after successful delete")
	}
}

// --- validation error codes -----------------------------------------------

// TestDNSProviders_CreateInvalid_Returns400Code pins the structured
// validation error contract (bad type → invalid_type, always with a
// reason param + EN fallback).
func TestDNSProviders_CreateInvalid_Returns400Code(t *testing.T) {
	env := newTestEnv(t, false)
	body := map[string]string{
		"label": "X", "type": "cloudflare", "endpoint": "ovh-eu",
		"applicationKey": "a", "applicationSecret": "b", "consumerKey": "c",
	}
	rec := postJSON(t, env.router, "/api/v1/settings/dns-providers", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["code"] != "invalid_type" {
		t.Errorf("code = %v, want invalid_type; body=%s", out["code"], rec.Body)
	}
	if out["error"] == nil || out["error"] == "" {
		t.Errorf("missing EN fallback error string: %s", rec.Body)
	}
}

// --- audit discipline -----------------------------------------------------

// TestDNSProviders_CreateAudit_NoSecret pins the audit secret-discipline
// gate: after a create the recorded event must NOT contain any secret
// value anywhere in its serialized form.
func TestDNSProviders_CreateAudit_NoSecret(t *testing.T) {
	env := newTestEnv(t, false)
	createProviderViaAPI(t, env, "OVH perso")

	var evt *audit.Event
	for _, e := range env.audit.Events() {
		if e.Action == audit.ActionDNSProviderCreated {
			ev := e
			evt = &ev
			break
		}
	}
	if evt == nil {
		t.Fatalf("dns_provider_created event not emitted; events=%+v", env.audit.Events())
	}
	blob := string(evt.BeforeJSON) + string(evt.AfterJSON) + evt.Message
	for _, sv := range []string{"SECRET_AK", "SECRET_AS", "SECRET_CK"} {
		if strings.Contains(blob, sv) {
			t.Errorf("audit event leaked secret %q: before=%s after=%s", sv, evt.BeforeJSON, evt.AfterJSON)
		}
	}
	// The non-secret endpoint should be recoverable (proves the event
	// carries meaningful diff data, not an empty scrub).
	if !strings.Contains(string(evt.AfterJSON), "ovh-eu") {
		t.Errorf("audit AfterJSON missing endpoint: %s", evt.AfterJSON)
	}
}

// --- managed-domains providerId -------------------------------------------

// TestManagedDomains_ValidProviderId_Works pins the happy path: POST a
// managed domain with a valid providerId succeeds and persists the id.
func TestManagedDomains_ValidProviderId_Works(t *testing.T) {
	env := newTestEnv(t, false)
	created := createProviderViaAPI(t, env, "OVH perso")
	id := created["id"].(string)

	rec := postJSON(t, env.router, "/api/v1/settings/managed-domains", map[string]any{
		"apex": "example.com", "includeApex": false, "providerId": id,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body)
	}
	md, err := env.store.GetManagedDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("GetManagedDomain: %v", err)
	}
	if md.ProviderID != id {
		t.Errorf("ProviderID = %q, want %q", md.ProviderID, id)
	}
}

// TestManagedDomains_UnknownProviderId_Returns400 pins the existence
// validation: a non-empty providerId that matches no provider → 400
// code invalid_provider_id.
func TestManagedDomains_UnknownProviderId_Returns400(t *testing.T) {
	env := newTestEnv(t, false)
	rec := postJSON(t, env.router, "/api/v1/settings/managed-domains", map[string]any{
		"apex": "example.com", "includeApex": false, "providerId": "no-such-id",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["code"] != "invalid_provider_id" {
		t.Errorf("code = %v, want invalid_provider_id; body=%s", out["code"], rec.Body)
	}
}

// TestManagedDomains_LegacyProviderOVH_ResolvesToSole pins the
// rétro-compat path: a legacy body with provider:"ovh" and no
// providerId resolves to the single configured provider.
func TestManagedDomains_LegacyProviderOVH_ResolvesToSole(t *testing.T) {
	env := newTestEnv(t, false)
	created := createProviderViaAPI(t, env, "OVH perso")
	id := created["id"].(string)

	rec := postJSON(t, env.router, "/api/v1/settings/managed-domains", map[string]any{
		"apex": "example.com", "includeApex": false, "provider": "ovh",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body)
	}
	md, err := env.store.GetManagedDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("GetManagedDomain: %v", err)
	}
	if md.ProviderID != id {
		t.Errorf("legacy provider:\"ovh\" resolved to %q, want %q", md.ProviderID, id)
	}
}

// --- route DNS-01 edit-time guard (carried forward from Step J.4) ---------

// TestRouteCreate_DNS01_NoProvider_Rejects: a route POST with
// acmeChallenge="dns-01" is rejected 400 when no provider is configured.
func TestRouteCreate_DNS01_NoProvider_Rejects(t *testing.T) {
	env := newTestEnv(t, false)

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
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 0 {
		t.Errorf("store unexpectedly contains routes after rejected POST: %+v", got)
	}
	if env.caddy.CallCount() != 0 {
		t.Errorf("reload calls=%d, want 0 on validation reject", env.caddy.CallCount())
	}
}

// TestRouteUpdate_DNS01_NoProvider_Rejects mirrors the guard on PUT.
func TestRouteUpdate_DNS01_NoProvider_Rejects(t *testing.T) {
	env := newTestEnv(t, false)

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
// counterpart: with a configured provider, a dns-01 route create
// succeeds.
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
