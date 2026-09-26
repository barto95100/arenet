// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/libdns/libdns"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.26 — multi-type DNS providers: generic wire, /types, /test.

func decodeMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", rec.Body, err)
	}
	return out
}

func createCloudflareViaAPI(t *testing.T, env *testEnv) map[string]any {
	t.Helper()
	rec := postJSON(t, env.router, "/api/v1/settings/dns-providers", map[string]any{
		"label": "CF", "type": "cloudflare",
		"credentials": map[string]string{"api_token": "CF_SECRET_TOKEN"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create cloudflare status = %d, body=%s", rec.Code, rec.Body)
	}
	return decodeMap(t, rec)
}

func TestDNSProviders_CreateCloudflare_GenericWire(t *testing.T) {
	env := newTestEnv(t, false)
	created := createCloudflareViaAPI(t, env)
	if created["type"] != "cloudflare" || created["configured"] != true {
		t.Errorf("view = %+v", created)
	}
	raw, _ := json.Marshal(created)
	if strings.Contains(string(raw), "CF_SECRET_TOKEN") {
		t.Fatalf("secret leaked in view: %s", raw)
	}
	set, _ := created["secretsSet"].(map[string]any)
	if set["api_token"] != true || set["zone_token"] != false {
		t.Errorf("secretsSet = %v, want api_token:true zone_token:false", set)
	}
	if fields, _ := created["fields"].(map[string]any); len(fields) != 0 {
		t.Errorf("cloudflare has no non-secret field, got %v", fields)
	}
	if created["endpoint"] != "" {
		t.Errorf("endpoint must be empty for non-OVH, got %v", created["endpoint"])
	}
	stored, err := env.store.GetDNSProvider(context.Background(), created["id"].(string))
	if err != nil || stored.Credentials["api_token"] != "CF_SECRET_TOKEN" {
		t.Errorf("stored = %+v, err = %v", stored, err)
	}

	// Audit row carries no secret.
	for _, e := range env.audit.Events() {
		if e.Action == audit.ActionDNSProviderCreated && strings.Contains(string(e.AfterJSON), "CF_SECRET_TOKEN") {
			t.Errorf("secret in audit row: %s", e.AfterJSON)
		}
	}
}

func TestDNSProviders_OVHView_ExposesNonSecretFieldsOnly(t *testing.T) {
	env := newTestEnv(t, false)
	created := createProviderViaAPI(t, env, "OVH") // legacy camelCase body
	fields, _ := created["fields"].(map[string]any)
	if fields["endpoint"] != "ovh-eu" || len(fields) != 1 {
		t.Errorf("fields = %v, want only endpoint", fields)
	}
	if created["endpoint"] != "ovh-eu" {
		t.Errorf("legacy endpoint wire field = %v", created["endpoint"])
	}
	set, _ := created["secretsSet"].(map[string]any)
	for _, k := range []string{"application_key", "application_secret", "consumer_key"} {
		if set[k] != true {
			t.Errorf("secretsSet[%s] = %v", k, set[k])
		}
	}
}

func TestDNSProviders_UpdateCloudflare_PreservesSecretAndRejectsUnknownKey(t *testing.T) {
	env := newTestEnv(t, false)
	id := createCloudflareViaAPI(t, env)["id"].(string)
	path := "/api/v1/settings/dns-providers/" + id

	rec := putJSONRaw(t, env, path, map[string]any{
		"label": "CF renamed", "type": "cloudflare", "credentials": map[string]string{"api_token": ""},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d, body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.GetDNSProvider(context.Background(), id)
	if got.Label != "CF renamed" || got.Credentials["api_token"] != "CF_SECRET_TOKEN" {
		t.Errorf("after update: %+v", got)
	}

	rec = putJSONRaw(t, env, path, map[string]any{
		"label": "CF", "type": "cloudflare", "credentials": map[string]string{"api_tokn": "x"},
	})
	if rec.Code != http.StatusBadRequest || decodeMap(t, rec)["code"] != "invalid_credential_field" {
		t.Errorf("unknown key: status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestDNSProviders_CreateMissingCredential_Returns400(t *testing.T) {
	env := newTestEnv(t, false)
	rec := postJSON(t, env.router, "/api/v1/settings/dns-providers", map[string]any{
		"label": "PB", "type": "porkbun", "credentials": map[string]string{"api_key": "k"},
	})
	if rec.Code != http.StatusBadRequest || decodeMap(t, rec)["code"] != "missing_credential" {
		t.Errorf("status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestDNSProviderTypes_ServesRegistry(t *testing.T) {
	env := newTestEnv(t, false)
	rec := getRec(t, env, "/api/v1/settings/dns-providers/types")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body)
	}
	var types []storage.DNSProviderType
	if err := json.Unmarshal(rec.Body.Bytes(), &types); err != nil {
		t.Fatal(err)
	}
	if len(types) != len(storage.DNSProviderTypesList()) || types[0].Type != "ovh" {
		t.Fatalf("types = %+v", types)
	}
	for _, pt := range types {
		if len(pt.Fields) == 0 || pt.DocsURL == "" {
			t.Errorf("%s: incomplete metadata %+v", pt.Type, pt)
		}
	}
}

// stubDNSProbe swaps dnsProviderProbe for the test's duration.
func stubDNSProbe(t *testing.T, fn func(ctx context.Context, c storage.DNSProviderConfig, zone string) (int, error)) {
	t.Helper()
	orig := dnsProviderProbe
	dnsProviderProbe = fn
	t.Cleanup(func() { dnsProviderProbe = orig })
}

func TestDNSProviderTest_ExplicitZone_OK(t *testing.T) {
	env := newTestEnv(t, false)
	id := createCloudflareViaAPI(t, env)["id"].(string)
	var gotZone string
	var gotToken string
	stubDNSProbe(t, func(_ context.Context, c storage.DNSProviderConfig, zone string) (int, error) {
		gotZone, gotToken = zone, c.Credentials["api_token"]
		return 7, nil
	})
	rec := postJSON(t, env.router, "/api/v1/settings/dns-providers/"+id+"/test", map[string]string{"zone": "Example.COM."})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body)
	}
	out := decodeMap(t, rec)
	if out["ok"] != true || out["records"] != float64(7) || out["zone"] != "example.com" {
		t.Errorf("response = %v", out)
	}
	if gotZone != "example.com." || gotToken != "CF_SECRET_TOKEN" {
		t.Errorf("probe called with zone=%q token=%q", gotZone, gotToken)
	}
}

func TestDNSProviderTest_DefaultsToManagedDomainZone(t *testing.T) {
	env := newTestEnv(t, false)
	id := createCloudflareViaAPI(t, env)["id"].(string)
	if err := env.store.PutManagedDomain(context.Background(), storage.ManagedDomain{Apex: "home.example.net", ProviderID: id}); err != nil {
		t.Fatal(err)
	}
	var gotZone string
	stubDNSProbe(t, func(_ context.Context, _ storage.DNSProviderConfig, zone string) (int, error) {
		gotZone = zone
		return 1, nil
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/dns-providers/"+id+"/test", nil) // no body at all
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || gotZone != "home.example.net." {
		t.Errorf("status=%d zone=%q body=%s", rec.Code, gotZone, rec.Body)
	}
}

func TestDNSProviderTest_ErrorsAndRedaction(t *testing.T) {
	env := newTestEnv(t, false)
	id := createCloudflareViaAPI(t, env)["id"].(string)
	testPath := "/api/v1/settings/dns-providers/" + id + "/test"

	stubDNSProbe(t, func(context.Context, storage.DNSProviderConfig, string) (int, error) {
		return 0, errors.New("403 Forbidden: token CF_SECRET_TOKEN lacks Zone.DNS:Edit")
	})
	rec := postJSON(t, env.router, testPath, map[string]string{"zone": "example.com"})
	out := decodeMap(t, rec)
	if rec.Code != http.StatusOK || out["ok"] != false {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if msg, _ := out["error"].(string); strings.Contains(msg, "CF_SECRET_TOKEN") || !strings.Contains(msg, "Zone.DNS:Edit") {
		t.Errorf("error not redacted (or over-redacted): %q", msg)
	}

	for _, tc := range []struct {
		name, path, zone, code string
		status                 int
	}{
		{"no zone, no managed domain", testPath, "", "zone_required", http.StatusBadRequest},
		{"wildcard zone", testPath, "*.example.com", "invalid_zone", http.StatusBadRequest},
		{"unknown provider", "/api/v1/settings/dns-providers/nope/test", "example.com", "provider_not_found", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postJSON(t, env.router, tc.path, map[string]string{"zone": tc.zone})
			if rec.Code != tc.status || decodeMap(t, rec)["code"] != tc.code {
				t.Errorf("status=%d body=%s, want %d %s", rec.Code, rec.Body, tc.status, tc.code)
			}
		})
	}
}

func TestDNSProviderEndpoints_ViewerRejected(t *testing.T) {
	env := newTestEnv(t, false)
	id := createCloudflareViaAPI(t, env)["id"].(string)
	ctx := context.Background()
	viewer, err := newTestUserStore(t, env).CreateOIDCUser(ctx, "viewer-dns", "Viewer DNS", "", "sub-viewer-dns")
	if err != nil {
		t.Fatalf("seed viewer: %v", err)
	}
	if viewer.Role != auth.UserRoleViewer {
		t.Fatalf("seed-viewer role = %q; want viewer", viewer.Role)
	}
	s, err := auth.NewSessionStore(env.store.DB()).Create(ctx, viewer.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	probed := false
	stubDNSProbe(t, func(context.Context, storage.DNSProviderConfig, string) (int, error) {
		probed = true
		return 0, nil
	})
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/settings/dns-providers/types", ""},
		{http.MethodPost, "/api/v1/settings/dns-providers/" + id + "/test", `{"zone":"example.com"}`},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: s.ID})
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("VIEWER ESCALATION REGRESSION: %s %s status=%d", tc.method, tc.path, rec.Code)
		}
	}
	if probed {
		t.Error("viewer request reached the provider probe")
	}
}

// --- real probe path (no network) -----------------------------------------

// fakeDNSModule is a Caddy module registered under dns.providers.arenettest
// so the REAL dnsProviderProbe (GetModule → strict decode → Provision →
// GetRecords) is exercised without any network or provider account.
type fakeDNSModule struct {
	Token       string `json:"token"`
	provisioned bool
}

func (fakeDNSModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "dns.providers.arenettest", New: func() caddy.Module { return new(fakeDNSModule) }}
}

func (m *fakeDNSModule) Provision(caddy.Context) error {
	m.provisioned = true
	return nil
}

func (m *fakeDNSModule) GetRecords(_ context.Context, zone string) ([]libdns.Record, error) {
	if !m.provisioned {
		return nil, errors.New("GetRecords before Provision")
	}
	if m.Token != "good" {
		return nil, errors.New("auth failed for token " + m.Token)
	}
	if zone != "example.com." {
		return nil, errors.New("unexpected zone " + zone)
	}
	return []libdns.Record{
		libdns.TXT{Name: "@", Text: "a"},
		libdns.TXT{Name: "www", Text: "b"},
	}, nil
}

func init() { caddy.RegisterModule(fakeDNSModule{}) }

func TestDNSProviderProbe_RealModulePath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := storage.DNSProviderConfig{Type: "arenettest", Credentials: map[string]string{"token": "good"}}
	n, err := dnsProviderProbe(ctx, c, "example.com.")
	if err != nil || n != 2 {
		t.Fatalf("probe = %d, %v; want 2 records", n, err)
	}
	c.Credentials["token"] = "bad"
	if _, err := dnsProviderProbe(ctx, c, "example.com."); err == nil {
		t.Error("expected auth failure")
	}
	c.Credentials = map[string]string{"tokn": "good"}
	if _, err := dnsProviderProbe(ctx, c, "example.com."); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("strict decode: err = %v", err)
	}
	if _, err := dnsProviderProbe(ctx, storage.DNSProviderConfig{Type: "nosuchmodule"}, "example.com."); err == nil {
		t.Error("expected unavailable-module error")
	}
}
