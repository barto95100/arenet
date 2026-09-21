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

package storage

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestDNSProviderRegistry_Sanity(t *testing.T) {
	list := DNSProviderTypesList()
	if len(list) != 9 {
		t.Fatalf("registry has %d types, want 9", len(list))
	}
	if list[0].Type != DNSProviderTypeOVH {
		t.Errorf("first type = %q, want ovh (reference provider first)", list[0].Type)
	}
	seen := map[string]bool{}
	for _, pt := range list {
		if seen[pt.Type] {
			t.Errorf("duplicate type %q", pt.Type)
		}
		seen[pt.Type] = true
		if pt.Label == "" || !strings.HasPrefix(pt.DocsURL, "https://") {
			t.Errorf("%s: missing label or https docs URL", pt.Type)
		}
		keys := map[string]bool{}
		hasRequiredSecret := false
		for _, f := range pt.Fields {
			if keys[f.Key] {
				t.Errorf("%s: duplicate field %q", pt.Type, f.Key)
			}
			keys[f.Key] = true
			if f.Default != "" && len(f.Enum) > 0 && !slices.Contains(f.Enum, f.Default) {
				t.Errorf("%s.%s: default %q not in enum", pt.Type, f.Key, f.Default)
			}
			if f.Secret && f.Required {
				hasRequiredSecret = true
			}
		}
		if !hasRequiredSecret {
			t.Errorf("%s: no required secret field", pt.Type)
		}
	}
	// The list is a copy: mutating it must not alter the registry.
	list[0].Type = "mutated"
	if _, ok := DNSProviderTypeByName(DNSProviderTypeOVH); !ok {
		t.Error("DNSProviderTypesList leaked the backing registry")
	}
}

func TestDNSProviderConfig_UnmarshalLegacyFlatFields(t *testing.T) {
	raw := `{"id":"p1","label":"OVH","endpoint":"ovh-ca","application_key":"ak","application_secret":"as","consumer_key":"ck"}`
	var c DNSProviderConfig
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"endpoint": "ovh-ca", "application_key": "ak", "application_secret": "as", "consumer_key": "ck"}
	if c.Type != DNSProviderTypeOVH || c.ID != "p1" || c.Label != "OVH" {
		t.Errorf("header fields = %+v", c)
	}
	for k, v := range want {
		if c.Credentials[k] != v {
			t.Errorf("Credentials[%s] = %q, want %q", k, c.Credentials[k], v)
		}
	}
	out, _ := json.Marshal(c)
	var top map[string]json.RawMessage
	if err := json.Unmarshal(out, &top); err != nil {
		t.Fatal(err)
	}
	if _, flat := top["application_key"]; flat {
		t.Errorf("re-marshal kept the flat shape: %s", out)
	}
	if _, ok := top["credentials"]; !ok {
		t.Errorf("re-marshal lacks credentials: %s", out)
	}
}

func TestDNSProviderConfig_UnmarshalCredentialsWinOverLegacy(t *testing.T) {
	raw := `{"id":"p1","label":"x","type":"ovh","credentials":{"endpoint":"ovh-us"},"endpoint":"ovh-eu"}`
	var c DNSProviderConfig
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	if c.Credentials["endpoint"] != "ovh-us" {
		t.Errorf("endpoint = %q, want the credentials-map value", c.Credentials["endpoint"])
	}
}

func TestDNSProviderConfig_Validate(t *testing.T) {
	cases := []struct {
		name    string
		c       DNSProviderConfig
		wantErr string
	}{
		{"ovh ok", DNSProviderConfig{Label: "a", Type: "ovh", Credentials: ovhTestCreds()}, ""},
		{"cloudflare ok, optional absent", DNSProviderConfig{Label: "a", Type: "cloudflare",
			Credentials: map[string]string{"api_token": "t"}}, ""},
		{"unknown type", DNSProviderConfig{Label: "a", Type: "bind9"}, "not a recognised provider type"},
		{"missing required", DNSProviderConfig{Label: "a", Type: "porkbun",
			Credentials: map[string]string{"api_key": "k"}}, "api_secret_key must not be empty"},
		{"bad enum", DNSProviderConfig{Label: "a", Type: "ovh", Credentials: map[string]string{
			"endpoint": "ovh-mars", "application_key": "a", "application_secret": "b", "consumer_key": "c"}},
			"is not one of"},
		{"unknown key", DNSProviderConfig{Label: "a", Type: "hetzner", Credentials: map[string]string{
			"api_token": "t", "api_tokn": "x"}}, `field "api_tokn" is not valid`},
		{"empty label", DNSProviderConfig{Type: "gandi", Credentials: map[string]string{"bearer_token": "t"}},
			"label must not be empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.c.validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestProviderConfiguredAndSecrets(t *testing.T) {
	c := DNSProviderConfig{Type: "route53", Credentials: map[string]string{
		"region": "eu-west-3", "access_key_id": "AKIA", "secret_access_key": "s3cr3t",
	}}
	if !ProviderConfigured(c) {
		t.Error("route53 with all required fields should be configured")
	}
	if got := SecretValues(c); !slices.Equal(got, []string{"s3cr3t"}) {
		t.Errorf("SecretValues = %v", got)
	}
	stripped := WithoutSecrets(c)
	if _, ok := stripped.Credentials["secret_access_key"]; ok {
		t.Error("WithoutSecrets kept the secret")
	}
	if stripped.Credentials["access_key_id"] != "AKIA" || c.Credentials["secret_access_key"] != "s3cr3t" {
		t.Error("WithoutSecrets must keep non-secrets and not mutate its input")
	}
	delete(c.Credentials, "region")
	if ProviderConfigured(c) {
		t.Error("missing required region should not be configured")
	}
	if ProviderConfigured(DNSProviderConfig{Type: "bind9"}) {
		t.Error("unknown type should not be configured")
	}
	if got := WithoutSecrets(DNSProviderConfig{Type: "bind9", Credentials: map[string]string{"k": "v"}}); len(got.Credentials) != 0 {
		t.Error("WithoutSecrets must drop everything for an unknown type")
	}
}

func TestDNSProvider_CreateDropsEmptyOptional(t *testing.T) {
	s := newStoreForTest(t)
	p, err := s.CreateDNSProvider(context.Background(), DNSProviderConfig{
		Label: "cf", Type: "cloudflare", Credentials: map[string]string{"api_token": "t", "zone_token": ""},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Credentials["zone_token"]; ok {
		t.Error("empty optional field should not be stored")
	}
}

func TestDNSProvider_UpdateTypeChangePreservesNothing(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, err := s.CreateDNSProvider(ctx, DNSProviderConfig{
		Label: "x", Type: "hetzner", Credentials: map[string]string{"api_token": "old"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Same key name, other type: the old secret must NOT carry over.
	if _, err := s.UpdateDNSProvider(ctx, p.ID, DNSProviderConfig{Label: "x", Type: "infomaniak"}); err == nil {
		t.Fatal("expected required-field error after type change without credentials")
	}
	got, err := s.UpdateDNSProvider(ctx, p.ID, DNSProviderConfig{
		Label: "x", Type: "infomaniak", Credentials: map[string]string{"api_token": "new"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Credentials["api_token"] != "new" {
		t.Errorf("api_token = %q", got.Credentials["api_token"])
	}
}

func TestDNSProvider_UpdateReplacesNonSecretAndProvidedSecret(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, err := s.CreateDNSProvider(ctx, DNSProviderConfig{
		Label: "x", Type: "scaleway", Credentials: map[string]string{"secret_key": "sk", "organization_id": "org1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.UpdateDNSProvider(ctx, p.ID, DNSProviderConfig{
		Label: "x", Type: "scaleway", Credentials: map[string]string{"organization_id": "org2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Credentials["organization_id"] != "org2" || got.Credentials["secret_key"] != "sk" {
		t.Errorf("credentials = %v", got.Credentials)
	}
	got, err = s.UpdateDNSProvider(ctx, p.ID, DNSProviderConfig{
		Label: "x", Type: "scaleway", Credentials: map[string]string{"secret_key": "sk2", "organization_id": "org2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Credentials["secret_key"] != "sk2" {
		t.Errorf("secret_key = %q, want replaced", got.Credentials["secret_key"])
	}
}

func TestMigrateDNSProviderCredentials_RewritesLegacyRowsIdempotently(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	legacy := []byte(`{"id":"p1","label":"OVH","type":"ovh","endpoint":"ovh-eu","application_key":"ak","application_secret":"as","consumer_key":"ck"}`)
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketDNSProviders)).Put([]byte("p1"), legacy)
	}); err != nil {
		t.Fatal(err)
	}
	modern, err := s.CreateDNSProvider(ctx, DNSProviderConfig{
		Label: "cf", Type: "cloudflare", Credentials: map[string]string{"api_token": "t"},
	})
	if err != nil {
		t.Fatal(err)
	}

	n, err := s.MigrateDNSProviderCredentials(ctx)
	if err != nil || n != 1 {
		t.Fatalf("first run: n=%d err=%v, want 1 row rewritten", n, err)
	}
	var raw []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		raw = append(raw, tx.Bucket([]byte(bucketDNSProviders)).Get([]byte("p1"))...)
		return nil
	})
	if legacyLeft, _ := hasLegacyDNSProviderFields(raw); legacyLeft {
		t.Errorf("row still has flat fields: %s", raw)
	}
	got, err := s.GetDNSProvider(ctx, "p1")
	if err != nil || got.Credentials["consumer_key"] != "ck" || got.Credentials["endpoint"] != "ovh-eu" {
		t.Errorf("migrated row = %+v, err=%v", got, err)
	}
	if n, err := s.MigrateDNSProviderCredentials(ctx); err != nil || n != 0 {
		t.Errorf("second run: n=%d err=%v, want no-op", n, err)
	}
	if got, _ := s.GetDNSProvider(ctx, modern.ID); got.Credentials["api_token"] != "t" {
		t.Error("modern row altered by migration")
	}
}

func TestRedactDNSSecrets(t *testing.T) {
	cf := DNSProviderConfig{Type: "cloudflare", Credentials: map[string]string{"api_token": "tok-SECRET"}}
	ovh := DNSProviderConfig{Type: "ovh", Credentials: map[string]string{
		"endpoint": "ovh-eu", "application_key": "ak12", "application_secret": "as-SECRET", "consumer_key": "ck",
	}}
	msg := "API token 'tok-SECRET' invalid; as-SECRET; key ak12; endpoint ovh-eu; ck"
	got := RedactDNSSecrets(msg, cf, ovh)
	for _, leaked := range []string{"tok-SECRET", "as-SECRET", "ak12"} {
		if strings.Contains(got, leaked) {
			t.Errorf("secret %q not redacted: %s", leaked, got)
		}
	}
	if !strings.Contains(got, "ovh-eu") {
		t.Errorf("non-secret endpoint must survive: %s", got)
	}
	if !strings.Contains(got, "; ck") {
		t.Errorf("secrets shorter than %d chars are left alone: %s", minRedactLen, got)
	}
}
