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

package backup

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.26 — registry-driven secret handling for multi-type DNS providers.

func TestRedactSnapshot_SentinelisesEverySecretCredential(t *testing.T) {
	cf := storage.DNSProviderConfig{ID: "cf", Label: "CF", Type: "cloudflare",
		Credentials: map[string]string{"api_token": "cf-tok", "zone_token": "cf-zone"}}
	r53 := storage.DNSProviderConfig{ID: "r53", Label: "R53", Type: "route53",
		Credentials: map[string]string{"region": "eu-west-3", "access_key_id": "AKIA", "secret_access_key": "aws-secret"}}
	snap := minimalSnapshot()
	snap.DNSProviders = []storage.DNSProviderConfig{cf, r53}

	redactSnapshotInPlace(snap)

	raw, _ := json.Marshal(snap.DNSProviders)
	for _, leaked := range []string{"cf-tok", "cf-zone", "aws-secret"} {
		if strings.Contains(string(raw), leaked) {
			t.Errorf("secret %q survived redaction: %s", leaked, raw)
		}
	}
	got := snap.DNSProviders[1].Credentials
	if got["region"] != "eu-west-3" || got["access_key_id"] != "AKIA" || got["secret_access_key"] != SentinelLiteral {
		t.Errorf("route53 credentials after redaction = %v", got)
	}
	if cf.Credentials["api_token"] != "cf-tok" {
		t.Error("redaction mutated the caller's credentials map")
	}
}

// A pre-v2.26 backup file carries the flat OVH fields; it must import
// into the Credentials shape through the normal JSON decode path.
func TestImport_PreV226FlatOVHBackupJSON(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	ctx := context.Background()

	var providers []storage.DNSProviderConfig
	legacy := `[{"id":"6f1c0f5e-0d5a-4a57-9a39-8d2b1e2f3a4b","label":"OVH perso","type":"ovh",
		"endpoint":"ovh-eu","application_key":"ak","application_secret":"as","consumer_key":"ck"}]`
	if err := json.Unmarshal([]byte(legacy), &providers); err != nil {
		t.Fatal(err)
	}
	snap := minimalSnapshot()
	snap.Users = []auth.User{seedFakeUser("u-1", "$argon2id$hash")}
	snap.DNSProviders = providers

	if _, err := Import(ctx, store, us, snap, ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}
	got, err := store.GetDNSProvider(ctx, "6f1c0f5e-0d5a-4a57-9a39-8d2b1e2f3a4b")
	if err != nil {
		t.Fatal(err)
	}
	if got.Credentials["endpoint"] != "ovh-eu" || got.Credentials["consumer_key"] != "ck" {
		t.Errorf("imported = %+v", got)
	}
}

// A sentinel must not inherit a same-named secret from a live provider
// of ANOTHER type (hetzner.api_token ≠ infomaniak.api_token).
func TestImport_DNSProvider_SentinelDoesNotInheritAcrossTypes(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	ctx := context.Background()
	_ = seedLiveUser(t, us, "admin", "admin-password-15c-x")

	live, err := store.CreateDNSProvider(ctx, storage.DNSProviderConfig{
		Label: "H", Type: "hetzner", Credentials: map[string]string{"api_token": "live-hetzner"},
	})
	if err != nil {
		t.Fatal(err)
	}
	snap := minimalSnapshot()
	snap.SecretsIncluded = false
	snap.Users = []auth.User{seedFakeUser("u-1", "$argon2id$hash")}
	snap.DNSProviders = []storage.DNSProviderConfig{
		{ID: live.ID, Label: "I", Type: "infomaniak", Credentials: map[string]string{"api_token": SentinelLiteral}},
	}
	if _, err := Import(ctx, store, us, snap, ImportOptions{}); err == nil || !IsUnresolvedSentinelError(err) {
		t.Fatalf("err = %v, want unresolved sentinel (no cross-type inheritance)", err)
	}

	report, err := Import(ctx, store, us, snap, ImportOptions{AllowIncompleteRestore: true})
	if err != nil {
		t.Fatalf("incomplete restore: %v", err)
	}
	if len(report.IncompleteRows) != 1 || report.IncompleteRows[0].Field != "api_token" {
		t.Errorf("incomplete rows = %+v", report.IncompleteRows)
	}
}

func TestImport_DNSProvider_SentinelInheritsCloudflareSecret(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	ctx := context.Background()
	_ = seedLiveUser(t, us, "admin", "admin-password-15c-x")

	live, err := store.CreateDNSProvider(ctx, storage.DNSProviderConfig{
		Label: "CF", Type: "cloudflare", Credentials: map[string]string{"api_token": "live-cf"},
	})
	if err != nil {
		t.Fatal(err)
	}
	snap := minimalSnapshot()
	snap.SecretsIncluded = false
	snap.Users = []auth.User{seedFakeUser("u-1", "$argon2id$hash")}
	snap.DNSProviders = []storage.DNSProviderConfig{
		{ID: live.ID, Label: "CF", Type: "cloudflare", Credentials: map[string]string{"api_token": SentinelLiteral}},
	}
	if _, err := Import(ctx, store, us, snap, ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}
	got, _ := store.GetDNSProvider(ctx, live.ID)
	if got.Credentials["api_token"] != "live-cf" {
		t.Errorf("api_token = %q, want inherited live value", got.Credentials["api_token"])
	}
}
