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

package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/secrets"
	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// Plaintext secrets seeded by seedAllSecrets. None may appear in the
// BoltDB file once encryption is enabled.
var atRestSecrets = map[string]string{
	"dns":        "dns-api-token-PLAIN",
	"extkey":     "-----BEGIN PRIVATE KEY-----PLAIN",
	"crowdsec":   "crowdsec-key-PLAIN",
	"watcher":    "watcher-pass-PLAIN",
	"maxmind":    "maxmind-license-PLAIN",
	"oidc":       "oidc-client-secret-PLAIN",
	"fwdauth":    "fwd-client-secret-PLAIN",
	"smtp":       "smtp-password-PLAIN",
	"authheader": "Bearer upstream-token-PLAIN",
}

const visibleHeaderValue = "not-a-secret-VISIBLE"

type seededIDs struct {
	dnsID, extID, channelID, routeID string
}

func keyringForTest(t *testing.T, b byte) *secrets.Keyring {
	t.Helper()
	k, err := secrets.New(bytes.Repeat([]byte{b}, secrets.KeySize))
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	return k
}

func openStoreAt(t *testing.T, path string) *Store {
	t.Helper()
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seedAllSecrets(t *testing.T, s *Store) seededIDs {
	t.Helper()
	ctx := context.Background()
	var ids seededIDs
	dns, err := s.CreateDNSProvider(ctx, DNSProviderConfig{
		ID: uuid.NewString(), Label: "cf", Type: "cloudflare",
		Credentials: map[string]string{"api_token": atRestSecrets["dns"]},
	})
	if err != nil {
		t.Fatalf("dns: %v", err)
	}
	ids.dnsID = dns.ID
	ext, err := s.CreateExternalCertificate(ctx, ExternalCertificate{Name: "x", CertPEM: "CERT", KeyPEM: atRestSecrets["extkey"]})
	if err != nil {
		t.Fatalf("ext cert: %v", err)
	}
	ids.extID = ext.ID
	if err := s.PutCrowdSecConfig(ctx, CrowdSecConfig{LAPIURL: "http://crowdsec:8080/", APIKey: atRestSecrets["crowdsec"]}); err != nil {
		t.Fatalf("crowdsec: %v", err)
	}
	if err := s.PutWatcherCredentials(ctx, WatcherCredentials{LAPIURL: "http://crowdsec:8080/", MachineID: "m", Password: atRestSecrets["watcher"]}); err != nil {
		t.Fatalf("watcher: %v", err)
	}
	if err := s.PutMaxMindConfig(ctx, MaxMindConfig{AccountID: 42, LicenseKey: atRestSecrets["maxmind"], EditionID: "GeoLite2-City"}); err != nil {
		t.Fatalf("maxmind: %v", err)
	}
	if err := s.PutOIDCConfig(ctx, OIDCConfig{
		IssuerURL: "https://idp.example", ClientID: "arenet", ClientSecret: atRestSecrets["oidc"],
		RedirectURL: "https://arenet.example/api/v1/auth/oidc/callback", Scopes: []string{"openid"},
	}); err != nil {
		t.Fatalf("oidc: %v", err)
	}
	if _, err := s.CreateForwardAuthProvider(ctx, ForwardAuthProvider{
		Name: "authelia", Kind: "authelia", VerifyURL: "http://authelia:9091",
		AuthRequestURI: "/api/authz/forward-auth", ClientSecret: atRestSecrets["fwdauth"],
	}); err != nil {
		t.Fatalf("forward auth: %v", err)
	}
	cfg, _ := json.Marshal(map[string]any{
		"smtpHost": "smtp.example.com", "smtpPort": 587, "smtpPassword": atRestSecrets["smtp"],
		"from": "a@example.com", "to": []string{"b@example.com"},
	})
	ch, err := s.CreateAlertChannel(ctx, Channel{ID: uuid.NewString(), Name: "mail", Kind: ChannelKindEmail, Enabled: true, Config: cfg})
	if err != nil {
		t.Fatalf("channel: %v", err)
	}
	ids.channelID = ch.ID
	r := minimalRoute("app.example.com", "http://10.0.0.1:80")
	r.RequestHeaders = map[string]string{"Authorization": atRestSecrets["authheader"], "X-Custom": visibleHeaderValue}
	route, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	ids.routeID = route.ID
	return ids
}

// assertSecretsReadable reads every seeded secret back through the
// public API.
func assertSecretsReadable(t *testing.T, s *Store, ids seededIDs) {
	t.Helper()
	ctx := context.Background()
	check := func(what, got, want string) {
		t.Helper()
		if got != want {
			t.Errorf("%s = %q, want %q", what, got, want)
		}
	}
	dns, err := s.GetDNSProvider(ctx, ids.dnsID)
	if err != nil {
		t.Fatalf("get dns: %v", err)
	}
	check("dns credential", dns.Credentials["api_token"], atRestSecrets["dns"])
	list, _ := s.ListDNSProviders(ctx)
	check("listed dns credential", list[0].Credentials["api_token"], atRestSecrets["dns"])
	ext, _ := s.GetExternalCertificate(ctx, ids.extID)
	check("ext key", ext.KeyPEM, atRestSecrets["extkey"])
	exts, _ := s.ListExternalCertificates(ctx)
	check("listed ext key", exts[0].KeyPEM, atRestSecrets["extkey"])
	cs, _ := s.GetCrowdSecConfig(ctx)
	check("crowdsec", cs.APIKey, atRestSecrets["crowdsec"])
	wc, _ := s.GetWatcherCredentials(ctx)
	check("watcher", wc.Password, atRestSecrets["watcher"])
	mm, _ := s.GetMaxMindConfig(ctx)
	check("maxmind", mm.LicenseKey, atRestSecrets["maxmind"])
	oidc, _ := s.GetOIDCConfig(ctx)
	check("oidc", oidc.ClientSecret, atRestSecrets["oidc"])
	fa, _ := s.GetForwardAuthProvider(ctx, "authelia")
	check("forward auth", fa.ClientSecret, atRestSecrets["fwdauth"])
	fas, _ := s.ListForwardAuthProviders(ctx)
	check("listed forward auth", fas[0].ClientSecret, atRestSecrets["fwdauth"])
	ch, _ := s.GetAlertChannel(ctx, ids.channelID)
	if !strings.Contains(string(ch.Config), atRestSecrets["smtp"]) || !json.Valid(ch.Config) {
		t.Errorf("channel config = %s", ch.Config)
	}
	chs, _ := s.ListAlertChannels(ctx)
	if !strings.Contains(string(chs[0].Config), atRestSecrets["smtp"]) {
		t.Errorf("listed channel config = %s", chs[0].Config)
	}
	r, _ := s.GetRoute(ctx, ids.routeID)
	check("route auth header", r.RequestHeaders["Authorization"], atRestSecrets["authheader"])
	check("route plain header", r.RequestHeaders["X-Custom"], visibleHeaderValue)
	rs, _ := s.ListRoutes(ctx)
	check("listed route header", rs[0].RequestHeaders["Authorization"], atRestSecrets["authheader"])
}

// assertFileHoldsNoSecret closes nothing: bbolt writes pages to the
// file on commit, so the committed bytes can be scanned directly.
func assertFileHoldsNoSecret(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read db file: %v", err)
	}
	for name, v := range atRestSecrets {
		if bytes.Contains(raw, []byte(v)) {
			t.Errorf("PLAINTEXT AT REST: %s (%q) found in the BoltDB file", name, v)
		}
	}
	if !bytes.Contains(raw, []byte(visibleHeaderValue)) {
		t.Error("a non-sensitive header value should stay in clear")
	}
}

func TestEncryption_MigratesExistingAndSealsNewWrites(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "arenet.db")
	s := openStoreAt(t, path)
	ids := seedAllSecrets(t, s) // written in clear (pre-v2.30 install)

	n, err := s.EnableEncryption(ctx, keyringForTest(t, 1))
	if err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if n != 9 { // dns, ext, crowdsec, watcher, maxmind, oidc, fwd, channel, route
		t.Errorf("rewritten rows = %d, want 9", n)
	}
	if err := s.Compact(); err != nil {
		t.Fatalf("Compact: %v", err)
	}
	assertSecretsReadable(t, s, ids)
	assertFileHoldsNoSecret(t, path)
	if fp, _ := s.SecretsKeyFingerprint(ctx); fp != keyringForTest(t, 1).Fingerprint() {
		t.Errorf("fingerprint %q not recorded", fp)
	}

	// Idempotent: a second boot rewrites nothing.
	if n, err := s.EnableEncryption(ctx, keyringForTest(t, 1)); err != nil || n != 0 {
		t.Errorf("second EnableEncryption = %d, %v", n, err)
	}

	// Writes after enabling are sealed too (update paths included).
	dns, _ := s.GetDNSProvider(ctx, ids.dnsID)
	dns.Credentials["api_token"] = atRestSecrets["dns"] // unchanged value, re-saved
	if _, err := s.UpdateDNSProvider(ctx, ids.dnsID, dns); err != nil {
		t.Fatalf("update dns: %v", err)
	}
	assertSecretsReadable(t, s, ids)
	assertFileHoldsNoSecret(t, path)
}

func TestEncryption_FreshStoreSealsOnWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arenet.db")
	s := openStoreAt(t, path)
	if _, err := s.EnableEncryption(context.Background(), keyringForTest(t, 1)); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	ids := seedAllSecrets(t, s)
	assertSecretsReadable(t, s, ids)
	assertFileHoldsNoSecret(t, path)
}

func TestEncryption_WrongOrMissingKey(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "arenet.db")
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if _, err := s.EnableEncryption(ctx, keyringForTest(t, 1)); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	seedAllSecrets(t, s)
	_ = s.Close()

	s2 := openStoreAt(t, path)
	// No key loaded: sealed values are never handed out as-is.
	if _, err := s2.GetOIDCConfig(ctx); !errors.Is(err, ErrSecretsKeyRequired) {
		t.Errorf("read without key: %v", err)
	}
	if _, err := s2.EnableEncryption(ctx, keyringForTest(t, 2)); !errors.Is(err, ErrSecretsKeyMismatch) {
		t.Errorf("wrong key: %v", err)
	}
	if _, err := s2.GetOIDCConfig(ctx); !errors.Is(err, ErrSecretsKeyRequired) {
		t.Errorf("a refused key must not be loaded: %v", err)
	}
}

// TestEncryption_SealedDataWithoutFingerprint: sealed values from a
// foreign key are detected even if the meta row is gone.
func TestEncryption_SealedDataWithoutFingerprint(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.EnableEncryption(ctx, keyringForTest(t, 1)); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	seedAllSecrets(t, s)
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketMeta)).Delete([]byte(metaKeySecretsFingerprint))
	}); err != nil {
		t.Fatalf("drop fingerprint: %v", err)
	}
	if _, err := s.EnableEncryption(ctx, keyringForTest(t, 2)); !errors.Is(err, ErrSecretsKeyMismatch) {
		t.Errorf("foreign sealed data: %v", err)
	}
}

func TestEncryption_RestoreSealsRows(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "arenet.db")
	s := openStoreAt(t, path)
	if _, err := s.EnableEncryption(ctx, keyringForTest(t, 1)); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	oidc, _ := json.Marshal(OIDCConfig{IssuerURL: "https://idp.example", ClientID: "arenet", ClientSecret: atRestSecrets["oidc"]})
	r := minimalRoute("app.example.com", "http://10.0.0.1:80")
	r.ID = "r1"
	r.RequestHeaders = map[string]string{"Authorization": atRestSecrets["authheader"], "X-Custom": visibleHeaderValue}
	route, _ := json.Marshal(r)
	if err := s.RestoreSnapshot(ctx, RestoreSnapshotInput{
		Routes: map[string][]byte{"r1": route}, OIDCConfig: oidc,
		Extras: &RestoreExtras{CrowdSecConfig: &CrowdSecConfig{LAPIURL: "http://c:8080/", APIKey: atRestSecrets["crowdsec"]}},
	}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, _ := s.GetOIDCConfig(ctx); got.ClientSecret != atRestSecrets["oidc"] {
		t.Errorf("restored oidc secret %q", got.ClientSecret)
	}
	raw, _ := os.ReadFile(path)
	for _, v := range []string{atRestSecrets["oidc"], atRestSecrets["authheader"], atRestSecrets["crowdsec"]} {
		if bytes.Contains(raw, []byte(v)) {
			t.Errorf("restore wrote %q in clear", v)
		}
	}
}

func TestSealRow_AADBindsBucketAndField(t *testing.T) {
	kr := keyringForTest(t, 1)
	sealed, _, err := sealRow(kr, bucketOIDCConfig, []byte(`{"client_secret":"x"}`))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// The same sealed value moved to another bucket's field must not open.
	var m map[string]string
	_ = json.Unmarshal(sealed, &m)
	moved, _ := json.Marshal(map[string]string{"client_secret": m["client_secret"]})
	if _, err := openRow(kr, bucketForwardAuthProviders, moved); !errors.Is(err, secrets.ErrOpen) {
		t.Errorf("moved value opened: %v", err)
	}
}
