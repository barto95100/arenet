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

package backup

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// seedLiveExternalCert persists an external certificate directly on the
// store (Task K.3 restore keys by the cert's own ID, so the returned ID
// is what the round-trip / sentinel-inherit tests match on).
func seedLiveExternalCert(t *testing.T, store *storage.Store, name, keyPEM string) storage.ExternalCertificate {
	t.Helper()
	c, err := store.CreateExternalCertificate(context.Background(), storage.ExternalCertificate{
		Name:     name,
		CertPEM:  "-----BEGIN CERTIFICATE-----\n" + name + "-cert\n-----END CERTIFICATE-----",
		KeyPEM:   keyPEM,
		ChainPEM: "-----BEGIN CERTIFICATE-----\n" + name + "-chain\n-----END CERTIFICATE-----",
		Subject:  "CN=" + name,
		DNSNames: []string{name + ".example.com"},
	})
	if err != nil {
		t.Fatalf("seed external cert: %v", err)
	}
	return c
}

// TestExportImport_ExternalCert_RoundTrip_IncludeSecrets is the CRITICAL
// data-loss anti-regression pin (review Finding #1): an external cert
// with a private key must round-trip through export --include-secrets →
// import into a fresh target, key intact. Before the fix the
// external_certificates bucket was entirely absent from the backup
// pipeline, so a config export→restore silently dropped every uploaded
// cert and every manual-cert route's CertID dangled.
func TestExportImport_ExternalCert_RoundTrip_IncludeSecrets(t *testing.T) {
	srcStore, srcUS := newTestStoreWithUserStore(t)
	ctx := context.Background()
	_ = seedLiveUser(t, srcUS, "admin", "admin-password-15c-x")
	cert := seedLiveExternalCert(t, srcStore, "app", "-----BEGIN PRIVATE KEY-----\nSECRET-KEY-MATERIAL\n-----END PRIVATE KEY-----")

	snap, err := Export(ctx, srcStore, srcUS, "test", true /* includeSecrets */)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(snap.ExternalCertificates) != 1 {
		t.Fatalf("exported %d external certs, want 1 (bucket absent from pipeline?)", len(snap.ExternalCertificates))
	}
	if snap.ExternalCertificates[0].KeyPEM == "" || snap.ExternalCertificates[0].KeyPEM == SentinelLiteral {
		t.Fatalf("--include-secrets export must carry cleartext key, got %q", snap.ExternalCertificates[0].KeyPEM)
	}

	dstStore, dstUS := newTestStoreWithUserStore(t)
	report, err := Import(ctx, dstStore, dstUS, snap, ImportOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if report.ExternalCertificatesImported != 1 {
		t.Errorf("report.ExternalCertificatesImported = %d, want 1", report.ExternalCertificatesImported)
	}

	list, err := dstStore.ListExternalCertificates(ctx)
	if err != nil {
		t.Fatalf("list after import: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("EXTERNAL-CERT RESTORE DATA LOSS: imported %d certs, want 1", len(list))
	}
	got := list[0]
	if got.ID != cert.ID {
		t.Errorf("cert ID not preserved: got %q, want %q", got.ID, cert.ID)
	}
	if got.KeyPEM != cert.KeyPEM {
		t.Errorf("KEY LOSS: key not restored: got %q, want %q", got.KeyPEM, cert.KeyPEM)
	}
	if got.CertPEM != cert.CertPEM || got.Name != "app" {
		t.Errorf("cert metadata mismatch after restore: %+v", got)
	}
}

// TestExport_ExternalCert_DefaultRedactsKey pins the redaction default:
// without --include-secrets the KeyPEM is replaced with the sentinel,
// while the public CertPEM / metadata travel verbatim (they are not
// secret).
func TestExport_ExternalCert_DefaultRedactsKey(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	_ = seedLiveUser(t, us, "admin", "admin-password-15c-x")
	_ = seedLiveExternalCert(t, store, "app", "-----BEGIN PRIVATE KEY-----\nSUPER-SECRET-KEY\n-----END PRIVATE KEY-----")

	snap, err := Export(context.Background(), store, us, "test", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(snap.ExternalCertificates) != 1 {
		t.Fatalf("exported %d external certs, want 1", len(snap.ExternalCertificates))
	}
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), "SUPER-SECRET-KEY") {
		t.Error("REDACTION LEAK: external cert private key leaked into default export")
	}
	ec := snap.ExternalCertificates[0]
	if ec.KeyPEM != SentinelLiteral {
		t.Errorf("KeyPEM not redacted: %q", ec.KeyPEM)
	}
	if !strings.Contains(ec.CertPEM, "app-cert") {
		t.Errorf("public CertPEM should travel verbatim, got %q", ec.CertPEM)
	}
	if ec.Subject != "CN=app" {
		t.Errorf("public Subject metadata should travel verbatim, got %q", ec.Subject)
	}
}

// TestImport_ExternalCert_SentinelInheritsByID confirms the
// preserve-on-import rule (review Finding #1): importing a redacted
// snapshot (KeyPEM == sentinel) against a live store that already holds
// the cert's key must inherit the live key — NOT overwrite it with the
// sentinel literal, NOT clear it.
func TestImport_ExternalCert_SentinelInheritsByID(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	ctx := context.Background()
	_ = seedLiveUser(t, us, "admin", "admin-password-15c-x")
	live := seedLiveExternalCert(t, store, "app", "-----BEGIN PRIVATE KEY-----\nLIVE-KEY\n-----END PRIVATE KEY-----")

	snap := minimalSnapshot()
	snap.SecretsIncluded = false
	snap.Users = []auth.User{seedFakeUser("u-1", "$argon2id$hash")}
	snap.ExternalCertificates = []storage.ExternalCertificate{
		{
			ID:       live.ID,
			Name:     "app",
			CertPEM:  live.CertPEM,
			KeyPEM:   SentinelLiteral,
			ChainPEM: live.ChainPEM,
			Subject:  "CN=app",
		},
	}

	report, err := Import(ctx, store, us, snap, ImportOptions{})
	if err != nil {
		t.Fatalf("import with sentinel inherit: %v", err)
	}
	if report.SentinelsInheritedTotal < 1 {
		t.Errorf("expected >=1 inherited sentinel (KeyPEM), got %d", report.SentinelsInheritedTotal)
	}

	got, err := store.GetExternalCertificate(ctx, live.ID)
	if err != nil {
		t.Fatalf("get after import: %v", err)
	}
	if got.KeyPEM == SentinelLiteral {
		t.Fatalf("SENTINEL LEAK: imported KeyPEM literal clobbered the stored key")
	}
	if got.KeyPEM != live.KeyPEM {
		t.Errorf("KEY LOSS: live key not inherited: got %q, want %q", got.KeyPEM, live.KeyPEM)
	}
}

// TestImport_ExternalCert_BackwardCompat_NoField pins forward-compat:
// a pre-v2.19.0 snapshot (no external_certificates field at all) imports
// cleanly — nil/empty slice, no error, no external certs in the target.
func TestImport_ExternalCert_BackwardCompat_NoField(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	ctx := context.Background()

	// A pre-v2.19.0 export JSON: no external_certificates key.
	raw := `{
		"schema_version": "1.0.0",
		"exported_at": "2026-01-01T00:00:00Z",
		"secrets_included": true,
		"arenet_version": "2.18.0",
		"routes": [],
		"dns_providers": [],
		"forward_auth_providers": [],
		"oidc_config": {},
		"users": [{"id":"u-1","username":"admin","password_hash":"$argon2id$hash","role":"admin","auth_source":"local"}]
	}`
	var snap Snapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		t.Fatalf("unmarshal legacy snapshot: %v", err)
	}
	if snap.ExternalCertificates != nil && len(snap.ExternalCertificates) != 0 {
		t.Fatalf("legacy snapshot should decode to nil/empty external certs, got %+v", snap.ExternalCertificates)
	}

	report, err := Import(ctx, store, us, &snap, ImportOptions{})
	if err != nil {
		t.Fatalf("BACKWARD-COMPAT REGRESSION: legacy snapshot without external_certificates failed to import: %v", err)
	}
	if report.ExternalCertificatesImported != 0 {
		t.Errorf("expected 0 external certs imported from legacy snapshot, got %d", report.ExternalCertificatesImported)
	}
	list, err := store.ListExternalCertificates(ctx)
	if err != nil {
		t.Fatalf("list after import: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty external cert bucket after legacy import, got %d", len(list))
	}
}
