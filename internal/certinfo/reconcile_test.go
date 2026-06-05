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

package certinfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeLeafPEM generates a fresh self-signed leaf cert and writes
// it to the certmagic-shaped on-disk path:
//
//	<root>/certificates/<issuerSafe>/<domainSafe>/<domainSafe>.crt
//
// Returns the SAN list put in the leaf so tests can assert
// pickPrimaryDomain pulled the right one.
func writeLeafPEM(t *testing.T, root, issuerSafe, domainSafe string, sans []string, notAfter time.Time) []string {
	t.Helper()
	dir := filepath.Join(root, "certificates", issuerSafe, domainSafe)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: sans[0]},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     sans,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	path := filepath.Join(dir, domainSafe+".crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return sans
}

func TestReconcileFromDisk_NilTracker(t *testing.T) {
	if _, err := ReconcileFromDisk(nil, t.TempDir()); err == nil {
		t.Fatalf("expected error on nil tracker")
	}
}

func TestReconcileFromDisk_EmptyStorageDir(t *testing.T) {
	if _, err := ReconcileFromDisk(NewTracker(), ""); err == nil {
		t.Fatalf("expected error on empty storageDir")
	}
}

// TestReconcileFromDisk_MissingDir pins the AC #15-style degraded
// path: a fresh install with no Caddy data dir yet must NOT
// surface as an error — boot continues with an empty tracker.
func TestReconcileFromDisk_MissingDir(t *testing.T) {
	tr := NewTracker()
	root := filepath.Join(t.TempDir(), "does-not-exist")
	count, err := ReconcileFromDisk(tr, root)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if count != 0 {
		t.Fatalf("count=%d want=0 on missing dir", count)
	}
}

// TestReconcileFromDisk_EmptyCertsDir: storage dir exists but the
// `certificates` subdir is empty (no issuers seen yet).
func TestReconcileFromDisk_EmptyCertsDir(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "certificates"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	tr := NewTracker()
	count, err := ReconcileFromDisk(tr, root)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if count != 0 {
		t.Fatalf("count=%d want=0 on empty certs dir", count)
	}
}

// TestReconcileFromDisk_SeedsValidCerts: the happy path —
// reconcile finds a leaf cert and seeds the tracker with the
// parsed metadata.
func TestReconcileFromDisk_SeedsValidCerts(t *testing.T) {
	root := t.TempDir()
	notAfter := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second).UTC()

	writeLeafPEM(t, root,
		"acme-v02.api.letsencrypt.org-directory",
		"valid.example.com",
		[]string{"valid.example.com"},
		notAfter,
	)

	tr := NewTracker()
	count, err := ReconcileFromDisk(tr, root)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if count != 1 {
		t.Fatalf("count=%d want=1", count)
	}

	info, ok := tr.Get("valid.example.com")
	if !ok {
		t.Fatalf("Get(valid.example.com) miss after reconcile")
	}
	if !info.NotAfter.Equal(notAfter) {
		t.Fatalf("NotAfter=%v want=%v", info.NotAfter, notAfter)
	}
	if info.Issuer != "Let's Encrypt" {
		t.Fatalf("Issuer=%q want=%q", info.Issuer, "Let's Encrypt")
	}
	if info.Source != SourceSpecific {
		t.Fatalf("Source=%q want=%q", info.Source, SourceSpecific)
	}
}

// TestReconcileFromDisk_WildcardSubject pins that a *.example.com
// SAN is preserved as the primary domain (wildcard takes precedence
// in pickPrimaryDomain) and Source flips to Wildcard.
func TestReconcileFromDisk_WildcardSubject(t *testing.T) {
	root := t.TempDir()
	notAfter := time.Now().Add(45 * 24 * time.Hour).Truncate(time.Second).UTC()
	writeLeafPEM(t, root,
		"acme-v02.api.letsencrypt.org-directory",
		"wildcard_.example.com",
		[]string{"*.example.com"},
		notAfter,
	)

	tr := NewTracker()
	count, _ := ReconcileFromDisk(tr, root)
	if count != 1 {
		t.Fatalf("count=%d want=1", count)
	}
	info, ok := tr.Get("*.example.com")
	if !ok {
		t.Fatalf("Get(*.example.com) miss")
	}
	if info.Source != SourceWildcard {
		t.Fatalf("Source=%q want=wildcard", info.Source)
	}
}

// TestReconcileFromDisk_SkipsCorruptedPEM pins resilience: a
// corrupted .crt file in one domain dir must NOT prevent the
// reconcile from processing the others. The bad dir is skipped
// (no entry in tracker, no error returned).
func TestReconcileFromDisk_SkipsCorruptedPEM(t *testing.T) {
	root := t.TempDir()
	notAfter := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second).UTC()

	// One valid cert.
	writeLeafPEM(t, root,
		"acme-v02.api.letsencrypt.org-directory",
		"good.example.com",
		[]string{"good.example.com"},
		notAfter,
	)
	// One corrupted cert (random bytes, not a real PEM).
	corruptedDir := filepath.Join(root, "certificates",
		"acme-v02.api.letsencrypt.org-directory", "bad.example.com")
	if err := os.MkdirAll(corruptedDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(corruptedDir, "bad.example.com.crt"),
		[]byte("this is not a PEM"), 0o600); err != nil {
		t.Fatalf("write corrupted: %v", err)
	}

	tr := NewTracker()
	count, err := ReconcileFromDisk(tr, root)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if count != 1 {
		t.Fatalf("count=%d want=1 (only the good cert)", count)
	}
	if _, ok := tr.Get("good.example.com"); !ok {
		t.Fatalf("good.example.com not in tracker")
	}
	if _, ok := tr.Get("bad.example.com"); ok {
		t.Fatalf("bad.example.com should be absent")
	}
}

// TestDecodeIssuerLabel: the on-disk issuer-key-safe strings the
// three known LE / Caddy issuers produce must map back to readable
// labels. Unknown keys pass through (defensive).
func TestDecodeIssuerLabel(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"acme-v02.api.letsencrypt.org-directory", "Let's Encrypt"},
		{"acme-staging-v02.api.letsencrypt.org-directory", "Let's Encrypt (staging)"},
		{"local", "Caddy local CA"},
		{"zerossl-foo", "zerossl-foo"}, // pass-through
	}
	for _, tc := range cases {
		if got := decodeIssuerLabel(tc.in); got != tc.want {
			t.Fatalf("decodeIssuerLabel(%q)=%q want=%q", tc.in, got, tc.want)
		}
	}
}

// TestInferSourceFromSubject: the wildcard-prefix heuristic.
func TestInferSourceFromSubject(t *testing.T) {
	if got := inferSourceFromSubject("*.example.com"); got != SourceWildcard {
		t.Fatalf("got=%q want=wildcard", got)
	}
	if got := inferSourceFromSubject("api.example.com"); got != SourceSpecific {
		t.Fatalf("got=%q want=specific", got)
	}
}

// TestReverseSafeDomain: the certmagic Safe transform's most
// operationally-surprising substitution.
func TestReverseSafeDomain(t *testing.T) {
	if got := reverseSafeDomain("wildcard_.example.com"); got != "*.example.com" {
		t.Fatalf("got=%q want=*.example.com", got)
	}
	if got := reverseSafeDomain("api.example.com"); got != "api.example.com" {
		t.Fatalf("got=%q want=passthrough", got)
	}
}
