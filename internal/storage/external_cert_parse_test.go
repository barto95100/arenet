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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func genSelfSigned(t *testing.T, cn string, notBefore, notAfter time.Time, dns []string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore, NotAfter: notAfter,
		DNSNames: dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestParseExternalCert_Valid(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM := genSelfSigned(t, "app.example.com", now.Add(-time.Hour), now.Add(365*24*time.Hour), []string{"app.example.com", "*.example.com"})
	meta, warnings, err := ParseExternalCert(certPEM, keyPEM, "")
	if err != nil {
		t.Fatalf("valid cert rejected: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %+v", warnings)
	}
	if len(meta.DNSNames) != 2 {
		t.Errorf("DNSNames = %v", meta.DNSNames)
	}
	if meta.NotAfter.IsZero() {
		t.Error("NotAfter not parsed")
	}
}

func TestParseExternalCert_KeyMismatch(t *testing.T) {
	certPEM, _ := genSelfSigned(t, "a", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []string{"a"})
	_, otherKey := genSelfSigned(t, "b", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []string{"b"})
	if _, _, err := ParseExternalCert(certPEM, otherKey, ""); err == nil {
		t.Error("want error for key not matching cert")
	}
}

func TestParseExternalCert_ExpiredWarns(t *testing.T) {
	certPEM, keyPEM := genSelfSigned(t, "old", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), []string{"old"})
	_, warnings, err := ParseExternalCert(certPEM, keyPEM, "")
	if err != nil {
		t.Fatalf("expired cert must warn not error: %v", err)
	}
	found := false
	for _, w := range warnings {
		if w.Code == CertWarnExpired {
			found = true
		}
	}
	if !found {
		t.Errorf("want cert_expired warning; got %+v", warnings)
	}
}

func TestParseExternalCert_CRLFNormalized(t *testing.T) {
	certPEM, keyPEM := genSelfSigned(t, "crlf", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []string{"crlf"})
	crlf := strings.ReplaceAll(certPEM, "\n", "\r\n")
	if _, _, err := ParseExternalCert(crlf, keyPEM, ""); err != nil {
		t.Errorf("CRLF PEM should parse after normalization: %v", err)
	}
}
