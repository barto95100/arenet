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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func parseCSRPEM(t *testing.T, csrPEM string) *x509.CertificateRequest {
	t.Helper()
	b, _ := pem.Decode([]byte(csrPEM))
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("csr PEM did not decode to a CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("csr signature invalid: %v", err)
	}
	return csr
}

func parseKeyPEM(t *testing.T, keyPEM string) any {
	t.Helper()
	b, _ := pem.Decode([]byte(keyPEM))
	if b == nil || b.Type != "PRIVATE KEY" {
		t.Fatalf("key PEM did not decode to a PKCS#8 PRIVATE KEY")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		t.Fatalf("parse pkcs8 key: %v", err)
	}
	return k
}

func TestGenerateKeyAndCSR_RSA4096(t *testing.T) {
	subj := CSRSubject{CommonName: "app.corp.local", SANs: []string{"app.corp.local"},
		Organization: "Corp", Country: "FR", KeyAlgorithm: CSRAlgorithmRSA4096}
	keyPEM, csrPEM, err := GenerateKeyAndCSR(subj)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	k := parseKeyPEM(t, keyPEM)
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", k)
	}
	if rk.N.BitLen() != 4096 {
		t.Fatalf("expected 4096-bit key, got %d", rk.N.BitLen())
	}
	csr := parseCSRPEM(t, csrPEM)
	if csr.Subject.CommonName != "app.corp.local" {
		t.Fatalf("CN = %q", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "app.corp.local" {
		t.Fatalf("SANs = %v", csr.DNSNames)
	}
}

func TestGenerateKeyAndCSR_ECDSAP256(t *testing.T) {
	subj := CSRSubject{CommonName: "api.corp.local", KeyAlgorithm: CSRAlgorithmECDSAP256}
	keyPEM, csrPEM, err := GenerateKeyAndCSR(subj)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, ok := parseKeyPEM(t, keyPEM).(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected *ecdsa.PrivateKey")
	}
	csr := parseCSRPEM(t, csrPEM)
	// CN auto-added to SANs when SANs empty.
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "api.corp.local" {
		t.Fatalf("expected CN auto-added to SANs, got %v", csr.DNSNames)
	}
}

func TestGenerateKeyAndCSR_Validation(t *testing.T) {
	if _, _, err := GenerateKeyAndCSR(CSRSubject{KeyAlgorithm: CSRAlgorithmRSA4096}); err != ErrCSRCNRequired {
		t.Fatalf("empty CN: want ErrCSRCNRequired, got %v", err)
	}
	if _, _, err := GenerateKeyAndCSR(CSRSubject{CommonName: "x", Country: "FRA", KeyAlgorithm: CSRAlgorithmRSA4096}); err != ErrCSRInvalidCountry {
		t.Fatalf("3-letter country: want ErrCSRInvalidCountry, got %v", err)
	}
	if _, _, err := GenerateKeyAndCSR(CSRSubject{CommonName: "x", KeyAlgorithm: "ed25519"}); err != ErrCSRInvalidKeyAlgorithm {
		t.Fatalf("bad algo: want ErrCSRInvalidKeyAlgorithm, got %v", err)
	}
}
