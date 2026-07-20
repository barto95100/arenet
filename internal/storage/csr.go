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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
)

// Key-algorithm identifiers accepted by GenerateKeyAndCSR (spec §Q3).
const (
	CSRAlgorithmRSA4096   = "rsa_4096"
	CSRAlgorithmECDSAP256 = "ecdsa_p256"
)

// Blocking validation errors — the API layer surfaces .Error() as the
// actionable code (cn_required, invalid_country, invalid_key_algorithm).
var (
	ErrCSRCNRequired          = errors.New("cn_required")
	ErrCSRInvalidCountry      = errors.New("invalid_country")
	ErrCSRInvalidKeyAlgorithm = errors.New("invalid_key_algorithm")
)

// CSRSubject is the operator-supplied PKCS#10 subject + SANs + chosen
// key algorithm. Stored on the pending ExternalCertificate row for
// display and for the re-import subject/SANs diff.
type CSRSubject struct {
	CommonName   string   `json:"commonName"`
	SANs         []string `json:"sans,omitempty"`
	Organization string   `json:"organization,omitempty"`
	OrgUnit      string   `json:"orgUnit,omitempty"`
	Country      string   `json:"country,omitempty"`
	Locality     string   `json:"locality,omitempty"`
	State        string   `json:"state,omitempty"`
	KeyAlgorithm string   `json:"keyAlgorithm"`
}

// GenerateKeyAndCSR builds a fresh private key and a CSR for the given
// subject. The key is PKCS#8-encoded (matches the SOCLE key format so
// tls.X509KeyPair accepts it on re-import); the CSR is PEM
// CERTIFICATE REQUEST. The CN is auto-added to the SAN list when absent
// (a bare-CN cert with no matching SAN is rejected by modern clients).
func GenerateKeyAndCSR(subject CSRSubject) (keyPEM string, csrPEM string, err error) {
	if subject.CommonName == "" {
		return "", "", ErrCSRCNRequired
	}
	if subject.Country != "" && len(subject.Country) != 2 {
		return "", "", ErrCSRInvalidCountry
	}

	var priv any
	var sigAlgo x509.SignatureAlgorithm
	switch subject.KeyAlgorithm {
	case CSRAlgorithmRSA4096:
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
		sigAlgo = x509.SHA256WithRSA
	case CSRAlgorithmECDSAP256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sigAlgo = x509.ECDSAWithSHA256
	default:
		return "", "", ErrCSRInvalidKeyAlgorithm
	}
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}

	sans := subject.SANs
	if !containsString(sans, subject.CommonName) {
		sans = append([]string{subject.CommonName}, sans...)
	}

	name := pkix.Name{CommonName: subject.CommonName}
	if subject.Organization != "" {
		name.Organization = []string{subject.Organization}
	}
	if subject.OrgUnit != "" {
		name.OrganizationalUnit = []string{subject.OrgUnit}
	}
	if subject.Country != "" {
		name.Country = []string{subject.Country}
	}
	if subject.Locality != "" {
		name.Locality = []string{subject.Locality}
	}
	if subject.State != "" {
		name.Province = []string{subject.State}
	}

	tmpl := &x509.CertificateRequest{
		Subject:            name,
		DNSNames:           sans,
		SignatureAlgorithm: sigAlgo,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		return "", "", fmt.Errorf("create csr: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("marshal key: %w", err)
	}

	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	csrPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	return keyPEM, csrPEM, nil
}

func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
