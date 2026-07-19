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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CertWarning is a non-blocking issue found while parsing an
// operator-uploaded external certificate (e.g. expiry, weak
// signature algorithm). Unlike a blocking error, the certificate is
// still accepted and stored.
type CertWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Warning codes returned by ParseExternalCert.
const (
	CertWarnExpired         = "cert_expired"
	CertWarnNotYetValid     = "cert_not_yet_valid"
	CertWarnWeakSigAlgo     = "signature_algorithm_weak"
	CertWarnChainIncomplete = "chain_incomplete"
)

func normalizePEM(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

// ParseExternalCert validates the leaf/key (blocking) and returns
// parsed metadata + non-blocking warnings. It does NOT verify the
// chain up to a system root (private CAs are the target audience).
func ParseExternalCert(certPEM, keyPEM, chainPEM string) (ExternalCertificate, []CertWarning, error) {
	certPEM = normalizePEM(certPEM)
	keyPEM = normalizePEM(keyPEM)
	chainPEM = normalizePEM(chainPEM)

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ExternalCertificate{}, nil, errors.New("invalid_cert_pem: leaf PEM does not decode")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ExternalCertificate{}, nil, fmt.Errorf("invalid_cert_pem: %w", err)
	}
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return ExternalCertificate{}, nil, fmt.Errorf("key_does_not_match_cert: %w", err)
	}
	if chainPEM != "" {
		if b, _ := pem.Decode([]byte(chainPEM)); b == nil {
			return ExternalCertificate{}, nil, errors.New("invalid_chain_pem: chain PEM does not decode")
		}
	}

	meta := ExternalCertificate{
		Issuer:             leaf.Issuer.String(),
		Subject:            leaf.Subject.String(),
		SerialNumber:       leaf.SerialNumber.String(),
		KeyAlgorithm:       leaf.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
		NotBefore:          leaf.NotBefore,
		NotAfter:           leaf.NotAfter,
		DNSNames:           leaf.DNSNames,
	}

	var warnings []CertWarning
	now := time.Now()
	if now.After(leaf.NotAfter) {
		warnings = append(warnings, CertWarning{CertWarnExpired, "certificate has expired (" + leaf.NotAfter.Format(time.RFC3339) + ")"})
	}
	if now.Before(leaf.NotBefore) {
		warnings = append(warnings, CertWarning{CertWarnNotYetValid, "certificate is not valid until " + leaf.NotBefore.Format(time.RFC3339)})
	}
	switch leaf.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1, x509.MD5WithRSA:
		warnings = append(warnings, CertWarning{CertWarnWeakSigAlgo, "weak signature algorithm: " + leaf.SignatureAlgorithm.String()})
	}
	return meta, warnings, nil
}
