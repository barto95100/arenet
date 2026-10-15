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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
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

// SplitLeafAndChain normalizes an operator upload where the Certificate
// field may hold a single leaf OR a "fullchain" bundle (leaf +
// intermediates concatenated — the common download format from most CAs,
// vendor-agnostic). It returns the leaf-only PEM and the chain PEM.
//
// Rules:
//   - certPEM with 1 CERTIFICATE block → leaf as-is, chain = chainPEM.
//   - certPEM with >1 block → first block is the leaf, the remaining
//     blocks become the chain (universal split, no CA-specific logic).
//   - if certPEM already carries extra blocks AND chainPEM is non-empty,
//     the chain is specified in two places → reject (ambiguous).
//
// It does NOT validate the certs (ParseExternalCert does that on the
// returned leaf/chain); it only re-partitions PEM blocks.
func SplitLeafAndChain(certPEM, chainPEM string) (leaf string, chain string, err error) {
	certPEM = normalizePEM(certPEM)
	chainPEM = normalizePEM(chainPEM)

	// A private key must never reach certPEM or chainPEM. Those fields
	// are returned to viewer-role callers, left unsealed by the at-rest
	// codec (secret_codec.go seals keyPEM only), and shipped in a
	// default-redacted backup. An operator who pasted a combined
	// cert+key bundle into the Certificate field — the HAProxy / `cat
	// cert.pem key.pem` layout — is refused outright rather than having
	// the key silently trimmed, because a silent trim would validate
	// against the real key in the Key field and hide the mistake. (F41)
	if pemHasPrivateKey(certPEM) {
		return "", "", errors.New("private_key_in_cert_field: the Certificate field contains a PRIVATE KEY block — the private key belongs only in the Key field")
	}
	if pemHasPrivateKey(chainPEM) {
		return "", "", errors.New("private_key_in_chain_field: the Chain field contains a PRIVATE KEY block — the private key belongs only in the Key field")
	}

	blocks := decodeCertificateBlocks(certPEM)
	if len(blocks) == 0 {
		// No certificate to split; hand the input to ParseExternalCert
		// for the actionable invalid_cert_pem error.
		return certPEM, chainPEM, nil
	}
	// >1 block in the cert field = a pasted fullchain; a non-empty Chain
	// field then specifies the chain in two places.
	if len(blocks) > 1 && strings.TrimSpace(chainPEM) != "" {
		return "", "", errors.New("chain_specified_twice: the Certificate field already contains a chain (" +
			strconv.Itoa(len(blocks)) + " certificates) and the Chain field is also filled — put the chain in only one place")
	}

	// Re-encode from the decoded CERTIFICATE blocks, never pass the raw
	// input through: that is what keeps a stray key, a comment block or
	// trailing junk out of the stored, viewer-readable certPEM/chainPEM.
	leaf = string(pem.EncodeToMemory(blocks[0]))
	var sb strings.Builder
	for _, b := range blocks[1:] {
		sb.Write(pem.EncodeToMemory(b))
	}
	// When the chain arrived in its own field (single leaf in the cert
	// field), re-encode its certificate blocks too.
	for _, b := range decodeCertificateBlocks(chainPEM) {
		sb.Write(pem.EncodeToMemory(b))
	}
	return leaf, sb.String(), nil
}

// decodeCertificateBlocks returns every CERTIFICATE PEM block in s, in
// order, dropping blocks of any other type.
func decodeCertificateBlocks(s string) []*pem.Block {
	var blocks []*pem.Block
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return blocks
		}
		if b.Type == "CERTIFICATE" {
			blocks = append(blocks, b)
		}
	}
}

// pemHasPrivateKey reports whether s carries any PRIVATE KEY block —
// "PRIVATE KEY", "RSA/EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY",
// "OPENSSH PRIVATE KEY" all match the substring.
func pemHasPrivateKey(s string) bool {
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return false
		}
		if strings.Contains(b.Type, "PRIVATE KEY") {
			return true
		}
	}
}

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
