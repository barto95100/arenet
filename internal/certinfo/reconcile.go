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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ReconcileFromDisk seeds the tracker with every certificate found
// in certmagic's on-disk storage tree, parsed straight from the
// PEM leaf via x509.ParseCertificate.
//
// Path conventions are the certmagic v0.25.3 layout (storage.go:
// 224-251, KeyBuilder.{CertsSitePrefix,SiteCert,SiteMeta}):
//
//	<storage>/
//	  certificates/
//	    <issuerKey-safe>/                e.g. acme-v02.api.letsencrypt.org-directory
//	      <domain-safe>/                 e.g. wildcard_.example.com  (for *.example.com)
//	        <domain-safe>.crt            PEM-encoded leaf + chain
//	        <domain-safe>.key            (we don't touch)
//	        <domain-safe>.json           certmagic CertificateResource metadata
//
// Default storage path on Linux (Caddy's storage.AppDataDir,
// storage.go:122-154): $XDG_DATA_HOME/caddy or $HOME/.local/share/
// caddy. On the AreNET-test VM where the process runs as user
// `arenet` with $HOME=/var/lib/arenet, that resolves to
// /var/lib/arenet/.local/share/caddy/.
//
// Returns (countSeeded, error). countSeeded is the number of certs
// successfully parsed and added to the tracker (failed parses are
// skipped, NOT counted). error is non-nil only for the
// storageDir-itself-broken case (e.g. permission denied at top);
// missing storageDir is NOT an error (returns 0, nil) — fresh
// installs have no storage yet, that's normal.
//
// Forward-compat: the function is a one-shot reconciler called at
// boot. It does not watch for filesystem changes. Once events
// start flowing through the EventHandler module, those are the
// authoritative refresh signal; reconcile only fills the cold-
// start gap.
func ReconcileFromDisk(tracker *Tracker, storageDir string) (int, error) {
	if tracker == nil {
		return 0, errors.New("certinfo.ReconcileFromDisk: tracker is nil")
	}
	if storageDir == "" {
		return 0, errors.New("certinfo.ReconcileFromDisk: storageDir is empty")
	}
	certsDir := filepath.Join(storageDir, "certificates")
	info, err := os.Stat(certsDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Fresh install — no certs yet. Not an error.
			return 0, nil
		}
		return 0, fmt.Errorf("certinfo.ReconcileFromDisk: stat %s: %w", certsDir, err)
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("certinfo.ReconcileFromDisk: %s is not a directory", certsDir)
	}

	// First level: per-issuer subdirectories (e.g.
	// "acme-v02.api.letsencrypt.org-directory"). We accept any
	// subdir here — a future Caddy/certmagic version that adds a
	// new issuer prefix shouldn't crash the reconcile.
	issuers, err := os.ReadDir(certsDir)
	if err != nil {
		return 0, fmt.Errorf("certinfo.ReconcileFromDisk: read %s: %w", certsDir, err)
	}

	count := 0
	for _, issuerEntry := range issuers {
		if !issuerEntry.IsDir() {
			continue
		}
		issuerDir := filepath.Join(certsDir, issuerEntry.Name())
		issuerLabel := decodeIssuerLabel(issuerEntry.Name())
		domains, err := os.ReadDir(issuerDir)
		if err != nil {
			// One bad issuer dir doesn't fail the rest. Logged at
			// caller level; here we just skip.
			continue
		}
		for _, domainEntry := range domains {
			if !domainEntry.IsDir() {
				continue
			}
			added := tryReconcileDomain(
				tracker,
				issuerDir,
				domainEntry.Name(),
				issuerLabel,
			)
			if added {
				count++
			}
		}
	}
	return count, nil
}

// tryReconcileDomain parses the leaf cert under the given
// per-domain directory and seeds the tracker entry. Returns true
// when the tracker was updated; false on any parse failure (the
// directory is skipped silently, the rest of the reconcile
// continues).
func tryReconcileDomain(tracker *Tracker, issuerDir, safeDomainName, issuerLabel string) bool {
	dir := filepath.Join(issuerDir, safeDomainName)
	crtPath := filepath.Join(dir, safeDomainName+".crt")

	pemBytes, err := os.ReadFile(crtPath)
	if err != nil {
		// .crt missing — skip. A directory might exist before the
		// cert is written (race during certmagic save); reconcile
		// retries on the next boot.
		return false
	}
	leaf, err := parseLeafFromPEM(pemBytes)
	if err != nil {
		return false
	}

	// Restore the human-readable subject from the certificate's
	// SAN list (preferred — exact case + wildcard preserved). The
	// directory name went through KeyBuilder.Safe which
	// transforms "*" to "wildcard_" and lowercases; the cert's
	// DNSNames are authoritative.
	primary := pickPrimaryDomain(leaf, safeDomainName)
	source := inferSourceFromSubject(primary)

	info := &CertRuntimeInfo{
		Domain:    primary,
		SANList:   append([]string(nil), leaf.DNSNames...),
		Issuer:    issuerLabel,
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		Source:    source,
	}
	tracker.RecordCert(info)
	return true
}

// parseLeafFromPEM decodes the first CERTIFICATE block from a PEM
// bundle (leaf cert) and returns the parsed x509.Certificate.
// certmagic writes leaf-first chains; the rest of the bundle is
// intermediate certs we don't care about here.
func parseLeafFromPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM block type %q", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// pickPrimaryDomain returns the most useful display name for the
// cert. The cert's DNSNames are authoritative; we prefer a
// wildcard subject when present (it's the human-readable
// representation of the wildcard apex). Falls back to decoding
// the on-disk directory name through reverseSafeDomain if the
// cert has no DNSNames (defensive — every well-formed leaf does).
func pickPrimaryDomain(leaf *x509.Certificate, safeDomainName string) string {
	if leaf == nil {
		return reverseSafeDomain(safeDomainName)
	}
	if len(leaf.DNSNames) > 0 {
		// Wildcard first if present — that's the operator-meaningful
		// representation. Otherwise the first SAN.
		for _, n := range leaf.DNSNames {
			if strings.HasPrefix(n, "*.") {
				return n
			}
		}
		return leaf.DNSNames[0]
	}
	if leaf.Subject.CommonName != "" {
		return leaf.Subject.CommonName
	}
	return reverseSafeDomain(safeDomainName)
}

// reverseSafeDomain undoes the certmagic KeyBuilder.Safe transform
// well enough for display purposes. The full transform (lowercase
// + char replacement + non-word regex strip) is not reversible in
// general — we restore the wildcard prefix (the most operationally
// surprising substitution) and otherwise return the path as-is.
// Used only as a fallback when the leaf cert has no DNSNames (a
// case we don't expect in practice).
func reverseSafeDomain(safe string) string {
	if strings.HasPrefix(safe, "wildcard_") {
		return "*." + strings.TrimPrefix(safe, "wildcard_.")
	}
	return safe
}

// inferSourceFromSubject classifies a cert as wildcard / apex /
// specific based on its primary subject string alone. The full
// type detection per §3.4 of the spec requires cross-referencing
// the managed-domain list, which the tracker doesn't carry at T.1
// scope — the API layer (T.2) does the cross-reference. For T.1's
// reconcile path, subject-string heuristic is sufficient:
//
//	"*.x.tld"     → wildcard
//	"x.tld"       → specific (default; the apex case is upgraded
//	                by the API layer when the operator declared
//	                a managed-domain with includeApex=true)
//
// The T.4 frontend renders Source as a sub-line; misclassifying
// apex-as-specific during the cold-start window before the API
// layer's cross-reference loads is a cosmetic edge case, not a
// data-correctness one.
func inferSourceFromSubject(domain string) Source {
	if strings.HasPrefix(domain, "*.") {
		return SourceWildcard
	}
	return SourceSpecific
}

// decodeIssuerLabel turns the on-disk issuer-key-safe directory
// name back into a human-readable label. The two issuers we
// currently see in production are:
//
//	"acme-v02.api.letsencrypt.org-directory"   → "Let's Encrypt"
//	"acme-staging-v02.api.letsencrypt.org-directory" → "Let's Encrypt (staging)"
//
// Anything else passes through verbatim — defensive against a
// future certmagic that adds new issuer keys we haven't seen.
// The wire shape's Issuer field is purely display; the frontend
// shows the label and the operator doesn't need machine-parseable
// issuer keys.
func decodeIssuerLabel(issuerKey string) string {
	switch issuerKey {
	case "acme-v02.api.letsencrypt.org-directory":
		return "Let's Encrypt"
	case "acme-staging-v02.api.letsencrypt.org-directory":
		return "Let's Encrypt (staging)"
	case "local":
		return "Caddy local CA"
	default:
		return issuerKey
	}
}
