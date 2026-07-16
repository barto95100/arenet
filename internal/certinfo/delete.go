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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/caddyserver/certmagic"
)

// DeleteCertFiles removes all on-disk certificate material for domain
// across every issuer directory under <storageDir>/certificates/.
// Returns the number of issuer directories from which the domain's
// cert directory was removed. Idempotent: a domain with no material
// on disk returns (0, nil).
//
// The per-domain directory name is derived with
// certmagic.StorageKeys.Safe so wildcard subjects map identically to
// how certmagic wrote them (e.g. "*.darro.ovh" -> "wildcard_.darro.ovh").
// Only the domain's own leaf directory is removed; sibling issuers,
// pki/, and locks/ are never touched.
func DeleteCertFiles(storageDir, domain string) (int, error) {
	if storageDir == "" {
		return 0, errors.New("certinfo.DeleteCertFiles: storageDir is empty")
	}
	if domain == "" {
		return 0, errors.New("certinfo.DeleteCertFiles: domain is empty")
	}
	safeDomain := certmagic.StorageKeys.Safe(domain)

	certsDir := filepath.Join(storageDir, "certificates")
	issuers, err := os.ReadDir(certsDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil // no certs at all — nothing to delete
		}
		return 0, fmt.Errorf("certinfo.DeleteCertFiles: read %s: %w", certsDir, err)
	}

	deleted := 0
	for _, issuerEntry := range issuers {
		if !issuerEntry.IsDir() {
			continue
		}
		domainDir := filepath.Join(certsDir, issuerEntry.Name(), safeDomain)
		if _, statErr := os.Stat(domainDir); statErr != nil {
			continue // this issuer has no dir for the domain
		}
		if rmErr := os.RemoveAll(domainDir); rmErr != nil {
			return deleted, fmt.Errorf("certinfo.DeleteCertFiles: remove %s: %w", domainDir, rmErr)
		}
		deleted++
	}
	return deleted, nil
}
