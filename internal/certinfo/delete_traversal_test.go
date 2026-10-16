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

package certinfo

import (
	"os"
	"path/filepath"
	"testing"
)

// certmagic's Safe() collapses ".." BEFORE it strips non-word characters
// (storage.go: the Replacer runs first, then safeKeyRE), so an input like
// ".,." / ".!." / "./." becomes the literal component ".." — which
// filepath.Join resolves one level up to the certificates root, and
// os.RemoveAll then wipes EVERY issuer and EVERY domain's key material
// (F30/F36). DeleteCertFiles must refuse a sanitized key that is not a
// single, non-dot path element.
func TestDeleteCertFiles_RefusesTraversal(t *testing.T) {
	for _, payload := range []string{".,.", ".!.", "./.", "..", "."} {
		dir := t.TempDir()
		// A cert tree: certificates/acme-v02/example.com/leaf + a
		// sibling domain whose survival proves nothing was wiped.
		mustWriteTree(t, dir, "acme-v02", "example.com")
		mustWriteTree(t, dir, "acme-v02", "other.com")

		n, err := DeleteCertFiles(dir, payload)
		if err == nil {
			t.Errorf("payload %q: want an error, got deleted=%d", payload, n)
		}
		// The whole tree must still be there.
		if _, statErr := os.Stat(filepath.Join(dir, "certificates", "acme-v02", "example.com")); statErr != nil {
			t.Errorf("payload %q WIPED the certificates tree: %v", payload, statErr)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "certificates", "acme-v02", "other.com")); statErr != nil {
			t.Errorf("payload %q wiped a sibling domain: %v", payload, statErr)
		}
	}
}

// A legitimate domain still deletes exactly its own directory.
func TestDeleteCertFiles_DeletesTheNamedDomainOnly(t *testing.T) {
	dir := t.TempDir()
	mustWriteTree(t, dir, "acme-v02", "example.com")
	mustWriteTree(t, dir, "acme-v02", "other.com")

	n, err := DeleteCertFiles(dir, "example.com")
	if err != nil || n != 1 {
		t.Fatalf("delete example.com: n=%d err=%v (want 1, nil)", n, err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "certificates", "acme-v02", "example.com")); statErr == nil {
		t.Error("example.com should have been deleted")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "certificates", "acme-v02", "other.com")); statErr != nil {
		t.Error("other.com must be untouched")
	}
}

func mustWriteTree(t *testing.T, storageDir, issuer, domain string) {
	t.Helper()
	d := filepath.Join(storageDir, "certificates", issuer, domain)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", d, err)
	}
	if err := os.WriteFile(filepath.Join(d, domain+".crt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write leaf: %v", err)
	}
}
