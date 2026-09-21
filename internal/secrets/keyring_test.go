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

package secrets

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKeyring(t *testing.T) *Keyring {
	t.Helper()
	k, err := New(bytes.Repeat([]byte{7}, KeySize))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return k
}

func TestSealOpen_RoundTrip(t *testing.T) {
	k := testKeyring(t)
	sealed, err := k.Seal("s3cret", "oidc_config.client_secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !IsSealed(sealed) || strings.Contains(sealed, "s3cret") {
		t.Fatalf("sealed value %q", sealed)
	}
	again, _ := k.Seal("s3cret", "oidc_config.client_secret")
	if again == sealed {
		t.Error("two seals of the same value must differ (random nonce)")
	}
	got, err := k.Open(sealed, "oidc_config.client_secret")
	if err != nil || got != "s3cret" {
		t.Fatalf("Open = %q, %v", got, err)
	}
}

func TestOpen_RejectsWrongFieldKeyOrTamper(t *testing.T) {
	k := testKeyring(t)
	sealed, _ := k.Seal("s3cret", "crowdsec_config.api_key")

	if _, err := k.Open(sealed, "oidc_config.client_secret"); !errors.Is(err, ErrOpen) {
		t.Errorf("wrong AAD: %v", err)
	}
	other, _ := New(bytes.Repeat([]byte{8}, KeySize))
	if _, err := other.Open(sealed, "crowdsec_config.api_key"); !errors.Is(err, ErrOpen) {
		t.Errorf("wrong key: %v", err)
	}
	tampered := sealed[:len(sealed)-4] + "AAAA"
	if _, err := k.Open(tampered, "crowdsec_config.api_key"); !errors.Is(err, ErrOpen) {
		t.Errorf("tampered: %v", err)
	}
	if _, err := k.Open(Prefix+"!!!", "x"); !errors.Is(err, ErrOpen) {
		t.Errorf("garbage: %v", err)
	}
}

func TestOpen_PassesPlaintextThrough_SealKeepsEmpty(t *testing.T) {
	k := testKeyring(t)
	if got, err := k.Open("legacy-plain", "x"); err != nil || got != "legacy-plain" {
		t.Errorf("plaintext passthrough: %q %v", got, err)
	}
	if got, err := k.Seal("", "x"); err != nil || got != "" {
		t.Errorf("empty seal: %q %v", got, err)
	}
}

func TestCreateLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arenet.key")
	created, err := Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != keyFileMode {
		t.Errorf("key file mode %o, want %o", perm, keyFileMode)
	}
	if _, err := Create(path); err == nil {
		t.Error("Create must refuse to overwrite an existing key")
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Fingerprint() != created.Fingerprint() || len(created.Fingerprint()) != 2*fingerprintBytes {
		t.Errorf("fingerprints %q vs %q", loaded.Fingerprint(), created.Fingerprint())
	}
	sealed, _ := created.Seal("v", "f")
	if got, err := loaded.Open(sealed, "f"); err != nil || got != "v" {
		t.Errorf("cross open: %q %v", got, err)
	}
}

func TestLoad_Errors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	bad := filepath.Join(dir, "bad")
	_ = os.WriteFile(bad, []byte("c2hvcnQ=\n"), 0o600) // "short"
	if _, err := Load(bad); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("short key: %v", err)
	}
	_ = os.WriteFile(bad, []byte("not base64 at all"), 0o600)
	if _, err := Load(bad); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("not base64: %v", err)
	}
}
