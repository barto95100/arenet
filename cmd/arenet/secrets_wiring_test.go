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

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/secrets"
	"github.com/barto95100/arenet/internal/storage"
)

func TestSecretKeyPath(t *testing.T) {
	none := func(string) string { return "" }
	if got := secretKeyPath(none, "/var/lib/arenet"); got != "/var/lib/arenet/arenet.key" {
		t.Errorf("default = %q", got)
	}
	env := func(k string) string {
		if k == envSecretKeyFile {
			return "/run/secrets/arenet_key"
		}
		return ""
	}
	if got := secretKeyPath(env, "/var/lib/arenet"); got != "/run/secrets/arenet_key" {
		t.Errorf("env override = %q", got)
	}
}

// bootOnce opens the store at dir like main does and enables
// encryption with the given key path.
func bootOnce(t *testing.T, dir, keyPath string, allowCreate bool) error {
	t.Helper()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err = secureStoreAtRest(context.Background(), logger, store, keyPath, allowCreate)
	if err == nil && allowCreate {
		// Leave a secret behind so later boots have sealed data.
		if perr := store.PutCrowdSecConfig(context.Background(), storage.CrowdSecConfig{LAPIURL: "http://c:8080/", APIKey: "k"}); perr != nil {
			t.Fatalf("seed: %v", perr)
		}
	}
	return err
}

func TestEnableSecretsEncryption_Lifecycle(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, secretKeyFileName)

	// First boot: key generated 0600.
	if err := bootOnce(t, dir, keyPath, true); err != nil {
		t.Fatalf("first boot: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", info, err)
	}
	// Restart with the same key.
	if err := bootOnce(t, dir, keyPath, true); err != nil {
		t.Fatalf("restart: %v", err)
	}
	// Key lost: refuse, never regenerate.
	moved := keyPath + ".bak"
	if err := os.Rename(keyPath, moved); err != nil {
		t.Fatal(err)
	}
	err = bootOnce(t, dir, keyPath, true)
	if err == nil || !strings.Contains(err.Error(), "is missing") {
		t.Fatalf("missing key: %v", err)
	}
	if _, statErr := os.Stat(keyPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Error("a new key was generated over encrypted data")
	}
	// Wrong key: refuse.
	if _, err := secrets.Create(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := bootOnce(t, dir, keyPath, true); !errors.Is(err, storage.ErrSecretsKeyMismatch) {
		t.Fatalf("wrong key: %v", err)
	}
	// Original key back: boots.
	_ = os.Remove(keyPath)
	_ = os.Rename(moved, keyPath)
	if err := bootOnce(t, dir, keyPath, true); err != nil {
		t.Fatalf("key restored: %v", err)
	}
}

// TestEnableSecretsEncryption_ExportDoesNotCreateKey: the read-only
// CLI export on a never-encrypted database leaves it as it is.
func TestEnableSecretsEncryption_ExportDoesNotCreateKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, secretKeyFileName)
	if err := bootOnce(t, dir, keyPath, false); err != nil {
		t.Fatalf("export boot: %v", err)
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("export created a key: %v", err)
	}
}
