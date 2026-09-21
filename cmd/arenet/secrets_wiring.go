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
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/barto95100/arenet/internal/api"
	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/secrets"
	"github.com/barto95100/arenet/internal/storage"
)

const (
	// envSecretKeyFile overrides the secrets key location (Docker
	// secret, separate disk…).
	envSecretKeyFile = "ARENET_SECRET_KEY_FILE"
	// secretKeyFileName is the default key file, in the data dir.
	secretKeyFileName = "arenet.key"
	// keyFileGroupOtherBits flags a key file readable beyond its owner.
	keyFileGroupOtherBits = 0o077
)

// secretKeyPath resolves the secrets key file.
func secretKeyPath(getenv func(string) string, dataDir string) string {
	if p := getenv(envSecretKeyFile); p != "" {
		return p
	}
	return filepath.Join(dataDir, secretKeyFileName)
}

// secureStoreAtRest turns on secrets encryption (enableSecretsEncryption),
// scrubs the secrets older versions wrote into audit payloads, and —
// when either pass rewrote rows — compacts arenet.db so the pages that
// held the plaintext are gone (bbolt only frees them). Must run before
// the store's *bolt.DB is shared: Compact replaces it.
func secureStoreAtRest(ctx context.Context, logger *slog.Logger, store *storage.Store, keyPath string, allowCreate bool) error {
	enabled, sealed, err := enableSecretsEncryption(ctx, logger, store, keyPath, allowCreate)
	if err != nil || !enabled {
		return err
	}
	scrubbed, err := api.ScrubAuditSecrets(ctx, audit.NewStore(store.DB()))
	if err != nil {
		return fmt.Errorf("secrets: scrub audit log: %w", err)
	}
	if scrubbed > 0 {
		logger.Info("removed secrets recorded in audit events by older versions", "events", scrubbed)
	}
	if sealed+scrubbed == 0 {
		return nil
	}
	if err := store.Compact(); err != nil {
		return fmt.Errorf("secrets: compact arenet.db: %w", err)
	}
	logger.Info("rewrote arenet.db so no plaintext copy of a secret remains")
	return nil
}

// enableSecretsEncryption loads the secrets key and turns on
// encryption at rest (v2.30), sealing any secret still in clear. A
// missing key is generated only when arenet.db was never encrypted:
// over encrypted data Arenet refuses to start rather than create a
// key that would make the secrets unreadable. With allowCreate false
// (read-only CLI export) a missing key on a never-encrypted database
// leaves it untouched (enabled false). sealed counts the rows that
// were still in clear.
func enableSecretsEncryption(ctx context.Context, logger *slog.Logger, store *storage.Store, keyPath string, allowCreate bool) (enabled bool, sealed int, err error) {
	fp, err := store.SecretsKeyFingerprint(ctx)
	if err != nil {
		return false, 0, fmt.Errorf("secrets: read key fingerprint: %w", err)
	}
	kr, err := secrets.Load(keyPath)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		if fp != "" {
			return false, 0, fmt.Errorf("secrets: arenet.db is encrypted (key fingerprint %s) but the key file %s is missing — "+
				"restore it from your backup, or point %s at it; Arenet never generates a new key over encrypted data",
				fp, keyPath, envSecretKeyFile)
		}
		if !allowCreate {
			return false, 0, nil
		}
		if kr, err = secrets.Create(keyPath); err != nil {
			return false, 0, err
		}
		logger.Warn("generated a new secrets key: back it up separately from arenet.db — without it the encrypted secrets cannot be recovered",
			"key_file", keyPath, "fingerprint", kr.Fingerprint())
	default:
		return false, 0, fmt.Errorf("secrets: load key %s: %w", keyPath, err)
	}
	if info, statErr := os.Stat(keyPath); statErr == nil && info.Mode().Perm()&keyFileGroupOtherBits != 0 {
		logger.Warn("secrets key file is readable by other users; restrict it to the Arenet user (chmod 600)",
			"key_file", keyPath, "mode", fmt.Sprintf("%o", info.Mode().Perm()))
	}
	sealed, err = store.EnableEncryption(ctx, kr)
	if err != nil {
		if errors.Is(err, storage.ErrSecretsKeyMismatch) {
			return false, 0, fmt.Errorf("secrets: %s is not the key arenet.db was encrypted with — restore the original key file: %w", keyPath, err)
		}
		return false, 0, fmt.Errorf("secrets: enable encryption: %w", err)
	}
	if sealed > 0 {
		logger.Info("encrypted the secrets stored in clear", "rows", sealed)
	}
	logger.Info("secrets encryption at rest enabled", "key_file", keyPath, "fingerprint", kr.Fingerprint())
	return true, sealed, nil
}
