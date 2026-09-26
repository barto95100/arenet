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

package backup

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/barto95100/arenet/internal/secrets"
	"golang.org/x/crypto/argon2"
)

// Passphrase-encrypted backups (v2.31). A backup "with secrets" keeps
// every secret sealed (AES-256-GCM, internal/secrets) with a key
// derived from a passphrase chosen at export (argon2id). The rest of
// the file stays readable JSON.

// SchemaVersionEncrypted is written into passphrase-encrypted exports.
// A different MAJOR on purpose: binaries before v2.31 reject the file
// ("schema major mismatch") instead of restoring the sealed strings
// as if they were the secrets — which would lock every user out.
const SchemaVersionEncrypted = "2.0.0"

// schemaMajorEncrypted is the MAJOR of SchemaVersionEncrypted.
const schemaMajorEncrypted = "2"

// MinPassphraseLen is the minimum passphrase length, in characters.
const MinPassphraseLen = 12

const (
	kdfArgon2id = "argon2id"
	// Default argon2id cost: 3 passes over 64 MiB, 4 lanes (~0.2 s).
	kdfTime      = 3
	kdfMemoryKiB = 64 * 1024
	kdfThreads   = 4
	kdfSaltBytes = 16
	// Upper bounds accepted on import, so a crafted file cannot make
	// the restore burn gigabytes of RAM or minutes of CPU.
	kdfMaxTime      = 10
	kdfMaxMemoryKiB = 1024 * 1024
	kdfMaxThreads   = 16
	// The check value proves the passphrase before any secret is
	// touched.
	checkPlaintext = "arenet-backup"
	checkAAD       = "backup/check"
)

// Encryption is the header of a passphrase-encrypted backup: how to
// derive the key again, plus a sealed check value.
type Encryption struct {
	KDF       string `json:"kdf"`
	Salt      string `json:"salt"` // base64
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	Check     string `json:"check"`
}

// ErrPassphraseRequired: the backup is encrypted and no passphrase was
// given.
var ErrPassphraseRequired = errors.New("backup: this backup is encrypted — a passphrase is required")

// ErrPassphraseInvalid: the passphrase does not decrypt the backup.
var ErrPassphraseInvalid = errors.New("backup: wrong passphrase (or altered file)")

// ErrPassphraseTooShort: the export passphrase is under MinPassphraseLen.
var ErrPassphraseTooShort = fmt.Errorf("backup: the passphrase must be at least %d characters", MinPassphraseLen)

// ErrSealedWithoutHeader: sealed values in a file without an
// encryption header (edited or corrupted file).
var ErrSealedWithoutHeader = errors.New("backup: the file holds encrypted values but no encryption header — it was altered")

// IsEncrypted reports whether the snapshot is passphrase-encrypted.
func (s *Snapshot) IsEncrypted() bool { return s.Encryption != nil }

// SealSnapshot encrypts every secret of a with-secrets snapshot with a
// key derived from passphrase, and marks the snapshot encrypted.
func SealSnapshot(s *Snapshot, passphrase string) error {
	if !s.SecretsIncluded {
		return errors.New("backup: only a with-secrets export can be encrypted")
	}
	if s.IsEncrypted() {
		return errors.New("backup: snapshot already encrypted")
	}
	if utf8.RuneCountInString(passphrase) < MinPassphraseLen {
		return ErrPassphraseTooShort
	}
	salt := make([]byte, kdfSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("backup: salt: %w", err)
	}
	enc := &Encryption{
		KDF: kdfArgon2id, Salt: base64.StdEncoding.EncodeToString(salt),
		Time: kdfTime, MemoryKiB: kdfMemoryKiB, Threads: kdfThreads,
	}
	kr, err := deriveKeyring(enc, passphrase)
	if err != nil {
		return err
	}
	if enc.Check, err = kr.Seal(checkPlaintext, checkAAD); err != nil {
		return err
	}
	if err := visitSecrets(s, func(path, v string) (string, error) { return kr.Seal(v, path) }); err != nil {
		return fmt.Errorf("backup: seal secrets: %w", err)
	}
	s.Encryption = enc
	s.SchemaVersion = SchemaVersionEncrypted
	return nil
}

// OpenSnapshot decrypts a passphrase-encrypted snapshot in place and
// turns it back into a plain with-secrets snapshot (schema 1.0.0). A
// snapshot that is not encrypted is left as-is.
func OpenSnapshot(s *Snapshot, passphrase string) error {
	if !s.IsEncrypted() {
		return nil
	}
	if passphrase == "" {
		return ErrPassphraseRequired
	}
	if err := checkKDFParams(s.Encryption); err != nil {
		return err
	}
	kr, err := deriveKeyring(s.Encryption, passphrase)
	if err != nil {
		return err
	}
	if got, err := kr.Open(s.Encryption.Check, checkAAD); err != nil || got != checkPlaintext {
		return ErrPassphraseInvalid
	}
	err = visitSecrets(s, func(path, v string) (string, error) {
		if !secrets.IsSealed(v) {
			return v, nil
		}
		plain, err := kr.Open(v, path)
		if err != nil {
			return "", fmt.Errorf("%w: %s cannot be decrypted", ErrPassphraseInvalid, path)
		}
		return plain, nil
	})
	if err != nil {
		return err
	}
	s.Encryption = nil
	s.SchemaVersion = SchemaVersion
	return nil
}

// checkNoSealedValues rejects an unencrypted snapshot carrying sealed
// values: importing them would store ciphertext as the secrets.
func checkNoSealedValues(s *Snapshot) error {
	cp := *s // visitSecrets clones what it rewrites; the identity fn changes nothing
	return visitSecrets(&cp, func(_, v string) (string, error) {
		if secrets.IsSealed(v) {
			return "", ErrSealedWithoutHeader
		}
		return v, nil
	})
}

func checkKDFParams(e *Encryption) error {
	if e.KDF != kdfArgon2id {
		return fmt.Errorf("backup: unsupported key derivation %q", e.KDF)
	}
	if e.Time == 0 || e.Time > kdfMaxTime || e.MemoryKiB == 0 || e.MemoryKiB > kdfMaxMemoryKiB ||
		e.Threads == 0 || e.Threads > kdfMaxThreads {
		return fmt.Errorf("backup: key derivation parameters out of bounds (time=%d memory=%dKiB threads=%d)", e.Time, e.MemoryKiB, e.Threads)
	}
	return nil
}

func deriveKeyring(e *Encryption, passphrase string) (*secrets.Keyring, error) {
	salt, err := base64.StdEncoding.DecodeString(e.Salt)
	if err != nil || len(salt) < kdfSaltBytes {
		return nil, errors.New("backup: invalid salt in the encryption header")
	}
	key := argon2.IDKey([]byte(passphrase), salt, e.Time, e.MemoryKiB, e.Threads, secrets.KeySize)
	return secrets.New(key)
}
