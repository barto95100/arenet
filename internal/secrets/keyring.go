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

// Package secrets seals individual secret values (DNS credentials,
// private keys, API keys…) with AES-256-GCM before they are written
// to arenet.db, and opens them on read.
//
// Sealed wire format: "enc:v1:" + base64(nonce ‖ ciphertext ‖ tag).
// The additional authenticated data (AAD) names the field the value
// belongs to, so a sealed value cannot be moved to another field.
// Values without the prefix are returned as-is by Open: that keeps a
// database readable while its plaintext rows are being migrated.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Prefix marks a sealed value.
const Prefix = "enc:v1:"

// KeySize is the AES-256 key length in bytes.
const KeySize = 32

// fingerprintBytes is how many bytes of SHA-256(key) the fingerprint
// keeps: enough to tell keys apart, useless to an attacker.
const fingerprintBytes = 8

// keyFileMode is the permission of a created key file.
const keyFileMode = 0o600

// ErrInvalidKey is returned when a key file does not hold a base64
// encoded 32-byte key.
var ErrInvalidKey = errors.New("secrets: key file must contain a base64-encoded 32-byte key")

// ErrOpen is returned when a sealed value cannot be decrypted: wrong
// key, wrong field (AAD) or altered data.
var ErrOpen = errors.New("secrets: cannot decrypt value (wrong key, wrong field or altered data)")

// Keyring seals and opens values with one AES-256-GCM key. It is safe
// for concurrent use.
type Keyring struct {
	aead        cipher.AEAD
	fingerprint string
}

// New builds a Keyring from a raw 32-byte key.
func New(key []byte) (*Keyring, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: gcm: %w", err)
	}
	sum := sha256.Sum256(key)
	return &Keyring{aead: aead, fingerprint: hex.EncodeToString(sum[:fingerprintBytes])}, nil
}

// Load reads a key file (base64 of 32 bytes, surrounding whitespace
// ignored). A missing file returns an error wrapping fs.ErrNotExist.
func Load(path string) (*Keyring, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secrets: read key file: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, ErrInvalidKey
	}
	return New(key)
}

// Create generates a random key and writes it to path, failing if the
// file already exists (a key is never overwritten).
func Create(path string) (*Keyring, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("secrets: generate key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, keyFileMode)
	if err != nil {
		return nil, fmt.Errorf("secrets: create key file: %w", err)
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("secrets: write key file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("secrets: sync key file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("secrets: close key file: %w", err)
	}
	return New(key)
}

// Fingerprint identifies the key (hex of the first 8 bytes of its
// SHA-256) without revealing it.
func (k *Keyring) Fingerprint() string { return k.fingerprint }

// IsSealed reports whether v carries the sealed-value prefix.
func IsSealed(v string) bool { return strings.HasPrefix(v, Prefix) }

// Seal encrypts plaintext bound to aad (the field name). An empty
// plaintext stays empty: "not set" is not a secret.
func (k *Keyring) Seal(plaintext, aad string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secrets: nonce: %w", err)
	}
	out := k.aead.Seal(nonce, nonce, []byte(plaintext), []byte(aad))
	return Prefix + base64.StdEncoding.EncodeToString(out), nil
}

// Open decrypts a sealed value bound to aad. A value without the
// prefix is returned unchanged.
func (k *Keyring) Open(value, aad string) (string, error) {
	if !IsSealed(value) {
		return value, nil
	}
	raw, err := base64.StdEncoding.DecodeString(value[len(Prefix):])
	if err != nil || len(raw) < k.aead.NonceSize() {
		return "", ErrOpen
	}
	n := k.aead.NonceSize()
	plain, err := k.aead.Open(nil, raw[:n], raw[n:], []byte(aad))
	if err != nil {
		return "", ErrOpen
	}
	return string(plain), nil
}
