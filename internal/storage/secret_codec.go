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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/barto95100/arenet/internal/secrets"
	bolt "go.etcd.io/bbolt"
)

// Secrets at rest (v2.30). Every secret field of the buckets below is
// sealed with the store's keyring on write and opened on read, so the
// rest of Arenet only ever sees plaintext. The codec works on the raw
// JSON row: writes go through encodeRow, reads through decodeRow.

const (
	// bucketMeta holds store-level metadata.
	bucketMeta = "meta"
	// metaKeySecretsFingerprint records the fingerprint of the key the
	// secrets are sealed with.
	metaKeySecretsFingerprint = "secrets_key_fingerprint"
)

// ErrSecretsKeyRequired is returned when a sealed value is read while
// no key is loaded.
var ErrSecretsKeyRequired = errors.New("storage: arenet.db holds encrypted secrets but no secrets key is loaded")

// ErrSecretsKeyMismatch is returned by EnableEncryption when the key
// differs from the one the secrets were sealed with.
var ErrSecretsKeyMismatch = errors.New("storage: the secrets key does not match the key arenet.db was encrypted with")

type secretKind int

const (
	// kindString: the field is a string.
	kindString secretKind = iota
	// kindMapValues: every value of a string map.
	kindMapValues
	// kindRawJSON: the whole field (any JSON) is sealed as a string.
	kindRawJSON
	// kindSensitiveHeaders: values of a header map whose name is
	// sensitive (IsSensitiveHeader).
	kindSensitiveHeaders
)

type secretField struct {
	name string
	kind secretKind
}

// secretFields lists, per bucket, the top-level JSON fields holding
// secrets. Adding a secret field to a stored type REQUIRES adding it
// here, or it is written in clear.
var secretFields = map[string][]secretField{
	bucketDNSProviders: {
		{"credentials", kindMapValues},
		// Pre-v2.26 flat OVH fields, in case the boot migration left
		// a row behind.
		{"application_key", kindString},
		{"application_secret", kindString},
		{"consumer_key", kindString},
	},
	bucketExternalCertificates: {{"keyPEM", kindString}},
	bucketCrowdSecConfig:       {{"api_key", kindString}},
	bucketAutomation:           {{"password", kindString}},
	bucketMaxMindConfig:        {{"license_key", kindString}},
	bucketOIDCConfig:           {{"client_secret", kindString}},
	bucketForwardAuthProviders: {{"client_secret", kindString}},
	bucketAlertingChannels:     {{"config", kindRawJSON}},
	bucketRoutes: {
		{"request_headers", kindSensitiveHeaders},
		{"response_headers", kindSensitiveHeaders},
	},
}

// secretAAD binds a sealed value to its field.
func secretAAD(bucket, field string) string { return bucket + "." + field }

// keyring returns the loaded keyring, nil when encryption is off.
func (s *Store) keyring() *secrets.Keyring { return s.secretsKey.Load() }

// encodeRow marshals v and seals its secret fields.
func (s *Store) encodeRow(bucket string, v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	out, _, err := sealRow(s.keyring(), bucket, raw)
	return out, err
}

// decodeRow opens the secret fields of raw and unmarshals it into out.
func (s *Store) decodeRow(bucket string, raw []byte, out any) error {
	plain, err := openRow(s.keyring(), bucket, raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, out)
}

// sealRow seals the plaintext secret fields of a raw row. Values
// already sealed are left as-is, so sealing is idempotent. With a nil
// keyring the row is returned unchanged. changed reports a rewrite.
func sealRow(kr *secrets.Keyring, bucket string, raw []byte) (out []byte, changed bool, err error) {
	fields := secretFields[bucket]
	if kr == nil || len(fields) == 0 {
		return raw, false, nil
	}
	return transformRow(bucket, raw, fields, func(field, name string, kind secretKind, v string) (string, error) {
		if v == "" || secrets.IsSealed(v) {
			return v, nil
		}
		if kind == kindSensitiveHeaders && !IsSensitiveHeader(name) {
			return v, nil
		}
		return kr.Seal(v, secretAAD(bucket, field))
	}, true)
}

// openRow opens every sealed secret field of a raw row. A sealed value
// with no keyring loaded is an error, never passed through.
func openRow(kr *secrets.Keyring, bucket string, raw []byte) ([]byte, error) {
	fields := secretFields[bucket]
	if len(fields) == 0 || !bytes.Contains(raw, []byte(secrets.Prefix)) {
		return raw, nil
	}
	out, _, err := transformRow(bucket, raw, fields, func(field, _ string, _ secretKind, v string) (string, error) {
		if !secrets.IsSealed(v) {
			return v, nil
		}
		if kr == nil {
			return "", ErrSecretsKeyRequired
		}
		plain, err := kr.Open(v, secretAAD(bucket, field))
		if err != nil {
			return "", fmt.Errorf("storage: %s.%s: %w", bucket, field, err)
		}
		return plain, nil
	}, false)
	return out, err
}

// valueFunc maps one secret value. field is the AAD field path, name
// the map key (empty for plain fields).
type valueFunc func(field, name string, kind secretKind, v string) (string, error)

// transformRow applies fn to every secret value of the row's fields.
// The row is re-encoded only when a value changed.
func transformRow(bucket string, raw []byte, fields []secretField, fn valueFunc, sealing bool) ([]byte, bool, error) {
	var row map[string]json.RawMessage
	if err := json.Unmarshal(raw, &row); err != nil {
		return nil, false, fmt.Errorf("storage: decode %s row: %w", bucket, err)
	}
	changed := false
	for _, f := range fields {
		val, ok := row[f.name]
		if !ok || isJSONNull(val) {
			continue
		}
		next, fieldChanged, err := transformField(f, val, fn, sealing)
		if err != nil {
			return nil, false, err
		}
		if fieldChanged {
			row[f.name] = next
			changed = true
		}
	}
	if !changed {
		return raw, false, nil
	}
	out, err := json.Marshal(row)
	if err != nil {
		return nil, false, fmt.Errorf("storage: encode %s row: %w", bucket, err)
	}
	return out, true, nil
}

func transformField(f secretField, val json.RawMessage, fn valueFunc, sealing bool) (json.RawMessage, bool, error) {
	switch f.kind {
	case kindString:
		var v string
		if err := json.Unmarshal(val, &v); err != nil {
			return nil, false, nil // not a string: not ours to touch
		}
		nv, err := fn(f.name, "", f.kind, v)
		if err != nil || nv == v {
			return nil, false, err
		}
		b, err := json.Marshal(nv)
		return b, true, err

	case kindMapValues, kindSensitiveHeaders:
		var m map[string]string
		if err := json.Unmarshal(val, &m); err != nil {
			return nil, false, nil
		}
		changed := false
		for k, v := range m {
			field := f.name + "." + k
			if f.kind == kindSensitiveHeaders {
				field = f.name // header names are operator data, not schema
			}
			nv, err := fn(field, k, f.kind, v)
			if err != nil {
				return nil, false, err
			}
			if nv != v {
				m[k] = nv
				changed = true
			}
		}
		if !changed {
			return nil, false, nil
		}
		b, err := json.Marshal(m)
		return b, true, err

	case kindRawJSON:
		var sealed string
		isString := json.Unmarshal(val, &sealed) == nil
		if sealing {
			if isString && secrets.IsSealed(sealed) {
				return nil, false, nil
			}
			nv, err := fn(f.name, "", f.kind, string(val))
			if err != nil {
				return nil, false, err
			}
			b, err := json.Marshal(nv)
			return b, true, err
		}
		if !isString || !secrets.IsSealed(sealed) {
			return nil, false, nil
		}
		plain, err := fn(f.name, "", f.kind, sealed)
		if err != nil {
			return nil, false, err
		}
		if !json.Valid([]byte(plain)) {
			return nil, false, fmt.Errorf("storage: %s: decrypted value is not JSON", f.name)
		}
		return json.RawMessage(plain), true, nil
	}
	return nil, false, nil
}

func isJSONNull(v json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(v), []byte("null"))
}

// SecretsKeyFingerprint returns the fingerprint of the key the secrets
// are sealed with, "" when the database was never encrypted.
func (s *Store) SecretsKeyFingerprint(ctx context.Context) (string, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	var fp string
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		fp = string(tx.Bucket([]byte(bucketMeta)).Get([]byte(metaKeySecretsFingerprint)))
		return nil
	})
	return fp, err
}

// EnableEncryption loads kr as the store's secrets key. It refuses a
// key other than the one recorded in the database, then seals every
// secret still stored in clear and records the key fingerprint, all in
// one transaction. Returns the number of rows rewritten. Idempotent.
func (s *Store) EnableEncryption(ctx context.Context, kr *secrets.Keyring) (int, error) {
	if kr == nil {
		return 0, errors.New("storage: nil secrets key")
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	rewritten := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		meta := tx.Bucket([]byte(bucketMeta))
		if fp := string(meta.Get([]byte(metaKeySecretsFingerprint))); fp != "" && fp != kr.Fingerprint() {
			return fmt.Errorf("%w (database key %s, loaded key %s)", ErrSecretsKeyMismatch, fp, kr.Fingerprint())
		}
		for bucket := range secretFields {
			b := tx.Bucket([]byte(bucket))
			type row struct{ k, v []byte }
			var updates []row
			err := b.ForEach(func(k, v []byte) error {
				// Every sealed value must open with this key: sealed
				// data without a recorded fingerprint means a foreign key.
				if _, err := openRow(kr, bucket, v); err != nil {
					return fmt.Errorf("%w: %s/%s: %v", ErrSecretsKeyMismatch, bucket, k, err)
				}
				out, changed, err := sealRow(kr, bucket, v)
				if err != nil {
					return fmt.Errorf("seal %s/%s: %w", bucket, k, err)
				}
				if changed {
					updates = append(updates, row{append([]byte(nil), k...), out})
				}
				return nil
			})
			if err != nil {
				return err
			}
			for _, u := range updates {
				if err := b.Put(u.k, u.v); err != nil {
					return fmt.Errorf("put %s/%s: %w", bucket, u.k, err)
				}
			}
			rewritten += len(updates)
		}
		return meta.Put([]byte(metaKeySecretsFingerprint), []byte(kr.Fingerprint()))
	})
	if err != nil {
		return 0, err
	}
	s.secretsKey.Store(kr)
	if rewritten > 0 {
		// bbolt is copy-on-write: the pages that held the plaintext
		// are only freed, not wiped. Rewrite the file so they are gone.
		if err := s.compact(); err != nil {
			return rewritten, fmt.Errorf("storage: compact after sealing secrets: %w", err)
		}
	}
	return rewritten, nil
}

// compactTxMaxSize bounds each copy transaction of compact.
const compactTxMaxSize = 64 << 20

// compact copies the database into a fresh file and swaps it in, so no
// freed page survives. It replaces s.db: callers must run it before
// the store's *bolt.DB is handed to anyone (boot only).
func (s *Store) compact() error {
	path := s.db.Path()
	tmp := path + ".compact"
	_ = os.Remove(tmp)
	dst, err := bolt.Open(tmp, 0o600, &bolt.Options{Timeout: boltOpenTimeout})
	if err != nil {
		return fmt.Errorf("open %s: %w", tmp, err)
	}
	if err := bolt.Compact(dst, s.db, compactTxMaxSize); err != nil {
		_ = dst.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("copy: %w", err)
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := s.db.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close database: %w", err)
	}
	renameErr := os.Rename(tmp, path)
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: boltOpenTimeout})
	if err != nil {
		return fmt.Errorf("reopen database: %w", err)
	}
	s.db = db
	if renameErr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace database file: %w", renameErr)
	}
	return nil
}

// sensitiveHeaderNames are header names whose values are credentials.
var sensitiveHeaderNames = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"set-cookie":          {},
	"x-api-key":           {},
	"api-key":             {},
}

// sensitiveHeaderFragments flag any header whose name contains them.
var sensitiveHeaderFragments = []string{"token", "secret", "password", "api-key", "apikey"}

// IsSensitiveHeader reports whether a route header's value is a
// credential: sealed at rest and redacted in backups.
func IsSensitiveHeader(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if _, ok := sensitiveHeaderNames[n]; ok {
		return true
	}
	for _, f := range sensitiveHeaderFragments {
		if strings.Contains(n, f) {
			return true
		}
	}
	return false
}
