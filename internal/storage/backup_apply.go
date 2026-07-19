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
	"context"
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// RestoreSnapshotInput is the wire shape the backup package hands to
// the storage layer. Each section carries pre-serialised JSON per
// row; the storage layer does NOT validate (the backup package owns
// validation + sentinel resolution). The bucket keys carry the
// correct identity per spec §5.3 (route id, user id, "ovh", forward-
// auth name, "default").
//
// All six sections are applied in a single bbolt write transaction.
// On any error, the entire transaction is rolled back — the BoltDB
// is left untouched. This is the spec §5.3 "all-or-nothing" property
// enforced at the storage layer.
type RestoreSnapshotInput struct {
	// Routes maps route ID → JSON-marshalled storage.Route.
	Routes map[string][]byte
	// Users maps user ID → JSON-marshalled auth.User.
	Users map[string][]byte
	// DNSProviders maps dns provider key (e.g. "ovh") → JSON-marshalled
	// storage.DNSProviderConfig. nil or empty clears the bucket.
	DNSProviders map[string][]byte
	// ForwardAuthProviders maps provider name → JSON-marshalled
	// storage.ForwardAuthProvider. nil or empty clears the bucket.
	ForwardAuthProviders map[string][]byte
	// OIDCConfig is the JSON-marshalled storage.OIDCConfig for the
	// "default" key, or nil/empty to clear the OIDC bucket.
	OIDCConfig []byte
	// MaxMindConfig is the JSON-marshalled storage.MaxMindConfig for
	// the "default" key, or nil/empty to clear the maxmind_config
	// bucket (mirrors the OIDCConfig single-record convention).
	MaxMindConfig []byte
	// ExternalCertificates maps external cert ID → JSON-marshalled
	// storage.ExternalCertificate (v2.19.0). nil or empty clears the
	// bucket.
	ExternalCertificates map[string][]byte
}

// RestoreSnapshot atomically replaces the contents of the six
// backup-relevant buckets with the supplied input. Every bucket is
// cleared first then refilled inside the same transaction; a bbolt
// commit failure rolls back to the prior state.
//
// SECURITY: this method MUST only be called by the
// internal/backup.Import path. It bypasses every domain validator
// (CreateRoute / UpdateUser / PutDNSProvider). The backup package
// is responsible for validating the entire snapshot BEFORE calling
// this, and for clearing fields explicitly when the operator has
// opted into --allow-incomplete-restore.
func (s *Store) RestoreSnapshot(ctx context.Context, in RestoreSnapshotInput) error {
	if s == nil || s.db == nil {
		return errors.New("storage: nil store")
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := resetAndFill(tx, bucketRoutes, in.Routes); err != nil {
			return fmt.Errorf("restore routes: %w", err)
		}
		if err := resetAndFill(tx, bucketUsers, in.Users); err != nil {
			return fmt.Errorf("restore users: %w", err)
		}
		if err := resetAndFill(tx, bucketDNSProviders, in.DNSProviders); err != nil {
			return fmt.Errorf("restore dns_providers: %w", err)
		}
		if err := resetAndFill(tx, bucketForwardAuthProviders, in.ForwardAuthProviders); err != nil {
			return fmt.Errorf("restore forward_auth_providers: %w", err)
		}
		oidcRows := map[string][]byte{}
		if len(in.OIDCConfig) > 0 {
			oidcRows["default"] = in.OIDCConfig
		}
		if err := resetAndFill(tx, bucketOIDCConfig, oidcRows); err != nil {
			return fmt.Errorf("restore oidc_config: %w", err)
		}
		maxMindRows := map[string][]byte{}
		if len(in.MaxMindConfig) > 0 {
			maxMindRows[maxMindConfigKey] = in.MaxMindConfig
		}
		if err := resetAndFill(tx, bucketMaxMindConfig, maxMindRows); err != nil {
			return fmt.Errorf("restore maxmind_config: %w", err)
		}
		if err := resetAndFill(tx, bucketExternalCertificates, in.ExternalCertificates); err != nil {
			return fmt.Errorf("restore external_certificates: %w", err)
		}
		return nil
	})
}

// resetAndFill clears every key in the bucket then re-inserts every
// row in rows. Bucket must already exist (NewStore creates them).
// Done inside the caller's transaction so the reset + fill are
// atomic with the rest of the restore.
func resetAndFill(tx *bolt.Tx, bucketName string, rows map[string][]byte) error {
	b := tx.Bucket([]byte(bucketName))
	if b == nil {
		return fmt.Errorf("bucket %q missing", bucketName)
	}
	// Collect keys first, then delete — modifying a bucket while
	// iterating it is undefined behaviour in bbolt.
	var keys [][]byte
	if err := b.ForEach(func(k, _ []byte) error {
		copyk := make([]byte, len(k))
		copy(copyk, k)
		keys = append(keys, copyk)
		return nil
	}); err != nil {
		return err
	}
	for _, k := range keys {
		if err := b.Delete(k); err != nil {
			return fmt.Errorf("delete %q: %w", string(k), err)
		}
	}
	for k, v := range rows {
		if err := b.Put([]byte(k), v); err != nil {
			return fmt.Errorf("put %q: %w", k, err)
		}
	}
	return nil
}
