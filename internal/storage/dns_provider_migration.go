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

package storage

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// legacyDNSProviderKey is the fixed bucket key used by the pre-v2.11
// singleton OVH provider. Kept only for the one-shot migration below.
// The consts that once named it (ManagedDomainProviderOVH /
// dnsProviderKeyOVH) were removed when the collection landed; the
// literal lives here because this is the only remaining reader.
const legacyDNSProviderKey = "ovh"

// migratedProviderLabel is the operator-facing label given to the
// singleton config when it is converted into a collection entry.
const migratedProviderLabel = "OVH (default)"

// MigrateLegacyDNSProvider converts the pre-v2.11 singleton OVH config
// (stored under the fixed "ovh" key) into a UUID-keyed collection entry
// labelled "OVH (default)", and repoints every managed domain that
// still carries the legacy provider="ovh" value (with an empty
// provider_id) to the new config's UUID.
//
// Idempotent BY STATE: it does work only while the legacy "ovh" key is
// present. Once migrated the key is gone, so subsequent boots no-op and
// return (false, nil). A fresh install (no legacy key) is likewise a
// (false, nil) no-op.
//
// ATOMICITY: the conversion, the legacy-key delete, and every
// managed-domain repoint happen inside ONE bbolt Update transaction.
// Any error returned from the closure (e.g. a malformed managed-domain
// row) aborts the whole transaction — bbolt rolls it back, leaving the
// legacy "ovh" key intact and no new UUID provider created. There is no
// half-migrated state; the next boot re-detects the legacy key and
// retries.
func (s *Store) MigrateLegacyDNSProvider(ctx context.Context) (bool, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	migrated := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		pb := tx.Bucket([]byte(bucketDNSProviders))
		raw := pb.Get([]byte(legacyDNSProviderKey))
		if raw == nil {
			return nil // already migrated / fresh install
		}
		migrated = true

		var legacy DNSProviderConfig
		if err := json.Unmarshal(raw, &legacy); err != nil {
			return fmt.Errorf("unmarshal legacy dns provider: %w", err)
		}
		newID := uuid.NewString()
		legacy.ID = newID
		legacy.Label = migratedProviderLabel
		legacy.Type = DNSProviderTypeOVH
		buf, err := json.Marshal(legacy)
		if err != nil {
			return fmt.Errorf("marshal migrated dns provider: %w", err)
		}
		if err := pb.Put([]byte(newID), buf); err != nil {
			return err
		}
		if err := pb.Delete([]byte(legacyDNSProviderKey)); err != nil {
			return err
		}

		// Repoint managed domains: read each row, and if its raw JSON
		// still carries provider=="ovh" with an empty provider_id, set
		// provider_id to the new UUID. Any unmarshal failure returns an
		// error, which aborts (and rolls back) the whole transaction.
		mb := tx.Bucket([]byte(bucketManagedDomains))
		type legacyMD struct {
			Apex        string `json:"apex"`
			IncludeApex bool   `json:"include_apex"`
			Provider    string `json:"provider"`
			ProviderID  string `json:"provider_id"`
		}
		return mb.ForEach(func(k, v []byte) error {
			var md legacyMD
			if err := json.Unmarshal(v, &md); err != nil {
				return fmt.Errorf("unmarshal managed domain %q: %w", string(k), err)
			}
			if md.ProviderID == "" && md.Provider == legacyDNSProviderKey {
				out := ManagedDomain{
					Apex:        md.Apex,
					IncludeApex: md.IncludeApex,
					ProviderID:  newID,
				}
				ob, err := json.Marshal(out)
				if err != nil {
					return fmt.Errorf("marshal repointed managed domain %q: %w", string(k), err)
				}
				if err := mb.Put(k, ob); err != nil {
					return err
				}
			}
			return nil
		})
	})
	if err != nil {
		return false, err
	}
	return migrated, nil
}

// MigrateDNSProviderCredentials is the v2.26 boot migration: it rewrites
// every DNS provider row still carrying the pre-v2.26 flat OVH fields
// (endpoint / application_key / application_secret / consumer_key) into
// the Credentials-map shape. The fold itself lives in
// DNSProviderConfig.UnmarshalJSON, so this only persists what every read
// already sees; it exists to keep the on-disk format uniform.
//
// Idempotent by state: rows without legacy keys are left untouched, so
// later boots return (0, nil). Runs in one bbolt transaction — any
// error rolls the whole rewrite back.
func (s *Store) MigrateDNSProviderCredentials(ctx context.Context) (int, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	rewritten := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketDNSProviders))
		type row struct{ key, val []byte }
		var pending []row
		err := b.ForEach(func(k, v []byte) error {
			legacy, err := hasLegacyDNSProviderFields(v)
			if err != nil {
				return fmt.Errorf("inspect dns provider %q: %w", string(k), err)
			}
			if !legacy {
				return nil
			}
			var c DNSProviderConfig
			if err := json.Unmarshal(v, &c); err != nil {
				return fmt.Errorf("unmarshal dns provider %q: %w", string(k), err)
			}
			buf, err := json.Marshal(c)
			if err != nil {
				return fmt.Errorf("marshal dns provider %q: %w", string(k), err)
			}
			pending = append(pending, row{key: append([]byte(nil), k...), val: buf})
			return nil
		})
		if err != nil {
			return err
		}
		// bbolt forbids mutating a bucket while iterating it.
		for _, r := range pending {
			if err := b.Put(r.key, r.val); err != nil {
				return err
			}
		}
		rewritten = len(pending)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return rewritten, nil
}
