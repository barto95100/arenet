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
	"encoding/json"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// seedLegacyProvider writes the pre-v2.11 singleton OVH row under the
// fixed "ovh" key with the given secrets, mirroring how a v2.10.x DB
// looks on disk before migration.
func seedLegacyProvider(t *testing.T, s *Store) {
	t.Helper()
	legacy := DNSProviderConfig{
		Endpoint:          "ovh-eu",
		ApplicationKey:    "ak",
		ApplicationSecret: "as",
		ConsumerKey:       "ck",
	}
	buf, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketDNSProviders)).Put([]byte("ovh"), buf)
	}); err != nil {
		t.Fatalf("seed legacy provider: %v", err)
	}
}

// putRawManagedDomain writes a raw managed-domain JSON row directly
// under the given key, bypassing the typed Put so we can inject legacy
// (provider="ovh") or malformed rows.
func putRawManagedDomain(t *testing.T, s *Store, key string, raw []byte) {
	t.Helper()
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketManagedDomains)).Put([]byte(key), raw)
	}); err != nil {
		t.Fatalf("seed managed domain %q: %v", key, err)
	}
}

// Gate (a) convert + repoint: legacy singleton becomes a UUID-keyed
// entry labelled "OVH (default)" with secrets carried, the legacy key
// is deleted, and a managed domain still carrying the legacy
// provider="ovh" value is repointed to the new UUID.
func TestMigrateLegacyDNSProvider_ConvertsAndRepoints(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	seedLegacyProvider(t, s)
	putRawManagedDomain(t, s, "example.com",
		[]byte(`{"apex":"example.com","include_apex":true,"provider":"ovh"}`))

	migrated, err := s.MigrateLegacyDNSProvider(ctx)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !migrated {
		t.Fatal("expected migrated=true on first run")
	}

	// Legacy "ovh" key gone; exactly one UUID-keyed provider now.
	list, err := s.ListDNSProviders(ctx)
	if err != nil {
		t.Fatalf("ListDNSProviders: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("providers = %d, want 1", len(list))
	}
	newID := list[0].ID
	if newID == "ovh" || newID == "" {
		t.Errorf("provider not re-keyed to a UUID: %q", newID)
	}
	if list[0].Label != "OVH (default)" || list[0].Type != "ovh" {
		t.Errorf("migrated provider = %+v", list[0])
	}
	if list[0].ApplicationKey != "ak" || list[0].ApplicationSecret != "as" || list[0].ConsumerKey != "ck" {
		t.Errorf("secrets not carried over: %+v", list[0])
	}

	// The legacy key must be gone from the bucket.
	if err := s.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte(bucketDNSProviders)).Get([]byte("ovh")) != nil {
			t.Error("legacy \"ovh\" key still present after migration")
		}
		return nil
	}); err != nil {
		t.Fatalf("view: %v", err)
	}

	// Managed domain repointed to the new UUID.
	md, err := s.GetManagedDomain(ctx, "example.com")
	if err != nil {
		t.Fatalf("GetManagedDomain: %v", err)
	}
	if md.ProviderID != newID {
		t.Errorf("managed domain ProviderID = %q, want %q", md.ProviderID, newID)
	}
	if md.Apex != "example.com" || !md.IncludeApex {
		t.Errorf("managed domain other fields corrupted: %+v", md)
	}
}

// Gate (b) idempotence: a second run is a no-op — returns
// migrated=false and does NOT create a duplicate provider.
func TestMigrateLegacyDNSProvider_Idempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	seedLegacyProvider(t, s)

	if migrated, err := s.MigrateLegacyDNSProvider(ctx); err != nil || !migrated {
		t.Fatalf("first migrate: migrated=%v err=%v, want true/nil", migrated, err)
	}

	migrated2, err := s.MigrateLegacyDNSProvider(ctx)
	if err != nil {
		t.Fatalf("migrate #2: %v", err)
	}
	if migrated2 {
		t.Error("second migration ran again; expected no-op (migrated=false)")
	}
	list, err := s.ListDNSProviders(ctx)
	if err != nil {
		t.Fatalf("ListDNSProviders: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("providers after 2nd run = %d, want 1 (no duplicate)", len(list))
	}
}

// Gate (c) fresh install: no legacy key → migrate returns (false, nil),
// 0 providers, no error.
func TestMigrateLegacyDNSProvider_FreshInstall(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	migrated, err := s.MigrateLegacyDNSProvider(ctx)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if migrated {
		t.Error("fresh install reported migrated=true; expected false")
	}
	list, err := s.ListDNSProviders(ctx)
	if err != nil {
		t.Fatalf("ListDNSProviders: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("providers on fresh install = %d, want 0", len(list))
	}
}

// Gate (d) atomic rollback: a repoint that fails mid-transaction (here,
// a malformed managed-domain row that fails to unmarshal) must abort the
// whole Update — the legacy "ovh" key STILL EXISTS and NO new UUID
// provider was created. This proves the migration is atomic: bbolt rolls
// the entire transaction back on any returned error.
func TestMigrateLegacyDNSProvider_AtomicRollbackOnRepointError(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	seedLegacyProvider(t, s)
	// Malformed JSON in the managed-domains bucket: the ForEach
	// unmarshal will error, which must abort the whole Update.
	putRawManagedDomain(t, s, "broken.com", []byte(`{not valid json`))

	migrated, err := s.MigrateLegacyDNSProvider(ctx)
	if err == nil {
		t.Fatal("expected a non-nil error from a malformed managed-domain row")
	}
	if migrated {
		t.Error("migrated=true reported despite a failed transaction")
	}

	// Legacy key must STILL be present (rolled back), and NO new
	// UUID-keyed provider must exist — the bucket holds exactly the
	// legacy "ovh" row and nothing else.
	if err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketDNSProviders))
		if b.Get([]byte("ovh")) == nil {
			t.Error("legacy \"ovh\" key was deleted despite rollback")
		}
		n := 0
		if err := b.ForEach(func(k, _ []byte) error {
			n++
			if string(k) != "ovh" {
				t.Errorf("unexpected provider key after rollback: %q", k)
			}
			return nil
		}); err != nil {
			return err
		}
		if n != 1 {
			t.Errorf("provider bucket has %d rows after rollback, want 1 (legacy only)", n)
		}
		return nil
	}); err != nil {
		t.Fatalf("view: %v", err)
	}
}

// Gate (e) wildcard link preservation: after a successful migrate,
// GetManagedDomain(apex).ProviderID resolves to a provider that
// GetDNSProvider returns without ErrNotFound — the link is valid
// end-to-end.
func TestMigrateLegacyDNSProvider_WildcardLinkPreserved(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	seedLegacyProvider(t, s)
	putRawManagedDomain(t, s, "example.com",
		[]byte(`{"apex":"example.com","include_apex":true,"provider":"ovh"}`))

	if _, err := s.MigrateLegacyDNSProvider(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	md, err := s.GetManagedDomain(ctx, "example.com")
	if err != nil {
		t.Fatalf("GetManagedDomain: %v", err)
	}
	if md.ProviderID == "" {
		t.Fatal("managed domain has empty ProviderID after migration")
	}
	prov, err := s.GetDNSProvider(ctx, md.ProviderID)
	if err != nil {
		t.Fatalf("GetDNSProvider(%q): %v — link is dangling", md.ProviderID, err)
	}
	if prov.ID != md.ProviderID {
		t.Errorf("resolved provider ID %q != managed domain ProviderID %q", prov.ID, md.ProviderID)
	}
}
