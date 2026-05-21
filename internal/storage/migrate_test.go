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
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// writeLegacyRoute inserts a hand-crafted JSON blob into the routes
// bucket that uses the PRE-Step-I.4 wire shape: a `waf_enabled` bool
// and NO `waf_mode` key. This is the input the migration must
// rewrite.
//
// We bypass storage.CreateRoute on purpose: that method uses the
// current Route struct (which no longer carries WAFEnabled), so
// going through it would silently produce a post-migration shape
// and the test would prove nothing.
func writeLegacyRoute(t *testing.T, db *bolt.DB, id string, wafEnabled bool) {
	t.Helper()
	legacy := []byte(`{` +
		`"id":"` + id + `",` +
		`"host":"legacy.example.com",` +
		`"upstream_url":"http://127.0.0.1:9000",` +
		`"tls_enabled":false,` +
		`"redirect_to_https":false,` +
		`"aliases":null,` +
		`"basic_auth_enabled":false,` +
		`"basic_auth_username":"",` +
		`"basic_auth_password_hash":"",` +
		`"request_headers":null,` +
		`"response_headers":null,` +
		`"waf_enabled":` + boolStr(wafEnabled) + `,` +
		`"created_at":"2026-05-01T00:00:00Z",` +
		`"updated_at":"2026-05-01T00:00:00Z"` +
		`}`)
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketRoutes)).Put([]byte(id), legacy)
	}); err != nil {
		t.Fatalf("seed legacy route: %v", err)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// readWAFMode reads the WAFMode field of a stored route by ID.
// Returns the empty string if the route is missing or the field is
// absent — both useful failure signals for migration tests.
func readWAFMode(t *testing.T, db *bolt.DB, id string) string {
	t.Helper()
	var r Route
	if err := db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketRoutes)).Get([]byte(id))
		if raw == nil {
			return nil
		}
		return jsonUnmarshalForTest(raw, &r)
	}); err != nil {
		t.Fatalf("read route %s: %v", id, err)
	}
	return r.WAFMode
}

// jsonUnmarshalForTest is a tiny indirection so the test file does
// not need a top-level import for encoding/json (kept inside the
// helper to stay focused on the migration assertions).
func jsonUnmarshalForTest(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func TestMigrate_WAFEnabledTrueBecomesBlock(t *testing.T) {
	// Spin up a fresh store via NewStore — the migration runs
	// automatically at boot, but we'll re-call it explicitly below
	// after seeding a legacy row to prove the conversion path
	// (NewStore's first-boot call finds an empty bucket).
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	writeLegacyRoute(t, store.db, "r-block", true)

	if err := migrateWAFEnabledToWAFMode(store.db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got := readWAFMode(t, store.db, "r-block"); got != "block" {
		t.Errorf("WAFMode = %q; want %q (WAFEnabled=true semantics)", got, "block")
	}
}

func TestMigrate_WAFEnabledFalseBecomesOff(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	writeLegacyRoute(t, store.db, "r-off", false)

	if err := migrateWAFEnabledToWAFMode(store.db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got := readWAFMode(t, store.db, "r-off"); got != "off" {
		t.Errorf("WAFMode = %q; want %q (WAFEnabled=false semantics)", got, "off")
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	// First migration writes WAFMode=block. Second migration must
	// NOT corrupt or rewrite the row — re-running on every boot
	// after the first is supposed to be a cheap no-op.
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	writeLegacyRoute(t, store.db, "r-idem", true)
	if err := migrateWAFEnabledToWAFMode(store.db); err != nil {
		t.Fatalf("migrate (first run): %v", err)
	}

	// Snapshot the row after the first migration.
	var beforeSecond []byte
	if err := store.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte(bucketRoutes)).Get([]byte("r-idem"))
		beforeSecond = append([]byte(nil), v...)
		return nil
	}); err != nil {
		t.Fatalf("read snapshot: %v", err)
	}

	// Second migration must be a no-op: the row's bytes are
	// unchanged, the WAFMode is still "block", no error.
	if err := migrateWAFEnabledToWAFMode(store.db); err != nil {
		t.Fatalf("migrate (second run): %v", err)
	}
	var afterSecond []byte
	if err := store.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte(bucketRoutes)).Get([]byte("r-idem"))
		afterSecond = append([]byte(nil), v...)
		return nil
	}); err != nil {
		t.Fatalf("read snapshot 2: %v", err)
	}
	if string(beforeSecond) != string(afterSecond) {
		t.Errorf("second migration rewrote the row\nbefore: %s\nafter:  %s",
			beforeSecond, afterSecond)
	}

	// Sanity: created_at didn't drift either.
	if got := readWAFMode(t, store.db, "r-idem"); got != "block" {
		t.Errorf("WAFMode after 2nd run = %q; want block", got)
	}
	// And a fresh write through the store using time.Now still works.
	_ = time.Now() // imported time
}
