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

// --- Step J.1 — UpstreamURL → Upstreams pool migration ---------------------

// writeLegacyJ1Route inserts a hand-crafted JSON blob into the routes
// bucket that uses the PRE-Step-J.1 wire shape: an `upstream_url`
// string and NO `upstreams` / `lb_policy` keys. The waf_mode key is
// already present (post-Step-I.4) because the J.1 migration's input
// is a route that has been through every prior migration. This is the
// shape migrateUpstreamURLToPool must rewrite.
//
// We bypass storage.CreateRoute on purpose, same reason as
// writeLegacyRoute above: the current Route struct no longer carries
// UpstreamURL, so going through CreateRoute would silently produce a
// post-migration shape and the test would prove nothing.
func writeLegacyJ1Route(t *testing.T, db *bolt.DB, id, upstreamURL string) {
	t.Helper()
	legacy := []byte(`{` +
		`"id":"` + id + `",` +
		`"host":"legacy.example.com",` +
		`"upstream_url":"` + upstreamURL + `",` +
		`"tls_enabled":false,` +
		`"redirect_to_https":false,` +
		`"aliases":null,` +
		`"basic_auth_enabled":false,` +
		`"basic_auth_username":"",` +
		`"basic_auth_password_hash":"",` +
		`"request_headers":null,` +
		`"response_headers":null,` +
		`"waf_mode":"off",` +
		`"created_at":"2026-05-01T00:00:00Z",` +
		`"updated_at":"2026-05-01T00:00:00Z"` +
		`}`)
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketRoutes)).Put([]byte(id), legacy)
	}); err != nil {
		t.Fatalf("seed legacy J.1 route: %v", err)
	}
}

func TestMigrate_UpstreamURLBecomesPool(t *testing.T) {
	// Spin up a fresh store via NewStore — the migration runs at boot
	// against an empty bucket (no-op), then we seed the legacy row and
	// re-call the migration explicitly to exercise the conversion path.
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	writeLegacyJ1Route(t, store.db, "r-pool", "http://127.0.0.1:9000")

	if err := migrateUpstreamURLToPool(store.db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Read the migrated row and assert: one-element pool with the
	// legacy URL and weight 1, lb_policy round_robin, no leftover
	// upstream_url key in the raw JSON.
	var r Route
	if err := store.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketRoutes)).Get([]byte("r-pool"))
		if raw == nil {
			t.Fatal("route r-pool missing after migration")
		}
		return jsonUnmarshalForTest(raw, &r)
	}); err != nil {
		t.Fatalf("read migrated route: %v", err)
	}

	if len(r.Upstreams) != 1 {
		t.Fatalf("Upstreams len = %d; want 1 (one-element pool from legacy URL)", len(r.Upstreams))
	}
	if r.Upstreams[0].URL != "http://127.0.0.1:9000" {
		t.Errorf("Upstreams[0].URL = %q; want %q", r.Upstreams[0].URL, "http://127.0.0.1:9000")
	}
	if r.Upstreams[0].Weight != 1 {
		t.Errorf("Upstreams[0].Weight = %d; want 1", r.Upstreams[0].Weight)
	}
	if r.LBPolicy != LBPolicyRoundRobin {
		t.Errorf("LBPolicy = %q; want %q", r.LBPolicy, LBPolicyRoundRobin)
	}

	// The post-J.1 Route struct has no UpstreamURL field, so the
	// re-marshal naturally drops the legacy key. Probe the raw JSON
	// to confirm it's gone (defensive: catches a future regression
	// where someone re-adds the field).
	var rawProbe map[string]any
	if err := store.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketRoutes)).Get([]byte("r-pool"))
		return jsonUnmarshalForTest(raw, &rawProbe)
	}); err != nil {
		t.Fatalf("read raw probe: %v", err)
	}
	if _, leftover := rawProbe["upstream_url"]; leftover {
		t.Errorf("legacy upstream_url key still present after migration: %v", rawProbe)
	}
}

func TestMigrate_UpstreamMigration_Idempotent(t *testing.T) {
	// First migration writes Upstreams + LBPolicy. Second migration
	// must NOT corrupt or rewrite the row — re-running on every boot
	// after the first is supposed to be a cheap no-op (the sentinel
	// len(Upstreams) > 0 fires).
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	writeLegacyJ1Route(t, store.db, "r-j1-idem", "http://127.0.0.1:9001")
	if err := migrateUpstreamURLToPool(store.db); err != nil {
		t.Fatalf("migrate (first run): %v", err)
	}

	// Snapshot the row after the first migration.
	var beforeSecond []byte
	if err := store.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte(bucketRoutes)).Get([]byte("r-j1-idem"))
		beforeSecond = append([]byte(nil), v...)
		return nil
	}); err != nil {
		t.Fatalf("read snapshot: %v", err)
	}

	// Second migration must be a no-op: the row's bytes are unchanged.
	if err := migrateUpstreamURLToPool(store.db); err != nil {
		t.Fatalf("migrate (second run): %v", err)
	}
	var afterSecond []byte
	if err := store.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte(bucketRoutes)).Get([]byte("r-j1-idem"))
		afterSecond = append([]byte(nil), v...)
		return nil
	}); err != nil {
		t.Fatalf("read snapshot 2: %v", err)
	}
	if string(beforeSecond) != string(afterSecond) {
		t.Errorf("second J.1 migration rewrote the row\nbefore: %s\nafter:  %s",
			beforeSecond, afterSecond)
	}
}

// TestMigrate_ChainedOrder_WAFThenUpstream pins the boot-order
// dependency between the two migrations: Step I.4 (waf_enabled →
// waf_mode) MUST run before Step J.1 (upstream_url → upstreams pool).
//
// Failure mode if the order is flipped: J.1's full-Route round-trip
// goes through json.Unmarshal into the current Route struct, which
// has no WAFEnabled field anymore — the legacy `waf_enabled` key
// would be silently dropped before Step I.4 ever saw it, leaving
// WAFMode at its zero value "" instead of being mapped to "block".
// The WAF would end up silently disabled on every pre-Step-I.4 route.
//
// This is the only migrate test that boots via NewStore, on purpose:
// we want to exercise the real production wiring, not the migrations
// in isolation. The flow is — open bbolt directly, create the routes
// bucket, write a doubly-legacy row (waf_enabled:true + upstream_url,
// no waf_mode + no upstreams), close, then call NewStore(path) which
// runs the two migrations in whatever order storage.go wires them.
// A future commit that flips the order in NewStore will trip the
// waf_mode assertion below.
func TestMigrate_ChainedOrder_WAFThenUpstream(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db")

	// Open bbolt directly to seed the doubly-legacy row BEFORE the
	// migrations have a chance to run. Going through NewStore would
	// trigger the migrations against an empty bucket (no-op), then
	// we'd seed a row in the post-migration shape — defeating the
	// point of this test.
	db, err := bolt.Open(dbPath, 0o600, nil)
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketRoutes)); err != nil {
			return err
		}
		// Same shape as writeLegacyRoute: waf_enabled + upstream_url,
		// no waf_mode + no upstreams. Inlined here because we need
		// to write before any Store wrapper exists.
		legacy := []byte(`{` +
			`"id":"r-chain",` +
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
			`"waf_enabled":true,` +
			`"created_at":"2026-05-01T00:00:00Z",` +
			`"updated_at":"2026-05-01T00:00:00Z"` +
			`}`)
		return tx.Bucket([]byte(bucketRoutes)).Put([]byte("r-chain"), legacy)
	}); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close pre-NewStore bolt: %v", err)
	}

	// Now boot through NewStore. This is what a real Arenet startup
	// does — and it's the path under test. The migrations run in
	// whatever order storage.go wires them.
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	var r Route
	if err := store.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketRoutes)).Get([]byte("r-chain"))
		if raw == nil {
			t.Fatal("route r-chain missing after NewStore boot")
		}
		return jsonUnmarshalForTest(raw, &r)
	}); err != nil {
		t.Fatalf("read chained route: %v", err)
	}

	// WAFMode: pre-I.4 waf_enabled:true → "block" per Step I.4 mapping.
	// If J.1 ran first via NewStore's ordering, this would be "" (Go
	// zero value) because the waf_enabled key would have been dropped
	// before I.4 read it.
	if r.WAFMode != "block" {
		t.Errorf("WAFMode = %q; want %q — Step I.4 mapping lost. "+
			"Did someone reorder the migrations in NewStore?", r.WAFMode, "block")
	}

	// Upstreams + LBPolicy: pre-J.1 upstream_url → one-element pool +
	// round_robin per Step J.1 mapping.
	if len(r.Upstreams) != 1 || r.Upstreams[0].URL != "http://127.0.0.1:9000" {
		t.Errorf("Upstreams = %+v; want one element with URL http://127.0.0.1:9000", r.Upstreams)
	}
	if r.LBPolicy != LBPolicyRoundRobin {
		t.Errorf("LBPolicy = %q; want %q", r.LBPolicy, LBPolicyRoundRobin)
	}
}

// TestMigrate_BasicAuthEnabledTrueBecomesBasicMode pins the
// Step K.1 mapping: a pre-K route with basic_auth_enabled=true
// migrates to auth_mode="basic" + the nested BasicAuth struct
// populated from the legacy flat fields.
func TestMigrate_BasicAuthEnabledTrueBecomesBasicMode(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	// Seed a pre-K row directly via bbolt, bypassing the route
	// validators (which would now reject the legacy shape).
	legacy := []byte(`{` +
		`"id":"r-pre-k-1",` +
		`"host":"protected.example.com",` +
		`"upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],` +
		`"lb_policy":"round_robin",` +
		`"tls_enabled":false,` +
		`"redirect_to_https":false,` +
		`"aliases":null,` +
		`"basic_auth_enabled":true,` +
		`"basic_auth_username":"admin",` +
		`"basic_auth_password_hash":"$argon2id$..fake..",` +
		`"request_headers":null,` +
		`"response_headers":null,` +
		`"waf_mode":"off",` +
		`"created_at":"2026-05-01T00:00:00Z",` +
		`"updated_at":"2026-05-01T00:00:00Z"` +
		`}`)
	if err := store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketRoutes)).Put([]byte("r-pre-k-1"), legacy)
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := migrateBasicAuthToAuthMode(store.db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var r Route
	if err := store.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketRoutes)).Get([]byte("r-pre-k-1"))
		return jsonUnmarshalForTest(raw, &r)
	}); err != nil {
		t.Fatalf("read: %v", err)
	}

	if r.AuthMode != RouteAuthBasic {
		t.Errorf("AuthMode = %q; want %q", r.AuthMode, RouteAuthBasic)
	}
	if r.BasicAuth.Username != "admin" {
		t.Errorf("BasicAuth.Username = %q; want admin", r.BasicAuth.Username)
	}
	if r.BasicAuth.PasswordHash != "$argon2id$..fake.." {
		t.Errorf("BasicAuth.PasswordHash = %q; want %q", r.BasicAuth.PasswordHash, "$argon2id$..fake..")
	}
	// Forward-auth nested struct must initialise to zero.
	if r.ForwardAuth.ProviderName != "" {
		t.Errorf("ForwardAuth.ProviderName = %q; want empty", r.ForwardAuth.ProviderName)
	}

	// Verify the legacy keys are GONE from the persisted row.
	var raw map[string]any
	if err := store.db.View(func(tx *bolt.Tx) error {
		bs := tx.Bucket([]byte(bucketRoutes)).Get([]byte("r-pre-k-1"))
		return jsonUnmarshalForTest(bs, &raw)
	}); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	for _, k := range []string{"basic_auth_enabled", "basic_auth_username", "basic_auth_password_hash"} {
		if _, present := raw[k]; present {
			t.Errorf("legacy key %q still present after migration", k)
		}
	}
}

// TestMigrate_BasicAuthEnabledFalseBecomesNoneMode pins the
// inverse mapping: basic_auth_enabled=false → auth_mode="none",
// nested BasicAuth empty.
func TestMigrate_BasicAuthEnabledFalseBecomesNoneMode(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	legacy := []byte(`{` +
		`"id":"r-pre-k-2",` +
		`"host":"open.example.com",` +
		`"upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],` +
		`"lb_policy":"round_robin",` +
		`"tls_enabled":false,` +
		`"redirect_to_https":false,` +
		`"aliases":null,` +
		`"basic_auth_enabled":false,` +
		`"basic_auth_username":"",` +
		`"basic_auth_password_hash":"",` +
		`"request_headers":null,` +
		`"response_headers":null,` +
		`"waf_mode":"off",` +
		`"created_at":"2026-05-01T00:00:00Z",` +
		`"updated_at":"2026-05-01T00:00:00Z"` +
		`}`)
	if err := store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketRoutes)).Put([]byte("r-pre-k-2"), legacy)
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := migrateBasicAuthToAuthMode(store.db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var r Route
	if err := store.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketRoutes)).Get([]byte("r-pre-k-2"))
		return jsonUnmarshalForTest(raw, &r)
	}); err != nil {
		t.Fatalf("read: %v", err)
	}

	if r.AuthMode != RouteAuthNone {
		t.Errorf("AuthMode = %q; want %q", r.AuthMode, RouteAuthNone)
	}
	if r.BasicAuth.Username != "" || r.BasicAuth.PasswordHash != "" {
		t.Errorf("BasicAuth populated despite none: %+v", r.BasicAuth)
	}
}

// TestMigrate_BasicAuthToAuthMode_Idempotent: re-running the
// migration on an already-migrated row must be a no-op.
func TestMigrate_BasicAuthToAuthMode_Idempotent(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	migrated := []byte(`{` +
		`"id":"r-already",` +
		`"host":"done.example.com",` +
		`"upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],` +
		`"lb_policy":"round_robin",` +
		`"tls_enabled":false,` +
		`"redirect_to_https":false,` +
		`"aliases":null,` +
		`"auth_mode":"basic",` +
		`"basic_auth":{"username":"admin","password_hash":"$argon2id$..hash.."},` +
		`"forward_auth":{"provider_name":""},` +
		`"request_headers":null,` +
		`"response_headers":null,` +
		`"waf_mode":"off",` +
		`"created_at":"2026-05-01T00:00:00Z",` +
		`"updated_at":"2026-05-01T00:00:00Z"` +
		`}`)
	if err := store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketRoutes)).Put([]byte("r-already"), migrated)
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Capture pre-state.
	var before []byte
	store.db.View(func(tx *bolt.Tx) error {
		before = append([]byte(nil), tx.Bucket([]byte(bucketRoutes)).Get([]byte("r-already"))...)
		return nil
	})

	if err := migrateBasicAuthToAuthMode(store.db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var after []byte
	store.db.View(func(tx *bolt.Tx) error {
		after = append([]byte(nil), tx.Bucket([]byte(bucketRoutes)).Get([]byte("r-already"))...)
		return nil
	})

	if string(before) != string(after) {
		t.Errorf("migration mutated an already-migrated row:\nbefore=%s\nafter =%s", before, after)
	}
}

// TestMigrate_ChainedOrder_IFourThenJOneThenKOne is the K.1
// extension of TestMigrate_ChainedOrder_WAFThenUpstream. It seeds
// a TRIPLY-legacy row (pre-I.4 waf_enabled + pre-J.1 upstream_url
// + pre-K basic_auth_enabled) and verifies that NewStore's
// migration sequence produces the final post-K shape correctly
// for all three concerns.
//
// Failure mode if K.1 ran before I.4 / J.1: the passthrough-map
// pattern in K.1 keeps unknown keys intact, so the chain order is
// less critical than the I.4→J.1 ordering — but a regression that
// swapped to a full-Route round-trip in K.1 would silently drop
// waf_enabled / upstream_url before they could be migrated.
func TestMigrate_ChainedOrder_IFourThenJOneThenKOne(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db")

	db, err := bolt.Open(dbPath, 0o600, nil)
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketRoutes)); err != nil {
			return err
		}
		legacy := []byte(`{` +
			`"id":"r-triple",` +
			`"host":"triple-legacy.example.com",` +
			`"upstream_url":"http://127.0.0.1:9000",` +
			`"tls_enabled":false,` +
			`"redirect_to_https":false,` +
			`"aliases":null,` +
			`"basic_auth_enabled":true,` +
			`"basic_auth_username":"admin",` +
			`"basic_auth_password_hash":"$argon2id$..legacy..",` +
			`"request_headers":null,` +
			`"response_headers":null,` +
			`"waf_enabled":true,` +
			`"created_at":"2026-05-01T00:00:00Z",` +
			`"updated_at":"2026-05-01T00:00:00Z"` +
			`}`)
		return tx.Bucket([]byte(bucketRoutes)).Put([]byte("r-triple"), legacy)
	}); err != nil {
		t.Fatalf("seed triple-legacy row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close pre-NewStore bolt: %v", err)
	}

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	var r Route
	if err := store.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketRoutes)).Get([]byte("r-triple"))
		if raw == nil {
			t.Fatal("triple-legacy row missing after NewStore boot")
		}
		return jsonUnmarshalForTest(raw, &r)
	}); err != nil {
		t.Fatalf("read: %v", err)
	}

	// All three migrations must have left their mark.
	if r.WAFMode != "block" {
		t.Errorf("WAFMode = %q; want %q (Step I.4 lost)", r.WAFMode, "block")
	}
	if len(r.Upstreams) != 1 || r.Upstreams[0].URL != "http://127.0.0.1:9000" {
		t.Errorf("Upstreams = %+v; want one element with the legacy URL (Step J.1 lost)", r.Upstreams)
	}
	if r.LBPolicy != LBPolicyRoundRobin {
		t.Errorf("LBPolicy = %q; want %q (Step J.1 lost)", r.LBPolicy, LBPolicyRoundRobin)
	}
	if r.AuthMode != RouteAuthBasic {
		t.Errorf("AuthMode = %q; want %q (Step K.1 lost)", r.AuthMode, RouteAuthBasic)
	}
	if r.BasicAuth.Username != "admin" {
		t.Errorf("BasicAuth.Username = %q; want admin (Step K.1 lost)", r.BasicAuth.Username)
	}
	if r.BasicAuth.PasswordHash != "$argon2id$..legacy.." {
		t.Errorf("BasicAuth.PasswordHash = %q; want preserved (Step K.1 lost)", r.BasicAuth.PasswordHash)
	}
}

// TestMigrate_UsersAuthSourceAndRole pins the K.2 mapping:
// pre-K user rows (no auth_source / role / oidc_sub keys) get
// auth_source="local" + role="admin" + oidc_sub="". Idempotent
// via the compound sentinel (both auth_source AND role
// non-empty).
func TestMigrate_UsersAuthSourceAndRole(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	legacy := []byte(`{` +
		`"id":"u-pre-k",` +
		`"username":"alice",` +
		`"display_name":"Alice",` +
		`"password_hash":"$argon2id$..fake..",` +
		`"hibp_check_status":"clean",` +
		`"password_compromised":false,` +
		`"created_at":"2026-04-01T00:00:00Z",` +
		`"updated_at":"2026-04-01T00:00:00Z"` +
		`}`)
	if err := store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketUsers)).Put([]byte("u-pre-k"), legacy)
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := migrateUsersAuthSourceAndRole(store.db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var raw map[string]any
	if err := store.db.View(func(tx *bolt.Tx) error {
		bs := tx.Bucket([]byte(bucketUsers)).Get([]byte("u-pre-k"))
		return jsonUnmarshalForTest(bs, &raw)
	}); err != nil {
		t.Fatalf("read: %v", err)
	}
	if raw["auth_source"] != "local" {
		t.Errorf("auth_source = %v; want local", raw["auth_source"])
	}
	if raw["role"] != "admin" {
		t.Errorf("role = %v; want admin (pre-K user privilege preserved)", raw["role"])
	}
	if raw["oidc_sub"] != "" {
		t.Errorf("oidc_sub = %v; want empty", raw["oidc_sub"])
	}
	// Existing field preserved.
	if raw["username"] != "alice" {
		t.Errorf("username clobbered: %v", raw["username"])
	}
}

// TestMigrate_UsersAuthSourceAndRole_Idempotent: re-running the
// migration on an already-migrated row must be a no-op.
func TestMigrate_UsersAuthSourceAndRole_Idempotent(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	migrated := []byte(`{` +
		`"id":"u-already",` +
		`"username":"bob",` +
		`"display_name":"Bob",` +
		`"password_hash":"$argon2id$..hash..",` +
		`"auth_source":"local",` +
		`"role":"admin",` +
		`"oidc_sub":"",` +
		`"created_at":"2026-04-01T00:00:00Z",` +
		`"updated_at":"2026-04-01T00:00:00Z"` +
		`}`)
	if err := store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketUsers)).Put([]byte("u-already"), migrated)
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var before []byte
	store.db.View(func(tx *bolt.Tx) error {
		before = append([]byte(nil), tx.Bucket([]byte(bucketUsers)).Get([]byte("u-already"))...)
		return nil
	})

	if err := migrateUsersAuthSourceAndRole(store.db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var after []byte
	store.db.View(func(tx *bolt.Tx) error {
		after = append([]byte(nil), tx.Bucket([]byte(bucketUsers)).Get([]byte("u-already"))...)
		return nil
	})

	if string(before) != string(after) {
		t.Errorf("migration mutated an already-migrated user row:\nbefore=%s\nafter =%s", before, after)
	}
}
