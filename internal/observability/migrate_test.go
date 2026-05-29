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

package observability

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// openV1OnDisk creates a fresh DB at path with the Step L v1
// schema baseline and version=1 (mimics a metrics.db that
// existed before Step M shipped). Used to exercise the
// v1→v2 migration path against a real on-disk DB.
func openV1OnDisk(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("openV1OnDisk: %v", err)
	}
	defer db.Close()
	const v1Schema = `
	CREATE TABLE bucket_1m (
	  route_id TEXT NOT NULL,
	  ts INTEGER NOT NULL,
	  req_count INTEGER NOT NULL,
	  fourxx_count INTEGER NOT NULL,
	  fivexx_count INTEGER NOT NULL,
	  latency_p95_ms INTEGER NOT NULL,
	  PRIMARY KEY (route_id, ts)
	);
	CREATE INDEX idx_bucket_1m_ts ON bucket_1m (ts);
	CREATE TABLE bucket_1h (
	  route_id TEXT NOT NULL,
	  ts INTEGER NOT NULL,
	  req_count INTEGER NOT NULL,
	  fourxx_count INTEGER NOT NULL,
	  fivexx_count INTEGER NOT NULL,
	  latency_p95_ms INTEGER NOT NULL,
	  PRIMARY KEY (route_id, ts)
	);
	CREATE INDEX idx_bucket_1h_ts ON bucket_1h (ts);
	CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
	INSERT INTO schema_version (version) VALUES (1);
	`
	if _, err := db.Exec(v1Schema); err != nil {
		t.Fatalf("openV1OnDisk seed: %v", err)
	}
	// Seed one bucket row so the migration's "preserve old
	// data" guarantee can be asserted post-upgrade.
	if _, err := db.Exec(`INSERT INTO bucket_1m (route_id, ts, req_count, fourxx_count, fivexx_count, latency_p95_ms)
	                      VALUES (?, ?, ?, ?, ?, ?)`,
		"r-pre-m", int64(1700000000), int64(42), int64(3), int64(1), int32(16)); err != nil {
		t.Fatalf("seed bucket_1m: %v", err)
	}
}

func TestMigrate_FreshDB_LandsAtCurrentVersion(t *testing.T) {
	// A brand-new in-memory DB should land at the current
	// schema version after Open returns. (Same assertion as
	// TestSchema_InitIdempotent but isolated here for trace
	// when adding future migration steps.)
	s, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	v, err := s.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if v != currentSchemaVersion {
		t.Fatalf("fresh DB version = %d, want %d", v, currentSchemaVersion)
	}
}

func TestMigrate_V1ToCurrent_PreservesExistingData(t *testing.T) {
	// Spec AC #6: opening a pre-Step-M metrics.db (schema v1)
	// must replay the full migrate chain to currentSchemaVersion
	// AND keep the existing rows intact. Each step runs in a
	// single transaction so partial failure cannot land at a
	// half-version.
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v1-metrics.db")

	openV1OnDisk(t, dbPath)

	// Open via the production code path — the migrate chain
	// should bump the file from v1 to currentSchemaVersion.
	s, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open v1 DB: %v", err)
	}
	defer s.Close()

	v, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if v != currentSchemaVersion {
		t.Fatalf("after migrate version = %d, want %d", v, currentSchemaVersion)
	}

	// Existing data must still be present and accessible
	// through the current Query path (proving the new columns
	// were added with sensible defaults for old rows).
	row := s.db.QueryRowContext(ctx, `SELECT req_count, fourxx_count, fivexx_count, waf_block_count, throttle_block_count, latency_p95_ms FROM bucket_1m WHERE route_id = 'r-pre-m'`)
	var req, fourxx, fivexx, waf, throttle int64
	var p95 int32
	if err := row.Scan(&req, &fourxx, &fivexx, &waf, &throttle, &p95); err != nil {
		t.Fatalf("scan pre-migrate row: %v", err)
	}
	if req != 42 || fourxx != 3 || fivexx != 1 || p95 != 16 {
		t.Fatalf("old data corrupted by migration: req=%d fourxx=%d fivexx=%d p95=%d", req, fourxx, fivexx, p95)
	}
	if waf != 0 {
		t.Fatalf("pre-existing row should have waf_block_count=0 (default for migrated rows), got %d", waf)
	}
	if throttle != 0 {
		t.Fatalf("pre-existing row should have throttle_block_count=0 (default for migrated rows), got %d", throttle)
	}

	// The waf_event table (v2) + throttle_event table (v3)
	// must both be present after the full chain replay.
	var name string
	if err := s.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name='waf_event'`).Scan(&name); err != nil {
		t.Fatalf("waf_event table missing after migrate: %v", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name='throttle_event'`).Scan(&name); err != nil {
		t.Fatalf("throttle_event table missing after migrate: %v", err)
	}
}

func TestMigrate_RerunOnCurrent_IsNoOp(t *testing.T) {
	// Idempotency: re-opening an already-current DB does
	// nothing (no transaction even started). Verified
	// indirectly by Open succeeding and the version
	// remaining unchanged.
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "current-metrics.db")

	// Fresh open → lands at currentSchemaVersion.
	s1, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	_ = s1.Close()

	// Second open → must succeed and stay at currentSchemaVersion.
	s2, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer s2.Close()
	v, err := s2.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if v != currentSchemaVersion {
		t.Fatalf("second open changed version: %d → %d", currentSchemaVersion, v)
	}
}

// openV2OnDisk creates a fresh DB at path with the Step M v2
// schema baseline (bootstrap v1 + bucket waf_block_count
// columns + waf_event table) and version=2. Used to exercise
// the v2→v3 migration path against a real on-disk DB without
// replaying v1→v2 — guards against a future refactor that
// hides a v2→v3 bug behind the v1 fast path.
func openV2OnDisk(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("openV2OnDisk: %v", err)
	}
	defer db.Close()
	const v2Schema = `
	CREATE TABLE bucket_1m (
	  route_id TEXT NOT NULL,
	  ts INTEGER NOT NULL,
	  req_count INTEGER NOT NULL,
	  fourxx_count INTEGER NOT NULL,
	  fivexx_count INTEGER NOT NULL,
	  waf_block_count INTEGER NOT NULL DEFAULT 0,
	  latency_p95_ms INTEGER NOT NULL,
	  PRIMARY KEY (route_id, ts)
	);
	CREATE INDEX idx_bucket_1m_ts ON bucket_1m (ts);
	CREATE TABLE bucket_1h (
	  route_id TEXT NOT NULL,
	  ts INTEGER NOT NULL,
	  req_count INTEGER NOT NULL,
	  fourxx_count INTEGER NOT NULL,
	  fivexx_count INTEGER NOT NULL,
	  waf_block_count INTEGER NOT NULL DEFAULT 0,
	  latency_p95_ms INTEGER NOT NULL,
	  PRIMARY KEY (route_id, ts)
	);
	CREATE INDEX idx_bucket_1h_ts ON bucket_1h (ts);
	CREATE TABLE waf_event (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  ts INTEGER NOT NULL,
	  route_id TEXT NOT NULL,
	  rule_id TEXT NOT NULL,
	  category TEXT NOT NULL,
	  severity INTEGER NOT NULL,
	  src_ip TEXT NOT NULL,
	  request_method TEXT NOT NULL,
	  request_path TEXT NOT NULL,
	  payload_sample TEXT NOT NULL
	);
	CREATE INDEX idx_waf_event_ts          ON waf_event (ts);
	CREATE INDEX idx_waf_event_route_ts    ON waf_event (route_id, ts);
	CREATE INDEX idx_waf_event_category_ts ON waf_event (category, ts);
	CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
	-- Natural post-v1→v2-migration state: one row at 2.
	-- (Open()'s bootstrap is now guarded against injecting a
	-- phantom version=1 row on reopen — see the comment in
	-- storage.go schemaSQL.)
	INSERT INTO schema_version (version) VALUES (2);
	`
	if _, err := db.Exec(v2Schema); err != nil {
		t.Fatalf("openV2OnDisk seed: %v", err)
	}
	// Seed one bucket row + one waf_event row so the
	// migration's "preserve old data" guarantee can be
	// asserted post-upgrade.
	if _, err := db.Exec(`INSERT INTO bucket_1m (route_id, ts, req_count, fourxx_count, fivexx_count, waf_block_count, latency_p95_ms)
	                      VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"r-pre-q", int64(1700000000), int64(99), int64(7), int64(2), int64(11), int32(22)); err != nil {
		t.Fatalf("seed bucket_1m: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO waf_event (ts, route_id, rule_id, category, severity, src_ip, request_method, request_path, payload_sample)
	                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		int64(1700000000), "r-pre-q", "942100", "SQLI", 5, "1.2.3.4", "GET", "/login", ""); err != nil {
		t.Fatalf("seed waf_event: %v", err)
	}
}

func TestMigrate_V2ToV3_PreservesExistingData(t *testing.T) {
	// Spec Q AC #6 (mirror of M's): opening a pre-Step-Q
	// metrics.db (schema v2) must add throttle_block_count columns
	// + throttle_event table + indexes WITHOUT touching
	// existing bucket or waf_event rows.
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v2-metrics.db")

	openV2OnDisk(t, dbPath)

	s, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open v2 DB: %v", err)
	}
	defer s.Close()

	v, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if v != currentSchemaVersion {
		t.Fatalf("after v2→v3 migrate version = %d, want %d", v, currentSchemaVersion)
	}

	// Bucket row preserved + throttle_block_count defaulted to 0.
	row := s.db.QueryRowContext(ctx, `SELECT req_count, waf_block_count, throttle_block_count FROM bucket_1m WHERE route_id = 'r-pre-q'`)
	var req, waf, throttle int64
	if err := row.Scan(&req, &waf, &throttle); err != nil {
		t.Fatalf("scan pre-Q bucket row: %v", err)
	}
	if req != 99 || waf != 11 {
		t.Fatalf("v2 bucket data corrupted: req=%d waf=%d (want 99, 11)", req, waf)
	}
	if throttle != 0 {
		t.Fatalf("pre-existing bucket row should have throttle_block_count=0, got %d", throttle)
	}

	// waf_event row preserved.
	var rule string
	if err := s.db.QueryRowContext(ctx, `SELECT rule_id FROM waf_event WHERE route_id = 'r-pre-q'`).Scan(&rule); err != nil {
		t.Fatalf("scan pre-Q waf_event row: %v", err)
	}
	if rule != "942100" {
		t.Fatalf("v2 waf_event data corrupted: rule=%s want 942100", rule)
	}

	// throttle_event table + indexes present.
	var name string
	if err := s.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name='throttle_event'`).Scan(&name); err != nil {
		t.Fatalf("throttle_event table missing after v2→v3 migrate: %v", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='index' AND name='idx_throttle_event_srcip_ts'`).Scan(&name); err != nil {
		t.Fatalf("idx_throttle_event_srcip_ts missing after v2→v3 migrate: %v", err)
	}
}

// openV3OnDisk creates a fresh DB at path with the Step Q v3
// schema baseline (full v1+v2+v3 shape) and version=3. Used
// to exercise the v3→v4 migration path against a real on-disk
// DB without replaying earlier steps — guards against a future
// refactor that hides a v3→v4 bug behind the v1 / v2 fast paths.
func openV3OnDisk(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("openV3OnDisk: %v", err)
	}
	defer db.Close()
	const v3Schema = `
	CREATE TABLE bucket_1m (
	  route_id TEXT NOT NULL,
	  ts INTEGER NOT NULL,
	  req_count INTEGER NOT NULL,
	  fourxx_count INTEGER NOT NULL,
	  fivexx_count INTEGER NOT NULL,
	  waf_block_count INTEGER NOT NULL DEFAULT 0,
	  throttle_block_count INTEGER NOT NULL DEFAULT 0,
	  latency_p95_ms INTEGER NOT NULL,
	  PRIMARY KEY (route_id, ts)
	);
	CREATE INDEX idx_bucket_1m_ts ON bucket_1m (ts);
	CREATE TABLE bucket_1h (
	  route_id TEXT NOT NULL,
	  ts INTEGER NOT NULL,
	  req_count INTEGER NOT NULL,
	  fourxx_count INTEGER NOT NULL,
	  fivexx_count INTEGER NOT NULL,
	  waf_block_count INTEGER NOT NULL DEFAULT 0,
	  throttle_block_count INTEGER NOT NULL DEFAULT 0,
	  latency_p95_ms INTEGER NOT NULL,
	  PRIMARY KEY (route_id, ts)
	);
	CREATE INDEX idx_bucket_1h_ts ON bucket_1h (ts);
	CREATE TABLE waf_event (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  ts INTEGER NOT NULL, route_id TEXT NOT NULL, rule_id TEXT NOT NULL,
	  category TEXT NOT NULL, severity INTEGER NOT NULL, src_ip TEXT NOT NULL,
	  request_method TEXT NOT NULL, request_path TEXT NOT NULL, payload_sample TEXT NOT NULL
	);
	CREATE INDEX idx_waf_event_ts          ON waf_event (ts);
	CREATE INDEX idx_waf_event_route_ts    ON waf_event (route_id, ts);
	CREATE INDEX idx_waf_event_category_ts ON waf_event (category, ts);
	CREATE TABLE throttle_event (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  ts INTEGER NOT NULL, tier INTEGER NOT NULL, src_ip TEXT NOT NULL,
	  attempted_username TEXT NOT NULL, blocked_until INTEGER NOT NULL,
	  block_duration_seconds INTEGER NOT NULL
	);
	CREATE INDEX idx_throttle_event_ts       ON throttle_event (ts);
	CREATE INDEX idx_throttle_event_srcip_ts ON throttle_event (src_ip, ts);
	CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
	INSERT INTO schema_version (version) VALUES (3);
	`
	if _, err := db.Exec(v3Schema); err != nil {
		t.Fatalf("openV3OnDisk seed: %v", err)
	}
	// Seed one bucket row + one waf_event + one throttle_event
	// so the v3→v4 migration's "preserve old data" guarantee
	// can be asserted post-upgrade.
	if _, err := db.Exec(`INSERT INTO bucket_1m (route_id, ts, req_count, fourxx_count, fivexx_count, waf_block_count, throttle_block_count, latency_p95_ms)
	                      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"r-pre-n", int64(1700000000), int64(50), int64(2), int64(0), int64(7), int64(3), int32(15)); err != nil {
		t.Fatalf("seed bucket_1m: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO waf_event (ts, route_id, rule_id, category, severity, src_ip, request_method, request_path, payload_sample)
	                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		int64(1700000000), "r-pre-n", "942100", "SQLI", 5, "1.2.3.4", "GET", "/", ""); err != nil {
		t.Fatalf("seed waf_event: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO throttle_event (ts, tier, src_ip, attempted_username, blocked_until, block_duration_seconds)
	                      VALUES (?, ?, ?, ?, ?, ?)`,
		int64(1700000000), 1, "5.6.7.8", "admin", int64(1700000900), 900); err != nil {
		t.Fatalf("seed throttle_event: %v", err)
	}
}

func TestMigrate_V3ToV4_PreservesExistingData(t *testing.T) {
	// Spec N AC #6 (mirror of Q's): opening a pre-Step-N
	// metrics.db (schema v3) must add crowdsec_decision_count
	// columns + decision_event table + 3 indexes WITHOUT
	// touching existing bucket / waf_event / throttle_event
	// rows.
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v3-metrics.db")

	openV3OnDisk(t, dbPath)

	s, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open v3 DB: %v", err)
	}
	defer s.Close()

	v, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if v != currentSchemaVersion {
		t.Fatalf("after v3→v4 migrate version = %d, want %d", v, currentSchemaVersion)
	}

	// Bucket row preserved + crowdsec_decision_count defaulted to 0.
	row := s.db.QueryRowContext(ctx, `SELECT req_count, waf_block_count, throttle_block_count, crowdsec_decision_count FROM bucket_1m WHERE route_id = 'r-pre-n'`)
	var req, waf, throttle, crowdsec int64
	if err := row.Scan(&req, &waf, &throttle, &crowdsec); err != nil {
		t.Fatalf("scan pre-N bucket row: %v", err)
	}
	if req != 50 || waf != 7 || throttle != 3 {
		t.Fatalf("v3 bucket data corrupted: req=%d waf=%d throttle=%d (want 50 / 7 / 3)", req, waf, throttle)
	}
	if crowdsec != 0 {
		t.Fatalf("pre-existing bucket row should have crowdsec_decision_count=0, got %d", crowdsec)
	}

	// waf_event + throttle_event rows preserved.
	var ruleID, srcIP string
	if err := s.db.QueryRowContext(ctx, `SELECT rule_id FROM waf_event WHERE route_id = 'r-pre-n'`).Scan(&ruleID); err != nil {
		t.Fatalf("scan pre-N waf_event row: %v", err)
	}
	if ruleID != "942100" {
		t.Fatalf("v3 waf_event data corrupted: rule_id=%s want 942100", ruleID)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT src_ip FROM throttle_event WHERE tier = 1`).Scan(&srcIP); err != nil {
		t.Fatalf("scan pre-N throttle_event row: %v", err)
	}
	if srcIP != "5.6.7.8" {
		t.Fatalf("v3 throttle_event data corrupted: src_ip=%s want 5.6.7.8", srcIP)
	}

	// decision_event table + 3 indexes present.
	var name string
	if err := s.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name='decision_event'`).Scan(&name); err != nil {
		t.Fatalf("decision_event table missing after v3→v4 migrate: %v", err)
	}
	for _, idx := range []string{"idx_decision_event_ts", "idx_decision_event_value_ts", "idx_decision_event_scenario_ts"} {
		if err := s.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&name); err != nil {
			t.Fatalf("%s missing after v3→v4 migrate: %v", idx, err)
		}
	}
}
