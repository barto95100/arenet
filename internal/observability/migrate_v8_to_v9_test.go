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
	"time"
)

// #R-DASHBOARD-WAF-COUNTERS-ZERO — v8→v9 migration tests.
// The migration adds the waf_detect_count column to both
// bucket_1m and bucket_1h (ALTER TABLE ADD COLUMN, default
// 0). Pre-fix rows MUST decode to WafDetectCount=0 (the
// operator-honest "no data" answer — the column didn't
// exist when those buckets were written).

// TestMigrate_V8ToV9_AddsWafDetectCountColumn confirms a
// freshly-opened DB (which migrates straight to v9) has
// the waf_detect_count column on both bucket tables, with
// the correct NOT NULL + DEFAULT 0 contract.
func TestMigrate_V8ToV9_AddsWafDetectCountColumn(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	v, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if v != currentSchemaVersion {
		t.Fatalf("schema version = %d; want %d", v, currentSchemaVersion)
	}

	// PRAGMA table_info gives one row per column with the
	// (cid, name, type, notnull, default, pk) tuple. We use
	// it on both bucket tables to assert the new column is
	// present with the right shape.
	for _, table := range []string{"bucket_1m", "bucket_1h"} {
		t.Run(table, func(t *testing.T) {
			rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
			if err != nil {
				t.Fatalf("pragma table_info(%s): %v", table, err)
			}
			defer rows.Close()
			found := false
			for rows.Next() {
				var cid int
				var name, ctype string
				var notnull int
				var dflt sql.NullString
				var pk int
				if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
					t.Fatalf("scan pragma row: %v", err)
				}
				if name == "waf_detect_count" {
					found = true
					if notnull != 1 {
						t.Errorf("%s.waf_detect_count notnull = %d; want 1", table, notnull)
					}
					if !dflt.Valid || dflt.String != "0" {
						t.Errorf("%s.waf_detect_count default = %v; want \"0\"", table, dflt)
					}
				}
			}
			if !found {
				t.Errorf("%s missing waf_detect_count column after migrate", table)
			}
		})
	}
}

// TestMigrate_V8ToV9_PreservesLegacyBucketRows seeds a v8
// DB on disk (with the country_block_event table but
// WITHOUT waf_detect_count on the bucket tables), inserts a
// bucket row, runs the migration via Open(), and verifies:
//   - the seeded row survives untouched (the W.bugfix
//     numerics round-trip);
//   - the new waf_detect_count field reads back as 0 (the
//     default the ADD COLUMN sets on pre-fix rows).
//
// Same shape as TestMigrate_V6ToV7_BackfillsLegacyWafEvent
// Rows (the Fix #1 mirror) and TestMigrate_V7ToV8_Adds
// CountryBlockTable.
func TestMigrate_V8ToV9_PreservesLegacyBucketRows(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v8-metrics.db")

	openV8OnDisk(t, dbPath)

	s, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open v8 DB: %v", err)
	}
	defer s.Close()

	v, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if v != currentSchemaVersion {
		t.Fatalf("after v8→v9 migrate version = %d, want %d", v, currentSchemaVersion)
	}

	// Read the seeded row back through the production Query
	// path (the wire-shape consumer, not a raw SQL stub).
	from := time.Unix(1700000000, 0).UTC()
	to := from.Add(time.Minute)
	rows, err := s.Query(ctx, Granularity1m, "r-pre-v9", from, to)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("seeded row count = %d; want 1 (migration must preserve)", len(rows))
	}
	got := rows[0]
	// Original numerics round-trip (regression check).
	if got.ReqCount != 50 || got.WafBlockCount != 7 {
		t.Errorf("legacy numerics drifted: %+v", got)
	}
	// New column reads back as 0 (the operator-honest "no
	// data" answer for pre-fix buckets).
	if got.WafDetectCount != 0 {
		t.Errorf("WafDetectCount = %d on pre-fix row; want 0 (ALTER TABLE default)", got.WafDetectCount)
	}
}

// openV8OnDisk seeds a v8 schema file (bucket_1m / bucket
// _1h WITH waf_block_count + action/status_code columns
// on waf_event but WITHOUT waf_detect_count on bucket
// tables). Mirrors the openV3OnDisk / openV6OnDisk
// helpers in this package's older migration tests.
func openV8OnDisk(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("openV8OnDisk open: %v", err)
	}
	defer db.Close()
	const v8Schema = `
	CREATE TABLE bucket_1m (
	  route_id TEXT NOT NULL,
	  ts INTEGER NOT NULL,
	  req_count INTEGER NOT NULL,
	  fourxx_count INTEGER NOT NULL,
	  fivexx_count INTEGER NOT NULL,
	  waf_block_count INTEGER NOT NULL DEFAULT 0,
	  throttle_block_count INTEGER NOT NULL DEFAULT 0,
	  crowdsec_decision_count INTEGER NOT NULL DEFAULT 0,
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
	  crowdsec_decision_count INTEGER NOT NULL DEFAULT 0,
	  latency_p95_ms INTEGER NOT NULL,
	  PRIMARY KEY (route_id, ts)
	);
	CREATE INDEX idx_bucket_1h_ts ON bucket_1h (ts);
	CREATE TABLE waf_event (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  ts INTEGER NOT NULL, route_id TEXT NOT NULL, rule_id TEXT NOT NULL,
	  category TEXT NOT NULL, severity INTEGER NOT NULL, src_ip TEXT NOT NULL,
	  request_method TEXT NOT NULL, request_path TEXT NOT NULL, payload_sample TEXT NOT NULL,
	  action TEXT NOT NULL DEFAULT 'BLOCK', status_code INTEGER NOT NULL DEFAULT 403
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
	CREATE TABLE decision_event (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  ts INTEGER NOT NULL, uuid TEXT NOT NULL,
	  scope TEXT NOT NULL, value TEXT NOT NULL,
	  type TEXT NOT NULL, scenario TEXT NOT NULL,
	  duration TEXT NOT NULL
	);
	CREATE INDEX idx_decision_event_ts          ON decision_event (ts);
	CREATE INDEX idx_decision_event_uuid        ON decision_event (uuid);
	CREATE TABLE cert_event (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  ts INTEGER NOT NULL, level TEXT NOT NULL,
	  cert_subject TEXT NOT NULL, message TEXT NOT NULL
	);
	CREATE INDEX idx_cert_event_ts ON cert_event (ts);
	CREATE TABLE auth_event (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  ts INTEGER NOT NULL, action TEXT NOT NULL,
	  username TEXT NOT NULL, src_ip TEXT NOT NULL,
	  success INTEGER NOT NULL, message TEXT NOT NULL
	);
	CREATE INDEX idx_auth_event_ts ON auth_event (ts);
	CREATE TABLE country_block_event (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  ts INTEGER NOT NULL,
	  route_id TEXT NOT NULL,
	  src_ip TEXT NOT NULL,
	  country TEXT NOT NULL DEFAULT '',
	  mode TEXT NOT NULL,
	  status_code INTEGER NOT NULL,
	  reason TEXT NOT NULL
	);
	CREATE INDEX idx_country_block_event_ts       ON country_block_event (ts);
	CREATE INDEX idx_country_block_event_route_ts ON country_block_event (route_id, ts);
	CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
	INSERT INTO schema_version (version) VALUES (8);
	`
	if _, err := db.Exec(v8Schema); err != nil {
		t.Fatalf("openV8OnDisk seed: %v", err)
	}
	// Seed one bucket_1m row so the migration's "preserve
	// existing data" guarantee can be asserted post-upgrade.
	// req_count + waf_block_count populated; the new
	// waf_detect_count must read back as 0 (the ADD COLUMN
	// default).
	if _, err := db.Exec(
		`INSERT INTO bucket_1m (route_id, ts, req_count, fourxx_count, fivexx_count, waf_block_count, throttle_block_count, crowdsec_decision_count, latency_p95_ms)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"r-pre-v9", int64(1700000000), int64(50), int64(2), int64(0), int64(7), int64(3), int64(0), int32(15)); err != nil {
		t.Fatalf("seed bucket_1m: %v", err)
	}
}
