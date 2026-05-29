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

func TestMigrate_V1ToV2_PreservesExistingData(t *testing.T) {
	// Spec AC #6: opening a pre-Step-M metrics.db (schema v1)
	// must add the v2 columns + tables AND keep the existing
	// rows intact. The migration runs in a single transaction
	// so partial failure cannot land at v1.5.
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v1-metrics.db")

	openV1OnDisk(t, dbPath)

	// Now open via the production code path — the migrate
	// chain should bump the file from v1 to v2.
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
	// through the v2 Query path (proving the new column was
	// added with a sensible default for old rows).
	row := s.db.QueryRowContext(ctx, `SELECT req_count, fourxx_count, fivexx_count, waf_block_count, latency_p95_ms FROM bucket_1m WHERE route_id = 'r-pre-m'`)
	var req, fourxx, fivexx, waf int64
	var p95 int32
	if err := row.Scan(&req, &fourxx, &fivexx, &waf, &p95); err != nil {
		t.Fatalf("scan pre-migrate row: %v", err)
	}
	if req != 42 || fourxx != 3 || fivexx != 1 || p95 != 16 {
		t.Fatalf("old data corrupted by migration: req=%d fourxx=%d fivexx=%d p95=%d", req, fourxx, fivexx, p95)
	}
	if waf != 0 {
		t.Fatalf("pre-existing row should have waf_block_count=0 (default for migrated rows), got %d", waf)
	}

	// The new waf_event table + indexes must be present.
	var name string
	if err := s.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name='waf_event'`).Scan(&name); err != nil {
		t.Fatalf("waf_event table missing after migrate: %v", err)
	}
}

func TestMigrate_RerunOnV2_IsNoOp(t *testing.T) {
	// Idempotency: re-opening an already-current DB does
	// nothing (no transaction even started). Verified
	// indirectly by Open succeeding and the version
	// remaining unchanged.
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v2-metrics.db")

	// Fresh open → lands at v2.
	s1, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	_ = s1.Close()

	// Second open → must succeed and stay at v2.
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
