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
	"fmt"
)

// currentSchemaVersion is the latest schema version this
// build of Arenet writes. Bumped per Step that touches the
// schema. Step L shipped at v1; Step M bumps to v2 (adds the
// waf_block_count column on both bucket tables + creates the
// waf_event table). Downgrade is not supported.
const currentSchemaVersion = 2

// migrate brings db from currentVersion to currentSchemaVersion
// by replaying every intervening migration step in a single
// transaction (so a partial failure leaves the DB at the
// previous version, never half-applied).
//
// Idempotent: when currentVersion equals currentSchemaVersion,
// migrate returns nil without touching the DB. Called from
// Open() after the bootstrap schemaSQL has run.
//
// This is the first real exercise of the L spec §6 migrate-
// chain. Future bumps add their step here; the chain pattern
// keeps each step focused on one delta.
func migrate(ctx context.Context, db *sql.DB, currentVersion int) error {
	if currentVersion == currentSchemaVersion {
		return nil
	}
	if currentVersion < 0 || currentVersion > currentSchemaVersion {
		return fmt.Errorf("observability: unsupported schema version %d (this build knows up to %d)", currentVersion, currentSchemaVersion)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("observability: begin migrate tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	for v := currentVersion; v < currentSchemaVersion; v++ {
		step := migrateSteps[v]
		if step == nil {
			return fmt.Errorf("observability: missing migrate step for v%d→v%d", v, v+1)
		}
		if err := step(ctx, tx); err != nil {
			return fmt.Errorf("observability: migrate v%d→v%d: %w", v, v+1, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE schema_version SET version = ?`, currentSchemaVersion); err != nil {
		return fmt.Errorf("observability: bump schema_version to %d: %w", currentSchemaVersion, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("observability: commit migrate: %w", err)
	}
	return nil
}

// migrateSteps maps a starting version V to the function that
// brings the DB from V to V+1. Each function operates inside
// the caller's transaction.
//
// Convention: index N is the v(N)→v(N+1) step. Index 0
// (v0→v1) is intentionally nil because v1 is the bootstrap
// shape produced by schemaSQL — a fresh DB never starts at
// v0. The first real step is index 1 (v1→v2) for Step M.
var migrateSteps = map[int]func(context.Context, *sql.Tx) error{
	1: migrateV1toV2,
}

// migrateV1toV2 — Step M. Adds the waf_block_count column on
// both bucket tables (default 0 so existing rows get a
// sensible value) AND creates the waf_event table with its
// three indexes (ts for time-range scans, route_id+ts for
// drill-down filters, category+ts for the summary
// breakdown).
//
// SQLite's ALTER TABLE ADD COLUMN is a metadata-only
// operation in modern versions — it does NOT rewrite the
// table, so the migration is O(1) regardless of row count.
func migrateV1toV2(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`ALTER TABLE bucket_1m ADD COLUMN waf_block_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE bucket_1h ADD COLUMN waf_block_count INTEGER NOT NULL DEFAULT 0`,
		`CREATE TABLE IF NOT EXISTS waf_event (
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
		)`,
		`CREATE INDEX IF NOT EXISTS idx_waf_event_ts          ON waf_event (ts)`,
		`CREATE INDEX IF NOT EXISTS idx_waf_event_route_ts    ON waf_event (route_id, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_waf_event_category_ts ON waf_event (category, ts)`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// firstLine returns the first non-empty line of s, trimmed.
// Used to keep migration error messages compact (the full
// DDL is verbose; the first line is the operator's cue).
func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
