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
// schema:
//   - v1: Step L bootstrap (bucket_1m + bucket_1h).
//   - v2: Step M (waf_block_count column on both bucket
//     tables + waf_event table + indexes).
//   - v3: Step Q (throttle_block_count column on both bucket
//     tables + throttle_event table + indexes).
//   - v4: Step N (crowdsec_decision_count column on both
//     bucket tables + decision_event table + indexes).
//   - v5: Step U.1 (cert_event table + indexes).
//   - v6: Step V.2 (auth_event table + indexes). 30 d
//     retention per spec §3.6 (short-window security
//     signal, not lifecycle record).
//   - v7: Step W.bugfix Fix #1 (action + status_code
//     columns on waf_event so the sink can distinguish
//     block-mode from detect-mode events).
//   - v8: Step W.4 (country_block_event table + indexes).
//   - v9: #R-DASHBOARD-WAF-COUNTERS-ZERO (waf_detect_count
//     column on both bucket tables so detect-mode events
//     surface in the dashboard counters as a sibling to
//     waf_block_count).
//
// Downgrade is not supported.
const currentSchemaVersion = 9

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
	2: migrateV2toV3,
	3: migrateV3toV4,
	4: migrateV4toV5,
	5: migrateV5toV6,
	6: migrateV6toV7,
	7: migrateV7toV8,
	8: migrateV8toV9,
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

// migrateV2toV3 — Step Q. Adds the throttle_block_count column on
// both bucket tables (default 0 so existing rows get a
// sensible value) AND creates the throttle_event table with
// its two indexes (ts for time-range scans, src_ip+ts for
// per-IP drill-down filters). Unlike waf_event, there is no
// category dimension to index — tier is a small enum (1 or 2)
// and SQLite will scan it cheaply.
//
// SQLite's ALTER TABLE ADD COLUMN is a metadata-only
// operation in modern versions — it does NOT rewrite the
// table, so the migration is O(1) regardless of row count.
func migrateV2toV3(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`ALTER TABLE bucket_1m ADD COLUMN throttle_block_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE bucket_1h ADD COLUMN throttle_block_count INTEGER NOT NULL DEFAULT 0`,
		`CREATE TABLE IF NOT EXISTS throttle_event (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  ts INTEGER NOT NULL,
		  tier INTEGER NOT NULL,
		  src_ip TEXT NOT NULL,
		  attempted_username TEXT NOT NULL,
		  blocked_until INTEGER NOT NULL,
		  block_duration_seconds INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_throttle_event_ts       ON throttle_event (ts)`,
		`CREATE INDEX IF NOT EXISTS idx_throttle_event_srcip_ts ON throttle_event (src_ip, ts)`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV3toV4 — Step N. Adds the crowdsec_decision_count
// column on both bucket tables AND creates the decision_event
// table with three indexes (ts for time-range scans,
// value+ts for per-IP-or-CIDR drill-down, scenario+ts for
// per-scenario aggregation).
//
// `uuid` is declared UNIQUE so duplicate-poll insertion
// surfaces as a constraint violation that the Sink's
// dedupe-before-bump path normally prevents — defence-in-
// depth against a future stream-consumer bug.
// `value` is the bouncer-observed IP / CIDR / country / AS
// (the LAPI decision's `Value` field interpreted per `Scope`).
//
// SQLite's ALTER TABLE ADD COLUMN is a metadata-only
// operation; the migration is O(1) regardless of row count.
func migrateV3toV4(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`ALTER TABLE bucket_1m ADD COLUMN crowdsec_decision_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE bucket_1h ADD COLUMN crowdsec_decision_count INTEGER NOT NULL DEFAULT 0`,
		`CREATE TABLE IF NOT EXISTS decision_event (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  uuid TEXT NOT NULL UNIQUE,
		  ts INTEGER NOT NULL,
		  scope TEXT NOT NULL,
		  value TEXT NOT NULL,
		  type TEXT NOT NULL,
		  scenario TEXT NOT NULL,
		  expires_at INTEGER NOT NULL,
		  duration_seconds INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_decision_event_ts          ON decision_event (ts)`,
		`CREATE INDEX IF NOT EXISTS idx_decision_event_value_ts    ON decision_event (value, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_decision_event_scenario_ts ON decision_event (scenario, ts)`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV4toV5 — Step U.1. Creates the cert_event table
// with the three indexes that match the read patterns the
// Activity log handler needs (ts for the time-ordered list,
// domain+ts for per-domain history drill-down, event_type+ts
// for filtered queries like "show me all failures").
//
// Unlike v2/v3/v4 there is no bucket-table column to add: cert
// events don't aggregate into per-minute counters (volume is
// too low; a single domain produces a handful of rows per day,
// per the §3.2 retention rationale). The schema is purely the
// per-event table.
//
// Columns chosen to match the wire shape from spec §5.2
// (camelCase JSON tags map to snake_case columns). `ts` is
// seconds-since-epoch consistent with waf_event /
// throttle_event / decision_event; the brief's "ts_unix_ns"
// proposal was a transcription drift — uniformity with the
// existing tables wins so an operator querying metrics.db
// reads the same unit everywhere.
//
// SQLite's CREATE TABLE IF NOT EXISTS makes the migration
// idempotent under partial-failure replay (a v4→v5 that died
// after the CREATE but before the schema_version bump
// re-applies cleanly on next boot).
func migrateV4toV5(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS cert_event (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  ts INTEGER NOT NULL,
		  level TEXT NOT NULL,
		  event_type TEXT NOT NULL,
		  domain TEXT NOT NULL,
		  issuer TEXT NOT NULL DEFAULT '',
		  challenge TEXT NOT NULL DEFAULT '',
		  renewal INTEGER NOT NULL DEFAULT 0,
		  error_msg TEXT NOT NULL DEFAULT '',
		  details TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_cert_event_ts            ON cert_event (ts)`,
		`CREATE INDEX IF NOT EXISTS idx_cert_event_domain_ts     ON cert_event (domain, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_cert_event_event_type_ts ON cert_event (event_type, ts)`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV5toV6 — Step V.2. Creates the auth_event table with
// the three indexes that match the read patterns spec §3.6
// anticipates: ts for the time-ordered list, src_ip+ts for
// per-IP drill-down (the geo map and the future per-IP
// timeline), kind+ts for filtered queries like "show me all
// session_expired events".
//
// Column shape locked at spec §3.6: kind (NOT "reason"),
// src_ip (NOT "source_ip"), username (NOT "user"). These names
// match the audit-bucket vocabulary so an operator joining
// auth_event with audit.Event on src_ip / username sees the
// same identifier on both sides.
//
// Indexes mirror cert_event's shape (Step U.1) so this table
// reads identically to its siblings — same ts-desc walks, same
// per-value drill-down strategy.
//
// SQLite's CREATE TABLE IF NOT EXISTS makes the migration
// idempotent under partial-failure replay.
func migrateV5toV6(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS auth_event (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  ts INTEGER NOT NULL,
		  kind TEXT NOT NULL,
		  src_ip TEXT NOT NULL,
		  username TEXT NOT NULL DEFAULT '',
		  path TEXT NOT NULL DEFAULT '',
		  details TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_event_ts        ON auth_event (ts)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_event_src_ip_ts ON auth_event (src_ip, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_event_kind_ts   ON auth_event (kind, ts)`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV6toV7 — Step W.bugfix Fix #1. Adds the action +
// status_code columns to waf_event so the sink can record
// whether a matched rule actually blocked the request
// (ActionBlock + 403) or merely detected it (ActionDetect +
// 0). Pre-migration rows are backfilled to ("BLOCK", 403)
// because every WAF event row in the legacy schema was
// emitted by a block-mode handler — the frontend's
// hardcoded "BLOCK 403" label was correct for legacy rows
// but lied for detect-mode rows that started being emitted
// once detect-mode existed (the regression that originally
// produced operator confusion). Backfilling to BLOCK keeps
// the historical attribution honest: those rows really did
// correspond to blocked requests.
//
// SQLite's ALTER TABLE ADD COLUMN is a metadata-only
// operation in modern versions — O(1) regardless of row
// count.
func migrateV6toV7(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`ALTER TABLE waf_event ADD COLUMN action TEXT NOT NULL DEFAULT 'BLOCK'`,
		`ALTER TABLE waf_event ADD COLUMN status_code INTEGER NOT NULL DEFAULT 403`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV7toV8 — Step W.4. Creates the country_block_event
// table + its two indexes (ts for time-range scans, route_id
// + ts for per-route drill-down). Mirrors the v5→v6
// (auth_event) + v6→v7 (waf_event extension) shape.
//
// Pre-W rows are absent (the table doesn't exist), so no
// backfill is needed — a v7 → v8 upgrade just adds the table.
// SQLite's CREATE TABLE IF NOT EXISTS makes the migration
// idempotent under partial-failure replay.
//
// Column rationale:
//   - ts (INTEGER): seconds-since-epoch, indexed for time-range
//     scans + retention prune. Matches the existing waf /
//     auth / throttle schemas.
//   - route_id, src_ip, country, mode, status_code, reason:
//     verbatim from countryblock.BlockMatch. country is
//     NULL-tolerable for the §D5 fail-open path that doesn't
//     currently emit but is reserved by the W.1 contract.
//   - mode: "allow" / "deny" — the route's enforcement mode
//     at decision time. Persisted so the W.5 activity log
//     can filter without a routes-table join.
//   - reason: W.1's matcher kebab-case enum ("allow-miss",
//     "deny-match", etc.). Frontend keys off this for
//     tooltip wording without parsing free text.
func migrateV7toV8(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS country_block_event (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  ts INTEGER NOT NULL,
		  route_id TEXT NOT NULL,
		  src_ip TEXT NOT NULL,
		  country TEXT NOT NULL DEFAULT '',
		  mode TEXT NOT NULL,
		  status_code INTEGER NOT NULL,
		  reason TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_country_block_event_ts       ON country_block_event (ts)`,
		`CREATE INDEX IF NOT EXISTS idx_country_block_event_route_ts ON country_block_event (route_id, ts)`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV8toV9 — #R-DASHBOARD-WAF-COUNTERS-ZERO. Adds the
// waf_detect_count column to both bucket_1m and bucket_1h
// so detect-mode WAF events surface in the dashboard
// counters as a sibling to the existing waf_block_count
// (block-mode events only). Default 0 on pre-fix rows: the
// column didn't exist when those buckets were written, so
// "no data" is the operator-honest answer rather than
// fabricating a value.
//
// SQLite's ALTER TABLE ADD COLUMN is a metadata-only
// operation in modern versions — O(1) regardless of row
// count, so this migration runs in constant time on the
// production AreNET-test database (~287 WAF events / 8
// days of trafic).
//
// Companion: the waf.Sink switch (sink.go absorb) is
// extended to BumpWafDetects on ActionDetect events,
// symmetric to the existing BumpWafBlocks on ActionBlock.
// Bumps happen BEFORE LRU dedup so the counter reflects
// attack volume (AC #3), not the deduplicated event-log
// count.
func migrateV8toV9(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`ALTER TABLE bucket_1m ADD COLUMN waf_detect_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE bucket_1h ADD COLUMN waf_detect_count INTEGER NOT NULL DEFAULT 0`,
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
