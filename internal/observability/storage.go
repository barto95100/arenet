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

// Package observability implements Step L's per-route metrics
// history: in-memory bucket aggregator + SQLite persistence +
// retention rollup. See docs/superpowers/specs/2026-05-28-step-l-observability.md.
package observability

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// schemaSQL is the schema applied at every Open. All statements
// are idempotent via IF NOT EXISTS / INSERT OR IGNORE, so calling
// Open on an existing DB file is a no-op (AC #11).
const schemaSQL = `
CREATE TABLE IF NOT EXISTS bucket_1m (
  route_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  req_count INTEGER NOT NULL,
  fourxx_count INTEGER NOT NULL,
  fivexx_count INTEGER NOT NULL,
  latency_p95_ms INTEGER NOT NULL,
  PRIMARY KEY (route_id, ts)
);
CREATE INDEX IF NOT EXISTS idx_bucket_1m_ts ON bucket_1m (ts);

CREATE TABLE IF NOT EXISTS bucket_1h (
  route_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  req_count INTEGER NOT NULL,
  fourxx_count INTEGER NOT NULL,
  fivexx_count INTEGER NOT NULL,
  latency_p95_ms INTEGER NOT NULL,
  PRIMARY KEY (route_id, ts)
);
CREATE INDEX IF NOT EXISTS idx_bucket_1h_ts ON bucket_1h (ts);

CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER PRIMARY KEY
);
INSERT OR IGNORE INTO schema_version (version) VALUES (1);
`

// Store owns the SQLite handle for the metrics database. Safe
// for concurrent use — the underlying *sql.DB has its own pool.
type Store struct {
	db   *sql.DB
	path string
}

// Open initialises the metrics DB at the given file path and
// applies the schema. Returns an error so the caller in main.go
// can implement the AC #13 degraded-mode policy (log + continue
// without metrics rather than abort the data plane).
//
// path may be ":memory:" for in-process tests.
func Open(ctx context.Context, path string) (*Store, error) {
	// _busy_timeout makes the driver wait on a locked write
	// instead of returning SQLITE_BUSY immediately — useful when
	// the aggregator flush and the retention loop touch the DB
	// concurrently. _journal=WAL gives us readers that don't
	// block writers, important for the future read API (L.2).
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("observability: sql.Open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("observability: ping: %w", err)
	}
	// Single writer is what SQLite guarantees in WAL mode anyway;
	// pin the pool to 1 writer to avoid spurious "database is
	// locked" under concurrent INSERTs from aggregator + retention.
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("observability: schema init: %w", err)
	}
	// Step M.1: run the migrate chain. Reads the current
	// schema_version (bootstrap leaves it at 1 on a fresh DB)
	// and applies every step up to currentSchemaVersion in a
	// single transaction. Idempotent on an already-current DB.
	var current int
	row := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_version`)
	if err := row.Scan(&current); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("observability: read current schema_version: %w", err)
	}
	if err := migrate(ctx, db, current); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("observability: migrate: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

// Close releases the underlying handle. Safe to call on a nil
// store (no-op) so the main.go degraded-mode path can defer it
// unconditionally.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Path returns the on-disk path the store was opened with.
// Returns ":memory:" for in-process test stores.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// SchemaVersion returns the current schema version stored in the
// schema_version table. Always 1 in Step L; future bumps wire
// through a migrate chain. Returns 0 on a fresh / unreadable DB.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	var v int
	row := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_version`)
	if err := row.Scan(&v); err != nil {
		return 0, fmt.Errorf("observability: schema version: %w", err)
	}
	return v, nil
}

// InsertBatch writes a slice of MetricBucket rows into the table
// selected by gran, inside a single transaction. Rows that
// already exist on (route_id, ts) are overwritten — this gives
// the aggregator a safe re-flush semantic if a previous flush
// partially failed.
//
// Empty batch is a no-op (returns nil). The whole batch is
// rolled back on first error so a failed flush leaves the DB
// untouched. AC #13: the aggregator caller logs the error and
// continues; it never propagates to the request path.
func (s *Store) InsertBatch(ctx context.Context, gran Granularity, rows []MetricBucket) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("observability: store closed")
	}
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("observability: begin tx: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO `+gran.tableName()+` (route_id, ts, req_count, fourxx_count, fivexx_count, waf_block_count, latency_p95_ms)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(route_id, ts) DO UPDATE SET
  req_count       = excluded.req_count,
  fourxx_count    = excluded.fourxx_count,
  fivexx_count    = excluded.fivexx_count,
  waf_block_count = excluded.waf_block_count,
  latency_p95_ms  = excluded.latency_p95_ms
`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("observability: prepare insert: %w", err)
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.ExecContext(ctx,
			r.RouteID,
			r.Ts.UTC().Unix(),
			r.ReqCount,
			r.FourxxCount,
			r.FivexxCount,
			r.WafBlockCount,
			r.LatencyP95Ms,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("observability: insert row (route=%s ts=%s): %w", r.RouteID, r.Ts, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("observability: commit: %w", err)
	}
	return nil
}

// Query returns every MetricBucket for routeID with timestamps
// in [from, to), in timestamp-ascending order. Missing buckets
// are NOT gap-filled here — the API layer at L.2 applies the
// AC #5 projection rule (0 for counts, null for p95) when
// shaping the JSON response.
//
// Returning the dense slice from the API layer would force a
// 1440-element walk per timeseries request; returning the
// sparse rows here keeps the storage layer cheap and lets the
// caller decide the gap-fill policy.
func (s *Store) Query(ctx context.Context, gran Granularity, routeID string, from, to time.Time) ([]MetricBucket, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT route_id, ts, req_count, fourxx_count, fivexx_count, waf_block_count, latency_p95_ms
FROM `+gran.tableName()+`
WHERE route_id = ? AND ts >= ? AND ts < ?
ORDER BY ts ASC
`, routeID, from.UTC().Unix(), to.UTC().Unix())
	if err != nil {
		return nil, fmt.Errorf("observability: query: %w", err)
	}
	defer rows.Close()
	var out []MetricBucket
	for rows.Next() {
		var b MetricBucket
		var tsUnix int64
		if err := rows.Scan(&b.RouteID, &tsUnix, &b.ReqCount, &b.FourxxCount, &b.FivexxCount, &b.WafBlockCount, &b.LatencyP95Ms); err != nil {
			return nil, fmt.Errorf("observability: scan: %w", err)
		}
		b.Ts = time.Unix(tsUnix, 0).UTC()
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: query iterate: %w", err)
	}
	return out, nil
}

// QueryAggregated returns one MetricBucket per `ts` aggregated
// across ALL routes, for the table selected by gran. Per
// Spec-1 §10.1 (added during L.3):
//
//   - req_count, fourxx_count, fivexx_count: SUM across routes
//     within each bucket. AC #3 holds: each counter is summed
//     independently — they NEVER collapse into a single
//     "errors" number.
//   - latency_p95_ms: req-weighted percentile-of-percentiles
//     across the routes that landed rows in the bucket. Same
//     approximation as the hourly rollup (AC #2 acknowledged).
//     Returned as 0 when the bucket has no traffic; the API
//     layer maps that to JSON null per AC #5.
//
// The returned RouteID is the empty string ("") on every row —
// these buckets are system-wide, not tied to a specific route.
// The API layer rewrites it to "all" for the wire response.
func (s *Store) QueryAggregated(ctx context.Context, gran Granularity, from, to time.Time) ([]MetricBucket, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	// Integer arithmetic in SQLite: the weighted-p95
	// numerator is Σ(latency_p95_ms × req_count) and the
	// denominator is Σ(req_count) when req_count > 0. Without
	// the CASE guard, a bucket with no traffic but a phantom
	// LatencyP95Ms > 0 would skew the average; the guard
	// keeps the math honest.
	rows, err := s.db.QueryContext(ctx, `
SELECT
  ts,
  SUM(req_count)        AS req_total,
  SUM(fourxx_count)     AS fourxx_total,
  SUM(fivexx_count)     AS fivexx_total,
  SUM(waf_block_count)  AS waf_total,
  CASE
    WHEN SUM(CASE WHEN req_count > 0 THEN req_count ELSE 0 END) > 0
    THEN SUM(latency_p95_ms * CASE WHEN req_count > 0 THEN req_count ELSE 0 END) / SUM(CASE WHEN req_count > 0 THEN req_count ELSE 0 END)
    ELSE 0
  END AS p95_weighted
FROM `+gran.tableName()+`
WHERE ts >= ? AND ts < ?
GROUP BY ts
ORDER BY ts ASC
`, from.UTC().Unix(), to.UTC().Unix())
	if err != nil {
		return nil, fmt.Errorf("observability: query aggregated: %w", err)
	}
	defer rows.Close()
	var out []MetricBucket
	for rows.Next() {
		var b MetricBucket
		var tsUnix int64
		var p95 int64 // SQLite SUM/CASE returns INTEGER; scan as int64 then narrow
		if err := rows.Scan(&tsUnix, &b.ReqCount, &b.FourxxCount, &b.FivexxCount, &b.WafBlockCount, &p95); err != nil {
			return nil, fmt.Errorf("observability: scan aggregated: %w", err)
		}
		b.Ts = time.Unix(tsUnix, 0).UTC()
		b.LatencyP95Ms = int32(p95)
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: query aggregated iterate: %w", err)
	}
	return out, nil
}

// PruneOlderThan deletes rows from the table selected by gran
// where ts < cutoff. Returns the number of rows deleted. Called
// by the retention loop; safe to call concurrently with inserts
// (SQLite serialises writers).
func (s *Store) PruneOlderThan(ctx context.Context, gran Granularity, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("observability: store closed")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM `+gran.tableName()+` WHERE ts < ?`, cutoff.UTC().Unix())
	if err != nil {
		return 0, fmt.Errorf("observability: prune: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("observability: prune rows affected: %w", err)
	}
	return n, nil
}

// --- Step M: waf_event store ------------------------------------------------

// WafEvent is the observability-layer mirror of waf.Event
// (same fields). Defined here so observability does not have
// to import internal/waf (dependency direction stays clean:
// the wiring layer in cmd/arenet/main.go bridges the two via
// a small adapter). The fields are storage-flat: all data
// already capped + redacted by the time it reaches Insert.
//
// See docs/superpowers/specs/2026-05-28-step-m-security.md
// §3.1 for the field-level semantics.
type WafEvent struct {
	ID            int64
	Ts            time.Time
	RouteID       string
	RuleID        string
	Category      string // matches waf.OwaspCategory at the type level
	Severity      int
	SrcIP         string
	RequestMethod string
	RequestPath   string
	PayloadSample string
}

// WafEventFilter narrows a QueryWafEvents call. All fields
// are optional; the API layer at M.2 maps query-string
// parameters into this struct. Limit > 100 is clamped by the
// store as a defence-in-depth on top of the API-layer cap.
type WafEventFilter struct {
	RouteID  string
	Category string
	From     time.Time // inclusive
	To       time.Time // exclusive; zero = open-ended (now)
	Limit    int
}

// wafEventLimitCap bounds the result set defensively. The
// API layer caps at 100 before calling; this is the
// belt-and-braces for any future internal caller that forgets.
const wafEventLimitCap = 100

// InsertWafEventBatch persists a slice of WafEvent rows in a
// single transaction. Errors are returned to the caller —
// the production caller (waf.Sink) logs + counts + swallows
// per AC #13 (the sink wraps this call; the store stays
// honest about failures so test fakes can simulate them).
//
// Empty batch is a no-op.
func (s *Store) InsertWafEventBatch(ctx context.Context, events []WafEvent) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("observability: store closed")
	}
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("observability: begin waf_event tx: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO waf_event (ts, route_id, rule_id, category, severity, src_ip, request_method, request_path, payload_sample)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("observability: prepare waf_event insert: %w", err)
	}
	defer stmt.Close()
	for _, e := range events {
		if _, err := stmt.ExecContext(ctx,
			e.Ts.UTC().Unix(),
			e.RouteID,
			e.RuleID,
			e.Category,
			e.Severity,
			e.SrcIP,
			e.RequestMethod,
			e.RequestPath,
			e.PayloadSample,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("observability: insert waf_event (route=%s rule=%s): %w", e.RouteID, e.RuleID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("observability: commit waf_event: %w", err)
	}
	return nil
}

// QueryWafEvents returns the waf_event rows matching filter,
// ts-descending (most recent first — the /security/events
// endpoint's natural ordering). Empty filter returns the most
// recent `wafEventLimitCap` rows. Limit > cap is silently
// clamped down.
//
// The route_id / category filters short-circuit via the
// matching index when set; the from/to filters use the ts
// index. Pure read, safe to call concurrently with inserts.
func (s *Store) QueryWafEvents(ctx context.Context, filter WafEventFilter) ([]WafEvent, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	limit := filter.Limit
	if limit <= 0 || limit > wafEventLimitCap {
		limit = wafEventLimitCap
	}
	q := `SELECT id, ts, route_id, rule_id, category, severity, src_ip, request_method, request_path, payload_sample
	      FROM waf_event WHERE 1=1`
	args := []any{}
	if filter.RouteID != "" {
		q += ` AND route_id = ?`
		args = append(args, filter.RouteID)
	}
	if filter.Category != "" {
		q += ` AND category = ?`
		args = append(args, filter.Category)
	}
	if !filter.From.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, filter.From.UTC().Unix())
	}
	if !filter.To.IsZero() {
		q += ` AND ts < ?`
		args = append(args, filter.To.UTC().Unix())
	}
	q += ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: query waf_event: %w", err)
	}
	defer rows.Close()
	var out []WafEvent
	for rows.Next() {
		var e WafEvent
		var tsUnix int64
		if err := rows.Scan(
			&e.ID, &tsUnix, &e.RouteID, &e.RuleID, &e.Category, &e.Severity,
			&e.SrcIP, &e.RequestMethod, &e.RequestPath, &e.PayloadSample,
		); err != nil {
			return nil, fmt.Errorf("observability: scan waf_event: %w", err)
		}
		e.Ts = time.Unix(tsUnix, 0).UTC()
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate waf_event: %w", err)
	}
	return out, nil
}

// PruneWafEventsOlderThan deletes waf_event rows with ts <
// cutoff. Returns the number of rows deleted. Called by the
// retention loop on the same hourly cadence as the bucket
// prunes.
func (s *Store) PruneWafEventsOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("observability: store closed")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM waf_event WHERE ts < ?`, cutoff.UTC().Unix())
	if err != nil {
		return 0, fmt.Errorf("observability: prune waf_event: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("observability: prune waf_event rows affected: %w", err)
	}
	return n, nil
}

// WafEventRuleAggregate is one row of the per-rule breakdown
// surfaced by AggregateWafEventsByRule and consumed by the M.4
// drill-down's per-rule table.
//
// Group key is (RuleID, Category). Two CRS rules sharing an ID
// are theoretically possible across upstream config drift, so
// the SQL groups by both — in practice the (rule_id → category)
// mapping is stable, but the query stays honest.
type WafEventRuleAggregate struct {
	RuleID   string
	Category string
	Count    int64
	LastSeen time.Time
}

// WafEventAggregateFilter narrows AggregateWafEventsByRule.
// Same shape as WafEventFilter minus Category (the aggregation
// is BY category; filtering by it would defeat the purpose) and
// minus Limit (an aggregated result is bounded by the number of
// distinct rules tripped in the window — typically << 100 — so
// no client-driven cap is needed).
type WafEventAggregateFilter struct {
	RouteID string
	From    time.Time // inclusive
	To      time.Time // exclusive; zero = open-ended (now)
}

// AggregateWafEventsByRule returns one row per (rule_id,
// category) tuple in the window, with the count of matching
// events + the most-recent ts. Ordered by count DESC so the
// API layer can hand it to the frontend table as-is.
//
// Closes the M.4 drift the spec §5.4 wording calls out:
// "per-rule breakdown table for the route's blocks OVER THE
// WINDOW". The M.4 frontend used to derive this client-side
// from the most-recent-100 events, which silently degraded on
// a 30d window. This endpoint computes it server-side from the
// full row set, honouring the window boundaries.
func (s *Store) AggregateWafEventsByRule(ctx context.Context, filter WafEventAggregateFilter) ([]WafEventRuleAggregate, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	q := `SELECT rule_id, category, COUNT(*) AS cnt, MAX(ts) AS last_ts
	      FROM waf_event WHERE 1=1`
	args := []any{}
	if filter.RouteID != "" {
		q += ` AND route_id = ?`
		args = append(args, filter.RouteID)
	}
	if !filter.From.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, filter.From.UTC().Unix())
	}
	if !filter.To.IsZero() {
		q += ` AND ts < ?`
		args = append(args, filter.To.UTC().Unix())
	}
	q += ` GROUP BY rule_id, category ORDER BY cnt DESC, last_ts DESC`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: aggregate waf_event by rule: %w", err)
	}
	defer rows.Close()
	var out []WafEventRuleAggregate
	for rows.Next() {
		var agg WafEventRuleAggregate
		var lastUnix int64
		if err := rows.Scan(&agg.RuleID, &agg.Category, &agg.Count, &lastUnix); err != nil {
			return nil, fmt.Errorf("observability: scan waf_event aggregate: %w", err)
		}
		agg.LastSeen = time.Unix(lastUnix, 0).UTC()
		out = append(out, agg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate waf_event aggregate: %w", err)
	}
	return out, nil
}
