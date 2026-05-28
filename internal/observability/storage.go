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
INSERT INTO `+gran.tableName()+` (route_id, ts, req_count, fourxx_count, fivexx_count, latency_p95_ms)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(route_id, ts) DO UPDATE SET
  req_count      = excluded.req_count,
  fourxx_count   = excluded.fourxx_count,
  fivexx_count   = excluded.fivexx_count,
  latency_p95_ms = excluded.latency_p95_ms
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
SELECT route_id, ts, req_count, fourxx_count, fivexx_count, latency_p95_ms
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
		if err := rows.Scan(&b.RouteID, &tsUnix, &b.ReqCount, &b.FourxxCount, &b.FivexxCount, &b.LatencyP95Ms); err != nil {
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
  SUM(req_count)     AS req_total,
  SUM(fourxx_count)  AS fourxx_total,
  SUM(fivexx_count)  AS fivexx_total,
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
		if err := rows.Scan(&tsUnix, &b.ReqCount, &b.FourxxCount, &b.FivexxCount, &p95); err != nil {
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
