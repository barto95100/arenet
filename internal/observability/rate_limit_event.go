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
	"fmt"
	"time"
)

// RateLimitEvent is the storage-flat shape of one row in the
// rate_limit_event table (Step Z spec §Z.1). One row per
// rate-limit-exceeded decision captured from the upstream
// mholt/caddy-ratelimit handler's "rate_limit_exceeded" event
// emit (handler.go:232).
//
// Schema v11 — added by migrateV10toV11. Mirror of
// ratelimit.Event (internal/ratelimit/event.go) field-for-
// field, defined here so observability does not have to
// import internal/ratelimit (dependency direction stays
// ratelimit → observability via the Inserter interface, with
// an adapter shim in cmd/arenet/main.go bridging the two
// flat structs — same pattern as throttleInserterAdapter).
//
// RouteID is the route UUID extracted at sink time by
// stripping the "route-" prefix from the upstream zone name.
// Operator-hand-crafted Caddy configs that bypass Arenet's
// emit path lose this attribution — RouteID == "" and the
// raw Zone string is preserved for forensic value.
//
// WaitMs is the milliseconds the upstream handler told the
// client to wait before retrying (Retry-After value computed
// from the sliding-window state). 0 when the upstream emit
// didn't include the wait field.
type RateLimitEvent struct {
	ID       int64
	Ts       time.Time
	RouteID  string
	Zone     string
	RemoteIP string
	WaitMs   int64
}

// RateLimitEventFilter narrows a QueryRateLimitEvents call.
// All fields are optional; Limit is clamped to
// rateLimitEventLimitCap.
type RateLimitEventFilter struct {
	RouteID  string
	RemoteIP string
	From     time.Time // inclusive
	To       time.Time // exclusive
	Limit    int
}

// rateLimitEventLimitCap mirrors the existing waf / auth /
// throttle / country_block defensive caps.
const rateLimitEventLimitCap = 100

// InsertRateLimitEventBatch persists a slice of
// RateLimitEvent rows in a single transaction. The production
// caller is the rateLimitInserterAdapter shim in
// cmd/arenet/main.go, which converts ratelimit.Event →
// observability.RateLimitEvent at the boundary so the
// observability package stays free of any ratelimit import
// (mirror of throttleInserterAdapter).
//
// Errors are returned to the caller; the production caller
// (ratelimit.Sink's flush goroutine) logs + counts + swallows
// per the AC #13 degraded-mode pattern shared with the other
// security sinks. Empty batch is a no-op.
func (s *Store) InsertRateLimitEventBatch(ctx context.Context, events []RateLimitEvent) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("observability: store closed")
	}
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("observability: begin rate_limit_event tx: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO rate_limit_event (ts, route_id, zone, remote_ip, wait_ms)
VALUES (?, ?, ?, ?, ?)
`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("observability: prepare rate_limit_event insert: %w", err)
	}
	defer stmt.Close()
	for _, e := range events {
		if _, err := stmt.ExecContext(ctx,
			e.Ts.UTC().Unix(),
			e.RouteID,
			e.Zone,
			e.RemoteIP,
			e.WaitMs,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("observability: insert rate_limit_event (route=%s ip=%s): %w", e.RouteID, e.RemoteIP, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("observability: commit rate_limit_event: %w", err)
	}
	return nil
}

// buildRateLimitEventWhere builds the shared WHERE clause +
// args slice for QueryRateLimitEvents.
func buildRateLimitEventWhere(filter RateLimitEventFilter) (string, []any) {
	q := ` WHERE 1=1`
	args := []any{}
	if filter.RouteID != "" {
		q += ` AND route_id = ?`
		args = append(args, filter.RouteID)
	}
	if filter.RemoteIP != "" {
		q += ` AND remote_ip = ?`
		args = append(args, filter.RemoteIP)
	}
	if !filter.From.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, filter.From.UTC().Unix())
	}
	if !filter.To.IsZero() {
		q += ` AND ts < ?`
		args = append(args, filter.To.UTC().Unix())
	}
	return q, args
}

// QueryRateLimitEvents returns rate_limit_event rows matching
// filter, ts-descending (most-recent first — natural ordering
// for the activity-log surfaces). Empty filter returns the
// most-recent rateLimitEventLimitCap rows. Pure read; safe
// to call concurrently with inserts.
func (s *Store) QueryRateLimitEvents(ctx context.Context, filter RateLimitEventFilter) ([]RateLimitEvent, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	limit := filter.Limit
	if limit <= 0 || limit > rateLimitEventLimitCap {
		limit = rateLimitEventLimitCap
	}
	where, args := buildRateLimitEventWhere(filter)
	q := `SELECT id, ts, route_id, zone, remote_ip, wait_ms
	      FROM rate_limit_event` + where + ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: query rate_limit_event: %w", err)
	}
	defer rows.Close()
	var out []RateLimitEvent
	for rows.Next() {
		var e RateLimitEvent
		var tsUnix int64
		if err := rows.Scan(
			&e.ID, &tsUnix, &e.RouteID, &e.Zone, &e.RemoteIP, &e.WaitMs,
		); err != nil {
			return nil, fmt.Errorf("observability: scan rate_limit_event: %w", err)
		}
		e.Ts = time.Unix(tsUnix, 0).UTC()
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate rate_limit_event: %w", err)
	}
	return out, nil
}

// CountRateLimitEventsByWindow returns the count of
// rate_limit_event rows with ts in [from, to). Powers the
// /api/v1/security/summary TotalRateLimitExceeded counter
// (Step Z.2 dashboard KPI sub-line).
func (s *Store) CountRateLimitEventsByWindow(ctx context.Context, from, to time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("observability: store closed")
	}
	q := `SELECT COUNT(*) FROM rate_limit_event WHERE ts >= ? AND ts < ?`
	var n int64
	if err := s.db.QueryRowContext(ctx, q, from.UTC().Unix(), to.UTC().Unix()).Scan(&n); err != nil {
		return 0, fmt.Errorf("observability: count rate_limit_event by window: %w", err)
	}
	return n, nil
}

// PruneRateLimitEventsOlderThan deletes rate_limit_event rows
// with ts < cutoff. Returns the number of rows deleted. Per
// Step Z spec the retention is 24h rolling — burst-shape
// information has short forensic value, and 429s can be very
// high-volume during a sustained DoS attempt. The
// observability retention loop schedules this with the 24h
// cutoff.
func (s *Store) PruneRateLimitEventsOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("observability: store closed")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM rate_limit_event WHERE ts < ?`, cutoff.UTC().Unix())
	if err != nil {
		return 0, fmt.Errorf("observability: prune rate_limit_event: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("observability: prune rate_limit_event rows affected: %w", err)
	}
	return n, nil
}
