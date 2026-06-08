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

// CountryBlockEvent is the storage-flat shape of one row in
// the country_block_event table (Step W.4 spec §3.5). One row
// per block decision the W.1 matcher emitted — i.e. per
// request whose source country failed the allow/deny gate.
//
// Schema v8 — added by migrateV7toV8. Columns mirror the
// W.1 BlockMatch struct field-for-field, with two
// intentional omissions:
//
//   - Host: the W.3 caddymgr emit elides the host JSON tag
//     (deviation #2), so the W.1 Handler doesn't carry it.
//     Cross-reference via route_id → host through the routes
//     API at the frontend.
//   - ASN: V.1's MMDB is City-only; ASN would require the
//     separate GeoLite2-ASN.mmdb. Deferred.
//
// Mode (the route's enforcement mode: "allow" or "deny") +
// Reason (W.1's matcher kebab-case enum: "allow-miss" /
// "deny-match" / etc.) land in dedicated columns rather
// than a single Details blob so the W.5 activity log can
// filter on them without parsing free text.
type CountryBlockEvent struct {
	ID         int64
	Ts         time.Time
	RouteID    string
	SrcIP      string
	Country    string // ISO 3166-1 alpha-2; may be "" on §D5 fail-open (not currently reachable)
	Mode       string // "allow" or "deny"
	StatusCode int    // 403 / 451 / 444
	Reason     string // W.1's stable matcher enum
}

// CountryBlockEventFilter narrows a QueryCountryBlockEvents
// call. All fields are optional; Limit is clamped to
// countryBlockEventLimitCap.
type CountryBlockEventFilter struct {
	RouteID string
	SrcIP   string
	Country string
	Mode    string
	From    time.Time // inclusive
	To      time.Time // exclusive
	Limit   int
}

// countryBlockEventLimitCap mirrors the existing waf / auth /
// throttle defensive caps. The API layer caps at 100 before
// calling; this is the belt-and-braces for any future internal
// caller.
const countryBlockEventLimitCap = 100

// InsertCountryBlockEventBatch persists a slice of
// CountryBlockEvent rows in a single transaction. Mirrors
// InsertWafEventBatch / InsertAuthEventBatch verbatim — same
// prepared-INSERT-in-transaction shape, same UTC().Unix()
// (seconds-since-epoch) convention. Empty batch is a no-op.
//
// Errors are returned to the caller; the production caller
// (geo.DefaultCountryBlockSink's flush goroutine) logs +
// counts + swallows per AC #13.
func (s *Store) InsertCountryBlockEventBatch(ctx context.Context, events []CountryBlockEvent) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("observability: store closed")
	}
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("observability: begin country_block_event tx: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO country_block_event (ts, route_id, src_ip, country, mode, status_code, reason)
VALUES (?, ?, ?, ?, ?, ?, ?)
`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("observability: prepare country_block_event insert: %w", err)
	}
	defer stmt.Close()
	for _, e := range events {
		if _, err := stmt.ExecContext(ctx,
			e.Ts.UTC().Unix(),
			e.RouteID,
			e.SrcIP,
			e.Country,
			e.Mode,
			e.StatusCode,
			e.Reason,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("observability: insert country_block_event (route=%s src=%s): %w", e.RouteID, e.SrcIP, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("observability: commit country_block_event: %w", err)
	}
	return nil
}

// buildCountryBlockEventWhere builds the shared WHERE clause +
// args slice for QueryCountryBlockEvents. Mirrors
// buildAuthEventWhere's shape.
func buildCountryBlockEventWhere(filter CountryBlockEventFilter) (string, []any) {
	q := ` WHERE 1=1`
	args := []any{}
	if filter.RouteID != "" {
		q += ` AND route_id = ?`
		args = append(args, filter.RouteID)
	}
	if filter.SrcIP != "" {
		q += ` AND src_ip = ?`
		args = append(args, filter.SrcIP)
	}
	if filter.Country != "" {
		q += ` AND country = ?`
		args = append(args, filter.Country)
	}
	if filter.Mode != "" {
		q += ` AND mode = ?`
		args = append(args, filter.Mode)
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

// QueryCountryBlockEvents returns country_block_event rows
// matching filter, ts-descending (most recent first — the
// frontend's natural ordering for activity-log surfaces).
// Empty filter returns the most recent countryBlockEventLimitCap
// rows. Pure read; safe to call concurrently with inserts.
func (s *Store) QueryCountryBlockEvents(ctx context.Context, filter CountryBlockEventFilter) ([]CountryBlockEvent, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	limit := filter.Limit
	if limit <= 0 || limit > countryBlockEventLimitCap {
		limit = countryBlockEventLimitCap
	}
	where, args := buildCountryBlockEventWhere(filter)
	q := `SELECT id, ts, route_id, src_ip, country, mode, status_code, reason
	      FROM country_block_event` + where + ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: query country_block_event: %w", err)
	}
	defer rows.Close()
	var out []CountryBlockEvent
	for rows.Next() {
		var e CountryBlockEvent
		var tsUnix int64
		if err := rows.Scan(
			&e.ID, &tsUnix, &e.RouteID, &e.SrcIP, &e.Country, &e.Mode, &e.StatusCode, &e.Reason,
		); err != nil {
			return nil, fmt.Errorf("observability: scan country_block_event: %w", err)
		}
		e.Ts = time.Unix(tsUnix, 0).UTC()
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate country_block_event: %w", err)
	}
	return out, nil
}

// PruneCountryBlockEventsOlderThan deletes country_block_event
// rows with ts < cutoff. Returns the number of rows deleted.
// Per spec §3.5 the cutoff is now - 30 d (short-window
// security signal, matching the existing waf / throttle /
// auth / decision retention horizons).
func (s *Store) PruneCountryBlockEventsOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("observability: store closed")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM country_block_event WHERE ts < ?`, cutoff.UTC().Unix())
	if err != nil {
		return 0, fmt.Errorf("observability: prune country_block_event: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("observability: prune country_block_event rows affected: %w", err)
	}
	return n, nil
}
