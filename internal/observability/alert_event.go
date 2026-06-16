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
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// AL.4.a — alert_event storage layer.
//
// Mirrors the cert_event / waf_event pattern: a typed
// row struct + InsertAlertEvent + QueryAlertEvents with
// a Filter, all hanging off *observability.Store. The
// schema (migrateV9toV10, shipped with AL.1.a) is
// unchanged; this file ships the read+write code paths
// the AL.4 endpoint + the dispatcher sink call into.

// AlertEvent is the observability-layer row shape. EventID
// is the AlertSender-facing UUID (alerting.AlertEvent.ID);
// the SQLite primary key ID is internal.
type AlertEvent struct {
	ID             int64
	EventID        string
	Ts             time.Time
	RuleID         string
	RuleName       string
	Severity       int
	Category       string
	Subject        string
	Body           string
	// JSON blobs persisted verbatim. The handler unmarshals
	// them only for the wire response; the storage layer
	// treats them as opaque.
	ContextJSON         string
	LabelsJSON          string
	ChannelsFiredJSON   string
	ChannelsFailedJSON  string
}

// AlertEventFilter narrows a QueryAlertEvents call. All
// fields optional; the API handler maps query-string
// params into this struct. Cursor is a tuple-encoded
// (ts, id) string; Limit is clamped at alertEventLimitCap.
type AlertEventFilter struct {
	RuleID   string
	Severity *int      // pointer so 0 (info) vs unset are distinguishable
	Category string
	From     time.Time // inclusive
	To       time.Time // exclusive; zero = open-ended (now)
	Limit    int
	// Cursor encodes the (ts, id) of the last row from the
	// previous page. Pass back as-is from the prior
	// response's NextCursor. Empty = first page.
	Cursor string
}

// alertEventLimitCap bounds the result set defensively.
// Matches the API-layer max (200 per the AL.4.a brief).
const alertEventLimitCap = 200

// InsertAlertEvent persists a single AlertEvent row. The
// dispatcher sink calls this once per fan-out after the
// per-channel dispatch loop completes, with
// ChannelsFiredJSON / ChannelsFailedJSON populated from
// the DispatchResult.
//
// The schema's UNIQUE constraint on event_id makes a
// re-insert with the same UUID a no-op (returns nil) so
// a retry path that re-emits the same event_id doesn't
// double-row. Non-UNIQUE errors propagate.
//
// Insert failures are not fatal at the dispatcher layer
// (logged, not surfaced) per the AC #13 degraded-
// observability contract.
func (s *Store) InsertAlertEvent(ctx context.Context, e AlertEvent) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("observability: store closed")
	}
	if e.EventID == "" {
		return errors.New("observability: alert_event EventID must not be empty")
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO alert_event (event_id, ts, rule_id, rule_name, severity, category, subject, body, context_json, labels_json, channels_fired_json, channels_failed_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(event_id) DO NOTHING
`,
		e.EventID,
		e.Ts.UTC().Unix(),
		e.RuleID,
		e.RuleName,
		e.Severity,
		e.Category,
		e.Subject,
		e.Body,
		e.ContextJSON,
		e.LabelsJSON,
		e.ChannelsFiredJSON,
		e.ChannelsFailedJSON,
	)
	if err != nil {
		return fmt.Errorf("observability: insert alert_event: %w", err)
	}
	return nil
}

// QueryAlertEvents returns rows matching filter, ordered
// (ts DESC, id DESC) so the most recent fires surface
// first — matches the operator's UI expectation (History
// tab shows newest at top). Limit > cap clamps silently.
//
// Cursor-based pagination: when filter.Cursor is set the
// query starts strictly after the (ts, id) tuple it
// encodes. Returns nextCursor encoding the last returned
// row, or "" when fewer than `limit` rows remain.
func (s *Store) QueryAlertEvents(ctx context.Context, filter AlertEventFilter) ([]AlertEvent, string, error) {
	if s == nil || s.db == nil {
		return nil, "", fmt.Errorf("observability: store closed")
	}
	limit := filter.Limit
	if limit <= 0 || limit > alertEventLimitCap {
		limit = alertEventLimitCap
	}

	q := `SELECT id, event_id, ts, rule_id, rule_name, severity, category, subject, body,
	             context_json, labels_json, channels_fired_json, channels_failed_json
	      FROM alert_event WHERE 1=1`
	args := []any{}
	if filter.RuleID != "" {
		q += ` AND rule_id = ?`
		args = append(args, filter.RuleID)
	}
	if filter.Severity != nil {
		q += ` AND severity = ?`
		args = append(args, *filter.Severity)
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
	if filter.Cursor != "" {
		cTs, cID, err := decodeAlertEventCursor(filter.Cursor)
		if err != nil {
			return nil, "", fmt.Errorf("observability: invalid cursor: %w", err)
		}
		// Strictly older than the cursor in (ts, id) DESC
		// order: row.ts < cursor.ts OR (row.ts = cursor.ts
		// AND row.id < cursor.id).
		q += ` AND (ts < ? OR (ts = ? AND id < ?))`
		args = append(args, cTs, cTs, cID)
	}
	q += ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("observability: query alert_event: %w", err)
	}
	defer rows.Close()
	var out []AlertEvent
	for rows.Next() {
		var e AlertEvent
		var tsUnix int64
		if err := rows.Scan(
			&e.ID, &e.EventID, &tsUnix, &e.RuleID, &e.RuleName, &e.Severity, &e.Category,
			&e.Subject, &e.Body, &e.ContextJSON, &e.LabelsJSON,
			&e.ChannelsFiredJSON, &e.ChannelsFailedJSON,
		); err != nil {
			return nil, "", fmt.Errorf("observability: scan alert_event: %w", err)
		}
		e.Ts = time.Unix(tsUnix, 0).UTC()
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("observability: iterate alert_event: %w", err)
	}

	nextCursor := ""
	// Only emit a cursor when the page filled — a short
	// page means there's no more data to fetch. Emitting a
	// cursor on a short page would force the operator to
	// drive one extra empty round-trip.
	if len(out) == limit && limit > 0 {
		last := out[len(out)-1]
		nextCursor = encodeAlertEventCursor(last.Ts, last.ID)
	}
	return out, nextCursor, nil
}

// PruneAlertEventsOlderThan deletes rows with ts < cutoff.
// Returns the number of rows deleted. Called by the
// retention loop alongside the other table prunes.
func (s *Store) PruneAlertEventsOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("observability: store closed")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM alert_event WHERE ts < ?`, cutoff.UTC().Unix())
	if err != nil {
		return 0, fmt.Errorf("observability: prune alert_event: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("observability: prune alert_event affected: %w", err)
	}
	return n, nil
}

// encodeAlertEventCursor encodes the (ts, id) tuple of
// the last row of a page into a URL-safe opaque string.
// The base64 wrapper hides the implementation detail
// from API consumers (they treat the cursor as opaque
// per HATEOAS) while keeping it short + parseable.
func encodeAlertEventCursor(ts time.Time, id int64) string {
	raw := fmt.Sprintf("%d:%d", ts.UTC().Unix(), id)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeAlertEventCursor inverts encodeAlertEventCursor.
// Returns an error on malformed input so the API layer
// can surface 400 to the caller.
func decodeAlertEventCursor(cursor string) (int64, int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, 0, fmt.Errorf("base64 decode: %w", err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return 0, 0, errors.New("expected ts:id format")
	}
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse ts: %w", err)
	}
	id, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse id: %w", err)
	}
	return ts, id, nil
}
