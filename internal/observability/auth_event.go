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

// AuthEvent is the storage-flat shape of one row in the
// auth_event table (Step V.2 spec §3.6). One row per
// 401/403 emission from the auth middleware — login failure,
// session expiry, OIDC callback rejection, forbidden access.
//
// Schema v6 — columns named to match spec §3.6 verbatim: Kind
// (NOT "reason"), SrcIP (NOT "source_ip"), Username (NOT
// "user"). These names align with the existing audit-bucket
// vocabulary so an operator joining auth_event with
// audit.Event on src_ip / username sees the same identifier
// on both sides.
//
// This sink is a parallel fan-out to the existing audit
// bucket: the audit log keeps the canonical record (Step Q
// D2.B); auth_event provides the real-time stream the V.3 geo
// bus consumes and the future per-IP timeline drills into. A
// single 401 produces TWO rows — one in audit_event (canonical
// record), one in auth_event (real-time signal). Operators see
// the same data through two lenses.
type AuthEvent struct {
	ID       int64
	Ts       time.Time
	Kind     AuthEventKind
	SrcIP    string
	Username string
	Path     string
	Details  string
}

// AuthEventKind classifies the auth failure. The four
// constants cover every 401/403 path the auth middleware +
// auth handlers emit today, per the spec §3.6 enumeration.
type AuthEventKind int

const (
	// AuthEventKindLoginFailure — wrong password, unknown
	// user, account locked at login. Mirrors
	// audit.ActionLoginFailure.
	AuthEventKindLoginFailure AuthEventKind = iota
	// AuthEventKindSessionExpired — soft-auth middleware
	// rejecting an expired or unknown session cookie. No
	// corresponding audit Action today; the auth_event sink is
	// the first place this signal becomes addressable.
	AuthEventKindSessionExpired
	// AuthEventKindOIDCCallbackRejected — OIDC callback failed
	// (state mismatch, token exchange failure, claims missing).
	// Covers both audit.ActionOIDCLoginRejected and
	// audit.ActionOIDCCallbackInvalid.
	AuthEventKindOIDCCallbackRejected
	// AuthEventKindForbidden — 403 paths: admin-required
	// endpoint accessed by a non-admin, session in idle lock
	// state, etc. Distinct from 401 because the client IS
	// authenticated but lacks authority — V.3 will color these
	// differently on the map.
	AuthEventKindForbidden
)

// String returns the on-the-wire token. Stable across the
// codebase (frontend type union, DB row, API response).
// Values mirror the spec §3.6 enumeration.
func (k AuthEventKind) String() string {
	switch k {
	case AuthEventKindLoginFailure:
		return "login_failure"
	case AuthEventKindSessionExpired:
		return "session_expired"
	case AuthEventKindOIDCCallbackRejected:
		return "oidc_callback_rejected"
	case AuthEventKindForbidden:
		return "forbidden"
	default:
		return "unknown"
	}
}

// ParseAuthEventKind inverts String for DB rows. Unknown
// inputs land on AuthEventKindLoginFailure defensively
// (same pattern as ParseCertEventLevel / ParseCertEventType) —
// the kind column is operator-facing metadata, not
// load-bearing for correctness.
func ParseAuthEventKind(s string) AuthEventKind {
	switch s {
	case "session_expired":
		return AuthEventKindSessionExpired
	case "oidc_callback_rejected":
		return AuthEventKindOIDCCallbackRejected
	case "forbidden":
		return AuthEventKindForbidden
	default:
		return AuthEventKindLoginFailure
	}
}

// AuthEventFilter narrows a QueryAuthEvents / CountAuthEvents
// call. All fields are optional. The single-value Kind and the
// multi-value Kinds follow the cert_event Level / Levels
// precedence rule: Kinds (when non-empty) wins.
type AuthEventFilter struct {
	SrcIP    string
	Kind     string // matches the String() form: "login_failure" / ...
	Kinds    []AuthEventKind
	Username string
	From     time.Time
	To       time.Time
	Search   string
	Limit    int
}

const authEventLimitCap = 100

// InsertAuthEventBatch persists a slice of AuthEvent rows in a
// single transaction. Mirrors InsertCertEventBatch verbatim —
// same prepared-INSERT-in-transaction shape, same UTC().Unix()
// (seconds-since-epoch) convention. Empty batch is a no-op.
//
// Errors are returned to the caller; the production caller
// (auth_event_sink.go's Sink) logs + counts + swallows per
// AC #13.
func (s *Store) InsertAuthEventBatch(ctx context.Context, events []AuthEvent) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("observability: store closed")
	}
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("observability: begin auth_event tx: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO auth_event (ts, kind, src_ip, username, path, details)
VALUES (?, ?, ?, ?, ?, ?)
`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("observability: prepare auth_event insert: %w", err)
	}
	defer stmt.Close()
	for _, e := range events {
		if _, err := stmt.ExecContext(ctx,
			e.Ts.UTC().Unix(),
			e.Kind.String(),
			e.SrcIP,
			e.Username,
			e.Path,
			e.Details,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("observability: insert auth_event (kind=%s src_ip=%s): %w", e.Kind, e.SrcIP, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("observability: commit auth_event: %w", err)
	}
	return nil
}

// buildAuthEventWhere builds the shared WHERE clause + args
// slice for QueryAuthEvents + CountAuthEvents. Mirrors
// buildCertEventWhere's shape.
func buildAuthEventWhere(filter AuthEventFilter) (string, []any) {
	q := ` WHERE 1=1`
	args := []any{}
	if filter.SrcIP != "" {
		q += ` AND src_ip = ?`
		args = append(args, filter.SrcIP)
	}
	if filter.Username != "" {
		q += ` AND username = ?`
		args = append(args, filter.Username)
	}
	if len(filter.Kinds) > 0 {
		q += ` AND kind IN (`
		for i, k := range filter.Kinds {
			if i > 0 {
				q += `, `
			}
			q += `?`
			args = append(args, k.String())
		}
		q += `)`
	} else if filter.Kind != "" {
		q += ` AND kind = ?`
		args = append(args, filter.Kind)
	}
	if !filter.From.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, filter.From.UTC().Unix())
	}
	if !filter.To.IsZero() {
		q += ` AND ts < ?`
		args = append(args, filter.To.UTC().Unix())
	}
	if s := filter.Search; s != "" {
		needle := "%" + s + "%"
		q += ` AND (` +
			`src_ip   LIKE ? COLLATE NOCASE OR ` +
			`username LIKE ? COLLATE NOCASE OR ` +
			`path     LIKE ? COLLATE NOCASE OR ` +
			`details  LIKE ? COLLATE NOCASE)`
		args = append(args, needle, needle, needle, needle)
	}
	return q, args
}

// QueryAuthEvents returns auth_event rows matching filter,
// ts-descending. Empty filter returns the most recent
// authEventLimitCap rows. Pure read.
func (s *Store) QueryAuthEvents(ctx context.Context, filter AuthEventFilter) ([]AuthEvent, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	limit := filter.Limit
	if limit <= 0 || limit > authEventLimitCap {
		limit = authEventLimitCap
	}
	where, args := buildAuthEventWhere(filter)
	q := `SELECT id, ts, kind, src_ip, username, path, details
	      FROM auth_event` + where + ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: query auth_event: %w", err)
	}
	defer rows.Close()
	var out []AuthEvent
	for rows.Next() {
		var e AuthEvent
		var tsUnix int64
		var kindStr string
		if err := rows.Scan(
			&e.ID, &tsUnix, &kindStr, &e.SrcIP, &e.Username, &e.Path, &e.Details,
		); err != nil {
			return nil, fmt.Errorf("observability: scan auth_event: %w", err)
		}
		e.Ts = time.Unix(tsUnix, 0).UTC()
		e.Kind = ParseAuthEventKind(kindStr)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate auth_event: %w", err)
	}
	return out, nil
}

// CountAuthEvents returns the total number of rows matching
// filter, ignoring its Limit. Used by future API surfaces
// that need a total count for pagination metadata.
func (s *Store) CountAuthEvents(ctx context.Context, filter AuthEventFilter) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("observability: store closed")
	}
	where, args := buildAuthEventWhere(filter)
	q := `SELECT COUNT(*) FROM auth_event` + where
	var n int64
	if err := s.db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("observability: count auth_event: %w", err)
	}
	return n, nil
}

// PruneAuthEventsOlderThan deletes auth_event rows with ts <
// cutoff. Returns the number of rows deleted. Per spec §3.6
// the cutoff is now - 30 d (short-window security signal,
// matching the existing waf / throttle / decision retention).
func (s *Store) PruneAuthEventsOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("observability: store closed")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM auth_event WHERE ts < ?`, cutoff.UTC().Unix())
	if err != nil {
		return 0, fmt.Errorf("observability: prune auth_event: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("observability: prune auth_event rows affected: %w", err)
	}
	return n, nil
}
