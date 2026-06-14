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

package observability

import (
	"context"
	"fmt"
	"time"
)

// CertEvent is the storage-flat shape of one row in the
// cert_event table (Step U.1 spec §3.1). One row per
// successful or failed cert lifecycle event certmagic emits;
// the noisier cert_obtaining and the informational
// cached_managed_cert / cached_unmanaged_cert events are NOT
// persisted (spec §3.3 + §3.5).
//
// Field-for-field mirror of the wire shape declared in spec
// §5.2 (camelCase JSON tags map to snake_case columns). The
// API layer (U.3) translates this shape into JSON for the
// frontend Activity log page.
//
// Why this lives in the observability package rather than in
// internal/certinfo: the storage tables — waf_event,
// throttle_event, decision_event, cert_event — share the same
// SQLite file and migration chain. Keeping the storage shape
// alongside its siblings here means the Insert/Query/Prune
// trio reads identically across the four event classes; the
// U.2 sink in internal/certinfo subscribes via the AC #18
// Tracker.Subscribe seam and translates from
// certinfo.Event → CertEvent before calling
// InsertCertEventBatch.
type CertEvent struct {
	ID        int64
	Ts        time.Time
	Level     CertEventLevel
	Type      CertEventType
	Domain    string
	Issuer    string
	Challenge string // 'DNS-01' / 'HTTP-01' / '' (heuristic; see Step T HF2)
	Renewal   bool
	Error     string
	Details   string
}

// CertEventLevel pins the operator-facing severity that maps
// to the Activity log's existing level segmented control
// (info → cyan, block → red). The wire form is the String()
// representation (uppercase string), stored verbatim in the
// `level` TEXT column.
type CertEventLevel int

const (
	// CertEventLevelInfo: obtained / removed / informational.
	CertEventLevelInfo CertEventLevel = iota
	// CertEventLevelError: failed / ocsp_revoked.
	CertEventLevelError
)

// String returns the on-the-wire token. Stable across the
// codebase (frontend type union, DB row, API response).
func (l CertEventLevel) String() string {
	switch l {
	case CertEventLevelInfo:
		return "INFO"
	case CertEventLevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// ParseCertEventLevel inverts String for DB rows. Unknown
// inputs land on CertEventLevelInfo defensively (rather than
// failing the row scan) — the level column is operator-facing
// metadata, not load-bearing for correctness.
func ParseCertEventLevel(s string) CertEventLevel {
	switch s {
	case "ERROR":
		return CertEventLevelError
	default:
		return CertEventLevelInfo
	}
}

// CertEventType pins the certmagic-event lineage of the row.
// The four values match the EventKind constants in
// internal/certinfo/types.go that the U.2 sink will translate
// from. cert_obtaining is intentionally absent — see spec §3.3.
type CertEventType int

const (
	// CertEventTypeObtained — certmagic cert_obtained event.
	// Renewal=true when this was a renewal rather than first
	// issuance (disambiguation per certmagic config.go:728
	// payload's `renewal` bool — verified during T.1 recon).
	CertEventTypeObtained CertEventType = iota
	// CertEventTypeFailed — certmagic cert_failed event. The
	// raw certmagic error string lands in CertEvent.Error.
	CertEventTypeFailed
	// CertEventTypeOCSPRevoked — certmagic cert_ocsp_revoked
	// event (maintain.go:375). Per spec §3.6 this is included
	// as an ERROR-level signal because cert revocation may
	// indicate compromise.
	CertEventTypeOCSPRevoked
)

// String returns the on-the-wire token, matching the
// certmagic event name verbatim so an operator filtering the
// Activity log with the literal certmagic event name finds
// the matching rows.
func (t CertEventType) String() string {
	switch t {
	case CertEventTypeObtained:
		return "cert_obtained"
	case CertEventTypeFailed:
		return "cert_failed"
	case CertEventTypeOCSPRevoked:
		return "cert_ocsp_revoked"
	default:
		return "unknown"
	}
}

// ParseCertEventType inverts String for DB rows. Unknown
// inputs land on CertEventTypeObtained defensively for the
// same reason ParseCertEventLevel falls back.
func ParseCertEventType(s string) CertEventType {
	switch s {
	case "cert_failed":
		return CertEventTypeFailed
	case "cert_ocsp_revoked":
		return CertEventTypeOCSPRevoked
	default:
		return CertEventTypeObtained
	}
}

// CertEventFilter narrows a QueryCertEvents / CountCertEvents
// call. All fields are optional; the API layer (U.3) maps
// query-string parameters into this struct. Limit > the cap
// constant (per the calling endpoint's contract) is clamped by
// the store.
type CertEventFilter struct {
	Domain string
	Type   string // matches the String() form: "cert_obtained" / ...
	// Level is the single-value short-circuit used by the
	// pre-U.3 callers. Levels (plural) is the U.3 multi-value
	// path; when Levels is non-empty it takes precedence over
	// Level. Both empty = all levels.
	Level  string
	Levels []CertEventLevel
	From   time.Time // inclusive
	To     time.Time // exclusive; zero = open-ended (now)
	// Search applies a case-insensitive substring match across
	// domain, issuer, error_msg, and details columns. Empty
	// string = no search filter (NOT a literal "match
	// everything containing empty"). The U.3 HTTP layer trims
	// whitespace before passing.
	Search string
	Limit  int
}

// certEventLimitCap defensively bounds the result set for
// callers that don't supply an explicit Limit. The U.3 HTTP
// surface caps separately at certEventAPILimitCap = 1000.
const certEventLimitCap = 100

// certEventAPILimitCap is the upper bound the U.3 HTTP
// endpoint clamps `limit` to. Larger than certEventLimitCap
// because the Activity log page may legitimately want a wider
// window than the default 100 for an investigation. SQLite
// scan over an indexed cert_event table stays cheap at this
// size given the table's expected cardinality (per-domain
// volume is bounded by the 90d retention window × renewal
// cadence; a homelab with 50 domains tops out in the low
// thousands).
const certEventAPILimitCap = 1000

// InsertCertEventBatch persists a slice of CertEvent rows in
// a single transaction. Errors are returned to the caller —
// the production caller (U.2's certinfo Sink) logs + counts +
// swallows per AC #13. Empty batch is a no-op.
//
// Mirrors InsertWafEventBatch / InsertThrottleEventBatch /
// InsertDecisionEventBatch verbatim — same prepared-INSERT-in-
// transaction shape, same error wrapping, same ts UTC().Unix()
// (seconds-since-epoch) convention.
func (s *Store) InsertCertEventBatch(ctx context.Context, events []CertEvent) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("observability: store closed")
	}
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("observability: begin cert_event tx: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO cert_event (ts, level, event_type, domain, issuer, challenge, renewal, error_msg, details)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("observability: prepare cert_event insert: %w", err)
	}
	defer stmt.Close()
	for _, e := range events {
		renewal := 0
		if e.Renewal {
			renewal = 1
		}
		if _, err := stmt.ExecContext(ctx,
			e.Ts.UTC().Unix(),
			e.Level.String(),
			e.Type.String(),
			e.Domain,
			e.Issuer,
			e.Challenge,
			renewal,
			e.Error,
			e.Details,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("observability: insert cert_event (domain=%s type=%s): %w", e.Domain, e.Type, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("observability: commit cert_event: %w", err)
	}
	return nil
}

// buildCertEventWhere builds the shared WHERE clause + args
// slice used by both QueryCertEvents and CountCertEvents. The
// returned clause starts with " WHERE 1=1" so callers can
// append "AND..." conditions; callers append their own ORDER /
// LIMIT.
//
// Search applies a case-insensitive LIKE %X% across domain,
// issuer, error_msg, and details. SQLite's default LIKE is
// case-insensitive for ASCII (which covers domain + the
// English error strings certmagic emits); for portability the
// clause emits explicit `COLLATE NOCASE` so the behavior is
// stable across SQLite builds with case-sensitive LIKE pragma.
//
// Levels []CertEventLevel takes precedence over the single
// Level field when non-empty: it expands to
// `level IN (?, ?, ...)`. Empty Levels falls back to the
// single-value Level filter (or no filter when that's empty
// too).
func buildCertEventWhere(filter CertEventFilter) (string, []any) {
	q := ` WHERE 1=1`
	args := []any{}
	if filter.Domain != "" {
		q += ` AND domain = ?`
		args = append(args, filter.Domain)
	}
	if filter.Type != "" {
		q += ` AND event_type = ?`
		args = append(args, filter.Type)
	}
	if len(filter.Levels) > 0 {
		// IN (?, ?, ...) — placeholder count matches len.
		q += ` AND level IN (`
		for i, lvl := range filter.Levels {
			if i > 0 {
				q += `, `
			}
			q += `?`
			args = append(args, lvl.String())
		}
		q += `)`
	} else if filter.Level != "" {
		q += ` AND level = ?`
		args = append(args, filter.Level)
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
		// Single bound parameter reused across four LIKE
		// comparisons. SQLite's query planner handles this
		// fine for our cardinality; if profiling ever shows
		// the search dominating, we can add a FTS5 virtual
		// table later.
		needle := "%" + s + "%"
		q += ` AND (` +
			`domain    LIKE ? COLLATE NOCASE OR ` +
			`issuer    LIKE ? COLLATE NOCASE OR ` +
			`error_msg LIKE ? COLLATE NOCASE OR ` +
			`details   LIKE ? COLLATE NOCASE)`
		args = append(args, needle, needle, needle, needle)
	}
	return q, args
}

// QueryCertEvents returns the cert_event rows matching
// filter, ts-descending (most recent first — the Activity log
// page's natural ordering). Empty filter returns the most
// recent certEventLimitCap rows. Limit > cap is silently
// clamped down.
//
// The domain / event_type / level filters short-circuit via
// the matching index when set; the from/to filters use the
// ts index. Search uses LIKE %X% across four text columns
// (case-insensitive). Pure read, safe to call concurrently
// with inserts.
func (s *Store) QueryCertEvents(ctx context.Context, filter CertEventFilter) ([]CertEvent, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	limit := filter.Limit
	if limit <= 0 || limit > certEventLimitCap {
		limit = certEventLimitCap
	}
	where, args := buildCertEventWhere(filter)
	q := `SELECT id, ts, level, event_type, domain, issuer, challenge, renewal, error_msg, details
	      FROM cert_event` + where + ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: query cert_event: %w", err)
	}
	defer rows.Close()
	var out []CertEvent
	for rows.Next() {
		var e CertEvent
		var tsUnix int64
		var levelStr, typeStr string
		var renewal int
		if err := rows.Scan(
			&e.ID, &tsUnix, &levelStr, &typeStr, &e.Domain,
			&e.Issuer, &e.Challenge, &renewal, &e.Error, &e.Details,
		); err != nil {
			return nil, fmt.Errorf("observability: scan cert_event: %w", err)
		}
		e.Ts = time.Unix(tsUnix, 0).UTC()
		e.Level = ParseCertEventLevel(levelStr)
		e.Type = ParseCertEventType(typeStr)
		e.Renewal = renewal != 0
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate cert_event: %w", err)
	}
	return out, nil
}

// CountCertEvents returns the total number of cert_event rows
// matching `filter`, IGNORING the filter's Limit. The U.3 HTTP
// surface uses this to populate the response's `total` and
// derive `hasMore` (true iff Total > len(Events)).
//
// Pure read, safe to call concurrently with inserts. Uses the
// same WHERE-clause helper as QueryCertEvents so any future
// filter addition automatically applies to both.
func (s *Store) CountCertEvents(ctx context.Context, filter CertEventFilter) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("observability: store closed")
	}
	where, args := buildCertEventWhere(filter)
	q := `SELECT COUNT(*) FROM cert_event` + where
	var n int64
	if err := s.db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("observability: count cert_event: %w", err)
	}
	return n, nil
}

// PruneCertEventsOlderThan deletes cert_event rows with ts <
// cutoff. Returns the number of rows deleted. Called by the
// retention loop on the same hourly cadence as the bucket
// prunes. Per spec §3.2 the cutoff is now - 90d (one full
// Let's Encrypt cert lifecycle — covers a renewal cycle for
// troubleshooting).
func (s *Store) PruneCertEventsOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("observability: store closed")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM cert_event WHERE ts < ?`, cutoff.UTC().Unix())
	if err != nil {
		return 0, fmt.Errorf("observability: prune cert_event: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("observability: prune cert_event rows affected: %w", err)
	}
	return n, nil
}

// CertEventAggregateFilter narrows AggregateCertEvents. From
// and To bound the window; Interval is the bucket size. Empty
// Interval defaults to 24h on the store side so the calling
// API handler can ship a zero-value filter for the common
// "30d, daily" shape.
type CertEventAggregateFilter struct {
	From     time.Time     // inclusive
	To       time.Time     // exclusive; zero = open-ended (now)
	Interval time.Duration // bucket size; zero defaults to 24h
}

// CertEventBucket is one row of the cert-event aggregation
// shipped to the dashboard. BucketStart is the inclusive Unix
// timestamp at the start of the bucket window; the three
// counters split the cert_obtained rows by Renewal (Issued =
// fresh, Renewed = post-first-issuance) and fold the
// cert_failed rows into Failed. cert_ocsp_revoked is excluded
// from this aggregate by design — the Phase 5 dashboard panel
// targets the three common lifecycle outcomes; OCSP
// revocations are vanishingly rare and surface in the Activity
// log when they happen.
type CertEventBucket struct {
	BucketStart time.Time
	Issued      int64
	Renewed     int64
	Failed      int64
}

// AggregateCertEvents groups cert_event rows by time bucket
// within the [From, To) window. Returns one CertEventBucket
// per Interval, ordered ascending by BucketStart.
//
// Bucketing uses integer division of (ts - From) by Interval
// in SQL — portable across SQLite versions, no dependency on
// strftime() format strings, and the boundary alignment is
// stable across calls with the same From.
//
// Empty buckets (no events in that interval) are emitted as
// zero-valued rows so the frontend can render a continuous
// line without gap-filling client-side. Phase 6 alerting will
// likely reuse this same shape for rule evaluation.
func (s *Store) AggregateCertEvents(ctx context.Context, filter CertEventAggregateFilter) ([]CertEventBucket, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	from := filter.From.UTC()
	to := filter.To.UTC()
	if to.IsZero() {
		to = time.Now().UTC()
	}
	interval := filter.Interval
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	if !from.Before(to) {
		return []CertEventBucket{}, nil
	}

	fromUnix := from.Unix()
	toUnix := to.Unix()
	intervalSecs := int64(interval / time.Second)
	if intervalSecs <= 0 {
		intervalSecs = 1
	}

	// Group every cert_event row in the window by
	// (ts - from) / interval. The three CASE-WHEN columns split
	// the bucket count by event_type + renewal so a single
	// query returns the three series the dashboard wants.
	q := `SELECT
	          ((ts - ?) / ?) AS bucket_idx,
	          SUM(CASE WHEN event_type = ? AND renewal = 0 THEN 1 ELSE 0 END) AS issued,
	          SUM(CASE WHEN event_type = ? AND renewal = 1 THEN 1 ELSE 0 END) AS renewed,
	          SUM(CASE WHEN event_type = ? THEN 1 ELSE 0 END) AS failed
	      FROM cert_event
	      WHERE ts >= ? AND ts < ?
	      GROUP BY bucket_idx
	      ORDER BY bucket_idx ASC`
	args := []any{
		fromUnix, intervalSecs,
		CertEventTypeObtained.String(),
		CertEventTypeObtained.String(),
		CertEventTypeFailed.String(),
		fromUnix, toUnix,
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: aggregate cert_event: %w", err)
	}
	defer rows.Close()

	// First pass: gather observed buckets into an index → row map.
	observed := map[int64]CertEventBucket{}
	for rows.Next() {
		var bucketIdx, issued, renewed, failed int64
		if err := rows.Scan(&bucketIdx, &issued, &renewed, &failed); err != nil {
			return nil, fmt.Errorf("observability: scan cert_event aggregate: %w", err)
		}
		bucketStart := time.Unix(fromUnix+(bucketIdx*intervalSecs), 0).UTC()
		observed[bucketIdx] = CertEventBucket{
			BucketStart: bucketStart,
			Issued:      issued,
			Renewed:     renewed,
			Failed:      failed,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate cert_event aggregate: %w", err)
	}

	// Second pass: emit ALL buckets in the window, including
	// empty ones, so the frontend can render a continuous
	// timeline without client-side gap-fill. Compute the bucket
	// count from the window/interval ratio (ceil to include the
	// partial trailing bucket if any).
	bucketCount := (toUnix - fromUnix + intervalSecs - 1) / intervalSecs
	out := make([]CertEventBucket, 0, bucketCount)
	for i := int64(0); i < bucketCount; i++ {
		if b, ok := observed[i]; ok {
			out = append(out, b)
			continue
		}
		out = append(out, CertEventBucket{
			BucketStart: time.Unix(fromUnix+(i*intervalSecs), 0).UTC(),
		})
	}
	return out, nil
}
