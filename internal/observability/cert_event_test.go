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
	"strings"
	"testing"
	"time"
)

func seedCertEvents(t *testing.T, s *Store, events []CertEvent) {
	t.Helper()
	if err := s.InsertCertEventBatch(context.Background(), events); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// TestCertEvent_InsertAndQuery_RoundTrip pins the happy path:
// every field a producer fills lands in the DB and comes back
// out via Query with the same value, in ts-descending order.
func TestCertEvent_InsertAndQuery_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	seedCertEvents(t, s, []CertEvent{
		{
			Ts: t0, Level: CertEventLevelInfo, Type: CertEventTypeObtained,
			Domain: "*.example.com", Issuer: "Let's Encrypt", Challenge: "DNS-01",
			Renewal: false,
		},
		{
			Ts: t0.Add(1 * time.Minute), Level: CertEventLevelError, Type: CertEventTypeFailed,
			Domain: "test.local", Issuer: "", Challenge: "",
			Error: "subject 'test.local' does not qualify for a public certificate",
		},
		{
			Ts: t0.Add(2 * time.Minute), Level: CertEventLevelError, Type: CertEventTypeOCSPRevoked,
			Domain: "revoked.example.com", Issuer: "Let's Encrypt",
		},
	})

	got, err := s.QueryCertEvents(ctx, CertEventFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("unfiltered rows = %d, want 3", len(got))
	}
	// AC: ordering is ts-descending.
	if !got[0].Ts.After(got[1].Ts) || !got[1].Ts.After(got[2].Ts) {
		t.Errorf("ordering: %v %v %v — want descending", got[0].Ts, got[1].Ts, got[2].Ts)
	}
	// Most recent row is the revoked.example.com OCSP entry.
	mostRecent := got[0]
	if mostRecent.Domain != "revoked.example.com" {
		t.Errorf("most recent domain = %q, want revoked.example.com", mostRecent.Domain)
	}
	if mostRecent.Type != CertEventTypeOCSPRevoked {
		t.Errorf("most recent type = %v, want OCSPRevoked", mostRecent.Type)
	}
	if mostRecent.Level != CertEventLevelError {
		t.Errorf("most recent level = %v, want Error", mostRecent.Level)
	}
	// Failed row carries the error message verbatim.
	failed := got[1]
	if failed.Domain != "test.local" {
		t.Errorf("failed row domain = %q, want test.local", failed.Domain)
	}
	if !strings.Contains(failed.Error, "does not qualify") {
		t.Errorf("failed row error = %q, want substring 'does not qualify'", failed.Error)
	}
	// Obtained row preserves Issuer + Challenge + Renewal.
	obtained := got[2]
	if obtained.Issuer != "Let's Encrypt" || obtained.Challenge != "DNS-01" || obtained.Renewal {
		t.Errorf("obtained row mismatch: %+v", obtained)
	}
}

// TestCertEvent_RenewalRoundTrip pins the boolean → INTEGER →
// boolean round-trip. The renewal flag distinguishes a first
// issuance from a successful renewal (per certmagic
// config.go:728 payload) — getting this wrong would lose the
// signal the Activity log uses to label the row.
func TestCertEvent_RenewalRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()

	t0 := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	seedCertEvents(t, s, []CertEvent{
		{Ts: t0, Type: CertEventTypeObtained, Domain: "a", Renewal: false},
		{Ts: t0.Add(time.Minute), Type: CertEventTypeObtained, Domain: "b", Renewal: true},
	})
	got, err := s.QueryCertEvents(ctx, CertEventFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("rows = %d, want 2", len(got))
	}
	// Order: b (renewal=true) first by ts.
	if got[0].Domain != "b" || !got[0].Renewal {
		t.Errorf("got[0]: %+v, want b/renewal=true", got[0])
	}
	if got[1].Domain != "a" || got[1].Renewal {
		t.Errorf("got[1]: %+v, want a/renewal=false", got[1])
	}
}

// TestCertEvent_FilterByDomain confirms the indexed
// domain-scoped drill-down used by the per-domain Activity log
// view (operator clicks a cert row in /certs → jumps to /logs
// pre-filtered by domain).
func TestCertEvent_FilterByDomain(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	seedCertEvents(t, s, []CertEvent{
		{Ts: t0, Type: CertEventTypeObtained, Domain: "a.example.com"},
		{Ts: t0.Add(time.Minute), Type: CertEventTypeObtained, Domain: "b.example.com"},
		{Ts: t0.Add(2 * time.Minute), Type: CertEventTypeFailed, Domain: "a.example.com"},
	})
	got, err := s.QueryCertEvents(ctx, CertEventFilter{Domain: "a.example.com"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("filtered rows = %d, want 2", len(got))
	}
	for _, e := range got {
		if e.Domain != "a.example.com" {
			t.Errorf("filter leaked: got domain %q", e.Domain)
		}
	}
}

// TestCertEvent_FilterByTypeAndLevel pins the combined filter
// path used by the Activity log's "errors only" segmented
// control.
func TestCertEvent_FilterByTypeAndLevel(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	seedCertEvents(t, s, []CertEvent{
		{Ts: t0, Level: CertEventLevelInfo, Type: CertEventTypeObtained, Domain: "ok"},
		{Ts: t0.Add(time.Minute), Level: CertEventLevelError, Type: CertEventTypeFailed, Domain: "bad1"},
		{Ts: t0.Add(2 * time.Minute), Level: CertEventLevelError, Type: CertEventTypeOCSPRevoked, Domain: "bad2"},
	})

	// Filter by type=cert_failed → 1 row.
	got, err := s.QueryCertEvents(ctx, CertEventFilter{Type: "cert_failed"})
	if err != nil {
		t.Fatalf("Query by type: %v", err)
	}
	if len(got) != 1 || got[0].Domain != "bad1" {
		t.Errorf("type filter: got %d rows, want 1 (bad1); first=%+v", len(got), got[0])
	}

	// Filter by level=ERROR → 2 rows.
	got, err = s.QueryCertEvents(ctx, CertEventFilter{Level: "ERROR"})
	if err != nil {
		t.Fatalf("Query by level: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("level filter: got %d rows, want 2", len(got))
	}
}

// TestCertEvent_FilterByTimeRange pins the From/To window
// filter the API layer maps from ?since= / ?until= query
// parameters.
func TestCertEvent_FilterByTimeRange(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	seedCertEvents(t, s, []CertEvent{
		{Ts: t0, Domain: "a"},
		{Ts: t0.Add(1 * time.Hour), Domain: "b"},
		{Ts: t0.Add(2 * time.Hour), Domain: "c"},
	})
	// Window [t0+30m, t0+90m) covers only b.
	got, err := s.QueryCertEvents(ctx, CertEventFilter{
		From: t0.Add(30 * time.Minute),
		To:   t0.Add(90 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || got[0].Domain != "b" {
		t.Errorf("window filter: got %d rows; first=%+v", len(got), got[0])
	}
}

// TestCertEvent_LimitCap_Clamps pins the defensive cap. A
// caller passing limit > 100 is silently clamped down to
// avoid runaway queries.
func TestCertEvent_LimitCap_Clamps(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	batch := make([]CertEvent, 0, 150)
	for i := 0; i < 150; i++ {
		batch = append(batch, CertEvent{
			Ts: t0.Add(time.Duration(i) * time.Second), Domain: "x",
		})
	}
	seedCertEvents(t, s, batch)
	got, err := s.QueryCertEvents(ctx, CertEventFilter{Limit: 500})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != certEventLimitCap {
		t.Errorf("limit=500 returned %d rows, want cap %d", len(got), certEventLimitCap)
	}
}

// TestCertEvent_EmptyBatch_NoOp pins the no-op contract: an
// empty Insert batch returns nil without opening a tx (the
// production sink flushes the empty buffer on every tick).
func TestCertEvent_EmptyBatch_NoOp(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	if err := s.InsertCertEventBatch(ctx, nil); err != nil {
		t.Errorf("InsertCertEventBatch(nil) = %v, want nil", err)
	}
	if err := s.InsertCertEventBatch(ctx, []CertEvent{}); err != nil {
		t.Errorf("InsertCertEventBatch([]) = %v, want nil", err)
	}
}

// TestPruneCertEventsOlderThan pins the 90-day retention
// boundary. Mirrors TestPruneDecisionEventsOlderThan_DeletesOlderRows
// shape: seed rows at varying ages, prune at the 90d cutoff,
// verify only the within-window rows survive AND repeat-prune
// is idempotent.
func TestPruneCertEventsOlderThan(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()

	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	cutoff := now.Add(-RetainCertEvents) // 90d horizon

	seedCertEvents(t, s, []CertEvent{
		{Ts: now.Add(-91 * 24 * time.Hour), Domain: "old", Type: CertEventTypeObtained},
		{Ts: cutoff, Domain: "boundary", Type: CertEventTypeObtained}, // strict <, survives
		{Ts: now.Add(-30 * 24 * time.Hour), Domain: "recent", Type: CertEventTypeObtained},
	})

	n, err := s.PruneCertEventsOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("PruneCertEventsOlderThan: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned n=%d, want 1 (old only — cutoff is strict <)", n)
	}

	got, err := s.QueryCertEvents(ctx, CertEventFilter{})
	if err != nil {
		t.Fatalf("Query post-prune: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("post-prune rows = %d, want 2 (boundary + recent)", len(got))
	}
	for _, e := range got {
		if e.Domain == "old" {
			t.Errorf("old row survived prune: %+v", e)
		}
	}

	// Repeat prune is idempotent.
	n, err = s.PruneCertEventsOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("repeat PruneCertEventsOlderThan: %v", err)
	}
	if n != 0 {
		t.Errorf("repeat prune n=%d, want 0 (idempotent)", n)
	}
}

// TestCertEventType_StringRoundTrip pins the on-wire token
// stability the Activity log filter relies on (search "cert_failed"
// matches the typed token verbatim).
func TestCertEventType_StringRoundTrip(t *testing.T) {
	cases := []struct {
		in   CertEventType
		want string
	}{
		{CertEventTypeObtained, "cert_obtained"},
		{CertEventTypeFailed, "cert_failed"},
		{CertEventTypeOCSPRevoked, "cert_ocsp_revoked"},
	}
	for _, tc := range cases {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("String(%v) = %q, want %q", tc.in, got, tc.want)
		}
		if got := ParseCertEventType(tc.want); got != tc.in {
			t.Errorf("Parse(%q) = %v, want %v", tc.want, got, tc.in)
		}
	}
}

// TestCertEventLevel_StringRoundTrip pins the level token
// stability — the frontend's level filter matches on the
// uppercase string verbatim.
func TestCertEventLevel_StringRoundTrip(t *testing.T) {
	cases := []struct {
		in   CertEventLevel
		want string
	}{
		{CertEventLevelInfo, "INFO"},
		{CertEventLevelError, "ERROR"},
	}
	for _, tc := range cases {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("String(%v) = %q, want %q", tc.in, got, tc.want)
		}
		if got := ParseCertEventLevel(tc.want); got != tc.in {
			t.Errorf("Parse(%q) = %v, want %v", tc.want, got, tc.in)
		}
	}
	// Unknown input falls back to Info defensively.
	if got := ParseCertEventLevel("not-a-level"); got != CertEventLevelInfo {
		t.Errorf("Parse(invalid) = %v, want Info fallback", got)
	}
}

// --- U.3 storage extensions: Search + CountCertEvents -----------------------

// TestQueryCertEvents_SearchCaseInsensitive pins the LIKE
// %X% COLLATE NOCASE behavior across the four searchable
// columns. The Activity log textbox matches operator queries
// like "let's encrypt" against rows that store "Let's
// Encrypt", and "cert" against the event_type token (but the
// search is column-scoped — event_type is NOT in the search
// set; the operator filters event types via the dedicated
// `level` parameter).
func TestQueryCertEvents_SearchCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()

	t0 := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	seedCertEvents(t, s, []CertEvent{
		{Ts: t0, Type: CertEventTypeObtained, Domain: "ApI.example.com", Issuer: "Let's Encrypt"},
		{Ts: t0.Add(time.Minute), Type: CertEventTypeFailed, Domain: "test.local", Error: "Subject DOES NOT qualify for a public CERTIFICATE"},
		{Ts: t0.Add(2 * time.Minute), Type: CertEventTypeObtained, Domain: "other.com", Issuer: "ZeroSSL", Details: "ARI hint: retry-after 24h"},
	})

	cases := []struct {
		name        string
		search      string
		wantDomains []string
	}{
		{"matches domain case-insensitive", "API.EXAMPLE", []string{"ApI.example.com"}},
		{"matches issuer case-insensitive", "let's encrypt", []string{"ApI.example.com"}},
		{"matches error_msg case-insensitive", "qualify for a public", []string{"test.local"}},
		{"matches details case-insensitive", "retry-after", []string{"other.com"}},
		{"non-matching needle returns empty", "no-such-substring", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.QueryCertEvents(ctx, CertEventFilter{Search: tc.search})
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if len(got) != len(tc.wantDomains) {
				t.Fatalf("len=%d want=%d", len(got), len(tc.wantDomains))
			}
			for i, e := range got {
				if e.Domain != tc.wantDomains[i] {
					t.Errorf("row[%d].Domain=%q want=%q", i, e.Domain, tc.wantDomains[i])
				}
			}
		})
	}
}

// TestQueryCertEvents_LevelsMulti pins the U.3 multi-level
// filter: Levels=[INFO, ERROR] returns everything,
// Levels=[ERROR] returns only ERROR rows. Falls back to
// single-Level when Levels is empty.
func TestQueryCertEvents_LevelsMulti(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()

	t0 := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	seedCertEvents(t, s, []CertEvent{
		{Ts: t0, Level: CertEventLevelInfo, Type: CertEventTypeObtained, Domain: "ok"},
		{Ts: t0.Add(time.Minute), Level: CertEventLevelError, Type: CertEventTypeFailed, Domain: "bad"},
	})

	// Both levels via Levels=[INFO, ERROR] → 2 rows.
	got, err := s.QueryCertEvents(ctx, CertEventFilter{
		Levels: []CertEventLevel{CertEventLevelInfo, CertEventLevelError},
	})
	if err != nil {
		t.Fatalf("Query both levels: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("multi-level = %d rows, want 2", len(got))
	}

	// ERROR only via Levels=[ERROR] → 1 row.
	got, err = s.QueryCertEvents(ctx, CertEventFilter{
		Levels: []CertEventLevel{CertEventLevelError},
	})
	if err != nil {
		t.Fatalf("Query ERROR: %v", err)
	}
	if len(got) != 1 || got[0].Domain != "bad" {
		t.Errorf("ERROR-only = %d rows; first.Domain=%q want=bad", len(got), got[0].Domain)
	}
}

// TestQueryCertEvents_LevelsTakesPrecedenceOverLevel: when
// both single Level and Levels are set, Levels wins. The
// HTTP handler only sets Levels; this pins the storage
// contract so an internal caller mixing both gets the
// documented behavior.
func TestQueryCertEvents_LevelsTakesPrecedenceOverLevel(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	seedCertEvents(t, s, []CertEvent{
		{Ts: t0, Level: CertEventLevelInfo, Domain: "info"},
		{Ts: t0.Add(time.Minute), Level: CertEventLevelError, Domain: "err"},
	})

	// Level="INFO" would normally return 1; Levels=[ERROR]
	// overrides and returns the ERROR row only.
	got, err := s.QueryCertEvents(ctx, CertEventFilter{
		Level:  "INFO",
		Levels: []CertEventLevel{CertEventLevelError},
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || got[0].Domain != "err" {
		t.Errorf("precedence: got %d rows; first=%+v", len(got), got[0])
	}
}

// TestCountCertEvents_MatchesQueryTotal pins the invariant
// the U.3 handler relies on: CountCertEvents returns the same
// number QueryCertEvents would return if Limit weren't
// applied. Filter must be honored identically.
func TestCountCertEvents_MatchesQueryTotal(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()

	t0 := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	batch := make([]CertEvent, 0, 50)
	for i := 0; i < 50; i++ {
		batch = append(batch, CertEvent{
			Ts:     t0.Add(time.Duration(i) * time.Second),
			Type:   CertEventTypeObtained,
			Domain: "x",
		})
	}
	seedCertEvents(t, s, batch)

	// No filter: Count == 50.
	total, err := s.CountCertEvents(ctx, CertEventFilter{})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if total != 50 {
		t.Errorf("Count = %d, want 50", total)
	}

	// Limited query still gets capped, but Count is unaffected
	// — that's the whole point of the separate primitive.
	got, _ := s.QueryCertEvents(ctx, CertEventFilter{Limit: 10})
	if len(got) != 10 {
		t.Errorf("Query Limit=10 returned %d", len(got))
	}
	total, _ = s.CountCertEvents(ctx, CertEventFilter{Limit: 10})
	if total != 50 {
		t.Errorf("Count with Limit=10 = %d, want 50 (Count ignores Limit)", total)
	}
}

// TestCountCertEvents_HonorsSearchFilter pins that the
// Search filter applies to Count the same way it does to
// Query — required for HasMore to compute correctly when
// the operator searches.
func TestCountCertEvents_HonorsSearchFilter(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	seedCertEvents(t, s, []CertEvent{
		{Ts: t0, Domain: "a.example.com", Issuer: "Let's Encrypt"},
		{Ts: t0.Add(time.Minute), Domain: "b.example.com", Issuer: "ZeroSSL"},
		{Ts: t0.Add(2 * time.Minute), Domain: "c.example.com", Issuer: "Let's Encrypt"},
	})

	total, err := s.CountCertEvents(ctx, CertEventFilter{Search: "let's encrypt"})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if total != 2 {
		t.Errorf("Count with Search='lets encrypt' = %d, want 2", total)
	}
}

// TestCountCertEvents_EmptyTable pins the boundary: Count on
// an empty table returns 0 without error.
func TestCountCertEvents_EmptyTable(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	total, err := s.CountCertEvents(ctx, CertEventFilter{})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if total != 0 {
		t.Errorf("Count empty table = %d, want 0", total)
	}
}
