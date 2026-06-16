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
	"path/filepath"
	"testing"
	"time"
)

// AL.4.a — alert_event storage layer pinning tests.

func newAlertStoreT(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(context.Background(), filepath.Join(dir, "metrics.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seedAlertEvent(t *testing.T, s *Store, eventID string, ts time.Time, severity int) {
	t.Helper()
	err := s.InsertAlertEvent(context.Background(), AlertEvent{
		EventID:           eventID,
		Ts:                ts,
		RuleID:            "rule-1",
		RuleName:          "test-rule",
		Severity:          severity,
		Category:          "waf",
		Subject:           "subj " + eventID,
		Body:              "body",
		ContextJSON:       "",
		LabelsJSON:        "",
		ChannelsFiredJSON: `["ch-1"]`,
	})
	if err != nil {
		t.Fatalf("seed %q: %v", eventID, err)
	}
}

func TestAlertEvent_InsertRoundTrip(t *testing.T) {
	s := newAlertStoreT(t)
	ts := time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC)
	seedAlertEvent(t, s, "evt-1", ts, 1)

	got, _, err := s.QueryAlertEvents(context.Background(), AlertEventFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d want 1", len(got))
	}
	if got[0].EventID != "evt-1" {
		t.Errorf("EventID=%q want evt-1", got[0].EventID)
	}
	if !got[0].Ts.Equal(ts) {
		t.Errorf("Ts=%v want %v", got[0].Ts, ts)
	}
	if got[0].ChannelsFiredJSON != `["ch-1"]` {
		t.Errorf("ChannelsFiredJSON=%q", got[0].ChannelsFiredJSON)
	}
}

func TestAlertEvent_Insert_EmptyEventID(t *testing.T) {
	s := newAlertStoreT(t)
	err := s.InsertAlertEvent(context.Background(), AlertEvent{})
	if err == nil {
		t.Errorf("nil err on empty EventID; want error")
	}
}

func TestAlertEvent_Insert_DuplicateEventIDIsNoOp(t *testing.T) {
	// UNIQUE constraint on event_id + ON CONFLICT DO NOTHING
	// should make a duplicate insert silently succeed (no
	// double-row, no error).
	s := newAlertStoreT(t)
	ts := time.Now().UTC()
	seedAlertEvent(t, s, "dup", ts, 1)
	// Re-insert same event_id with different body — should
	// not error, must not write a second row, original row
	// preserved.
	err := s.InsertAlertEvent(context.Background(), AlertEvent{
		EventID:  "dup",
		Ts:       ts.Add(time.Hour),
		RuleID:   "rule-x",
		RuleName: "overwrite-attempt",
		Severity: 3,
		Subject:  "second insert",
	})
	if err != nil {
		t.Fatalf("dup insert: %v", err)
	}
	got, _, _ := s.QueryAlertEvents(context.Background(), AlertEventFilter{Limit: 10})
	if len(got) != 1 {
		t.Errorf("len=%d after duplicate; want 1 (ON CONFLICT DO NOTHING)", len(got))
	}
	if got[0].Subject != "subj dup" {
		t.Errorf("original row clobbered by duplicate; subj=%q", got[0].Subject)
	}
}

func TestAlertEvent_Query_FilterBySeverity(t *testing.T) {
	s := newAlertStoreT(t)
	ts := time.Now().UTC()
	seedAlertEvent(t, s, "info", ts, 0)
	seedAlertEvent(t, s, "warn", ts, 1)
	seedAlertEvent(t, s, "crit", ts, 2)

	want := 2
	got, _, err := s.QueryAlertEvents(context.Background(), AlertEventFilter{
		Severity: &want, Limit: 10,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("severity filter len=%d want 1", len(got))
	}
	if got[0].EventID != "crit" {
		t.Errorf("EventID=%q want crit", got[0].EventID)
	}
}

func TestAlertEvent_Query_FilterByRuleID(t *testing.T) {
	s := newAlertStoreT(t)
	ts := time.Now().UTC()
	err := s.InsertAlertEvent(context.Background(), AlertEvent{
		EventID: "evt-a", Ts: ts, RuleID: "rule-a", RuleName: "a", Severity: 1, Category: "cat", Subject: "s",
	})
	if err != nil {
		t.Fatalf("seed a: %v", err)
	}
	err = s.InsertAlertEvent(context.Background(), AlertEvent{
		EventID: "evt-b", Ts: ts, RuleID: "rule-b", RuleName: "b", Severity: 1, Category: "cat", Subject: "s",
	})
	if err != nil {
		t.Fatalf("seed b: %v", err)
	}
	got, _, _ := s.QueryAlertEvents(context.Background(), AlertEventFilter{
		RuleID: "rule-b", Limit: 10,
	})
	if len(got) != 1 || got[0].EventID != "evt-b" {
		t.Errorf("RuleID filter mismatch: %+v", got)
	}
}

func TestAlertEvent_Query_DateRange(t *testing.T) {
	s := newAlertStoreT(t)
	base := time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC)
	seedAlertEvent(t, s, "early", base, 1)
	seedAlertEvent(t, s, "mid", base.Add(time.Hour), 1)
	seedAlertEvent(t, s, "late", base.Add(2*time.Hour), 1)

	got, _, _ := s.QueryAlertEvents(context.Background(), AlertEventFilter{
		From: base.Add(30 * time.Minute), // exclusive of early
		To:   base.Add(90 * time.Minute), // exclusive of late
		Limit: 10,
	})
	if len(got) != 1 || got[0].EventID != "mid" {
		t.Errorf("date range mismatch: got %+v", got)
	}
}

func TestAlertEvent_Query_PaginationCursor(t *testing.T) {
	s := newAlertStoreT(t)
	base := time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC)
	// 5 events, distinct timestamps so order is deterministic.
	for i := 0; i < 5; i++ {
		seedAlertEvent(t, s, "e"+string(rune('0'+i)), base.Add(time.Duration(i)*time.Second), 1)
	}

	// Page 1: limit=3 → 3 most recent (e4, e3, e2).
	page1, nextCursor, err := s.QueryAlertEvents(context.Background(), AlertEventFilter{Limit: 3})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1) != 3 {
		t.Fatalf("page1 len=%d want 3", len(page1))
	}
	if nextCursor == "" {
		t.Fatalf("nextCursor empty on full page; want continuation token")
	}
	if page1[0].EventID != "e4" || page1[2].EventID != "e2" {
		t.Errorf("page1 ordering wrong: %s, %s, %s",
			page1[0].EventID, page1[1].EventID, page1[2].EventID)
	}

	// Page 2: cursor → 2 remaining (e1, e0). Empty nextCursor
	// (short page).
	page2, nextCursor2, err := s.QueryAlertEvents(context.Background(), AlertEventFilter{
		Limit: 3, Cursor: nextCursor,
	})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2) != 2 {
		t.Fatalf("page2 len=%d want 2", len(page2))
	}
	if page2[0].EventID != "e1" || page2[1].EventID != "e0" {
		t.Errorf("page2 ordering wrong: %s, %s",
			page2[0].EventID, page2[1].EventID)
	}
	if nextCursor2 != "" {
		t.Errorf("nextCursor2=%q want empty on final page", nextCursor2)
	}
}

func TestAlertEvent_Query_InvalidCursor(t *testing.T) {
	s := newAlertStoreT(t)
	_, _, err := s.QueryAlertEvents(context.Background(), AlertEventFilter{
		Cursor: "not-valid-base64!!", Limit: 10,
	})
	if err == nil {
		t.Errorf("nil err on bad cursor; want error")
	}
}

func TestAlertEvent_Prune(t *testing.T) {
	s := newAlertStoreT(t)
	old := time.Now().UTC().Add(-48 * time.Hour)
	recent := time.Now().UTC().Add(-1 * time.Hour)
	seedAlertEvent(t, s, "old", old, 1)
	seedAlertEvent(t, s, "recent", recent, 1)

	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	n, err := s.PruneAlertEventsOlderThan(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned=%d want 1", n)
	}
	got, _, _ := s.QueryAlertEvents(context.Background(), AlertEventFilter{Limit: 10})
	if len(got) != 1 || got[0].EventID != "recent" {
		t.Errorf("after prune got %+v; want only [recent]", got)
	}
}

func TestAlertEvent_CursorEncodeDecode(t *testing.T) {
	ts := time.Date(2026, 6, 16, 12, 34, 56, 0, time.UTC)
	enc := encodeAlertEventCursor(ts, 12345)
	gotTs, gotID, err := decodeAlertEventCursor(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gotTs != ts.Unix() {
		t.Errorf("ts=%d want %d", gotTs, ts.Unix())
	}
	if gotID != 12345 {
		t.Errorf("id=%d want 12345", gotID)
	}
}
