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
	"testing"
	"time"
)

// W.4 — v7→v8 migration tests. The migration adds the
// country_block_event table + 2 indexes. Pre-W.4 databases
// have no rows in the new table; legacy rows aren't
// affected.

// TestMigrate_V7ToV8_AddsCountryBlockTable verifies that
// after Open() against a fresh in-memory DB (which migrates
// straight to v8), the country_block_event table exists
// with the expected columns.
func TestMigrate_V7ToV8_AddsCountryBlockTable(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	var name string
	if err := s.db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name='country_block_event'`,
	).Scan(&name); err != nil {
		t.Fatalf("country_block_event table missing after migrate: %v", err)
	}

	// The two indexes must also be present.
	for _, idx := range []string{
		"idx_country_block_event_ts",
		"idx_country_block_event_route_ts",
	} {
		var n int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, idx,
		).Scan(&n); err != nil {
			t.Errorf("scan index %s: %v", idx, err)
		}
		if n != 1 {
			t.Errorf("index %s missing after migrate", idx)
		}
	}
}

// TestInsertCountryBlockEventBatch_RoundTrip — write a row,
// read it back, assert every field survives the schema.
func TestInsertCountryBlockEventBatch_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	ts := time.Unix(1717689600, 0).UTC()
	rows := []CountryBlockEvent{{
		Ts:         ts,
		RouteID:    "route-uuid-1",
		SrcIP:      "203.0.113.5",
		Country:    "RU",
		Mode:       "deny",
		StatusCode: 451,
		Reason:     "deny-match",
	}}
	if err := s.InsertCountryBlockEventBatch(ctx, rows); err != nil {
		t.Fatalf("InsertCountryBlockEventBatch: %v", err)
	}

	got, err := s.QueryCountryBlockEvents(ctx, CountryBlockEventFilter{})
	if err != nil {
		t.Fatalf("QueryCountryBlockEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row; got %d", len(got))
	}
	r := got[0]
	if !r.Ts.Equal(ts) {
		t.Errorf("Ts = %v; want %v", r.Ts, ts)
	}
	if r.RouteID != "route-uuid-1" || r.SrcIP != "203.0.113.5" {
		t.Errorf("RouteID/SrcIP mismatch: %+v", r)
	}
	if r.Country != "RU" || r.Mode != "deny" || r.Reason != "deny-match" {
		t.Errorf("Country/Mode/Reason mismatch: %+v", r)
	}
	if r.StatusCode != 451 {
		t.Errorf("StatusCode = %d; want 451", r.StatusCode)
	}
}

// TestQueryCountryBlockEvents_RouteFilter pins the per-
// route drill-down filter.
func TestQueryCountryBlockEvents_RouteFilter(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	if err := s.InsertCountryBlockEventBatch(ctx, []CountryBlockEvent{
		{Ts: now, RouteID: "r-a", SrcIP: "1.1.1.1", Country: "RU", Mode: "deny", StatusCode: 403, Reason: "deny-match"},
		{Ts: now, RouteID: "r-b", SrcIP: "2.2.2.2", Country: "RU", Mode: "deny", StatusCode: 403, Reason: "deny-match"},
		{Ts: now, RouteID: "r-a", SrcIP: "3.3.3.3", Country: "KP", Mode: "deny", StatusCode: 403, Reason: "deny-match"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	gotA, err := s.QueryCountryBlockEvents(ctx, CountryBlockEventFilter{RouteID: "r-a"})
	if err != nil {
		t.Fatalf("QueryCountryBlockEvents r-a: %v", err)
	}
	if len(gotA) != 2 {
		t.Errorf("route filter r-a: got %d; want 2", len(gotA))
	}
	gotB, err := s.QueryCountryBlockEvents(ctx, CountryBlockEventFilter{RouteID: "r-b"})
	if err != nil {
		t.Fatalf("QueryCountryBlockEvents r-b: %v", err)
	}
	if len(gotB) != 1 {
		t.Errorf("route filter r-b: got %d; want 1", len(gotB))
	}
}

// TestPruneCountryBlockEventsOlderThan deletes ts < cutoff
// rows + keeps newer ones.
func TestPruneCountryBlockEventsOlderThan(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	old := now.Add(-40 * 24 * time.Hour) // beyond 30d retention
	fresh := now.Add(-1 * time.Hour)
	if err := s.InsertCountryBlockEventBatch(ctx, []CountryBlockEvent{
		{Ts: old, RouteID: "r", SrcIP: "1.1.1.1", Country: "RU", Mode: "deny", StatusCode: 403, Reason: "deny-match"},
		{Ts: fresh, RouteID: "r", SrcIP: "2.2.2.2", Country: "RU", Mode: "deny", StatusCode: 403, Reason: "deny-match"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cutoff := now.Add(-30 * 24 * time.Hour)
	deleted, err := s.PruneCountryBlockEventsOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deletion; got %d", deleted)
	}
	remaining, _ := s.QueryCountryBlockEvents(ctx, CountryBlockEventFilter{})
	if len(remaining) != 1 {
		t.Errorf("expected 1 row remaining; got %d", len(remaining))
	}
}
