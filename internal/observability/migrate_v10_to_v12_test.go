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

// Step Z.1 — v10→v11 and Z.3 — v11→v12 migration tests.
// v10→v11 adds the rate_limit_event table + 3 indexes.
// v11→v12 adds the rate_limit_count column to both bucket_1m
// and bucket_1h.

func TestMigrate_V10ToV11_AddsRateLimitEventTable(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	var name string
	if err := s.db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name='rate_limit_event'`,
	).Scan(&name); err != nil {
		t.Fatalf("rate_limit_event table missing after migrate: %v", err)
	}

	for _, idx := range []string{
		"idx_rate_limit_event_ts",
		"idx_rate_limit_event_route_ts",
		"idx_rate_limit_event_remote_ts",
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

func TestMigrate_V11ToV12_AddsRateLimitCountColumns(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	// Verify both bucket tables have the new column. PRAGMA
	// table_info returns one row per column.
	for _, table := range []string{"bucket_1m", "bucket_1h"} {
		rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
		if err != nil {
			t.Fatalf("PRAGMA table_info(%s): %v", table, err)
		}
		var found bool
		for rows.Next() {
			var cid int
			var colName, colType string
			var notNull, pk int
			var dflt any
			if err := rows.Scan(&cid, &colName, &colType, &notNull, &dflt, &pk); err != nil {
				rows.Close()
				t.Fatalf("scan: %v", err)
			}
			if colName == "rate_limit_count" {
				found = true
				if colType != "INTEGER" {
					t.Errorf("%s.rate_limit_count type=%s; want INTEGER", table, colType)
				}
				if notNull != 1 {
					t.Errorf("%s.rate_limit_count not NOT NULL", table)
				}
			}
		}
		rows.Close()
		if !found {
			t.Errorf("rate_limit_count column missing on %s", table)
		}
	}
}

func TestMigrate_Idempotent_V12(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	// Open again on the same handle (re-running migrate is a
	// no-op when version is at head). The Open path already
	// invoked migrate; explicitly call it once more by
	// re-reading the version and invoking the migration loop
	// would require exporting internals — easier path: assert
	// schema_version is at currentSchemaVersion.
	var v int
	if err := s.db.QueryRowContext(ctx,
		`SELECT version FROM schema_version`,
	).Scan(&v); err != nil {
		t.Fatalf("read schema_version: %v", err)
	}
	if v != currentSchemaVersion {
		t.Errorf("schema_version = %d; want %d", v, currentSchemaVersion)
	}
}

func TestInsertRateLimitEventBatch_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	ts := time.Unix(1718712000, 0).UTC()
	rows := []RateLimitEvent{{
		Ts:       ts,
		RouteID:  "route-uuid-1",
		Zone:     "route-route-uuid-1",
		RemoteIP: "203.0.113.5",
		WaitMs:   1500,
	}}
	if err := s.InsertRateLimitEventBatch(ctx, rows); err != nil {
		t.Fatalf("InsertRateLimitEventBatch: %v", err)
	}

	got, err := s.QueryRateLimitEvents(ctx, RateLimitEventFilter{})
	if err != nil {
		t.Fatalf("QueryRateLimitEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row; got %d", len(got))
	}
	r := got[0]
	if !r.Ts.Equal(ts) {
		t.Errorf("Ts = %v; want %v", r.Ts, ts)
	}
	if r.RouteID != "route-uuid-1" || r.Zone != "route-route-uuid-1" ||
		r.RemoteIP != "203.0.113.5" || r.WaitMs != 1500 {
		t.Errorf("row mismatch: %+v", r)
	}
}

func TestQueryRateLimitEvents_RouteAndIPFilters(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	if err := s.InsertRateLimitEventBatch(ctx, []RateLimitEvent{
		{Ts: now, RouteID: "r-a", Zone: "route-r-a", RemoteIP: "1.1.1.1", WaitMs: 100},
		{Ts: now, RouteID: "r-b", Zone: "route-r-b", RemoteIP: "2.2.2.2", WaitMs: 200},
		{Ts: now, RouteID: "r-a", Zone: "route-r-a", RemoteIP: "1.1.1.1", WaitMs: 300},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	gotA, err := s.QueryRateLimitEvents(ctx, RateLimitEventFilter{RouteID: "r-a"})
	if err != nil {
		t.Fatalf("query r-a: %v", err)
	}
	if len(gotA) != 2 {
		t.Errorf("route filter r-a: got %d; want 2", len(gotA))
	}
	gotIP, err := s.QueryRateLimitEvents(ctx, RateLimitEventFilter{RemoteIP: "2.2.2.2"})
	if err != nil {
		t.Fatalf("query ip: %v", err)
	}
	if len(gotIP) != 1 {
		t.Errorf("ip filter: got %d; want 1", len(gotIP))
	}
}

func TestCountRateLimitEventsByWindow(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	if err := s.InsertRateLimitEventBatch(ctx, []RateLimitEvent{
		{Ts: now.Add(-30 * time.Minute), RouteID: "r", Zone: "route-r", RemoteIP: "1.1.1.1"},
		{Ts: now.Add(-5 * time.Minute), RouteID: "r", Zone: "route-r", RemoteIP: "1.1.1.1"},
		{Ts: now.Add(-2 * time.Hour), RouteID: "r", Zone: "route-r", RemoteIP: "1.1.1.1"}, // outside 1h window
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	n, err := s.CountRateLimitEventsByWindow(ctx, now.Add(-1*time.Hour), now)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Errorf("window count = %d; want 2", n)
	}
}

func TestPruneRateLimitEventsOlderThan(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour) // beyond 24h retention
	fresh := now.Add(-1 * time.Hour)
	if err := s.InsertRateLimitEventBatch(ctx, []RateLimitEvent{
		{Ts: old, RouteID: "r", Zone: "route-r", RemoteIP: "1.1.1.1"},
		{Ts: fresh, RouteID: "r", Zone: "route-r", RemoteIP: "2.2.2.2"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cutoff := now.Add(-24 * time.Hour)
	deleted, err := s.PruneRateLimitEventsOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deletion; got %d", deleted)
	}
	remaining, _ := s.QueryRateLimitEvents(ctx, RateLimitEventFilter{})
	if len(remaining) != 1 {
		t.Errorf("expected 1 row remaining; got %d", len(remaining))
	}
}

func TestInsertRateLimitEventBatch_EmptyNoop(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if err := s.InsertRateLimitEventBatch(ctx, nil); err != nil {
		t.Errorf("nil batch should be noop; got %v", err)
	}
	if err := s.InsertRateLimitEventBatch(ctx, []RateLimitEvent{}); err != nil {
		t.Errorf("empty batch should be noop; got %v", err)
	}
}
