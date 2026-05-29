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

func seedEvents(t *testing.T, s *Store, events []WafEvent) {
	t.Helper()
	if err := s.InsertWafEventBatch(context.Background(), events); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestWafEvent_InsertAndQuery_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	seedEvents(t, s, []WafEvent{
		{Ts: t0, RouteID: "r-a", RuleID: "942100", Category: "SQLi", Severity: 4,
			SrcIP: "1.2.3.4", RequestMethod: "GET", RequestPath: "/?id=1' OR 1=1", PayloadSample: "id=1' OR 1=1"},
		{Ts: t0.Add(time.Minute), RouteID: "r-a", RuleID: "941100", Category: "XSS", Severity: 3,
			SrcIP: "5.6.7.8", RequestMethod: "POST", RequestPath: "/search", PayloadSample: "<script>"},
		{Ts: t0.Add(2 * time.Minute), RouteID: "r-b", RuleID: "942100", Category: "SQLi", Severity: 4,
			SrcIP: "1.2.3.4", RequestMethod: "GET", RequestPath: "/x", PayloadSample: "x"},
	})

	// Unfiltered → 3 rows, ts-descending.
	got, err := s.QueryWafEvents(ctx, WafEventFilter{})
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
	// Field round-trip.
	if got[0].RuleID != "942100" && got[0].RuleID != "941100" {
		// Most recent is at t0+2m, route r-b, rule 942100.
		t.Logf("most recent: %+v", got[0])
	}
	if got[0].RouteID != "r-b" || got[0].Category != "SQLi" {
		t.Errorf("most recent row mismatch: %+v", got[0])
	}
}

func TestWafEvent_FilterByRoute(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	seedEvents(t, s, []WafEvent{
		{Ts: t0, RouteID: "r-a", RuleID: "1", Category: "SQLi"},
		{Ts: t0.Add(time.Minute), RouteID: "r-b", RuleID: "1", Category: "SQLi"},
		{Ts: t0.Add(2 * time.Minute), RouteID: "r-a", RuleID: "2", Category: "XSS"},
	})
	got, _ := s.QueryWafEvents(ctx, WafEventFilter{RouteID: "r-a"})
	if len(got) != 2 {
		t.Fatalf("r-a filter rows = %d, want 2", len(got))
	}
	for _, e := range got {
		if e.RouteID != "r-a" {
			t.Errorf("filter leak: %+v", e)
		}
	}
}

func TestWafEvent_FilterByCategory(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	seedEvents(t, s, []WafEvent{
		{Ts: t0, RouteID: "r-a", RuleID: "942100", Category: "SQLi"},
		{Ts: t0.Add(time.Minute), RouteID: "r-a", RuleID: "941100", Category: "XSS"},
		{Ts: t0.Add(2 * time.Minute), RouteID: "r-b", RuleID: "942200", Category: "SQLi"},
	})
	got, _ := s.QueryWafEvents(ctx, WafEventFilter{Category: "SQLi"})
	if len(got) != 2 {
		t.Fatalf("SQLi filter rows = %d, want 2", len(got))
	}
}

func TestWafEvent_FilterByTimeRange(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	seedEvents(t, s, []WafEvent{
		{Ts: t0.Add(-1 * time.Hour), RouteID: "r", RuleID: "1", Category: "SQLi"},
		{Ts: t0, RouteID: "r", RuleID: "1", Category: "SQLi"},
		{Ts: t0.Add(time.Hour), RouteID: "r", RuleID: "1", Category: "SQLi"},
	})
	got, _ := s.QueryWafEvents(ctx, WafEventFilter{
		From: t0.Add(-30 * time.Minute),
		To:   t0.Add(30 * time.Minute),
	})
	if len(got) != 1 {
		t.Fatalf("time-range rows = %d, want 1 (only t0 falls in [t0-30m, t0+30m))", len(got))
	}
}

func TestWafEvent_LimitClampedToCap(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	// Seed 200 rows; the cap should clamp the result to 100.
	events := make([]WafEvent, 200)
	for i := range events {
		events[i] = WafEvent{
			Ts: t0.Add(time.Duration(i) * time.Second),
			RouteID: "r", RuleID: "1", Category: "SQLi",
		}
	}
	seedEvents(t, s, events)

	// Ask for 500 → server clamps to wafEventLimitCap (100).
	got, _ := s.QueryWafEvents(ctx, WafEventFilter{Limit: 500})
	if len(got) != wafEventLimitCap {
		t.Fatalf("Limit=500 should clamp to %d, got %d", wafEventLimitCap, len(got))
	}
	// Limit=0 (unset) ALSO defaults to the cap.
	got, _ = s.QueryWafEvents(ctx, WafEventFilter{})
	if len(got) != wafEventLimitCap {
		t.Fatalf("Limit=0 (default) should yield %d rows, got %d", wafEventLimitCap, len(got))
	}
}

func TestWafEvent_PruneOlderThan(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	seedEvents(t, s, []WafEvent{
		{Ts: now.Add(-31 * 24 * time.Hour), RouteID: "r", RuleID: "1", Category: "SQLi"}, // stale
		{Ts: now.Add(-29 * 24 * time.Hour), RouteID: "r", RuleID: "1", Category: "SQLi"}, // kept
		{Ts: now, RouteID: "r", RuleID: "1", Category: "SQLi"},                            // kept
	})
	n, err := s.PruneWafEventsOlderThan(ctx, now.Add(-30*24*time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d rows, want 1", n)
	}
	got, _ := s.QueryWafEvents(ctx, WafEventFilter{})
	if len(got) != 2 {
		t.Fatalf("post-prune rows = %d, want 2", len(got))
	}
}

func TestWafEvent_EmptyBatch_NoOp(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	if err := s.InsertWafEventBatch(ctx, nil); err != nil {
		t.Fatalf("nil batch: %v", err)
	}
	if err := s.InsertWafEventBatch(ctx, []WafEvent{}); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
}
