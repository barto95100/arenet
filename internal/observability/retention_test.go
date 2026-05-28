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

func TestRetention_Rollup1hCorrect(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	// Seed 60 1-minute buckets for route r-a in the 10:00 hour.
	// Each minute has the same req_count=100 + fourxx=2 +
	// fivexx=1 + p95=20, so sums are deterministic: 6000 reqs,
	// 120 4xx, 60 5xx, p95 weighted = 20 (since every weight
	// equal).
	hour := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	rows := make([]MetricBucket, 0, 60)
	for i := 0; i < 60; i++ {
		rows = append(rows, MetricBucket{
			RouteID:      "r-a",
			Ts:           hour.Add(time.Duration(i) * time.Minute),
			ReqCount:     100,
			FourxxCount:  2,
			FivexxCount:  1,
			LatencyP95Ms: 20,
		})
	}
	// One bucket with a very different p95 to test the weighted
	// average is not the unweighted max.
	rows = append(rows, MetricBucket{
		RouteID:      "r-b",
		Ts:           hour.Add(0 * time.Minute),
		ReqCount:     10,
		LatencyP95Ms: 100,
	})
	rows = append(rows, MetricBucket{
		RouteID:      "r-b",
		Ts:           hour.Add(1 * time.Minute),
		ReqCount:     90,
		LatencyP95Ms: 20,
	})
	if err := s.InsertBatch(ctx, Granularity1m, rows); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Drive the runner at 11:00 (currentHour = 11:00, last
	// closed hour = 10:00).
	r := NewRetentionRunner(s, silentLogger())
	r.SetClock(func() time.Time { return time.Date(2026, 5, 28, 11, 0, 30, 0, time.UTC) })
	// lastRollupHour starts at currentHour-1h-1h = 09:00 so
	// the catch-up loop picks 10:00.
	r.lastRollupHour = time.Date(2026, 5, 28, 9, 0, 0, 0, time.UTC)

	r.Tick(ctx)

	gotA, err := s.Query(ctx, Granularity1h, "r-a", hour, hour.Add(time.Hour))
	if err != nil {
		t.Fatalf("Query r-a 1h: %v", err)
	}
	if len(gotA) != 1 {
		t.Fatalf("r-a 1h rows = %d, want 1: %+v", len(gotA), gotA)
	}
	if gotA[0].ReqCount != 6000 {
		t.Fatalf("r-a ReqCount = %d, want 6000", gotA[0].ReqCount)
	}
	if gotA[0].FourxxCount != 120 {
		t.Fatalf("r-a FourxxCount = %d, want 120", gotA[0].FourxxCount)
	}
	if gotA[0].FivexxCount != 60 {
		t.Fatalf("r-a FivexxCount = %d, want 60", gotA[0].FivexxCount)
	}
	if gotA[0].LatencyP95Ms != 20 {
		t.Fatalf("r-a LatencyP95Ms = %d, want 20 (uniform input)", gotA[0].LatencyP95Ms)
	}

	// r-b weighted p95: (10*100 + 90*20) / (10+90) = 2800/100 = 28.
	// NOT the unweighted max of 100 — that's the
	// approximation contract per AC #2.
	gotB, err := s.Query(ctx, Granularity1h, "r-b", hour, hour.Add(time.Hour))
	if err != nil {
		t.Fatalf("Query r-b 1h: %v", err)
	}
	if len(gotB) != 1 {
		t.Fatalf("r-b 1h rows = %d, want 1", len(gotB))
	}
	if gotB[0].LatencyP95Ms != 28 {
		t.Fatalf("r-b LatencyP95Ms = %d, want 28 (weighted, NOT unweighted max 100)", gotB[0].LatencyP95Ms)
	}
}

func TestRetention_Prune1mOlder24h(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	rows := []MetricBucket{
		// 25h ago — should be pruned.
		{RouteID: "r-a", Ts: now.Add(-25 * time.Hour), ReqCount: 1},
		// 23h ago — should be kept.
		{RouteID: "r-a", Ts: now.Add(-23 * time.Hour), ReqCount: 2},
		// Current — kept.
		{RouteID: "r-a", Ts: now, ReqCount: 3},
	}
	if err := s.InsertBatch(ctx, Granularity1m, rows); err != nil {
		t.Fatalf("seed: %v", err)
	}

	r := NewRetentionRunner(s, silentLogger())
	r.SetClock(func() time.Time { return now })
	// Suppress rollup catch-up for this test (set
	// lastRollupHour to the current hour so the for-loop
	// doesn't iterate).
	r.lastRollupHour = now.Truncate(time.Hour)
	r.Tick(ctx)

	got, err := s.Query(ctx, Granularity1m, "r-a", now.Add(-30*time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Query post-prune: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("post-prune rows = %d, want 2 (pruned the 25h-old one): %+v", len(got), got)
	}
	for _, b := range got {
		if b.Ts.Before(now.Add(-24 * time.Hour)) {
			t.Fatalf("row survived prune that should have been deleted: %+v", b)
		}
	}
}

func TestRetention_Prune1hOlder30d(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	rows := []MetricBucket{
		// 31d ago — pruned.
		{RouteID: "r-a", Ts: now.Add(-31 * 24 * time.Hour), ReqCount: 1},
		// 29d ago — kept.
		{RouteID: "r-a", Ts: now.Add(-29 * 24 * time.Hour), ReqCount: 2},
	}
	if err := s.InsertBatch(ctx, Granularity1h, rows); err != nil {
		t.Fatalf("seed: %v", err)
	}

	r := NewRetentionRunner(s, silentLogger())
	r.SetClock(func() time.Time { return now })
	r.lastRollupHour = now.Truncate(time.Hour)
	r.Tick(ctx)

	got, err := s.Query(ctx, Granularity1h, "r-a", now.Add(-365*24*time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Query post-prune: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("post-prune 1h rows = %d, want 1", len(got))
	}
	if got[0].Ts.Before(now.Add(-30 * 24 * time.Hour)) {
		t.Fatalf("row survived 30d prune: %+v", got[0])
	}
}

func TestRetention_RollupSkipsAlreadyDone(t *testing.T) {
	// Anti-regression for double-rollup on restart: lastRollupHour
	// already set to the previous hour means the next Tick
	// must NOT re-aggregate it.
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	hour := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	if err := s.InsertBatch(ctx, Granularity1m, []MetricBucket{
		{RouteID: "r-a", Ts: hour, ReqCount: 100, LatencyP95Ms: 10},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	r := NewRetentionRunner(s, silentLogger())
	r.SetClock(func() time.Time { return hour.Add(2 * time.Hour) })
	// Mark 10:00 as already rolled up.
	r.lastRollupHour = hour
	r.Tick(ctx)

	got, _ := s.Query(ctx, Granularity1h, "r-a", hour, hour.Add(time.Hour))
	if len(got) != 0 {
		t.Fatalf("rollup re-ran on already-rolled-up hour: %+v", got)
	}
}
