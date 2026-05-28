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

func TestSchema_InitIdempotent(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "metrics.db")

	// First open creates schema.
	s1, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	v1, err := s1.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("schema version 1: %v", err)
	}
	if v1 != 1 {
		t.Fatalf("schema version = %d, want 1", v1)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close 1: %v", err)
	}

	// Second open on the same file must be a no-op (no error,
	// same schema version).
	s2, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer s2.Close()
	v2, err := s2.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("schema version 2: %v", err)
	}
	if v2 != 1 {
		t.Fatalf("after reopen schema version = %d, want 1", v2)
	}
}

func TestOpen_InMemory(t *testing.T) {
	// In-memory DB is the workhorse for the rest of the test
	// suite — verify Open accepts ":memory:" and produces a
	// usable store.
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open :memory:: %v", err)
	}
	defer s.Close()
	v, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if v != 1 {
		t.Fatalf("in-memory schema version = %d, want 1", v)
	}
}

func TestClose_NilSafe(t *testing.T) {
	// AC #13: degraded-mode boot must be able to defer Close
	// unconditionally even if Open returned nil.
	var s *Store
	if err := s.Close(); err != nil {
		t.Fatalf("nil store Close: %v", err)
	}
}

func TestStore_Insert1mAndQuery1m(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	rows := []MetricBucket{
		{RouteID: "r-a", Ts: t0.Add(0 * time.Minute), ReqCount: 100, FourxxCount: 2, FivexxCount: 1, LatencyP95Ms: 16},
		{RouteID: "r-a", Ts: t0.Add(1 * time.Minute), ReqCount: 110, FourxxCount: 3, FivexxCount: 0, LatencyP95Ms: 32},
		{RouteID: "r-b", Ts: t0.Add(0 * time.Minute), ReqCount: 50, FourxxCount: 10, FivexxCount: 5, LatencyP95Ms: 64},
	}
	if err := s.InsertBatch(ctx, Granularity1m, rows); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	// Query r-a over a 5-minute window — must return 2 rows in
	// ascending ts order, NOT include r-b's bucket.
	got, err := s.Query(ctx, Granularity1m, "r-a", t0, t0.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Query returned %d rows, want 2: %+v", len(got), got)
	}
	if got[0].Ts.Unix() > got[1].Ts.Unix() {
		t.Fatalf("rows not in ascending ts order: %v", got)
	}
	if got[0].ReqCount != 100 || got[1].ReqCount != 110 {
		t.Fatalf("ReqCount mismatch: %+v", got)
	}
	if got[0].FourxxCount != 2 || got[1].FourxxCount != 3 {
		t.Fatalf("FourxxCount mismatch: %+v", got)
	}
	if got[0].FivexxCount != 1 || got[1].FivexxCount != 0 {
		t.Fatalf("FivexxCount mismatch: %+v", got)
	}
	if got[0].LatencyP95Ms != 16 || got[1].LatencyP95Ms != 32 {
		t.Fatalf("LatencyP95Ms mismatch: %+v", got)
	}
}

func TestStore_InsertBatchUpsert(t *testing.T) {
	// Re-flush semantics: the aggregator may retry a flush
	// after a transient error. The second insert on the same
	// (route_id, ts) must overwrite, not error or duplicate.
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	first := []MetricBucket{{RouteID: "r-a", Ts: t0, ReqCount: 100, LatencyP95Ms: 16}}
	second := []MetricBucket{{RouteID: "r-a", Ts: t0, ReqCount: 200, LatencyP95Ms: 32}}

	if err := s.InsertBatch(ctx, Granularity1m, first); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := s.InsertBatch(ctx, Granularity1m, second); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := s.Query(ctx, Granularity1m, "r-a", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected upsert (1 row), got %d", len(got))
	}
	if got[0].ReqCount != 200 || got[0].LatencyP95Ms != 32 {
		t.Fatalf("upsert did not overwrite: %+v", got[0])
	}
}

func TestStore_InsertBatchEmpty(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if err := s.InsertBatch(ctx, Granularity1m, nil); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
}

func TestStore_QueryAggregated_SumsAcrossRoutes(t *testing.T) {
	// Spec-1 §10.1: aggregated timeseries for the global view.
	// Two routes, one minute apart, two minutes each → the
	// aggregated query MUST sum each counter independently
	// per bucket. p95 must be req-weighted.
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	rows := []MetricBucket{
		// Bucket t0: r-a heavy, r-b light. Weighted p95 ≠ max.
		{RouteID: "r-a", Ts: t0, ReqCount: 90, FourxxCount: 5, FivexxCount: 0, LatencyP95Ms: 20},
		{RouteID: "r-b", Ts: t0, ReqCount: 10, FourxxCount: 0, FivexxCount: 3, LatencyP95Ms: 100},
		// Bucket t0+1m: only r-a.
		{RouteID: "r-a", Ts: t0.Add(time.Minute), ReqCount: 50, FourxxCount: 2, FivexxCount: 1, LatencyP95Ms: 16},
	}
	if err := s.InsertBatch(ctx, Granularity1m, rows); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := s.QueryAggregated(ctx, Granularity1m, t0, t0.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("QueryAggregated: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("rows = %d, want 2 (one per bucket): %+v", len(got), got)
	}
	// Bucket 0: req=100, 4xx=5, 5xx=3, p95 weighted
	// = (90*20 + 10*100) / (90+10) = 2800/100 = 28. Critically
	// NOT the unweighted max of 100 — the weighting is the
	// AC #2 contract restated for the global view.
	if got[0].ReqCount != 100 || got[0].FourxxCount != 5 || got[0].FivexxCount != 3 {
		t.Errorf("bucket0 counts mismatch: %+v", got[0])
	}
	if got[0].LatencyP95Ms != 28 {
		t.Errorf("bucket0 LatencyP95Ms = %d, want 28 (weighted, NOT 100 unweighted max)", got[0].LatencyP95Ms)
	}
	// Bucket 1: just r-a. Counters as-is, p95 = 16.
	if got[1].ReqCount != 50 || got[1].FourxxCount != 2 || got[1].FivexxCount != 1 || got[1].LatencyP95Ms != 16 {
		t.Errorf("bucket1 mismatch: %+v", got[1])
	}
	// AC #3 anti-regression at the storage layer: the
	// aggregation must keep each counter independent. A 4xx
	// row from r-a must NEVER inflate r-b's 5xx total.
	if got[0].FivexxCount == 0 {
		t.Errorf("bucket0 FivexxCount should be 3 (from r-b), got 0 — aggregation lost r-b's 5xx")
	}
}

func TestStore_QueryAggregated_FourxxOnlyDoesNotContaminate5xx(t *testing.T) {
	// Reciprocal AC #3 check at the aggregation layer.
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	if err := s.InsertBatch(ctx, Granularity1m, []MetricBucket{
		{RouteID: "r-a", Ts: t0, ReqCount: 100, FourxxCount: 30, FivexxCount: 0, LatencyP95Ms: 10},
		{RouteID: "r-b", Ts: t0, ReqCount: 50, FourxxCount: 10, FivexxCount: 0, LatencyP95Ms: 10},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := s.QueryAggregated(ctx, Granularity1m, t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("QueryAggregated: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("rows = %d, want 1", len(got))
	}
	if got[0].FourxxCount != 40 {
		t.Errorf("FourxxCount aggregate = %d, want 40", got[0].FourxxCount)
	}
	if got[0].FivexxCount != 0 {
		t.Errorf("FivexxCount = %d, want 0 — a 4xx-only spike across routes MUST NOT inflate 5xx (AC #3 reciprocal)", got[0].FivexxCount)
	}
}

func TestStore_QueryAggregated_EmptyWindow(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	got, err := s.QueryAggregated(ctx, Granularity1m,
		time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 5, 28, 11, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("QueryAggregated: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty window should yield 0 rows, got %d", len(got))
	}
}

func TestStore_PruneOlderThan(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	rows := []MetricBucket{
		{RouteID: "r-a", Ts: t0.Add(-2 * time.Hour), ReqCount: 1},
		{RouteID: "r-a", Ts: t0.Add(-1 * time.Hour), ReqCount: 2},
		{RouteID: "r-a", Ts: t0, ReqCount: 3},
	}
	if err := s.InsertBatch(ctx, Granularity1m, rows); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}
	n, err := s.PruneOlderThan(ctx, Granularity1m, t0.Add(-30*time.Minute))
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 2 {
		t.Fatalf("pruned %d rows, want 2", n)
	}
	got, err := s.Query(ctx, Granularity1m, "r-a", t0.Add(-24*time.Hour), t0.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || got[0].ReqCount != 3 {
		t.Fatalf("after prune got %+v, want one row with ReqCount=3", got)
	}
}
