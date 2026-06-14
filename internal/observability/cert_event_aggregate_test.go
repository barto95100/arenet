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
	"testing"
	"time"
)

// Phase 5 — AggregateCertEvents tests.
//
// Pins:
//   1. Empty window → all buckets emitted, all zero counts
//   2. Multi-bucket window correctly splits Issued / Renewed
//      / Failed across day boundaries
//   3. cert_ocsp_revoked rows are NOT counted (excluded from
//      the V1 aggregate)
//   4. Bucket boundaries align with (ts - From) / Interval,
//      so a single fresh cert_obtained event lands in exactly
//      one bucket regardless of where in the window it sits
//   5. Empty buckets in the middle of the window are emitted
//      with zero counts (no client-side gap-fill required)

func TestAggregateCertEvents_EmptyWindow_AllBucketsZeroed(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Hour)
	from := now.Add(-3 * 24 * time.Hour)

	out, err := s.AggregateCertEvents(ctx, CertEventAggregateFilter{
		From:     from,
		To:       now,
		Interval: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("AggregateCertEvents: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 buckets (3-day window, 24h interval), got %d", len(out))
	}
	for i, b := range out {
		if b.Issued != 0 || b.Renewed != 0 || b.Failed != 0 {
			t.Errorf("bucket %d: want zero counts, got issued=%d renewed=%d failed=%d",
				i, b.Issued, b.Renewed, b.Failed)
		}
	}
}

func TestAggregateCertEvents_SplitsIssuedRenewedFailed(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	// Anchor "now" at the top of an hour so the bucket math is
	// deterministic regardless of wall-clock skew.
	now := time.Now().UTC().Truncate(time.Hour)
	from := now.Add(-3 * 24 * time.Hour)

	// Bucket 0 (day -3): 2 issued, 1 failed
	// Bucket 1 (day -2): 0 events
	// Bucket 2 (day -1): 1 renewed, 1 issued, 1 failed
	seedCertEvents(t, s, []CertEvent{
		{Ts: from.Add(1 * time.Hour), Level: CertEventLevelInfo, Type: CertEventTypeObtained, Domain: "a.example", Renewal: false},
		{Ts: from.Add(2 * time.Hour), Level: CertEventLevelInfo, Type: CertEventTypeObtained, Domain: "b.example", Renewal: false},
		{Ts: from.Add(3 * time.Hour), Level: CertEventLevelError, Type: CertEventTypeFailed, Domain: "c.example", Error: "rate limit"},
		// Bucket 1 intentionally empty.
		{Ts: from.Add(50 * time.Hour), Level: CertEventLevelInfo, Type: CertEventTypeObtained, Domain: "d.example", Renewal: true},
		{Ts: from.Add(51 * time.Hour), Level: CertEventLevelInfo, Type: CertEventTypeObtained, Domain: "e.example", Renewal: false},
		{Ts: from.Add(52 * time.Hour), Level: CertEventLevelError, Type: CertEventTypeFailed, Domain: "f.example", Error: "DNS-01 timeout"},
	})

	out, err := s.AggregateCertEvents(ctx, CertEventAggregateFilter{
		From:     from,
		To:       now,
		Interval: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("AggregateCertEvents: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 buckets, got %d", len(out))
	}

	if got := out[0]; got.Issued != 2 || got.Renewed != 0 || got.Failed != 1 {
		t.Errorf("bucket 0: got issued=%d renewed=%d failed=%d, want 2/0/1",
			got.Issued, got.Renewed, got.Failed)
	}
	if got := out[1]; got.Issued != 0 || got.Renewed != 0 || got.Failed != 0 {
		t.Errorf("bucket 1 (empty middle): got issued=%d renewed=%d failed=%d, want 0/0/0",
			got.Issued, got.Renewed, got.Failed)
	}
	if got := out[2]; got.Issued != 1 || got.Renewed != 1 || got.Failed != 1 {
		t.Errorf("bucket 2: got issued=%d renewed=%d failed=%d, want 1/1/1",
			got.Issued, got.Renewed, got.Failed)
	}
}

func TestAggregateCertEvents_OCSPRevokedExcluded(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Hour)
	from := now.Add(-24 * time.Hour)

	seedCertEvents(t, s, []CertEvent{
		{Ts: from.Add(1 * time.Hour), Level: CertEventLevelInfo, Type: CertEventTypeObtained, Domain: "a.example"},
		// V1 brief explicitly drops ocsp_revoked from the chart.
		// The row exists in cert_event but must not increment
		// Failed or any other counter.
		{Ts: from.Add(2 * time.Hour), Level: CertEventLevelError, Type: CertEventTypeOCSPRevoked, Domain: "b.example"},
	})

	out, err := s.AggregateCertEvents(ctx, CertEventAggregateFilter{
		From:     from,
		To:       now,
		Interval: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("AggregateCertEvents: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 bucket, got %d", len(out))
	}
	if got := out[0]; got.Issued != 1 || got.Failed != 0 {
		t.Errorf("OCSP revoked leaked into counts: got issued=%d failed=%d, want 1/0",
			got.Issued, got.Failed)
	}
}

func TestAggregateCertEvents_EmptyOrInvertedWindow_ReturnsEmpty(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	// To <= From → empty slice (not an error).
	out, err := s.AggregateCertEvents(ctx, CertEventAggregateFilter{
		From: now,
		To:   now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("AggregateCertEvents: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("inverted window: want empty slice, got %d buckets", len(out))
	}
}

func TestAggregateCertEvents_DefaultIntervalIs24h(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Hour)
	from := now.Add(-3 * 24 * time.Hour)

	// Interval omitted → defaults to 24h. 3-day window → 3 buckets.
	out, err := s.AggregateCertEvents(ctx, CertEventAggregateFilter{
		From: from,
		To:   now,
	})
	if err != nil {
		t.Fatalf("AggregateCertEvents: %v", err)
	}
	if len(out) != 3 {
		t.Errorf("default interval should yield 3 buckets on 3-day window, got %d", len(out))
	}
}

func TestAggregateCertEvents_HourlyInterval(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Hour)
	from := now.Add(-6 * time.Hour)

	// One event in each of bucket 1 and bucket 4 (relative
	// to `from`). Other buckets stay zero.
	seedCertEvents(t, s, []CertEvent{
		{Ts: from.Add(70 * time.Minute), Level: CertEventLevelInfo, Type: CertEventTypeObtained, Domain: "a.example"},
		{Ts: from.Add(4*time.Hour + 10*time.Minute), Level: CertEventLevelError, Type: CertEventTypeFailed, Domain: "b.example"},
	})

	out, err := s.AggregateCertEvents(ctx, CertEventAggregateFilter{
		From:     from,
		To:       now,
		Interval: time.Hour,
	})
	if err != nil {
		t.Fatalf("AggregateCertEvents: %v", err)
	}
	if len(out) != 6 {
		t.Fatalf("want 6 hourly buckets in 6h window, got %d", len(out))
	}
	if out[1].Issued != 1 {
		t.Errorf("bucket 1: want 1 issued, got %d", out[1].Issued)
	}
	if out[4].Failed != 1 {
		t.Errorf("bucket 4: want 1 failed, got %d", out[4].Failed)
	}
	for i, b := range out {
		if i == 1 || i == 4 {
			continue
		}
		if b.Issued+b.Renewed+b.Failed != 0 {
			t.Errorf("bucket %d should be empty, got issued=%d renewed=%d failed=%d",
				i, b.Issued, b.Renewed, b.Failed)
		}
	}
}
