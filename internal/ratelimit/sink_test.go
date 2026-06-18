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

package ratelimit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type recordingInserter struct {
	mu      sync.Mutex
	batches [][]Event
}

func (r *recordingInserter) InsertRateLimitEventBatch(_ context.Context, events []Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]Event, len(events))
	copy(cp, events)
	r.batches = append(r.batches, cp)
	return nil
}

func (r *recordingInserter) totalEvents() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	total := 0
	for _, b := range r.batches {
		total += len(b)
	}
	return total
}

type failingInserter struct {
	err   error
	calls atomic.Uint64
}

func (f *failingInserter) InsertRateLimitEventBatch(_ context.Context, _ []Event) error {
	f.calls.Add(1)
	return f.err
}

type recordingBucketCounter struct {
	mu    sync.Mutex
	bumps map[string]int
}

func newRecordingBucketCounter() *recordingBucketCounter {
	return &recordingBucketCounter{bumps: map[string]int{}}
}

func (r *recordingBucketCounter) BumpRateLimitExceeded(routeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bumps[routeID]++
}

func TestSink_Emit_NonBlockingWhenChannelFull(t *testing.T) {
	s := NewSink(nil, nil, silentLogger(), SinkConfig{
		ChannelBuffer: 1,
	})
	s.Emit(Event{RouteID: "r1"})
	s.Emit(Event{RouteID: "r1"})
	if got := s.DroppedByChannel(); got != 1 {
		t.Fatalf("DroppedByChannel = %d, want 1", got)
	}
}

func TestSink_AllEventsPersisted_NoLRUSuppression(t *testing.T) {
	// Step Z spec: NO LRU suppression — operator wants the
	// full burst shape. 10 identical events → 10 rows.
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval:  20 * time.Millisecond,
		FlushBatchSize: 100,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	defer func() { cancel(); <-s.Done() }()

	for i := 0; i < 10; i++ {
		s.Emit(Event{RouteID: "r1", RemoteIP: "1.2.3.4", WaitMs: 100})
	}
	// Wait for at least one flush tick.
	time.Sleep(80 * time.Millisecond)

	if got := rec.totalEvents(); got != 10 {
		t.Errorf("totalEvents = %d; want 10 (no LRU suppression)", got)
	}
}

func TestSink_BucketCounter_BumpedPerEvent(t *testing.T) {
	rec := &recordingInserter{}
	counter := newRecordingBucketCounter()
	s := NewSink(rec, counter, silentLogger(), SinkConfig{
		FlushInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	defer func() { cancel(); <-s.Done() }()

	s.Emit(Event{RouteID: "r-a"})
	s.Emit(Event{RouteID: "r-a"})
	s.Emit(Event{RouteID: "r-b"})
	s.Emit(Event{RouteID: ""}) // empty routeID → skip bump
	time.Sleep(80 * time.Millisecond)

	counter.mu.Lock()
	defer counter.mu.Unlock()
	if counter.bumps["r-a"] != 2 {
		t.Errorf("r-a bumps = %d; want 2", counter.bumps["r-a"])
	}
	if counter.bumps["r-b"] != 1 {
		t.Errorf("r-b bumps = %d; want 1", counter.bumps["r-b"])
	}
	if counter.bumps[""] != 0 {
		t.Errorf("empty routeID bumps = %d; want 0 (skipped)", counter.bumps[""])
	}
}

func TestSink_NilInserter_DegradedMode(t *testing.T) {
	// AC #13: nil inserter → sink drains silently, never errors.
	s := NewSink(nil, nil, silentLogger(), SinkConfig{
		FlushInterval: 10 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	defer func() { cancel(); <-s.Done() }()

	s.Emit(Event{RouteID: "r"})
	time.Sleep(50 * time.Millisecond)

	if s.FlushErrBatches() != 0 {
		t.Errorf("FlushErrBatches = %d; want 0 (nil inserter must not error)", s.FlushErrBatches())
	}
}

func TestSink_InserterError_CountedNotPropagated(t *testing.T) {
	f := &failingInserter{err: errors.New("disk full")}
	s := NewSink(f, nil, silentLogger(), SinkConfig{
		FlushInterval: 10 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	defer func() { cancel(); <-s.Done() }()

	s.Emit(Event{RouteID: "r"})
	time.Sleep(50 * time.Millisecond)

	if got := s.FlushErrBatches(); got == 0 {
		t.Errorf("FlushErrBatches = 0; want >0")
	}
	if got := f.calls.Load(); got == 0 {
		t.Errorf("inserter calls = 0; want >0")
	}
}

func TestSink_BatchSizeTrigger_FlushesBeforeTick(t *testing.T) {
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval:  10 * time.Second, // long tick → only size triggers
		FlushBatchSize: 3,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	defer func() { cancel(); <-s.Done() }()

	for i := 0; i < 3; i++ {
		s.Emit(Event{RouteID: "r"})
	}
	// Give the absorb goroutine time to schedule flush.
	time.Sleep(50 * time.Millisecond)

	if got := rec.totalEvents(); got != 3 {
		t.Errorf("totalEvents = %d; want 3 (batch-size flush trigger)", got)
	}
}

func TestSetGetGlobalSink_Roundtrip(t *testing.T) {
	defer SetGlobalSink(nil)
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval: 10 * time.Millisecond,
	})
	SetGlobalSink(s)
	got := GetGlobalSink()
	if got == nil {
		t.Fatal("GetGlobalSink returned nil after Set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	defer func() { cancel(); <-s.Done() }()
	// Emit through the global handle — must reach the same sink.
	got.Emit(Event{RouteID: "r"})
	time.Sleep(50 * time.Millisecond)
	if got := s.Emitted(); got != 1 {
		t.Errorf("Emitted via global = %d; want 1", got)
	}
}

func TestSetGlobalSink_NilClearsExisting(t *testing.T) {
	defer SetGlobalSink(nil)
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{})
	SetGlobalSink(s)
	if GetGlobalSink() == nil {
		t.Fatal("sink should be installed")
	}
	SetGlobalSink(nil)
	if GetGlobalSink() != nil {
		t.Errorf("GetGlobalSink should be nil after SetGlobalSink(nil)")
	}
}

func TestRouteIDFromZone(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"route-abc-123", "abc-123"},
		{"route-", ""},
		{"custom-zone", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := routeIDFromZone(c.in); got != c.want {
			t.Errorf("routeIDFromZone(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}
