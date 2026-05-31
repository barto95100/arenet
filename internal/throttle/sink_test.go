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

package throttle

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// silentLogger discards log output during tests so the
// verbose error logs don't drown the test runner.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// recordingInserter captures every batch the sink flushes.
// Thread-safe so tests that drive Run + Emit from multiple
// goroutines can assert post-hoc.
type recordingInserter struct {
	mu      sync.Mutex
	batches [][]Event
}

func (r *recordingInserter) InsertThrottleEventBatch(_ context.Context, events []Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Copy — the sink reuses its pending slice after flush.
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

func (r *recordingInserter) batchCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.batches)
}

// failingInserter returns the configured error from every
// batch — used for AC #13 runtime-failure tests.
type failingInserter struct {
	err   error
	calls atomic.Uint64
}

func (f *failingInserter) InsertThrottleEventBatch(_ context.Context, _ []Event) error {
	f.calls.Add(1)
	return f.err
}

func TestSink_Emit_NonBlockingWhenChannelFull(t *testing.T) {
	// Channel-buffer of 1 + no Run goroutine → second Emit
	// MUST drop instead of blocking. AC #13.
	s := NewSink(nil, nil, silentLogger(), SinkConfig{
		ChannelBuffer: 1,
	})
	s.Emit(Event{SrcIP: "1.2.3.4", Tier: 1})
	s.Emit(Event{SrcIP: "1.2.3.4", Tier: 2})
	if got := s.DroppedByChannel(); got != 1 {
		t.Fatalf("DroppedByChannel = %d, want 1", got)
	}
}

func TestSink_LRU_SuppressesRepeats_BatchPersistsOnce(t *testing.T) {
	// Spec §1.6.5: a sustained burst on the same (srcIP, tier)
	// tuple should produce ONE row.
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval:  20 * time.Millisecond,
		FlushBatchSize: 1000, // bigger than the burst → flush triggered by interval, not size
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	for i := 0; i < 1000; i++ {
		s.Emit(Event{SrcIP: "1.2.3.4", Tier: 1, Ts: time.Now()})
	}
	// Give the sink time to drain the channel + flush.
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-s.Done()

	if got := rec.totalEvents(); got != 1 {
		t.Fatalf("persisted events = %d, want 1 (LRU should suppress the rest)", got)
	}
	if got := s.SuppressedByLRU(); got < 999 {
		t.Fatalf("SuppressedByLRU = %d, want >= 999", got)
	}
}

func TestSink_BatchedFlushAt_FlushBatchSize(t *testing.T) {
	// FlushBatchSize=10 + interval set very high → flush
	// triggers on batch fill, not on the timer.
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval:  10 * time.Second,
		FlushBatchSize: 10,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	// 25 events with DIFFERENT IPs so the LRU lets them all
	// through (same tier is fine — (srcIP, tier) keying makes
	// distinct IPs distinct tuples). Should produce >= 2
	// batches (10 + 10), the trailing 5 wait for the
	// timer-OR-ctx-cancel.
	for i := 0; i < 25; i++ {
		s.Emit(Event{SrcIP: "ip-" + strconv.Itoa(i), Tier: 1, Ts: time.Now()})
	}
	// Wait for at least 2 batches to land.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && rec.batchCount() < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-s.Done()

	if got := rec.batchCount(); got < 2 {
		t.Fatalf("batchCount = %d, want >= 2 (size-triggered flushes + a final cancel flush)", got)
	}
	if got := rec.totalEvents(); got != 25 {
		t.Fatalf("totalEvents = %d, want 25", got)
	}
}

func TestSink_FailingInserter_DoesNotPropagate(t *testing.T) {
	// AC #13 runtime-failure half: a sink whose Inserter
	// returns an error from every batch MUST log + count +
	// continue. Emit MUST stay non-blocking.
	fail := &failingInserter{err: errors.New("disk full")}
	s := NewSink(fail, nil, silentLogger(), SinkConfig{
		FlushInterval:  20 * time.Millisecond,
		FlushBatchSize: 5,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	for i := 0; i < 50; i++ {
		// Different IPs so the LRU doesn't deduplicate.
		s.Emit(Event{SrcIP: "ip-" + strconv.Itoa(i), Tier: 1, Ts: time.Now()})
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-s.Done()

	if got := s.FlushErrBatches(); got == 0 {
		t.Fatalf("FlushErrBatches = 0; expected the failing inserter to be called and counted")
	}
	if got := s.FlushSuccessBatches(); got != 0 {
		t.Fatalf("FlushSuccessBatches = %d; expected 0 (inserter always fails)", got)
	}
	// Emit must have kept working even though every flush failed.
	if got := s.Emitted(); got == 0 {
		t.Fatal("Emitted = 0; the channel should have absorbed events despite flush errors")
	}
}

func TestSink_NilInserter_DegradedNoOp(t *testing.T) {
	// AC #13 boot-failure half: nil inserter (observability
	// store failed to open) → sink runs, drains channel,
	// drops the buffer silently. Emit + Run must not panic.
	s := NewSink(nil, nil, silentLogger(), SinkConfig{
		FlushInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	for i := 0; i < 10; i++ {
		s.Emit(Event{SrcIP: "ip-" + strconv.Itoa(i), Tier: 1, Ts: time.Now()})
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-s.Done()

	if got := s.FlushErrBatches(); got != 0 {
		t.Fatalf("FlushErrBatches = %d in degraded mode; expected 0 (no inserter to fail)", got)
	}
}

func TestSink_CleanShutdownFlushesPending(t *testing.T) {
	// Ctx-cancel must trigger a final flush so events
	// buffered between flushInterval ticks aren't lost on a
	// clean shutdown.
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval:  10 * time.Second, // never fires during this test
		FlushBatchSize: 1000,             // never fills during this test
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	s.Emit(Event{SrcIP: "1.2.3.4", Tier: 1, Ts: time.Now()})
	time.Sleep(30 * time.Millisecond) // let the goroutine absorb
	cancel()
	<-s.Done()

	if got := rec.totalEvents(); got != 1 {
		t.Fatalf("clean shutdown lost the in-flight event: persisted=%d", got)
	}
}

// TestSink_CrashLossBound_FlushedEventsPersist_PendingLost is the
// throttle-side companion of the L+M+Q+N+O crash-recovery
// consolidation pinned in backlog #M.5-3. See the WAF sink
// test of the same name for the full rationale; this is the
// throttle_event-table equivalent (Step Q.1 sink shape).
func TestSink_CrashLossBound_FlushedEventsPersist_PendingLost(t *testing.T) {
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval:  10 * time.Second,
		FlushBatchSize: 3,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	// 7 distinct IPs → LRU passes all through; tier=1 fixed.
	for i := 0; i < 7; i++ {
		s.Emit(Event{SrcIP: "ip-crash-" + strconv.Itoa(i), Tier: 1, Ts: time.Now()})
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && rec.batchCount() < 2 {
		time.Sleep(10 * time.Millisecond)
	}

	if got := rec.totalEvents(); got != 6 {
		t.Fatalf("pre-crash disk state: persisted=%d, want 6 (2 full batches)", got)
	}
	if got := rec.batchCount(); got != 2 {
		t.Fatalf("pre-crash batch count: %d, want 2", got)
	}
	if got := s.FlushedEvents(); got != 6 {
		t.Fatalf("FlushedEvents = %d, want 6", got)
	}

	// The 7th event is in pending — would be lost on SIGKILL.

	cancel()
	<-s.Done()
	if got := rec.totalEvents(); got != 7 {
		t.Fatalf("post-cancel disk state: persisted=%d, want 7 (SIGTERM-path recovery)", got)
	}
}

func TestSink_RecoversFromPanic(t *testing.T) {
	// AC #13: a panic inside the goroutine MUST be recovered
	// + logged, sink exits cleanly, no proxy impact. We test
	// via a panicking inserter; the deferred recover in
	// Run() takes the panic.
	panicked := false
	rec := &panickingInserter{onCall: func() {
		if !panicked {
			panicked = true
			panic("synthetic panic")
		}
	}}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval:  10 * time.Millisecond,
		FlushBatchSize: 1,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Emit(Event{SrcIP: "1.2.3.4", Tier: 1, Ts: time.Now()})

	// Wait for Done — if the recover works, Done closes
	// (goroutine exits gracefully). If the panic escapes,
	// the test will panic too.
	select {
	case <-s.Done():
		// expected
	case <-time.After(500 * time.Millisecond):
		t.Fatal("sink Done did not fire — recover may have failed")
	}
}

type panickingInserter struct {
	onCall func()
}

func (p *panickingInserter) InsertThrottleEventBatch(_ context.Context, _ []Event) error {
	p.onCall()
	return nil
}

// recordingCounter captures BumpThrottleBlocks calls per IP.
type recordingCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func newRecordingCounter() *recordingCounter {
	return &recordingCounter{counts: map[string]int{}}
}

func (c *recordingCounter) BumpThrottleBlocks(srcIP string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[srcIP]++
}

func (c *recordingCounter) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := 0
	for _, v := range c.counts {
		t += v
	}
	return t
}

func TestSink_BlockCounter_BumpedOnEveryAbsorb_IncludingSuppressed(t *testing.T) {
	// AC #3 invariant: the per-minute throttle block counter
	// MUST increment on every block, even ones the LRU
	// suppresses for event-table persistence. Otherwise a
	// sustained credential-stuffing burst would show up as
	// one row in the event log and ZERO on the dashboard
	// timeline — exactly the wrong signal.
	rec := &recordingInserter{}
	counter := newRecordingCounter()
	s := NewSink(rec, counter, silentLogger(), SinkConfig{
		FlushInterval:  20 * time.Millisecond,
		FlushBatchSize: 1000,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	// 100 identical events on the same (srcIP, tier) tuple →
	// LRU lets the first through, suppresses the other 99.
	// The COUNTER should record all 100 bumps.
	for i := 0; i < 100; i++ {
		s.Emit(Event{SrcIP: "1.2.3.4", Tier: 1, Ts: time.Now()})
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-s.Done()

	if got := rec.totalEvents(); got != 1 {
		t.Fatalf("event table rows = %d, want 1 (LRU suppressed the rest)", got)
	}
	if got := counter.total(); got != 100 {
		t.Fatalf("BumpThrottleBlocks total = %d, want 100 (every absorbed event, incl. suppressed)", got)
	}
}

func TestSink_NilBlockCounter_NoPanic(t *testing.T) {
	// nil counter (degraded mode or test that doesn't care
	// about the bucket side) must be tolerated silently.
	s := NewSink(nil, nil, silentLogger(), SinkConfig{
		FlushInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Emit(Event{SrcIP: "1.2.3.4", Tier: 1, Ts: time.Now()})
	time.Sleep(50 * time.Millisecond)
	// Test passes if Run didn't panic.
}
