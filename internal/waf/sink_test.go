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

package waf

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

func (r *recordingInserter) InsertWafEventBatch(_ context.Context, events []Event) error {
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

func (f *failingInserter) InsertWafEventBatch(_ context.Context, _ []Event) error {
	f.calls.Add(1)
	return f.err
}

func TestSink_Emit_NonBlockingWhenChannelFull(t *testing.T) {
	// Channel-buffer of 1 + no Run goroutine → second Emit
	// MUST drop instead of blocking. AC #13.
	s := NewSink(nil, nil, silentLogger(), SinkConfig{
		ChannelBuffer: 1,
	})
	s.Emit(Event{RouteID: "r", SrcIP: "1.2.3.4", RuleID: "1"})
	s.Emit(Event{RouteID: "r", SrcIP: "1.2.3.4", RuleID: "2"})
	if got := s.DroppedByChannel(); got != 1 {
		t.Fatalf("DroppedByChannel = %d, want 1", got)
	}
}

func TestSink_LRU_SuppressesRepeats_BatchPersistsOnce(t *testing.T) {
	// Spec §1.6.6: a sustained burst on the same
	// (route, srcIP, ruleID) triple should produce ONE row.
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval:  20 * time.Millisecond,
		FlushBatchSize: 1000, // bigger than the burst → flush triggered by interval, not size
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	for i := 0; i < 1000; i++ {
		s.Emit(Event{RouteID: "r", SrcIP: "1.2.3.4", RuleID: "942100", Ts: time.Now()})
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

	// 25 events with DIFFERENT triples so the LRU lets them
	// all through. Should produce >= 2 batches (10 + 10),
	// the trailing 5 wait for the timer-OR-ctx-cancel.
	for i := 0; i < 25; i++ {
		s.Emit(Event{RouteID: "r", SrcIP: "ip-x", RuleID: "rule-" + string(rune('a'+i)), Ts: time.Now()})
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
		// Different triples so the LRU doesn't deduplicate.
		s.Emit(Event{RouteID: "r", SrcIP: "ip", RuleID: "rule-" + string(rune('a'+(i%26))) + "-" + string(rune('0'+(i/26))), Ts: time.Now()})
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
		s.Emit(Event{RouteID: "r", SrcIP: "ip", RuleID: "rule-" + string(rune('a'+i)), Ts: time.Now()})
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

	s.Emit(Event{RouteID: "r", SrcIP: "ip", RuleID: "942100", Ts: time.Now()})
	time.Sleep(30 * time.Millisecond) // let the goroutine absorb
	cancel()
	<-s.Done()

	if got := rec.totalEvents(); got != 1 {
		t.Fatalf("clean shutdown lost the in-flight event: persisted=%d", got)
	}
}

// TestSink_CrashLossBound_FlushedEventsPersist_PendingLost pins
// the SIGKILL crash semantic per backlog #M.5-3 (consolidated
// across L+M+Q+N+O). The invariant:
//
//   - Events flushed before the crash → durably on disk.
//   - Events still in the in-memory pending slice or input
//     channel at crash time → LOST.
//
// The bound is: at-most one batch's worth of events
// (FlushBatchSize - 1, since the Nth event triggers the flush)
// + whatever sits in the unbuffered input channel.
//
// Why this exists (alongside TestSink_BatchedFlushAt and
// TestSink_CleanShutdownFlushesPending):
//   - TestSink_BatchedFlushAt asserts that batch fills DO flush.
//   - TestSink_CleanShutdownFlushesPending asserts that
//     ctx-cancel flushes the trailing remainder.
//   - This test asserts the FLIP SIDE: ABSENT ctx-cancel
//     (i.e. SIGKILL semantic), the remainder is INDEED lost —
//     the invariant the operator must understand for crash
//     planning. Pin the bound so a future refactor that adds
//     a write-ahead log or per-event flush silently shifts
//     the contract.
//
// The companion tests in the throttle + crowdsec sink packages
// pin the same invariant for the corresponding event types
// (waf_event / throttle_event / decision_event all share the
// batched-channel-flush shape).
func TestSink_CrashLossBound_FlushedEventsPersist_PendingLost(t *testing.T) {
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval:  10 * time.Second, // disable timer flush
		FlushBatchSize: 3,                // deterministic batch boundary
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	// Emit 7 events with distinct triples (LRU passes them
	// all through). At FlushBatchSize=3 we expect:
	//   - 2 batches of 3 → 6 events on disk pre-crash.
	//   - 1 event still in the pending slice → lost on crash.
	for i := 0; i < 7; i++ {
		s.Emit(Event{
			RouteID: "r",
			SrcIP:   "ip",
			RuleID:  "crash-bound-" + string(rune('a'+i)),
			Ts:      time.Now(),
		})
	}

	// Wait for the 2 expected batches to land. Bounded poll
	// so a slow CI doesn't flake.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && rec.batchCount() < 2 {
		time.Sleep(10 * time.Millisecond)
	}

	// At crash time (BEFORE we cancel), check the disk state.
	if got := rec.totalEvents(); got != 6 {
		t.Fatalf("pre-crash disk state: persisted=%d, want 6 (2 full batches)", got)
	}
	if got := rec.batchCount(); got != 2 {
		t.Fatalf("pre-crash batch count: %d, want 2", got)
	}
	// FlushedEvents is the sink's own counter; must agree
	// with the recorder.
	if got := s.FlushedEvents(); got != 6 {
		t.Fatalf("FlushedEvents = %d, want 6 (matches rec.totalEvents)", got)
	}

	// "Crash" simulation: we observe HERE, before cancel,
	// that the 7th event is in the pending slice, not on
	// disk. This is the bound — a SIGKILL at this exact
	// moment loses that event.

	// Clean up so the test exits. The post-cancel flush
	// is the SIGTERM path already pinned by
	// TestSink_CleanShutdownFlushesPending; we re-check the
	// recovered count here for symmetry.
	cancel()
	<-s.Done()
	if got := rec.totalEvents(); got != 7 {
		t.Fatalf("post-cancel disk state: persisted=%d, want 7 (the 7th event lands on clean shutdown)", got)
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

	s.Emit(Event{RouteID: "r", SrcIP: "ip", RuleID: "x", Ts: time.Now()})

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

func (p *panickingInserter) InsertWafEventBatch(_ context.Context, _ []Event) error {
	p.onCall()
	return nil
}

// recordingCounter captures BumpWafBlocks calls per route.
type recordingCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func newRecordingCounter() *recordingCounter {
	return &recordingCounter{counts: map[string]int{}}
}

func (c *recordingCounter) BumpWafBlocks(routeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[routeID]++
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
	// AC #3 invariant: the per-minute WAF block counter MUST
	// increment on every block, even ones the LRU suppresses
	// for event-table persistence. Otherwise a sustained
	// attack would show up as one row in the event log and
	// ZERO on the dashboard timeline — exactly the wrong
	// signal.
	rec := &recordingInserter{}
	counter := newRecordingCounter()
	s := NewSink(rec, counter, silentLogger(), SinkConfig{
		FlushInterval:  20 * time.Millisecond,
		FlushBatchSize: 1000,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	// 100 identical events on the same triple → LRU lets the
	// first through, suppresses the other 99. The COUNTER
	// should record all 100 bumps.
	//
	// W.bugfix Fix #1: the counter only bumps when Action ==
	// ActionBlock (detect-mode events still persist as event-
	// table rows but DO NOT inflate the block-volume
	// timeseries). The pre-fix test emitted bare Events with
	// an implicit "always block" intent — add the Action
	// explicitly so the assertion is unambiguous.
	for i := 0; i < 100; i++ {
		s.Emit(Event{RouteID: "r", SrcIP: "1.2.3.4", RuleID: "942100", Ts: time.Now(), Action: ActionBlock})
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-s.Done()

	if got := rec.totalEvents(); got != 1 {
		t.Fatalf("event table rows = %d, want 1 (LRU suppressed the rest)", got)
	}
	if got := counter.total(); got != 100 {
		t.Fatalf("BumpWafBlocks total = %d, want 100 (every absorbed event, incl. suppressed)", got)
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

	s.Emit(Event{RouteID: "r", SrcIP: "1.2.3.4", RuleID: "1", Ts: time.Now()})
	time.Sleep(50 * time.Millisecond)
	// Test passes if Run didn't panic.
}
