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

package crowdsec

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

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// recordingInserter captures inserted batches + tombstones.
type recordingInserter struct {
	mu         sync.Mutex
	batches    [][]Decision
	tombstones []string
}

func (r *recordingInserter) InsertDecisionEventBatch(_ context.Context, events []Decision) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]Decision, len(events))
	copy(cp, events)
	r.batches = append(r.batches, cp)
	return nil
}

func (r *recordingInserter) MarkDecisionExpired(_ context.Context, uuid string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tombstones = append(r.tombstones, uuid)
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

func (r *recordingInserter) tombCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.tombstones)
}

func (r *recordingInserter) batchCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.batches)
}

// failingInserter returns the configured error.
type failingInserter struct {
	err         error
	tombErr     error
	insertCalls atomic.Uint64
	tombCalls   atomic.Uint64
}

func (f *failingInserter) InsertDecisionEventBatch(_ context.Context, _ []Decision) error {
	f.insertCalls.Add(1)
	return f.err
}

func (f *failingInserter) MarkDecisionExpired(_ context.Context, _ string) error {
	f.tombCalls.Add(1)
	return f.tombErr
}

// recordingCounter captures BumpCrowdSecDecisions calls.
type recordingCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func newRecordingCounter() *recordingCounter {
	return &recordingCounter{counts: map[string]int{}}
}

func (c *recordingCounter) BumpCrowdSecDecisions(srcIP string) {
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

func TestSink_Emit_NonBlockingWhenChannelFull(t *testing.T) {
	s := NewSink(nil, nil, silentLogger(), SinkConfig{ChannelBuffer: 1})
	s.Emit(Decision{UUID: "a"})
	s.Emit(Decision{UUID: "b"})
	if got := s.DroppedByChannel(); got != 1 {
		t.Fatalf("DroppedByChannel = %d, want 1", got)
	}
}

func TestSink_DedupeBeforeBump_CounterTicksOncePerUUID(t *testing.T) {
	// CRITICAL Step N spec D4.A invariant: LAPI re-emits the
	// same active decision on every poll cycle. The Sink
	// MUST suppress repeat emissions AND the bucket counter
	// bump. After N Emit() calls with the same UUID, expect:
	//   - exactly 1 event row persisted (LRU dedupe)
	//   - exactly 1 BlockCounter bump (dedupe-BEFORE-bump)
	//
	// This is OPPOSITE to M/Q where the counter ticks on
	// every absorb regardless of LRU outcome. The asymmetry
	// is the load-bearing semantic the test pins.
	rec := &recordingInserter{}
	counter := newRecordingCounter()
	s := NewSink(rec, counter, silentLogger(), SinkConfig{
		FlushInterval:  20 * time.Millisecond,
		FlushBatchSize: 1000,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	// 100 emissions of the same UUID — simulates ~100
	// poll cycles re-publishing the same active ban.
	for i := 0; i < 100; i++ {
		s.Emit(Decision{
			UUID:  "stable-uuid-1",
			Ts:    time.Now(),
			Scope: "ip",
			Value: "1.2.3.4",
			Type:  "ban",
		})
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-s.Done()

	if got := rec.totalEvents(); got != 1 {
		t.Fatalf("persisted events = %d, want 1 (LRU dedupe)", got)
	}
	if got := counter.total(); got != 1 {
		t.Fatalf("BlockCounter bumps = %d, want 1 (dedupe-BEFORE-bump per N spec D4.A — NOT %d which would be M/Q's bump-then-suppress)", got, 100)
	}
	if got := s.SuppressedByLRU(); got < 99 {
		t.Fatalf("SuppressedByLRU = %d, want >= 99", got)
	}
}

func TestSink_DifferentUUIDs_BothCounted(t *testing.T) {
	// Two distinct decisions for the same IP — both should
	// persist AND both should bump the counter (UUID is the
	// dedupe key, not the IP).
	rec := &recordingInserter{}
	counter := newRecordingCounter()
	s := NewSink(rec, counter, silentLogger(), SinkConfig{
		FlushInterval:  20 * time.Millisecond,
		FlushBatchSize: 1000,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	s.Emit(Decision{UUID: "u1", Value: "1.2.3.4", Type: "ban"})
	s.Emit(Decision{UUID: "u2", Value: "1.2.3.4", Type: "ban"}) // same IP, different decision
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-s.Done()

	if got := rec.totalEvents(); got != 2 {
		t.Errorf("persisted events = %d, want 2", got)
	}
	if got := counter.total(); got != 2 {
		t.Errorf("BlockCounter bumps = %d, want 2 (one per UUID)", got)
	}
}

func TestSink_Tombstone_LRUForget_PlusInserterMark(t *testing.T) {
	// LAPI signals a decision was revoked → Tombstone()
	// calls Inserter.MarkDecisionExpired AND forgets the
	// LRU entry. After a tombstone, re-emitting the same
	// UUID is treated as fresh (LRU was cleared).
	rec := &recordingInserter{}
	counter := newRecordingCounter()
	s := NewSink(rec, counter, silentLogger(), SinkConfig{
		FlushInterval:  20 * time.Millisecond,
		FlushBatchSize: 1000,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	s.Emit(Decision{UUID: "u1", Value: "1.2.3.4", Type: "ban"})
	time.Sleep(50 * time.Millisecond)
	s.Tombstone("u1")
	time.Sleep(50 * time.Millisecond)
	// Re-emit after tombstone — should be treated as fresh.
	s.Emit(Decision{UUID: "u1", Value: "1.2.3.4", Type: "ban"})
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-s.Done()

	if got := rec.tombCount(); got != 1 {
		t.Errorf("MarkDecisionExpired calls = %d, want 1", got)
	}
	if got := rec.totalEvents(); got != 2 {
		t.Errorf("persisted events = %d, want 2 (one before tombstone, one after — LRU was cleared)", got)
	}
	if got := counter.total(); got != 2 {
		t.Errorf("BlockCounter bumps = %d, want 2 (re-emit after tombstone is fresh)", got)
	}
	if got := s.TombstoneCount(); got != 1 {
		t.Errorf("TombstoneCount = %d, want 1", got)
	}
}

func TestSink_BatchedFlushAt_FlushBatchSize(t *testing.T) {
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval:  10 * time.Second,
		FlushBatchSize: 5,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	// 12 distinct UUIDs → 2 flushes of 5 + a trailing 2.
	for i := 0; i < 12; i++ {
		s.Emit(Decision{UUID: "u-" + strconv.Itoa(i), Value: "1.2.3.4"})
	}
	time.Sleep(500 * time.Millisecond)
	cancel()
	<-s.Done()

	if rec.totalEvents() != 12 {
		t.Errorf("totalEvents = %d, want 12", rec.totalEvents())
	}
}

func TestSink_FailingInserter_DoesNotPropagate(t *testing.T) {
	// AC #13 runtime-failure half: insert errors are logged
	// + counted, never propagated. Emit stays non-blocking.
	fail := &failingInserter{err: errors.New("disk full")}
	s := NewSink(fail, nil, silentLogger(), SinkConfig{
		FlushInterval:  20 * time.Millisecond,
		FlushBatchSize: 5,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	for i := 0; i < 50; i++ {
		s.Emit(Decision{UUID: "u-" + strconv.Itoa(i), Value: "ip"})
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-s.Done()

	if s.FlushErrBatches() == 0 {
		t.Fatal("FlushErrBatches = 0; expected the failing inserter to be called and counted")
	}
	if s.FlushSuccessBatches() != 0 {
		t.Fatal("expected zero successful flushes — every batch should fail")
	}
	if s.Emitted() == 0 {
		t.Fatal("Emitted = 0; channel should have absorbed events despite flush errors")
	}
}

func TestSink_FailingTombstone_DoesNotPropagate(t *testing.T) {
	// Tombstone path is also AC #13 — Inserter.MarkExpired
	// errors get logged but never propagate or crash.
	fail := &failingInserter{tombErr: errors.New("locked")}
	s := NewSink(fail, nil, silentLogger(), SinkConfig{
		FlushInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	for i := 0; i < 10; i++ {
		s.Tombstone("u-" + strconv.Itoa(i))
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-s.Done()

	if fail.tombCalls.Load() != 10 {
		t.Errorf("Tombstone calls = %d, want 10", fail.tombCalls.Load())
	}
	// No crash, no panic — that's the AC #13 win.
}

func TestSink_NilInserter_DegradedNoOp(t *testing.T) {
	// AC #13 boot-failure half.
	s := NewSink(nil, nil, silentLogger(), SinkConfig{
		FlushInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	for i := 0; i < 10; i++ {
		s.Emit(Decision{UUID: "u-" + strconv.Itoa(i)})
	}
	s.Tombstone("u-3")
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-s.Done()

	if s.FlushErrBatches() != 0 {
		t.Errorf("FlushErrBatches = %d in degraded mode; want 0", s.FlushErrBatches())
	}
}

func TestSink_NilBlockCounter_NoPanic(t *testing.T) {
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Emit(Decision{UUID: "u1", Value: "1.2.3.4"})
	time.Sleep(50 * time.Millisecond)
	// Test passes if Run didn't panic.
}

func TestSink_CleanShutdownFlushesPending(t *testing.T) {
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval:  10 * time.Second,
		FlushBatchSize: 1000,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	s.Emit(Decision{UUID: "u1", Value: "1.2.3.4"})
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-s.Done()

	if rec.totalEvents() != 1 {
		t.Fatalf("clean shutdown lost the in-flight event: persisted=%d", rec.totalEvents())
	}
}

// TestSink_CrashLossBound_FlushedEventsPersist_PendingLost is the
// crowdsec-side companion of the L+M+Q+N+O crash-recovery
// consolidation pinned in backlog #M.5-3. See the WAF sink
// test of the same name for the full rationale; this is the
// decision_event-table equivalent (Step N.2 sink shape).
//
// One semantic difference vs WAF / throttle worth noting:
// crowdsec's sink dedupes BEFORE bump per spec N D4.A (LRU
// gates the bucket counter), but the persistence path is the
// same batched-channel-flush shape, so the crash-loss bound
// is identical. Re-emit-on-restart is the recovery mechanism
// for crowdsec (LAPI re-sends every active decision on
// ?startup=true; the next Emit re-stores any in-flight rows
// lost on crash).
func TestSink_CrashLossBound_FlushedEventsPersist_PendingLost(t *testing.T) {
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval:  10 * time.Second,
		FlushBatchSize: 3,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	// 7 distinct UUIDs so the LRU passes all through.
	for i := 0; i < 7; i++ {
		s.Emit(Decision{UUID: "u-crash-" + strconv.Itoa(i), Value: "1.2.3.4"})
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

	// The 7th decision is in pending — would be lost on SIGKILL.
	// LAPI re-emit on restart recovers it (see test
	// rationale comment above).

	cancel()
	<-s.Done()
	if got := rec.totalEvents(); got != 7 {
		t.Fatalf("post-cancel disk state: persisted=%d, want 7 (SIGTERM-path recovery)", got)
	}
}

type panickingInserter struct {
	onCall func()
}

func (p *panickingInserter) InsertDecisionEventBatch(_ context.Context, _ []Decision) error {
	p.onCall()
	return nil
}

func (p *panickingInserter) MarkDecisionExpired(_ context.Context, _ string) error {
	return nil
}

func TestSink_RecoversFromPanic(t *testing.T) {
	// AC #13: panic in the goroutine MUST be recovered.
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

	s.Emit(Decision{UUID: "u1"})
	select {
	case <-s.Done():
		// expected
	case <-time.After(500 * time.Millisecond):
		t.Fatal("sink Done did not fire — recover may have failed")
	}
}

// TestSink_TombstoneListener_FiredOnAbsorb pins spec §3.6 /
// D6.A: when a tombstone-listener is registered, it fires on
// every successful absorbTombstone with the decision's UUID.
// The trigger engine uses this to seed its cooldown LRU.
func TestSink_TombstoneListener_FiredOnAbsorb(t *testing.T) {
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval:  20 * time.Millisecond,
		FlushBatchSize: 1000,
	})

	var (
		mu        sync.Mutex
		seenUUIDs []string
	)
	s.SetTombstoneListener(func(uuid string) {
		mu.Lock()
		seenUUIDs = append(seenUUIDs, uuid)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	s.Emit(Decision{UUID: "u-listener-1", Value: "1.2.3.4", Type: "ban"})
	time.Sleep(50 * time.Millisecond)
	s.Tombstone("u-listener-1")
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-s.Done()

	mu.Lock()
	defer mu.Unlock()
	if len(seenUUIDs) != 1 {
		t.Fatalf("listener fired %d times, want 1", len(seenUUIDs))
	}
	if seenUUIDs[0] != "u-listener-1" {
		t.Errorf("listener got uuid=%q, want u-listener-1", seenUUIDs[0])
	}
}

// TestSink_AbsorbTombstone_NoListener_Unchanged pins AC #21
// (Step N read-side unchanged): when no listener is
// registered, the existing absorbTombstone path
// (LRU forget + MarkDecisionExpired) executes identically
// to the pre-P.2 behaviour. No new code path for the
// no-listener case.
func TestSink_AbsorbTombstone_NoListener_Unchanged(t *testing.T) {
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval:  20 * time.Millisecond,
		FlushBatchSize: 1000,
	})
	// NO SetTombstoneListener call — fanout is nil.
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	s.Emit(Decision{UUID: "u-no-listener", Value: "1.2.3.4", Type: "ban"})
	time.Sleep(50 * time.Millisecond)
	s.Tombstone("u-no-listener")
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-s.Done()

	// Tombstone counter advanced — proves the original
	// absorbTombstone path ran.
	if got := s.TombstoneCount(); got != 1 {
		t.Errorf("TombstoneCount = %d, want 1 (listener=nil must NOT skip the absorb path)", got)
	}
	// And the inserter saw the MarkDecisionExpired call —
	// recorded as a tombstone in the test fake.
	if rec.tombCount() != 1 {
		t.Errorf("inserter.tombCount = %d, want 1 (MarkDecisionExpired must still fire)", rec.tombCount())
	}
}

// TestSink_TombstoneListener_NilRegistration_DisablesFanout
// pins the unregister path: SetTombstoneListener(nil)
// removes the listener. Subsequent tombstones fire only the
// original absorbTombstone path.
func TestSink_TombstoneListener_NilRegistration_DisablesFanout(t *testing.T) {
	rec := &recordingInserter{}
	s := NewSink(rec, nil, silentLogger(), SinkConfig{
		FlushInterval:  20 * time.Millisecond,
		FlushBatchSize: 1000,
	})

	var calls atomic.Int32
	s.SetTombstoneListener(func(_ string) { calls.Add(1) })
	// Now unregister.
	s.SetTombstoneListener(nil)

	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	s.Emit(Decision{UUID: "u-unreg", Value: "1.2.3.4", Type: "ban"})
	time.Sleep(50 * time.Millisecond)
	s.Tombstone("u-unreg")
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-s.Done()

	if calls.Load() != 0 {
		t.Errorf("listener calls = %d, want 0 after unregister", calls.Load())
	}
}
