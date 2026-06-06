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
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recordingInserter is a CertInserter test double that
// captures every batch it sees so the test can assert what
// the sink actually persisted. Safe for concurrent calls from
// the sink goroutine.
type recordingInserter struct {
	mu       sync.Mutex
	batches  [][]CertEvent
	failNext atomic.Bool // when true, the next Insert returns an error
}

func (r *recordingInserter) InsertCertEventBatch(ctx context.Context, events []CertEvent) error {
	if r.failNext.Swap(false) {
		return errors.New("simulated insert failure")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// Copy the slice so a later sink reuse can't mutate what
	// the test inspects.
	cp := append([]CertEvent(nil), events...)
	r.batches = append(r.batches, cp)
	return nil
}

func (r *recordingInserter) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, b := range r.batches {
		n += len(b)
	}
	return n
}

func (r *recordingInserter) batchCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.batches)
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(noopWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
}

type noopWriter struct{}

func (noopWriter) Write(p []byte) (int, error) { return len(p), nil }

// TestCertEventSink_SubmitAndFlush pins the happy path: N
// submits → N events land in the inserter after a flush tick.
func TestCertEventSink_SubmitAndFlush(t *testing.T) {
	ins := &recordingInserter{}
	sink := NewCertEventSink(ins, quietLogger(), CertSinkConfig{
		ChannelBuffer:  64,
		FlushInterval:  50 * time.Millisecond,
		FlushBatchSize: 32,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	for i := 0; i < 10; i++ {
		sink.Submit(CertEvent{
			Ts:     time.Now(),
			Type:   CertEventTypeObtained,
			Domain: "example.com",
		})
	}

	// Wait for the flush tick to drain.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) && ins.total() < 10 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := ins.total(); got != 10 {
		t.Fatalf("inserter saw %d events after flush, want 10", got)
	}
	if got := sink.FlushedEvents(); got != 10 {
		t.Errorf("FlushedEvents counter = %d, want 10", got)
	}
	if got := sink.Submitted(); got != 10 {
		t.Errorf("Submitted counter = %d, want 10", got)
	}
}

// TestCertEventSink_BatchSize_TriggersFlush pins the
// batch-size-driven flush path: filling pending past
// FlushBatchSize triggers an immediate flush rather than
// waiting for the tick.
func TestCertEventSink_BatchSize_TriggersFlush(t *testing.T) {
	ins := &recordingInserter{}
	sink := NewCertEventSink(ins, quietLogger(), CertSinkConfig{
		ChannelBuffer:  256,
		FlushInterval:  10 * time.Second, // long tick — won't fire in this test
		FlushBatchSize: 4,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = sink.Start(ctx)

	// Submit 8 events; with batch=4, the sink should flush twice.
	for i := 0; i < 8; i++ {
		sink.Submit(CertEvent{Type: CertEventTypeObtained, Domain: "x"})
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && ins.total() < 8 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := ins.total(); got != 8 {
		t.Errorf("batch-flush total = %d, want 8", got)
	}
}

// TestCertEventSink_DropsWhenFull pins the non-blocking
// contract. With a tiny channel and a slow-draining
// goroutine, Submit must return immediately and increment
// the drop counter rather than block.
func TestCertEventSink_DropsWhenFull(t *testing.T) {
	ins := &recordingInserter{}
	sink := NewCertEventSink(ins, quietLogger(), CertSinkConfig{
		ChannelBuffer:  4, // tiny buffer
		FlushInterval:  10 * time.Second,
		FlushBatchSize: 1000,
	})
	// Do NOT call Start — the goroutine never drains, so the
	// channel fills after exactly ChannelBuffer submits.
	for i := 0; i < 100; i++ {
		sink.Submit(CertEvent{Type: CertEventTypeObtained, Domain: "x"})
	}
	if got := sink.Submitted(); got != 4 {
		t.Errorf("Submitted = %d, want 4 (buffer cap)", got)
	}
	if got := sink.DroppedByChannel(); got != 96 {
		t.Errorf("DroppedByChannel = %d, want 96", got)
	}
}

// TestCertEventSink_StopFlushesPending pins the
// drain-on-shutdown contract: ctx-cancel must flush whatever
// is pending before the goroutine exits, so a clean shutdown
// doesn't lose buffered events.
func TestCertEventSink_StopFlushesPending(t *testing.T) {
	ins := &recordingInserter{}
	sink := NewCertEventSink(ins, quietLogger(), CertSinkConfig{
		ChannelBuffer:  64,
		FlushInterval:  10 * time.Second, // tick never fires
		FlushBatchSize: 1000,
	})
	ctx, cancel := context.WithCancel(context.Background())
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Submit 5 events — none flushed yet (batch=1000, tick=10s).
	for i := 0; i < 5; i++ {
		sink.Submit(CertEvent{Type: CertEventTypeObtained, Domain: "x"})
	}
	// Give the run goroutine time to absorb them into pending.
	time.Sleep(50 * time.Millisecond)
	if ins.total() != 0 {
		t.Fatalf("pre-shutdown total = %d, want 0 (no flush yet)", ins.total())
	}

	// Cancel + wait for drain.
	cancel()
	if err := sink.Stop(2 * time.Second); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := ins.total(); got != 5 {
		t.Errorf("post-shutdown total = %d, want 5 (drain flushed pending)", got)
	}
}

// TestCertEventSink_NilInserter_DegradedMode pins the AC #13
// degraded path: nil inserter → no panic, events drain into
// /dev/null, counters reflect the drain but flushErrBatches
// stays at 0 (this is not a runtime error, it's boot-failed
// observability).
func TestCertEventSink_NilInserter_DegradedMode(t *testing.T) {
	sink := NewCertEventSink(nil, quietLogger(), CertSinkConfig{
		ChannelBuffer:  16,
		FlushInterval:  50 * time.Millisecond,
		FlushBatchSize: 1,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = sink.Start(ctx)

	for i := 0; i < 5; i++ {
		sink.Submit(CertEvent{Type: CertEventTypeObtained, Domain: "x"})
	}
	time.Sleep(200 * time.Millisecond)

	if sink.FlushErrBatches() != 0 {
		t.Errorf("FlushErrBatches = %d, want 0 (nil inserter is degraded mode, not an error)", sink.FlushErrBatches())
	}
	if sink.Submitted() == 0 {
		t.Errorf("Submitted = 0, want >0 (events reached the channel)")
	}
}

// TestCertEventSink_FlushError_CountsAndContinues pins the
// error-handling contract: an Insert error increments
// flushErrBatches but the sink keeps running for subsequent
// submits.
func TestCertEventSink_FlushError_CountsAndContinues(t *testing.T) {
	ins := &recordingInserter{}
	sink := NewCertEventSink(ins, quietLogger(), CertSinkConfig{
		ChannelBuffer:  16,
		FlushInterval:  30 * time.Millisecond,
		FlushBatchSize: 1,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = sink.Start(ctx)

	// First submit + flush fails.
	ins.failNext.Store(true)
	sink.Submit(CertEvent{Type: CertEventTypeObtained, Domain: "a"})
	time.Sleep(150 * time.Millisecond)
	if got := sink.FlushErrBatches(); got != 1 {
		t.Errorf("after fail: FlushErrBatches = %d, want 1", got)
	}

	// Second submit should still flow.
	sink.Submit(CertEvent{Type: CertEventTypeObtained, Domain: "b"})
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && ins.total() < 1 {
		time.Sleep(20 * time.Millisecond)
	}
	if ins.total() != 1 {
		t.Errorf("post-recovery total = %d, want 1 (sink continued after error)", ins.total())
	}
}
