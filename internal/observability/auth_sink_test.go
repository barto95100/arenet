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
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAuthInserter captures every batch the sink hands it so
// tests can assert on the persisted rows without spinning up
// a real *Store. Optional err makes the inserter fail.
type fakeAuthInserter struct {
	mu      sync.Mutex
	batches [][]AuthEvent
	err     error
	calls   uint64
}

func (f *fakeAuthInserter) InsertAuthEventBatch(_ context.Context, ev []AuthEvent) error {
	atomic.AddUint64(&f.calls, 1)
	if f.err != nil {
		return f.err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]AuthEvent, len(ev))
	copy(cp, ev)
	f.batches = append(f.batches, cp)
	return nil
}

func (f *fakeAuthInserter) totalEvents() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, b := range f.batches {
		n += len(b)
	}
	return n
}

func TestAuthEventSink_SubmitAndFlush(t *testing.T) {
	fake := &fakeAuthInserter{}
	sink := NewAuthEventSink(fake, nil, AuthSinkConfig{
		ChannelBuffer:  16,
		FlushInterval:  20 * time.Millisecond,
		FlushBatchSize: 4,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	for i := 0; i < 5; i++ {
		sink.Submit(AuthEvent{Ts: time.Now().UTC(), Kind: AuthEventKindLoginFailure, SrcIP: "1.1.1.1"})
	}

	// Wait for at least one tick.
	deadline := time.After(500 * time.Millisecond)
	for {
		if fake.totalEvents() >= 5 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("flush deadline exceeded; totalEvents=%d submitted=%d", fake.totalEvents(), sink.Submitted())
		case <-time.After(10 * time.Millisecond):
		}
	}

	cancel()
	if err := sink.Stop(time.Second); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if sink.FlushSuccessBatches() == 0 {
		t.Errorf("FlushSuccessBatches=0, want >=1")
	}
	if sink.FlushedEvents() < 5 {
		t.Errorf("FlushedEvents=%d, want >=5", sink.FlushedEvents())
	}
}

func TestAuthEventSink_DropsWhenFull(t *testing.T) {
	// Block the inserter so the in-flight buffer fills up and
	// downstream channel pressure exposes the drop path.
	blocking := make(chan struct{})
	fake := &fakeAuthInserter{}
	// Sink with a tiny channel so a single sustained burst overflows.
	sink := NewAuthEventSink(fake, nil, AuthSinkConfig{
		ChannelBuffer:  2,
		FlushInterval:  10 * time.Second, // never tick during this test
		FlushBatchSize: 1024,
	})
	// Don't start drain — Submit alone should drop when channel
	// fills up. This isolates the Submit drop path from any flush
	// behavior.

	for i := 0; i < 100; i++ {
		sink.Submit(AuthEvent{SrcIP: "1.1.1.1"})
	}

	if got := sink.Submitted(); got != 2 {
		t.Errorf("Submitted = %d, want 2 (channel cap)", got)
	}
	if got := sink.DroppedByChannel(); got != 98 {
		t.Errorf("DroppedByChannel = %d, want 98", got)
	}
	close(blocking)
}

func TestAuthEventSink_StopFlushesPending(t *testing.T) {
	fake := &fakeAuthInserter{}
	sink := NewAuthEventSink(fake, nil, AuthSinkConfig{
		ChannelBuffer:  16,
		FlushInterval:  10 * time.Second, // never tick during the test
		FlushBatchSize: 100,              // never trigger size-based flush
	})

	ctx, cancel := context.WithCancel(context.Background())
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	for i := 0; i < 3; i++ {
		sink.Submit(AuthEvent{SrcIP: "1.1.1.1", Kind: AuthEventKindLoginFailure})
	}

	cancel()
	if err := sink.Stop(time.Second); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := fake.totalEvents(); got != 3 {
		t.Errorf("totalEvents = %d, want 3 (drain on shutdown)", got)
	}
}

func TestAuthEventSink_NilInserter_Degraded(t *testing.T) {
	sink := NewAuthEventSink(nil, nil, AuthSinkConfig{
		ChannelBuffer:  16,
		FlushInterval:  10 * time.Millisecond,
		FlushBatchSize: 2,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	for i := 0; i < 5; i++ {
		sink.Submit(AuthEvent{SrcIP: "1.1.1.1"})
	}

	time.Sleep(80 * time.Millisecond)
	if sink.FlushSuccessBatches() != 0 {
		t.Errorf("FlushSuccessBatches = %d, want 0 (degraded mode)", sink.FlushSuccessBatches())
	}
	if sink.FlushErrBatches() != 0 {
		t.Errorf("FlushErrBatches = %d, want 0 (degraded mode is silent drop, not error)", sink.FlushErrBatches())
	}
}

func TestAuthEventSink_FlushError_LogsAndCounts(t *testing.T) {
	fake := &fakeAuthInserter{err: errors.New("disk full")}
	sink := NewAuthEventSink(fake, nil, AuthSinkConfig{
		ChannelBuffer:  16,
		FlushInterval:  10 * time.Millisecond,
		FlushBatchSize: 2,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	for i := 0; i < 5; i++ {
		sink.Submit(AuthEvent{SrcIP: "1.1.1.1"})
	}

	deadline := time.After(500 * time.Millisecond)
	for {
		if sink.FlushErrBatches() > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("flush err deadline exceeded; flushErr=%d", sink.FlushErrBatches())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if sink.FlushSuccessBatches() != 0 {
		t.Errorf("FlushSuccessBatches = %d, want 0 (all attempts failed)", sink.FlushSuccessBatches())
	}
}

func TestAuthEventSink_NilReceiver_SubmitNoOp(t *testing.T) {
	var s *AuthEventSink
	s.Submit(AuthEvent{SrcIP: "1.1.1.1"})
}
