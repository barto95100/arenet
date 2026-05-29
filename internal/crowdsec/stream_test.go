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
	"testing"
	"time"
)

// fakeSource is the test double for the Source interface.
// Pushes canned StreamDelta values onto its Out channel from
// the test goroutine, simulating LAPI poll cycles. closeOnEOF
// closes the channel after all deltas have been pushed —
// useful to assert the consumer exits gracefully when its
// upstream goes away.
type fakeSource struct {
	deltas     []StreamDelta
	out        chan StreamDelta
	startErr   error
	closeOnEOF bool
}

func newFakeSource(deltas []StreamDelta, closeOnEOF bool) *fakeSource {
	return &fakeSource{
		deltas:     deltas,
		out:        make(chan StreamDelta, len(deltas)+1),
		closeOnEOF: closeOnEOF,
	}
}

func (f *fakeSource) Start(ctx context.Context) error {
	if f.startErr != nil {
		return f.startErr
	}
	go func() {
		for _, d := range f.deltas {
			select {
			case <-ctx.Done():
				return
			case f.out <- d:
			}
		}
		if f.closeOnEOF {
			close(f.out)
		}
	}()
	return nil
}

func (f *fakeSource) Out() <-chan StreamDelta {
	return f.out
}

func TestConsumer_DispatchesNewAndDeleted(t *testing.T) {
	// One delta with 3 new + 2 deleted → 3 Emit, 2 Tombstone.
	delta := StreamDelta{
		New: []Decision{
			{UUID: "u1", Value: "1.2.3.4", Type: "ban"},
			{UUID: "u2", Value: "5.6.7.8", Type: "ban"},
			{UUID: "u3", Value: "9.9.9.9", Type: "captcha"},
		},
		Deleted: []string{"old-uuid-1", "old-uuid-2"},
	}
	src := newFakeSource([]StreamDelta{delta}, false)
	sink := &stubSink{}
	c := NewConsumer(src, sink, silentLogger())

	ctx, cancel := context.WithCancel(context.Background())
	go c.Run(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-c.Done()

	if sink.emits.Load() != 3 {
		t.Errorf("emits = %d, want 3", sink.emits.Load())
	}
	if sink.tombstones.Load() != 2 {
		t.Errorf("tombstones = %d, want 2", sink.tombstones.Load())
	}
	if c.TotalDeltas() != 1 {
		t.Errorf("TotalDeltas = %d, want 1", c.TotalDeltas())
	}
	if c.TotalEmits() != 3 {
		t.Errorf("TotalEmits = %d, want 3", c.TotalEmits())
	}
	if c.TotalTombstones() != 2 {
		t.Errorf("TotalTombstones = %d, want 2", c.TotalTombstones())
	}
}

func TestConsumer_MultipleDeltas(t *testing.T) {
	deltas := []StreamDelta{
		{New: []Decision{{UUID: "a"}, {UUID: "b"}}},
		{New: []Decision{{UUID: "c"}}, Deleted: []string{"a"}},
		{Deleted: []string{"b", "c"}},
	}
	src := newFakeSource(deltas, false)
	sink := &stubSink{}
	c := NewConsumer(src, sink, silentLogger())

	ctx, cancel := context.WithCancel(context.Background())
	go c.Run(ctx)
	time.Sleep(80 * time.Millisecond)
	cancel()
	<-c.Done()

	if c.TotalDeltas() != 3 {
		t.Errorf("TotalDeltas = %d, want 3", c.TotalDeltas())
	}
	if sink.emits.Load() != 3 {
		t.Errorf("emits = %d, want 3", sink.emits.Load())
	}
	if sink.tombstones.Load() != 3 {
		t.Errorf("tombstones = %d, want 3", sink.tombstones.Load())
	}
}

func TestConsumer_SourceChannelClosed_ConsumerExits(t *testing.T) {
	// When the upstream Source signals shutdown by closing
	// its Out channel, the Consumer must exit cleanly
	// without requiring a ctx cancel.
	src := newFakeSource([]StreamDelta{{New: []Decision{{UUID: "u1"}}}}, true)
	sink := &stubSink{}
	c := NewConsumer(src, sink, silentLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	select {
	case <-c.Done():
		// Expected — source channel was closed.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("consumer did not exit after source channel close")
	}

	if sink.emits.Load() != 1 {
		t.Errorf("emits = %d, want 1", sink.emits.Load())
	}
}

func TestConsumer_StartError_LogsAndExits(t *testing.T) {
	// AC #13 boot-failure path: Source.Start returning an
	// error must NOT crash the consumer. The Run goroutine
	// exits gracefully; the data plane (the bouncer
	// enforcement loop) is unaffected.
	src := &fakeSource{startErr: errors.New("config invalid")}
	sink := &stubSink{}
	c := NewConsumer(src, sink, silentLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	select {
	case <-c.Done():
		// Expected — Start returned error.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("consumer did not exit on Start error")
	}
}

func TestConsumer_NilSink_DegradedNoOp(t *testing.T) {
	// AC #13 degraded boot: nil sink (SetGlobalSink never
	// called because LAPI key wasn't configured) → consumer
	// drains the source's channel but doesn't dispatch.
	// MUST NOT panic.
	src := newFakeSource([]StreamDelta{
		{New: []Decision{{UUID: "u1"}}, Deleted: []string{"old"}},
	}, false)
	c := NewConsumer(src, nil, silentLogger())

	ctx, cancel := context.WithCancel(context.Background())
	go c.Run(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-c.Done()

	if c.TotalDeltas() != 1 {
		t.Errorf("TotalDeltas = %d, want 1 (channel still drained)", c.TotalDeltas())
	}
	// TotalEmits/TotalTombstones not incremented when sink
	// is nil — verified implicitly by the absence of panic.
}

// panickingSink fires panic on every Emit, simulating a
// catastrophic bug in the persistence path.
type panickingSink struct{}

func (panickingSink) Emit(_ Decision)    { panic("synthetic panic in sink.Emit") }
func (panickingSink) Tombstone(_ string) {}

func TestConsumer_RecoversFromSinkPanic(t *testing.T) {
	// AC #13: a panic inside the consumer's dispatch loop
	// (i.e. inside Sink.Emit) MUST be recovered + counted +
	// logged. The Consumer goroutine exits cleanly; the data
	// plane is unaffected.
	src := newFakeSource([]StreamDelta{
		{New: []Decision{{UUID: "u1"}}},
	}, false)
	c := NewConsumer(src, panickingSink{}, silentLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	select {
	case <-c.Done():
		// Expected: recover() fired, goroutine exited.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("consumer did not exit after sink panic — recover() may have failed")
	}

	if c.TotalPanicRecovs() != 1 {
		t.Errorf("TotalPanicRecovs = %d, want 1", c.TotalPanicRecovs())
	}
}

func TestSleepInterval_MatchesSpec(t *testing.T) {
	// Anti-regression: Step N spec D7.A locks 60s. A future
	// refactor that drops it to 10s would silently 6× the
	// LAPI poll volume — pin the constant.
	if SleepInterval != 60*time.Second {
		t.Errorf("SleepInterval = %v, want 60s (Step N spec D7.A)", SleepInterval)
	}
}
