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
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Default tuning parameters. Mostly internal — exposed as
// consts so the wiring code in main.go can reference them
// when emitting boot log lines, and so tests can refer to
// the same numbers without magic literals.
const (
	// DefaultChannelBuffer sizes the Emit ingress channel.
	// 1024 is enough to ride out a ~1 s flush stall at
	// >1000 events/s; channel-full drops are counted but
	// never block the request path.
	DefaultChannelBuffer = 1024

	// DefaultFlushInterval upper-bounds the time between
	// disk flushes; the sink ALSO flushes when the in-flight
	// buffer reaches DefaultFlushBatchSize, whichever fires
	// first.
	DefaultFlushInterval = 250 * time.Millisecond

	// DefaultFlushBatchSize forces a flush once this many
	// events accumulate in-flight. Bounds peak memory.
	DefaultFlushBatchSize = 100

	// DefaultLRUCap and DefaultLRUTTL control per-triple
	// emit rate-limiting (see lru.go). 10k entries × ~32 B
	// per entry ≈ 320 KB, negligible.
	DefaultLRUCap = 10_000
	DefaultLRUTTL = 60 * time.Second
)

// Inserter is the persistence surface the sink depends on.
// Defined as an interface so a test can inject a fake
// without spinning up SQLite, and so the AC #13 runtime-
// failure path is exerciseable with a synthetic failing
// inserter (same shape as L's bucketSink).
//
// The production implementation is *observability.Store,
// wired in cmd/arenet/main.go at boot. A nil Inserter is
// the AC #13 degraded-mode case (boot-failed metrics DB);
// NewSink tolerates it and the sink runs in no-op mode.
type Inserter interface {
	InsertWafEventBatch(ctx context.Context, events []Event) error
}

// BlockCounter increments a per-route per-minute WAF block
// counter. Called on EVERY successful WAF block — including
// blocks the LRU suppresses for event-table persistence
// (the count is the dashboard's primary timeseries; suppressing
// repeat events doesn't suppress the operator's view of attack
// volume).
//
// AC #3 invariant (spec §2): the per-minute counter is
// incremented INDEPENDENTLY from the L request/4xx/5xx
// counters by this Bump call; the 403 returned by the WAF
// block must NOT also bump the 4xx counter (the route
// metrics middleware checks for the block flag and skips
// the 4xx classification — wired in M.5 caddymgr swap).
//
// Implementation note: the production wiring uses
// observability.Aggregator.BumpWafBlocks; the bump-or-not is
// internal to the aggregator (it folds into the next minute's
// flush). A nil BlockCounter is tolerated (degraded mode).
type BlockCounter interface {
	BumpWafBlocks(routeID string)
}

// EventSink is the package-level abstraction the Caddy
// module emits events into. The production type is *Sink;
// tests can substitute their own implementation behind the
// SetGlobalSink shim (see global.go in step 4) without
// going through the channel-buffered batching.
type EventSink interface {
	Emit(Event)
}

// Sink is the production EventSink. It owns:
//   - An ingress channel for non-blocking Emit (drops on full).
//   - An LRU rate-limiter that suppresses repeated event
//     emissions for the same (route, src, rule) within ttl.
//   - A background flush goroutine that batches events into
//     the Inserter every flushInterval or when the in-flight
//     buffer reaches flushBatchSize.
//   - Counters for observability into the sink itself
//     (dropped-by-channel, suppressed-by-LRU, flushed,
//     flush-errors).
//
// AC #13: Emit MUST be non-blocking and MUST NOT perform
// I/O on the calling goroutine. Flush errors are logged +
// counted, never returned to the caller. A panic inside the
// flush goroutine is recovered + logged + the goroutine
// exits cleanly (the sink stays alive in degraded mode,
// dropping subsequent emits).
type Sink struct {
	inserter       Inserter
	counter        BlockCounter
	logger         *slog.Logger
	lru            *emitLRU
	in             chan Event
	flushInterval  time.Duration
	flushBatchSize int
	done           chan struct{}

	// Counters. atomics so tests can assert without locks.
	emitted             uint64 // events that passed the channel + LRU and are pending or persisted
	droppedByChannel    uint64 // Emit calls where the channel was full
	suppressedByLRU     uint64 // emits where the triple was recently seen
	flushSuccessBatches uint64 // successful InsertWafEventBatch calls
	flushErrBatches     uint64 // failed InsertWafEventBatch calls
	flushedEvents       uint64 // total events successfully persisted

	// Mutex protects the in-flight buffer. The flush
	// goroutine holds it for the duration of a flush so
	// emits arriving during the flush land in the next
	// batch.
	mu      sync.Mutex
	pending []Event
}

// SinkConfig groups the tunables; nil-valued fields fall
// back to the Default* constants. Lets callers override one
// knob without spelling out every other.
type SinkConfig struct {
	ChannelBuffer  int
	FlushInterval  time.Duration
	FlushBatchSize int
	LRUCap         int
	LRUTTL         time.Duration
}

// NewSink constructs a Sink. inserter and counter may be nil
// (degraded mode); logger may be nil (falls back to
// slog.Default). The returned sink is NOT yet running — call
// Run on a goroutine to drain the ingress channel.
func NewSink(inserter Inserter, counter BlockCounter, logger *slog.Logger, cfg SinkConfig) *Sink {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.ChannelBuffer <= 0 {
		cfg.ChannelBuffer = DefaultChannelBuffer
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultFlushInterval
	}
	if cfg.FlushBatchSize <= 0 {
		cfg.FlushBatchSize = DefaultFlushBatchSize
	}
	if cfg.LRUCap <= 0 {
		cfg.LRUCap = DefaultLRUCap
	}
	if cfg.LRUTTL <= 0 {
		cfg.LRUTTL = DefaultLRUTTL
	}
	return &Sink{
		inserter:       inserter,
		counter:        counter,
		logger:         logger,
		lru:            newEmitLRU(cfg.LRUCap, cfg.LRUTTL),
		in:             make(chan Event, cfg.ChannelBuffer),
		flushInterval:  cfg.FlushInterval,
		flushBatchSize: cfg.FlushBatchSize,
		done:           make(chan struct{}),
		pending:        make([]Event, 0, cfg.FlushBatchSize),
	}
}

// Emit queues an event for persistence. Non-blocking: if the
// ingress channel is full, the event is dropped and the
// droppedByChannel counter increments. NEVER blocks the
// request path — AC #13.
//
// The LRU is consulted INSIDE the flush goroutine (not here)
// so Emit's hot path stays minimal: one channel send attempt,
// no map lookup, no lock.
func (s *Sink) Emit(e Event) {
	select {
	case s.in <- e:
	default:
		atomic.AddUint64(&s.droppedByChannel, 1)
	}
}

// Run drives the sink goroutine until ctx is cancelled. On
// cancellation, flushes whatever is pending so a clean
// shutdown doesn't lose buffered events. Wrapped in a
// recover so a panic inside the goroutine logs + exits but
// does NOT bring down the proxy.
func (s *Sink) Run(ctx context.Context) {
	defer close(s.done)
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("waf: sink panic; security event emission disabled for the rest of this process",
				slog.Any("panic", r),
			)
		}
	}()

	tick := time.NewTicker(s.flushInterval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			s.flush(context.Background())
			return
		case e := <-s.in:
			s.absorb(e)
		case <-tick.C:
			s.flush(ctx)
		}
	}
}

// Done returns a channel closed once Run has exited.
func (s *Sink) Done() <-chan struct{} {
	return s.done
}

// absorb folds one event into the pending buffer, applying
// the LRU rate-limit on the way. Runs on the sink goroutine
// — no concurrent access to s.pending besides the flush
// branch (also goroutine-local).
//
// Bump-then-suppress: the BlockCounter is incremented on
// EVERY absorbed event of ActionBlock, including those the
// LRU is about to suppress for event-table persistence. Per
// spec §1.3 D1 implications and AC #3 / AC #5 wording — the
// dashboard's per-minute counter must reflect attack volume
// even when the event log only carries one representative
// row per (route, IP, rule) per ttl. Nil counter is the
// degraded mode (skipped).
//
// W.bugfix Fix #1: detect-mode events DO NOT bump the
// block-volume counter. The "WAF blocks per minute"
// timeseries is the operator's signal for actual
// enforcement; in detect mode the WAF allowed the request
// through, so counting it as a "block" would inflate the
// signal the same way the old labels lied. The event row
// itself is still persisted (frontend renders DETECT
// alongside BLOCK rows in the activity log).
func (s *Sink) absorb(e Event) {
	if s.counter != nil && e.Action == ActionBlock {
		s.counter.BumpWafBlocks(e.RouteID)
	}
	if !s.lru.shouldEmit(e.RouteID, e.SrcIP, e.RuleID) {
		atomic.AddUint64(&s.suppressedByLRU, 1)
		return
	}
	atomic.AddUint64(&s.emitted, 1)
	s.mu.Lock()
	s.pending = append(s.pending, e)
	shouldFlush := len(s.pending) >= s.flushBatchSize
	s.mu.Unlock()
	if shouldFlush {
		s.flush(context.Background())
	}
}

// flush persists the in-flight buffer and resets it. AC #13:
// errors are logged + counted, never propagated. A nil
// inserter (boot-failed degraded mode) drops the buffer
// silently after a debug log.
func (s *Sink) flush(ctx context.Context) {
	s.mu.Lock()
	if len(s.pending) == 0 {
		s.mu.Unlock()
		return
	}
	batch := s.pending
	s.pending = make([]Event, 0, s.flushBatchSize)
	s.mu.Unlock()

	if s.inserter == nil {
		s.logger.Debug("waf: flush skipped (no inserter — degraded mode)",
			slog.Int("dropped_events", len(batch)),
		)
		return
	}

	if err := s.inserter.InsertWafEventBatch(ctx, batch); err != nil {
		atomic.AddUint64(&s.flushErrBatches, 1)
		s.logger.Error("waf: flush failed; events lost",
			slog.String("err", err.Error()),
			slog.Int("lost_events", len(batch)),
		)
		return
	}
	atomic.AddUint64(&s.flushSuccessBatches, 1)
	atomic.AddUint64(&s.flushedEvents, uint64(len(batch)))
}

// --- Counters (test + ops introspection) -----------------------------------

// DroppedByChannel returns the number of Emit calls that
// found a full ingress channel. Cumulative since sink start.
func (s *Sink) DroppedByChannel() uint64 {
	return atomic.LoadUint64(&s.droppedByChannel)
}

// SuppressedByLRU returns the number of events that the LRU
// rate-limiter suppressed (same triple within ttl).
func (s *Sink) SuppressedByLRU() uint64 {
	return atomic.LoadUint64(&s.suppressedByLRU)
}

// FlushSuccessBatches returns the number of batched flushes
// that completed without error.
func (s *Sink) FlushSuccessBatches() uint64 {
	return atomic.LoadUint64(&s.flushSuccessBatches)
}

// FlushErrBatches returns the number of batched flushes that
// failed (logged + counted; never propagated to Emit).
func (s *Sink) FlushErrBatches() uint64 {
	return atomic.LoadUint64(&s.flushErrBatches)
}

// FlushedEvents returns the total number of events successfully
// persisted via the Inserter.
func (s *Sink) FlushedEvents() uint64 {
	return atomic.LoadUint64(&s.flushedEvents)
}

// Emitted returns the count of Emit calls that passed the
// channel + LRU (i.e. became eligible for persistence). Note
// some of these may still be in the pending buffer waiting
// for the next flush.
func (s *Sink) Emitted() uint64 {
	return atomic.LoadUint64(&s.emitted)
}
