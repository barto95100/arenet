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

// This file mirrors internal/waf/sink.go closely on purpose
// — see Step Q spec §3.3. The throttle pipeline reuses the
// same shape the WAF pipeline already validated:
//   - Non-blocking Emit (channel-buffered, drops on full).
//   - Background flush goroutine (250 ms / 100-event batch).
//   - LRU rate-limit per (srcIP, tier) tuple.
//   - BlockCounter bumped on EVERY absorb (including LRU-
//     suppressed) so the per-minute bucket counter reflects
//     attack volume even when the event log only carries one
//     representative row per (srcIP, tier) per ttl.
//   - Recover-on-panic at the goroutine boundary so a sink
//     bug never brings down the auth handler.
//
// A future refactor could consolidate the two sinks behind a
// generic shape; for Step Q we mirror the M code instead of
// introducing a generic abstraction that the codebase doesn't
// otherwise need.

package throttle

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Default tuning parameters. Mirrors the WAF sink's defaults.
const (
	DefaultChannelBuffer  = 1024
	DefaultFlushInterval  = 250 * time.Millisecond
	DefaultFlushBatchSize = 100
	DefaultLRUCap         = 10_000
	DefaultLRUTTL         = 60 * time.Second
)

// Inserter is the persistence surface the sink depends on.
// *observability.Store satisfies it via
// InsertThrottleEventBatch. A nil Inserter is the AC #13
// degraded-mode case (boot-failed observability); NewSink
// tolerates it and the sink runs as a no-op drain.
type Inserter interface {
	InsertThrottleEventBatch(ctx context.Context, events []Event) error
}

// BlockCounter increments a per-IP per-minute throttle block
// counter. Called on EVERY successful Tier-1/Tier-2 block —
// including blocks the LRU suppresses for event-table
// persistence. AC #3 invariant: the per-minute counter
// reflects attack volume; suppressing repeat event rows does
// NOT suppress the dashboard timeline tick.
//
// Production wiring uses observability.Aggregator.
// BumpThrottleBlocks. A nil BlockCounter is tolerated
// (degraded mode).
type BlockCounter interface {
	BumpThrottleBlocks(srcIP string)
}

// Sink is the production EventSink. Mirror of waf.Sink.
type Sink struct {
	inserter       Inserter
	counter        BlockCounter
	logger         *slog.Logger
	lru            *emitLRU
	in             chan Event
	flushInterval  time.Duration
	flushBatchSize int
	done           chan struct{}

	emitted             uint64
	droppedByChannel    uint64
	suppressedByLRU     uint64
	flushSuccessBatches uint64
	flushErrBatches     uint64
	flushedEvents       uint64

	mu      sync.Mutex
	pending []Event
}

// SinkConfig groups the tunables; nil-valued fields fall back
// to the Default* constants.
type SinkConfig struct {
	ChannelBuffer  int
	FlushInterval  time.Duration
	FlushBatchSize int
	LRUCap         int
	LRUTTL         time.Duration
}

// NewSink constructs a Sink. inserter and counter may be nil
// (degraded mode); logger may be nil (falls back to
// slog.Default). The returned sink is NOT running — call Run
// on a goroutine to drain the ingress channel.
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

// Emit queues an event for persistence. Non-blocking: full
// channel → drop + droppedByChannel++. NEVER blocks the auth
// path. AC #13 invariant + spec §1.6.4.
func (s *Sink) Emit(e Event) {
	select {
	case s.in <- e:
	default:
		atomic.AddUint64(&s.droppedByChannel, 1)
	}
}

// Run drives the sink goroutine until ctx is cancelled. On
// cancellation, performs one final flush so buffered events
// aren't lost. Wrapped in recover() per AC #13.
func (s *Sink) Run(ctx context.Context) {
	defer close(s.done)
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("throttle: sink panic; rate-limit event emission disabled for the rest of this process",
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
// the LRU rate-limit + bumping the BlockCounter on EVERY
// absorbed event (including suppressed). Bump-then-suppress
// invariant per AC #3.
func (s *Sink) absorb(e Event) {
	if s.counter != nil {
		s.counter.BumpThrottleBlocks(e.SrcIP)
	}
	if !s.lru.shouldEmit(e.SrcIP, e.Tier) {
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

// flush serialises the in-flight buffer and resets it. AC #13:
// errors are logged + counted, never returned. Nil inserter
// → silent skip (still resets state so the next minute starts
// clean).
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
		s.logger.Debug("throttle: flush skipped (no inserter — degraded mode)",
			slog.Int("dropped_events", len(batch)),
		)
		return
	}

	if err := s.inserter.InsertThrottleEventBatch(ctx, batch); err != nil {
		atomic.AddUint64(&s.flushErrBatches, 1)
		s.logger.Error("throttle: flush failed; events lost",
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
// found a full ingress channel.
func (s *Sink) DroppedByChannel() uint64 {
	return atomic.LoadUint64(&s.droppedByChannel)
}

// SuppressedByLRU returns the number of events the LRU
// rate-limiter suppressed.
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

// FlushedEvents returns the total number of events
// successfully persisted via the Inserter.
func (s *Sink) FlushedEvents() uint64 {
	return atomic.LoadUint64(&s.flushedEvents)
}

// Emitted returns the count of Emit calls that passed the
// channel + LRU (i.e. became eligible for persistence).
func (s *Sink) Emitted() uint64 {
	return atomic.LoadUint64(&s.emitted)
}
