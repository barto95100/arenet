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

// This file mirrors internal/throttle/sink.go's
// channel-buffered batch-insert pattern minus the per-(srcIP,
// tier) LRU. The auth throttle's LRU exists because Tier-1
// blocks on a high-volume brute-force can fire thousands of
// times per minute against the same (IP, tier) tuple ; the
// LRU collapses them to one representative row per ttl so
// the operator's event table doesn't drown.
//
// Rate-limit 429s are bursty too, but the operator's
// mental model is "I want to see EVERY 429 with its zone +
// remote_ip so I can correlate temporally". Suppressing
// repeats would erase the burst shape — exactly the
// information the operator opens /logs to see. So we batch
// for SQLite throughput but DON'T suppress.
//
// Per-route bucket counter wiring (Step Z.3) layers on top
// of this absorb path : every event bumps the route's
// rate_limit_count column in bucket_1m as a side effect.

package ratelimit

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Default tuning parameters mirror the throttle sink's
// defaults.
const (
	DefaultChannelBuffer  = 1024
	DefaultFlushInterval  = 250 * time.Millisecond
	DefaultFlushBatchSize = 100
)

// Inserter is the persistence surface the sink depends on.
// *observability.Store satisfies it via
// InsertRateLimitEventBatch. A nil Inserter is the AC #13
// degraded-mode case ; the sink runs as a no-op drain.
type Inserter interface {
	InsertRateLimitEventBatch(ctx context.Context, events []Event) error
}

// BucketCounter increments a per-route per-minute rate-
// limit counter. Production wiring uses
// observability.Aggregator.BumpRateLimitExceeded (Step Z.3).
// A nil BucketCounter is tolerated (degraded mode or
// running without the per-route timeseries layer).
type BucketCounter interface {
	BumpRateLimitExceeded(routeID string)
}

// Sink is the production EventSink.
type Sink struct {
	inserter       Inserter
	counter        BucketCounter
	logger         *slog.Logger
	in             chan Event
	flushInterval  time.Duration
	flushBatchSize int
	done           chan struct{}

	emitted             uint64
	droppedByChannel    uint64
	flushSuccessBatches uint64
	flushErrBatches     uint64
	flushedEvents       uint64

	mu      sync.Mutex
	pending []Event
}

// SinkConfig groups the tunables ; nil-valued fields fall
// back to the Default* constants.
type SinkConfig struct {
	ChannelBuffer  int
	FlushInterval  time.Duration
	FlushBatchSize int
}

// NewSink constructs a Sink. inserter and counter may be
// nil (degraded mode) ; logger may be nil (falls back to
// slog.Default). The returned sink is NOT running — call
// Run on a goroutine to drain the ingress channel.
func NewSink(inserter Inserter, counter BucketCounter, logger *slog.Logger, cfg SinkConfig) *Sink {
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
	return &Sink{
		inserter:       inserter,
		counter:        counter,
		logger:         logger,
		in:             make(chan Event, cfg.ChannelBuffer),
		flushInterval:  cfg.FlushInterval,
		flushBatchSize: cfg.FlushBatchSize,
		done:           make(chan struct{}),
		pending:        make([]Event, 0, cfg.FlushBatchSize),
	}
}

// Emit queues an event for persistence. Non-blocking : full
// channel → drop + droppedByChannel++.
func (s *Sink) Emit(e Event) {
	select {
	case s.in <- e:
	default:
		atomic.AddUint64(&s.droppedByChannel, 1)
	}
}

// Run drives the sink goroutine until ctx is cancelled. On
// cancellation, performs one final flush so buffered events
// aren't lost.
func (s *Sink) Run(ctx context.Context) {
	defer close(s.done)
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("ratelimit: sink panic ; event emission disabled for the rest of this process",
				slog.Any("panic", r))
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

// absorb folds one event into the pending buffer and bumps
// the per-route bucket counter (when wired). No LRU
// suppression — the operator wants the full burst shape
// on /logs.
func (s *Sink) absorb(e Event) {
	if s.counter != nil && e.RouteID != "" {
		s.counter.BumpRateLimitExceeded(e.RouteID)
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

// flush serialises the in-flight buffer and resets it.
// Errors logged + counted, never returned. Nil inserter →
// silent skip.
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
		s.logger.Debug("ratelimit: flush skipped (no inserter — degraded mode)",
			slog.Int("dropped_events", len(batch)))
		return
	}
	if err := s.inserter.InsertRateLimitEventBatch(ctx, batch); err != nil {
		atomic.AddUint64(&s.flushErrBatches, 1)
		s.logger.Error("ratelimit: flush failed ; events lost",
			slog.String("err", err.Error()),
			slog.Int("lost_events", len(batch)))
		return
	}
	atomic.AddUint64(&s.flushSuccessBatches, 1)
	atomic.AddUint64(&s.flushedEvents, uint64(len(batch)))
}

// --- Counters (test + ops introspection) ---

func (s *Sink) DroppedByChannel() uint64    { return atomic.LoadUint64(&s.droppedByChannel) }
func (s *Sink) FlushSuccessBatches() uint64 { return atomic.LoadUint64(&s.flushSuccessBatches) }
func (s *Sink) FlushErrBatches() uint64     { return atomic.LoadUint64(&s.flushErrBatches) }
func (s *Sink) FlushedEvents() uint64       { return atomic.LoadUint64(&s.flushedEvents) }
func (s *Sink) Emitted() uint64             { return atomic.LoadUint64(&s.emitted) }
