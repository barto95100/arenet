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

// CertEventSink — Step U.1 spec §4. Channel + batcher wrapper
// around InsertCertEventBatch. Designed to be subscribed to
// the certinfo.Tracker's AC #18 Subscribe seam by U.2 (the
// caller translates certinfo.Event → CertEvent and calls
// Submit). U.1 ships the sink + the boot-log signal; U.2
// hooks it up. The sink itself runs to completion regardless
// — even with no producer attached, Start succeeds and Stop
// drains cleanly.
//
// Differences vs internal/waf/sink.go and
// internal/throttle/sink.go:
//   - NO LRU dedupe. Cert events are operationally low-volume
//     (a handful of rows per domain per day, even on a fail
//     loop — certmagic's exponential backoff caps the rate);
//     the LRU's reason-for-being (suppress repeat WAF blocks
//     at attack rate) doesn't apply. Spec §3.3 already filters
//     cert_obtaining at the upstream Subscribe handler in U.2,
//     which removes the noisiest signal.
//   - NO companion BlockCounter. Cert events don't aggregate
//     into the per-minute bucket counters (no operator
//     dashboard tile for "certs obtained per minute"); the
//     WAF/throttle bump-and-suppress invariant has no
//     equivalent.
//   - NO context.Context on Submit. The certinfo Subscribe
//     dispatch path is synchronous from the tracker writer
//     goroutine (per the spec freeze §6 dispatch guarantees);
//     Submit must be non-blocking and return immediately.
//     Background context wraps the channel send so a
//     cancelled producer context can't deadlock the sink.

package observability

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Default tuning parameters. Mirrors the WAF/throttle sink
// defaults — same channel buffer, slower flush interval
// because cert events are low-volume and a 2s flush is
// operator-tolerable for the Activity log's 10s poll cadence.
const (
	DefaultCertChannelBuffer  = 1024
	DefaultCertFlushInterval  = 2 * time.Second
	DefaultCertFlushBatchSize = 64
)

// CertInserter is the persistence surface the sink depends
// on. *Store satisfies it via InsertCertEventBatch. A nil
// CertInserter is the AC #13 degraded-mode case (boot-failed
// observability); NewCertEventSink tolerates it and the sink
// runs as a no-op drain (channel receive + count + drop).
type CertInserter interface {
	InsertCertEventBatch(ctx context.Context, events []CertEvent) error
}

// CertEventSink is the production EventSink for cert
// lifecycle events. Mirror of waf.Sink / throttle.Sink, minus
// the LRU and BlockCounter (see file-level comment for the
// rationale).
type CertEventSink struct {
	inserter       CertInserter
	logger         *slog.Logger
	in             chan CertEvent
	flushInterval  time.Duration
	flushBatchSize int
	done           chan struct{}

	// Counters. atomics so tests can assert without locks.
	submitted           uint64 // Submit calls that landed in the channel
	droppedByChannel    uint64 // Submit calls where the channel was full
	flushSuccessBatches uint64 // successful InsertCertEventBatch calls
	flushErrBatches     uint64 // failed InsertCertEventBatch calls
	flushedEvents       uint64 // total events successfully persisted

	// Mutex protects the in-flight buffer. The flush goroutine
	// holds it for the duration of a flush so submits arriving
	// during the flush land in the next batch.
	mu      sync.Mutex
	pending []CertEvent
}

// CertSinkConfig groups the tunables; zero-valued fields fall
// back to the Default* constants.
type CertSinkConfig struct {
	ChannelBuffer  int
	FlushInterval  time.Duration
	FlushBatchSize int
}

// NewCertEventSink constructs a CertEventSink. inserter may
// be nil (degraded mode); logger may be nil (falls back to
// slog.Default). The returned sink is NOT yet running — call
// Start to spawn the drain goroutine.
func NewCertEventSink(inserter CertInserter, logger *slog.Logger, cfg CertSinkConfig) *CertEventSink {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.ChannelBuffer <= 0 {
		cfg.ChannelBuffer = DefaultCertChannelBuffer
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultCertFlushInterval
	}
	if cfg.FlushBatchSize <= 0 {
		cfg.FlushBatchSize = DefaultCertFlushBatchSize
	}
	return &CertEventSink{
		inserter:       inserter,
		logger:         logger,
		in:             make(chan CertEvent, cfg.ChannelBuffer),
		flushInterval:  cfg.FlushInterval,
		flushBatchSize: cfg.FlushBatchSize,
		done:           make(chan struct{}),
		pending:        make([]CertEvent, 0, cfg.FlushBatchSize),
	}
}

// Submit queues an event for persistence. Non-blocking: if
// the ingress channel is full, the event is dropped and the
// droppedByChannel counter increments. NEVER blocks the
// caller — required by the certinfo Subscribe dispatch
// contract (tracker writer goroutine, must not stall).
func (s *CertEventSink) Submit(e CertEvent) {
	select {
	case s.in <- e:
		atomic.AddUint64(&s.submitted, 1)
	default:
		atomic.AddUint64(&s.droppedByChannel, 1)
	}
}

// Start spawns the drain goroutine. Returns nil
// unconditionally for symmetry with future sinks that may
// fail to acquire resources; today the sink's only resource
// is the channel (allocated in NewCertEventSink), so Start
// can't fail. ctx is the parent context the drain goroutine
// honors for shutdown.
func (s *CertEventSink) Start(ctx context.Context) error {
	go s.run(ctx)
	return nil
}

// Stop signals the drain goroutine to exit and waits up to
// timeout for it to drain pending events and finish. Returns
// nil on clean shutdown, an error wrapping the timeout if the
// drain didn't complete in time.
//
// The caller is expected to cancel the Start context BEFORE
// calling Stop so the goroutine receives the exit signal;
// Stop only waits for the done channel.
func (s *CertEventSink) Stop(timeout time.Duration) error {
	select {
	case <-s.done:
		return nil
	case <-time.After(timeout):
		return context.DeadlineExceeded
	}
}

// run is the drain goroutine. Honors ctx cancellation by
// flushing the pending buffer one last time before exiting.
// Wrapped in a recover so a panic logs + the goroutine exits
// but does NOT bring down the proxy.
func (s *CertEventSink) run(ctx context.Context) {
	defer close(s.done)
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("cert event sink panic; cert event persistence disabled for the rest of this process",
				slog.Any("panic", r),
			)
		}
	}()

	tick := time.NewTicker(s.flushInterval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			s.drain()
			s.flush(context.Background())
			return
		case e := <-s.in:
			s.absorb(e)
		case <-tick.C:
			s.flush(ctx)
		}
	}
}

// drain pulls every event still in the channel into the
// pending buffer without blocking. Called once on ctx
// cancellation so the final flush captures everything the
// producer submitted before shutdown.
func (s *CertEventSink) drain() {
	for {
		select {
		case e := <-s.in:
			s.absorb(e)
		default:
			return
		}
	}
}

// absorb folds one event into the pending buffer. Runs on the
// drain goroutine — no concurrent access to s.pending besides
// the flush branch (also goroutine-local).
func (s *CertEventSink) absorb(e CertEvent) {
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
func (s *CertEventSink) flush(ctx context.Context) {
	s.mu.Lock()
	if len(s.pending) == 0 {
		s.mu.Unlock()
		return
	}
	batch := s.pending
	s.pending = make([]CertEvent, 0, s.flushBatchSize)
	s.mu.Unlock()

	if s.inserter == nil {
		s.logger.Debug("cert event sink: flush skipped (no inserter — degraded mode)",
			slog.Int("dropped_events", len(batch)),
		)
		return
	}

	if err := s.inserter.InsertCertEventBatch(ctx, batch); err != nil {
		atomic.AddUint64(&s.flushErrBatches, 1)
		s.logger.Error("cert event sink: flush failed; events lost",
			slog.String("err", err.Error()),
			slog.Int("lost_events", len(batch)),
		)
		return
	}
	atomic.AddUint64(&s.flushSuccessBatches, 1)
	atomic.AddUint64(&s.flushedEvents, uint64(len(batch)))
}

// --- Counters (test + ops introspection) -----------------------------------

// Submitted returns the number of Submit calls that landed in
// the channel (not dropped). Cumulative since sink start.
func (s *CertEventSink) Submitted() uint64 {
	return atomic.LoadUint64(&s.submitted)
}

// DroppedByChannel returns the number of Submit calls that
// found a full ingress channel.
func (s *CertEventSink) DroppedByChannel() uint64 {
	return atomic.LoadUint64(&s.droppedByChannel)
}

// FlushSuccessBatches returns the number of batched flushes
// that completed without error.
func (s *CertEventSink) FlushSuccessBatches() uint64 {
	return atomic.LoadUint64(&s.flushSuccessBatches)
}

// FlushErrBatches returns the number of batched flushes that
// failed (logged + counted; never propagated to Submit).
func (s *CertEventSink) FlushErrBatches() uint64 {
	return atomic.LoadUint64(&s.flushErrBatches)
}

// FlushedEvents returns the total number of events
// successfully persisted via the Inserter.
func (s *CertEventSink) FlushedEvents() uint64 {
	return atomic.LoadUint64(&s.flushedEvents)
}
