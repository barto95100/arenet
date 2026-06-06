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

// AuthEventSink — Step V.2 spec §3.6. Channel + batcher
// wrapper around InsertAuthEventBatch. The auth-failure
// fan-out point in internal/api/audit_helpers.go submits to
// this sink alongside the existing audit-bucket append. The
// audit log keeps the canonical record (Step Q D2.B); this
// sink is the real-time stream the V.3 geo bus and the future
// per-IP timeline consume.
//
// Direct mirror of CertEventSink (Step U.1) — same
// non-blocking Submit, same drain-on-shutdown, same AC #13
// nil-inserter degraded mode. Refer to cert_sink.go for the
// pattern's rationale; this file is the Auth-shaped
// instantiation.
//
// Differences vs CertEventSink:
//   - NO LRU dedupe. Auth failures CAN be high-volume under a
//     brute-force scenario, but the V.3 ring buffer + the
//     30 d retention cap on the table already bound the
//     storage growth. The dedupe trade-off (suppress
//     repeated rows) would hide exactly the signal an
//     operator wants to see — a 1000-failures-from-one-IP
//     burst should produce 1000 rows, not one.
//   - NO companion BlockCounter. Auth events don't aggregate
//     into per-minute bucket counters today (no auth-rate
//     dashboard tile); the WAF/throttle bump-and-suppress
//     invariant has no equivalent.

package observability

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Default tuning parameters. Mirror the CertEventSink
// defaults — same channel buffer, same flush cadence. Auth
// failures and cert events both live alongside the 10 s
// Activity log poll cadence; a 2 s flush is operator-
// tolerable for either.
const (
	DefaultAuthChannelBuffer  = 1024
	DefaultAuthFlushInterval  = 2 * time.Second
	DefaultAuthFlushBatchSize = 64
)

// AuthInserter is the persistence surface the sink depends
// on. *Store satisfies it via InsertAuthEventBatch. A nil
// AuthInserter is the AC #13 degraded-mode case
// (boot-failed observability); NewAuthEventSink tolerates it
// and the sink runs as a no-op drain (channel receive +
// count + drop).
type AuthInserter interface {
	InsertAuthEventBatch(ctx context.Context, events []AuthEvent) error
}

// AuthEventSink is the production EventSink for auth failure
// events. Mirror of CertEventSink — same non-blocking Submit
// contract because the audit_helpers.appendAudit fan-out runs
// on the request goroutine and MUST NOT stall the response.
type AuthEventSink struct {
	inserter       AuthInserter
	logger         *slog.Logger
	in             chan AuthEvent
	flushInterval  time.Duration
	flushBatchSize int
	done           chan struct{}

	submitted           uint64
	droppedByChannel    uint64
	flushSuccessBatches uint64
	flushErrBatches     uint64
	flushedEvents       uint64

	mu      sync.Mutex
	pending []AuthEvent
}

// AuthSinkConfig groups the tunables; zero-valued fields fall
// back to the Default* constants.
type AuthSinkConfig struct {
	ChannelBuffer  int
	FlushInterval  time.Duration
	FlushBatchSize int
}

// NewAuthEventSink constructs an AuthEventSink. inserter may
// be nil (degraded mode); logger may be nil (falls back to
// slog.Default). The returned sink is NOT yet running — call
// Start to spawn the drain goroutine.
func NewAuthEventSink(inserter AuthInserter, logger *slog.Logger, cfg AuthSinkConfig) *AuthEventSink {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.ChannelBuffer <= 0 {
		cfg.ChannelBuffer = DefaultAuthChannelBuffer
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultAuthFlushInterval
	}
	if cfg.FlushBatchSize <= 0 {
		cfg.FlushBatchSize = DefaultAuthFlushBatchSize
	}
	return &AuthEventSink{
		inserter:       inserter,
		logger:         logger,
		in:             make(chan AuthEvent, cfg.ChannelBuffer),
		flushInterval:  cfg.FlushInterval,
		flushBatchSize: cfg.FlushBatchSize,
		done:           make(chan struct{}),
		pending:        make([]AuthEvent, 0, cfg.FlushBatchSize),
	}
}

// Submit queues an event for persistence. Non-blocking: if
// the ingress channel is full, the event is dropped and the
// droppedByChannel counter increments. NEVER blocks the
// caller — required by the audit_helpers fan-out contract
// (runs on the request goroutine, must not stall the 401/403
// response).
//
// Safe to call on a nil receiver: dropped silently (the
// audit_helpers fan-out is nil-safe by design so degraded
// observability never breaks the auth path).
func (s *AuthEventSink) Submit(e AuthEvent) {
	if s == nil {
		return
	}
	select {
	case s.in <- e:
		atomic.AddUint64(&s.submitted, 1)
	default:
		atomic.AddUint64(&s.droppedByChannel, 1)
	}
}

// Start spawns the drain goroutine. Returns nil
// unconditionally for symmetry with future sinks that may
// fail to acquire resources.
func (s *AuthEventSink) Start(ctx context.Context) error {
	go s.run(ctx)
	return nil
}

// Stop signals the drain goroutine to exit and waits up to
// timeout for it to drain pending events and finish.
// Returns context.DeadlineExceeded when the timeout fires.
func (s *AuthEventSink) Stop(timeout time.Duration) error {
	select {
	case <-s.done:
		return nil
	case <-time.After(timeout):
		return context.DeadlineExceeded
	}
}

func (s *AuthEventSink) run(ctx context.Context) {
	defer close(s.done)
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("auth event sink panic; auth event persistence disabled for the rest of this process",
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

func (s *AuthEventSink) drain() {
	for {
		select {
		case e := <-s.in:
			s.absorb(e)
		default:
			return
		}
	}
}

func (s *AuthEventSink) absorb(e AuthEvent) {
	s.mu.Lock()
	s.pending = append(s.pending, e)
	shouldFlush := len(s.pending) >= s.flushBatchSize
	s.mu.Unlock()
	if shouldFlush {
		s.flush(context.Background())
	}
}

func (s *AuthEventSink) flush(ctx context.Context) {
	s.mu.Lock()
	if len(s.pending) == 0 {
		s.mu.Unlock()
		return
	}
	batch := s.pending
	s.pending = make([]AuthEvent, 0, s.flushBatchSize)
	s.mu.Unlock()

	if s.inserter == nil {
		s.logger.Debug("auth event sink: flush skipped (no inserter — degraded mode)",
			slog.Int("dropped_events", len(batch)),
		)
		return
	}

	if err := s.inserter.InsertAuthEventBatch(ctx, batch); err != nil {
		atomic.AddUint64(&s.flushErrBatches, 1)
		s.logger.Error("auth event sink: flush failed; events lost",
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
func (s *AuthEventSink) Submitted() uint64 {
	return atomic.LoadUint64(&s.submitted)
}

// DroppedByChannel returns the number of Submit calls that
// found a full ingress channel.
func (s *AuthEventSink) DroppedByChannel() uint64 {
	return atomic.LoadUint64(&s.droppedByChannel)
}

// FlushSuccessBatches returns the number of batched flushes
// that completed without error.
func (s *AuthEventSink) FlushSuccessBatches() uint64 {
	return atomic.LoadUint64(&s.flushSuccessBatches)
}

// FlushErrBatches returns the number of batched flushes that
// failed (logged + counted; never propagated to Submit).
func (s *AuthEventSink) FlushErrBatches() uint64 {
	return atomic.LoadUint64(&s.flushErrBatches)
}

// FlushedEvents returns the total number of events
// successfully persisted via the Inserter.
func (s *AuthEventSink) FlushedEvents() uint64 {
	return atomic.LoadUint64(&s.flushedEvents)
}
