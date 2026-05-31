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

// sink.go mirrors internal/throttle/sink.go closely on purpose
// — Step N spec §3.3 + §5.2. The shape (non-blocking Emit,
// channel-buffered Run, batched flush, BlockCounter, recover-
// on-panic) transfers verbatim from M/Q. ONE structural
// INVERSION (per spec D4.A):
//
//   - M and Q: dedupe AFTER bump. Every absorb bumps the
//     bucket counter regardless of LRU outcome; the LRU only
//     gates the event-table row ("bump-then-suppress"
//     invariant — bucket reflects attack volume, event log
//     stays de-duplicated).
//
//   - N: dedupe BEFORE bump. CrowdSec LAPI re-emits every
//     active decision on every poll cycle (via the
//     ?startup=true initial response AND every steady-state
//     delta poll). A naive bump-on-every-absorb would inflate
//     the bucket counter by (active_count × polls_per_minute)
//     every minute. Placing the LRU AS A GATE before the
//     BlockCounter means the counter reflects "decisions
//     ARRIVED this minute" (new bans) not "decisions ACTIVE
//     this minute".
//
// Smoke verification at N.5: trip a single LAPI decision,
// observe ONE bucket counter tick across multiple poll cycles
// (not N ticks).

package crowdsec

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Default tuning parameters. ChannelBuffer is 16× the WAF/
// throttle default (per Step N risks §7): an LAPI burst at
// startup can return 10k+ active decisions in one response,
// which would overrun the 1024-slot M/Q default and surface
// as `droppedByChannel` counter ticks.
const (
	DefaultChannelBuffer  = 16_384
	DefaultFlushInterval  = 250 * time.Millisecond
	DefaultFlushBatchSize = 200
	DefaultLRUCap         = 50_000
	DefaultLRUTTL         = time.Hour
)

// Inserter is the persistence surface the sink depends on.
// *observability.Store satisfies it via
// InsertDecisionEventBatch (added at N.2 storage step). Nil
// Inserter is the AC #13 degraded-mode case; NewSink tolerates
// it and the sink runs as a no-op drain.
type Inserter interface {
	InsertDecisionEventBatch(ctx context.Context, decisions []Decision) error
	// MarkDecisionExpired records a tombstone for the given
	// UUID (LAPI signalled the decision was revoked or
	// expired). Production wiring sets the row's expires_at
	// to now() to flag it as inactive without deleting the
	// historical record — the operator dashboard needs the
	// row for forensic review even after expiry; the
	// retention.go prune step is what eventually removes it
	// after the 30d horizon (D8.A).
	//
	// Nil-tolerant: returning nil is the AC #13 contract on
	// runtime failures.
	MarkDecisionExpired(ctx context.Context, uuid string) error
}

// BlockCounter increments the per-minute decision counter
// under the sentinel routeID "_crowdsec" (Step N spec §3.5,
// mirror of Q's _throttle pattern). Called by absorb on FIRST
// SIGHT of a decision UUID — NOT on every absorb (the LRU is
// the gate; see the module-level inversion note).
//
// Production wiring is observability.Aggregator.
// BumpCrowdSecDecisions. Nil counter is tolerated (degraded
// mode).
type BlockCounter interface {
	BumpCrowdSecDecisions(srcIP string)
}

// Sink is the production EventSink. Mirror of waf.Sink and
// throttle.Sink modulo the dedupe-before-bump inversion + the
// Tombstone method.
type Sink struct {
	inserter       Inserter
	counter        BlockCounter
	logger         *slog.Logger
	lru            *decisionLRU
	in             chan sinkOp
	flushInterval  time.Duration
	flushBatchSize int
	done           chan struct{}

	emitted             uint64
	droppedByChannel    uint64
	suppressedByLRU     uint64
	tombstoneCount      uint64
	flushSuccessBatches uint64
	flushErrBatches     uint64
	flushedEvents       uint64

	mu      sync.Mutex
	pending []Decision

	// Step P.2 — opt-in tombstone fanout. The auto-classify
	// trigger engine registers a listener via
	// SetTombstoneListener to drive its operator-cooldown
	// LRU (spec D6.A). nil = no fanout, AC #21 (Step N
	// read-side unchanged) preserved.
	tombstoneListenerMu sync.RWMutex
	tombstoneListener   func(uuid string)
}

// sinkOp is the discriminated union pushed onto the ingress
// channel. A union beats two separate channels because the
// Run() select then has one input regardless of op type,
// preserving ordering between an Emit and a subsequent
// Tombstone for the same UUID (matters when LAPI publishes a
// new[] entry and then a deleted[] entry within the same
// stream payload — uncommon but legal).
type sinkOp struct {
	kind   sinkOpKind
	dec    Decision // populated when kind=opEmit
	tombID string   // populated when kind=opTombstone
}

type sinkOpKind uint8

const (
	opEmit sinkOpKind = iota
	opTombstone
)

// SinkConfig groups the tunables; zero-valued fields fall
// back to the Default* constants.
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
		lru:            newDecisionLRU(cfg.LRUCap, cfg.LRUTTL),
		in:             make(chan sinkOp, cfg.ChannelBuffer),
		flushInterval:  cfg.FlushInterval,
		flushBatchSize: cfg.FlushBatchSize,
		done:           make(chan struct{}),
		pending:        make([]Decision, 0, cfg.FlushBatchSize),
	}
}

// Emit queues a NEW decision for persistence + dedupe-then-
// bump. Non-blocking: full channel → drop +
// droppedByChannel++. NEVER blocks the StreamBouncer consumer
// goroutine (AC #13 invariant).
func (s *Sink) Emit(d Decision) {
	select {
	case s.in <- sinkOp{kind: opEmit, dec: d}:
	default:
		atomic.AddUint64(&s.droppedByChannel, 1)
	}
}

// Tombstone queues a REVOKED decision UUID. Same non-blocking
// channel discipline as Emit; sink.absorbTombstone updates the
// LRU + asks the Inserter to MarkDecisionExpired.
func (s *Sink) Tombstone(uuid string) {
	select {
	case s.in <- sinkOp{kind: opTombstone, tombID: uuid}:
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
			s.logger.Error("crowdsec: sink panic; decision event emission disabled for the rest of this process",
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
		case op := <-s.in:
			switch op.kind {
			case opEmit:
				s.absorbEmit(op.dec)
			case opTombstone:
				s.absorbTombstone(op.tombID)
			}
		case <-tick.C:
			s.flush(ctx)
		}
	}
}

// Done returns a channel closed once Run has exited.
func (s *Sink) Done() <-chan struct{} {
	return s.done
}

// absorbEmit folds one NEW decision into the pending buffer,
// applying the dedupe-BEFORE-bump invariant (Step N spec D4.A):
//
//  1. LRU.shouldEmit gates BOTH the event-table row AND the
//     BlockCounter bump. If false, neither happens — the
//     decision is a re-poll of an already-known UUID and
//     should add nothing to either surface.
//  2. If shouldEmit returns true: bump the per-minute counter
//     AND queue the row for persistence.
//
// This is OPPOSITE to M/Q where the counter ticks on every
// absorb. The asymmetry is structural by design — see the
// module-level comment in this file + spec §3.2.
func (s *Sink) absorbEmit(d Decision) {
	if !s.lru.shouldEmit(d.UUID) {
		atomic.AddUint64(&s.suppressedByLRU, 1)
		return
	}
	if s.counter != nil {
		// First-sight only — see invariant above.
		s.counter.BumpCrowdSecDecisions(d.Value)
	}
	atomic.AddUint64(&s.emitted, 1)
	s.mu.Lock()
	s.pending = append(s.pending, d)
	shouldFlush := len(s.pending) >= s.flushBatchSize
	s.mu.Unlock()
	if shouldFlush {
		s.flush(context.Background())
	}
}

// absorbTombstone updates the LRU + the persistence layer for
// a revoked decision. The LRU.forget call frees the slot so a
// future re-grant with a fresh UUID is treated as a brand-new
// decision (clean semantics).
//
// MarkDecisionExpired is a soft delete on the persistence
// side — it updates `expires_at` on the existing row without
// removing it, so the operator dashboard's historical view
// retains the record until the 30d retention prune fires
// (D8.A). Errors from the inserter are logged + counted,
// never propagated (AC #13).
func (s *Sink) absorbTombstone(uuid string) {
	s.lru.forget(uuid)
	atomic.AddUint64(&s.tombstoneCount, 1)
	if s.inserter != nil {
		if err := s.inserter.MarkDecisionExpired(context.Background(), uuid); err != nil {
			s.logger.Error("crowdsec: mark decision expired failed",
				slog.String("uuid", uuid),
				slog.String("err", err.Error()),
			)
		}
	}
	// Step P.2 — fan out to the auto-classify cooldown LRU
	// listener if one is registered. Spec D6.A + §3.6. The
	// listener resolves the UUID to (src_ip, scenario) via
	// the observability decision_event mirror table. Errors
	// inside the listener are the listener's responsibility;
	// we don't surface them here because the original
	// tombstone-absorb semantic (LRU forget + persistence
	// mark) is unaffected by listener failures.
	s.tombstoneListenerMu.RLock()
	fn := s.tombstoneListener
	s.tombstoneListenerMu.RUnlock()
	if fn != nil {
		fn(uuid)
	}
}

// SetTombstoneListener installs (or unregisters via nil) a
// callback that fires on every successful tombstone absorption.
// Spec §3.6 (D6.A): the auto-classify trigger engine uses this
// to drive its operator-cooldown LRU. nil clears the listener
// (the AC #15 boot-degraded path where no automation is wired
// returns to zero-cost fanout).
//
// AC #21 invariant: the original absorbTombstone path (LRU
// forget + MarkDecisionExpired) executes regardless of whether
// a listener is registered. The fanout is purely additive.
// Pinned by TestSink_AbsorbTombstone_NoListener_Unchanged.
func (s *Sink) SetTombstoneListener(fn func(uuid string)) {
	s.tombstoneListenerMu.Lock()
	s.tombstoneListener = fn
	s.tombstoneListenerMu.Unlock()
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
	s.pending = make([]Decision, 0, s.flushBatchSize)
	s.mu.Unlock()

	if s.inserter == nil {
		s.logger.Debug("crowdsec: flush skipped (no inserter — degraded mode)",
			slog.Int("dropped_decisions", len(batch)),
		)
		return
	}

	if err := s.inserter.InsertDecisionEventBatch(ctx, batch); err != nil {
		atomic.AddUint64(&s.flushErrBatches, 1)
		s.logger.Error("crowdsec: flush failed; decisions lost",
			slog.String("err", err.Error()),
			slog.Int("lost_decisions", len(batch)),
		)
		return
	}
	atomic.AddUint64(&s.flushSuccessBatches, 1)
	atomic.AddUint64(&s.flushedEvents, uint64(len(batch)))
}

// --- Counters (test + ops introspection) -----------------------------------

// DroppedByChannel returns the number of Emit/Tombstone calls
// that found a full ingress channel.
func (s *Sink) DroppedByChannel() uint64 {
	return atomic.LoadUint64(&s.droppedByChannel)
}

// SuppressedByLRU returns the number of Emit calls the LRU
// dedupe-before-bump path suppressed (UUID already known +
// fresh).
func (s *Sink) SuppressedByLRU() uint64 {
	return atomic.LoadUint64(&s.suppressedByLRU)
}

// TombstoneCount returns the number of Tombstone calls
// absorbed.
func (s *Sink) TombstoneCount() uint64 {
	return atomic.LoadUint64(&s.tombstoneCount)
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

// FlushedEvents returns the total number of decision rows
// successfully persisted via the Inserter.
func (s *Sink) FlushedEvents() uint64 {
	return atomic.LoadUint64(&s.flushedEvents)
}

// Emitted returns the count of Emit calls that passed the
// LRU dedupe (i.e. became eligible for persistence AND counter
// bump — these are equal in N because of dedupe-before-bump).
func (s *Sink) Emitted() uint64 {
	return atomic.LoadUint64(&s.emitted)
}
