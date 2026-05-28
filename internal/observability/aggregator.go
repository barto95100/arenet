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
	"log/slog"
	"sync"
	"time"
)

// TickDelta is one second of accumulated per-route counters
// produced by the Step E pipeline. Step 7 will wire the Step E
// Broadcaster to emit one of these per tick alongside its
// existing wire snapshot; the aggregator below consumes them
// via Ingest and produces minute buckets without ever touching
// the request path.
//
// Reqs, Fourxx, Fivexx are counts since the previous tick (NOT
// cumulative). LatencyP95Ms is the p95 over the same tick
// window — for the aggregator's purpose we store it as the
// representative latency of this 1-second sample and pick the
// max across the 60 samples at minute boundary (per spec §3
// "percentile-of-percentiles approximation").
type TickDelta struct {
	RouteID      string
	Reqs         uint64
	Fourxx       uint64
	Fivexx       uint64
	LatencyP95Ms int32
}

// routeState is the aggregator's in-memory accumulator for one
// route between two minute boundaries. All access is serialised
// by the aggregator goroutine — no mutex needed.
type routeState struct {
	req      int64
	fourxx   int64
	fivexx   int64
	p95MaxMs int32 // max across all 1-second samples this minute
	samples  int   // number of non-empty 1-second samples
}

// bucketSink is the minimal write surface the aggregator depends
// on. Defined as an interface so AC #13 runtime-failure tests can
// inject a sink whose InsertBatch returns a synthetic error,
// proving the aggregator survives a flush error mid-run (the
// alternative — closing a real *Store and racing the test
// against `sql: database is closed`-style state — is brittle and
// touches real I/O).
//
// *Store satisfies this interface in production via its
// existing InsertBatch method. A nil sink is the degraded-mode
// case from AC #13 boot-failure path.
type bucketSink interface {
	InsertBatch(ctx context.Context, gran Granularity, rows []MetricBucket) error
}

// Aggregator accumulates per-second tick deltas into per-minute
// buckets and flushes them to the Store at minute boundaries.
//
// AC #13 invariants:
//   - Ingest is non-blocking: a slow flush goroutine never blocks
//     the producer (caller drops the tick if the channel is full,
//     visible via the Dropped() counter).
//   - Flush errors are logged + counted, never returned. A
//     persistent flush failure (locked DB, disk full) yields lost
//     buckets, not lost requests. The in-memory state is reset
//     BEFORE the flush attempt so a slow / failing flush does not
//     stall the next minute's accumulation.
//   - The Now func is injectable for synthetic-clock tests.
type Aggregator struct {
	sink   bucketSink
	logger *slog.Logger
	now    func() time.Time

	// in is the ingress channel. Buffered so a brief stall in
	// the aggregator goroutine doesn't propagate backpressure
	// to the Broadcaster.
	in chan TickDelta

	// state is owned by the goroutine. Indexed by routeID. A
	// route appears here only after its first non-zero tick.
	state map[string]*routeState

	// currentMinute is the truncated-to-minute timestamp of the
	// bucket currently being accumulated.
	currentMinute time.Time

	// metrics (test/debug only)
	mu        sync.Mutex
	dropped   uint64
	flushes   uint64
	flushErrs uint64

	done chan struct{}
}

// NewAggregator builds a fresh aggregator. store may be nil —
// this is the AC #13 degraded-mode case where the metrics DB
// failed to open at boot. The aggregator still accepts ticks
// (so the producer never blocks) but skips the flush.
//
// chanBuf sizes the ingress channel; 1024 is a sensible default
// (sufficient to ride out a ~1 s flush stall at >1000 events/s).
func NewAggregator(store *Store, logger *slog.Logger, chanBuf int) *Aggregator {
	return newAggregatorWithSink(toSink(store), logger, chanBuf)
}

// toSink lifts a *Store to a bucketSink, returning a nil
// interface (not a non-nil interface wrapping a nil *Store) when
// the store itself is nil. The distinction matters: `var s
// bucketSink = (*Store)(nil)` is non-nil to interface comparisons
// but would crash when InsertBatch is called.
func toSink(s *Store) bucketSink {
	if s == nil {
		return nil
	}
	return s
}

func newAggregatorWithSink(sink bucketSink, logger *slog.Logger, chanBuf int) *Aggregator {
	if logger == nil {
		logger = slog.Default()
	}
	if chanBuf < 1 {
		chanBuf = 1024
	}
	return &Aggregator{
		sink:   sink,
		logger: logger,
		now:    func() time.Time { return time.Now().UTC() },
		in:     make(chan TickDelta, chanBuf),
		state:  make(map[string]*routeState),
		done:   make(chan struct{}),
	}
}

// SetClock overrides the time source. For tests only — production
// uses the default time.Now().UTC().
func (a *Aggregator) SetClock(now func() time.Time) {
	a.now = now
}

// Ingest queues one tick delta for aggregation. Non-blocking:
// if the ingress channel is full, the tick is dropped and the
// dropped counter is incremented. The producer (Broadcaster
// tick) MUST stay on the request-adjacent goroutine and never
// block here — AC #13.
func (a *Aggregator) Ingest(d TickDelta) {
	select {
	case a.in <- d:
	default:
		a.mu.Lock()
		a.dropped++
		a.mu.Unlock()
	}
}

// Consume implements metrics.TickConsumer. Adapter so the Step E
// ticker can fan its per-route deltas out to the observability
// pipeline without an import-direction reversal (internal/metrics
// never imports internal/observability).
//
// Non-blocking by construction: delegates to Ingest, which drops
// silently when the ingress channel is full (AC #13).
func (a *Aggregator) Consume(routeID string, reqs, fourxx, fivexx uint64, latencyP95Ms int32) {
	a.Ingest(TickDelta{
		RouteID:      routeID,
		Reqs:         reqs,
		Fourxx:       fourxx,
		Fivexx:       fivexx,
		LatencyP95Ms: latencyP95Ms,
	})
}

// FlushNow flushes whatever has accumulated in the current
// minute, immediately. Used by tests and by a clean shutdown
// path that wants to persist the partial bucket.
func (a *Aggregator) FlushNow(ctx context.Context) {
	a.flush(ctx)
}

// Dropped returns the number of ticks dropped because the
// ingress channel was full. Cumulative since aggregator start.
func (a *Aggregator) Dropped() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dropped
}

// FlushCount returns the number of successful flush cycles
// completed (including empty flushes). Test helper.
func (a *Aggregator) FlushCount() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.flushes
}

// FlushErrors returns the number of flush attempts that failed.
// AC #13: failures are counted, never propagated to the request
// path.
func (a *Aggregator) FlushErrors() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.flushErrs
}

// Run drives the aggregator goroutine until ctx is cancelled.
// On cancellation, performs one final flush so the partial
// bucket isn't lost.
//
// Wrapped in a recover() per AC #13: a panic inside the
// aggregator must not bring down the proxy. The panic is
// logged at error level and the goroutine exits — the request
// path keeps running with the in-memory Step E counters only.
func (a *Aggregator) Run(ctx context.Context) {
	defer close(a.done)
	defer func() {
		if r := recover(); r != nil {
			a.logger.Error("observability: aggregator panic; metrics disabled for the rest of this process",
				slog.Any("panic", r),
			)
		}
	}()

	a.currentMinute = a.now().Truncate(time.Minute)

	// Internal tick at 1 s: drives the minute-boundary check.
	// Production aggregator polls a.now() on each tick rather
	// than relying on time.NewTicker so synthetic-clock tests
	// can advance the clock between Ingest calls without a real
	// goroutine sleep.
	checkTicker := time.NewTicker(time.Second)
	defer checkTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.flush(context.Background())
			return
		case d := <-a.in:
			a.absorb(d)
			a.maybeFlush(ctx)
		case <-checkTicker.C:
			a.maybeFlush(ctx)
		}
	}
}

// Done returns a channel that closes once Run has exited
// (after the final flush). Test helper for clean teardown.
func (a *Aggregator) Done() <-chan struct{} {
	return a.done
}

// absorb folds one tick delta into the current minute's
// accumulator state. Goroutine-local, no locking.
func (a *Aggregator) absorb(d TickDelta) {
	if d.RouteID == "" {
		return
	}
	rs, ok := a.state[d.RouteID]
	if !ok {
		rs = &routeState{}
		a.state[d.RouteID] = rs
	}
	rs.req += int64(d.Reqs)
	rs.fourxx += int64(d.Fourxx)
	rs.fivexx += int64(d.Fivexx)
	if d.LatencyP95Ms > rs.p95MaxMs {
		rs.p95MaxMs = d.LatencyP95Ms
	}
	if d.Reqs > 0 {
		rs.samples++
	}
}

// maybeFlush checks whether the wall-clock minute has rolled
// over since the last flush, and if so, persists the
// accumulator and resets. Cheap when no rollover happened.
func (a *Aggregator) maybeFlush(ctx context.Context) {
	nowMin := a.now().Truncate(time.Minute)
	if !nowMin.After(a.currentMinute) {
		return
	}
	a.flush(ctx)
	a.currentMinute = nowMin
}

// flush serialises the in-memory accumulator to one batched
// insert and resets state. AC #13: errors are logged + counted,
// never returned. A nil store (degraded mode) results in a
// silent no-op flush — the state is still reset so the next
// minute starts clean.
func (a *Aggregator) flush(ctx context.Context) {
	a.mu.Lock()
	a.flushes++
	a.mu.Unlock()

	if len(a.state) == 0 {
		return
	}
	rows := make([]MetricBucket, 0, len(a.state))
	for id, rs := range a.state {
		rows = append(rows, MetricBucket{
			RouteID:      id,
			Ts:           a.currentMinute,
			ReqCount:     rs.req,
			FourxxCount:  rs.fourxx,
			FivexxCount:  rs.fivexx,
			LatencyP95Ms: rs.p95MaxMs,
		})
	}
	// Reset before the write so a slow / failing flush doesn't
	// stall the next minute's accumulation.
	a.state = make(map[string]*routeState, len(rows))

	if a.sink == nil {
		// Degraded mode: log once per flush at debug level so
		// we don't spam at error level for the whole process
		// lifetime.
		a.logger.Debug("observability: aggregator flush skipped (sink disabled)",
			slog.Int("rows", len(rows)),
		)
		return
	}
	if err := a.sink.InsertBatch(ctx, Granularity1m, rows); err != nil {
		a.mu.Lock()
		a.flushErrs++
		a.mu.Unlock()
		a.logger.Error("observability: aggregator flush failed",
			slog.String("err", err.Error()),
			slog.Int("rows", len(rows)),
		)
	}
}
