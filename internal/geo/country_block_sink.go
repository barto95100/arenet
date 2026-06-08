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

package geo

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/barto95100/arenet/internal/observability"
)

// Step W.4 — country-block sink.
//
// Surfaces W.1 block decisions as (a) GeoEvent{category:
// "country_block"} on the geo bus so /map renders gray
// arcs, AND (b) persisted country_block_event rows so the
// W.5 activity log can drill into "which countries hit
// which routes, when". The dual fan-out matches the design
// the spec §3.5 locked: real-time visualization + 30-day
// retrievable history.
//
// Gates (in order, mirror of DefaultNormalSink):
//
//   1. Sampling gate — random sample at SamplePct%. The
//      brief reuses the V.1 ARENET_NORMAL_TRAFFIC_SAMPLE_PCT
//      env var rather than introducing a category-specific
//      one — env-var sprawl is the bigger UX hazard at homelab
//      scale than the loss of per-category tuning.
//   2. Per-IP cooldown gate — same LRU + ipCooldownCache
//      as the V.1 sink so a sustained block burst from one
//      source doesn't flood the activity log + map.
//
// The W.1 matcher already RFC1918-bypasses BEFORE block
// decisions reach the sink (matcher.go Layer 2), so the
// sink never sees a LAN source — no LAN-counter integration
// is needed here, unlike the V.1 normal sink.
//
// Persistence happens INSIDE the sink (batched flush
// goroutine, AC #13 non-blocking), mirroring the WAF sink's
// pattern. A nil Inserter is the degraded-mode case (boot-
// failed observability): events publish to the bus but are
// not persisted; the sink stays alive.
//
// Sink is nil-receiver-safe: (*DefaultCountryBlockSink)(nil)
// .Submit(...) is a no-op. The geoForwardingCountryBlockSink
// wrapper in cmd/arenet relies on this for the AC #13
// degraded-mode path.

// CountryBlockInserter is the persistence seam the sink
// depends on. Defined as an interface so a test can inject
// a fake without spinning up SQLite. *observability.Store
// satisfies it via InsertCountryBlockEventBatch.
type CountryBlockInserter interface {
	InsertCountryBlockEventBatch(ctx context.Context, events []observability.CountryBlockEvent) error
}

// CountryBlockSink is the seam the W.1
// countryblock.BlockSink dispatches to (via the
// geoForwardingCountryBlockSink wrapper in cmd/arenet).
// Declared as an interface so V.1.2-shaped tests can stub
// without the LRU + PRNG + bus + inserter dependencies.
type CountryBlockSink interface {
	// SubmitCountryBlock takes a single block observation.
	// Implementations MUST be non-blocking (called on the
	// request goroutine via the W.1 module's ServeHTTP).
	SubmitCountryBlock(ts time.Time, routeID, srcIP, country, mode, reason string, statusCode int)

	// Close releases background resources (the flush
	// goroutine). Idempotent.
	Close() error
}

// Default tuning constants for the country-block sink.
// Mirror the V.1 normal_sink + WAF sink shapes.
const (
	defaultCBChannelBuffer  = 1024
	defaultCBFlushInterval  = 250 * time.Millisecond
	defaultCBFlushBatchSize = 100
	defaultCBCacheCap       = 4096
)

// CountryBlockSinkConfig groups the operator-tunable knobs.
// Per the brief, SamplePct + Cooldown REUSE the V.1.3
// normal-traffic env vars to avoid sprawl. Tests construct
// the config directly.
type CountryBlockSinkConfig struct {
	// SamplePct (0..100). 0 disables emission entirely —
	// SubmitCountryBlock returns immediately on the cheap
	// PCT compare. Per the brief, the production wiring
	// reads this from ARENET_NORMAL_TRAFFIC_SAMPLE_PCT.
	SamplePct int

	// Cooldown is the per-IP rate cap. 0 disables the
	// cooldown gate (sampling alone bounds the rate).
	Cooldown time.Duration

	// CacheCapacity is the LRU max entries. Default 4096
	// when ≤ 0.
	CacheCapacity int

	// ChannelBuffer, FlushInterval, FlushBatchSize control
	// the background batched-flush goroutine. Default
	// to the package constants when ≤ 0. Operators don't
	// tune these today; the fields exist for tests that
	// need fast flush.
	ChannelBuffer  int
	FlushInterval  time.Duration
	FlushBatchSize int
}

// DefaultCountryBlockSink is the production
// CountryBlockSink. It owns the sampling PRNG, the per-IP
// cooldown LRU, the geo enricher reference, the bus
// reference, AND the batched-flush goroutine. The flush
// goroutine drains an ingress channel into the Inserter
// every FlushInterval or when FlushBatchSize accumulates.
//
// AC #13: SubmitCountryBlock is non-blocking. Channel-full
// drops increment the droppedByChannel counter without
// stalling the request goroutine. Flush errors are logged
// + counted, never returned.
type DefaultCountryBlockSink struct {
	bus      *Bus
	enricher *Enricher
	inserter CountryBlockInserter
	logger   *slog.Logger

	samplePct      int
	cooldown       time.Duration
	cache          *ipCooldownCache
	flushInterval  time.Duration
	flushBatchSize int

	in   chan observability.CountryBlockEvent
	done chan struct{}

	// PRNG for the sample gate; mutex-guarded because
	// rand.Rand isn't safe for concurrent use. Same shape
	// as the V.1 normal sink.
	prngMu sync.Mutex
	prng   *rand.Rand

	// Atomics for ops introspection. Mirror the WAF sink
	// counter shape.
	emitted             uint64
	droppedByChannel    uint64
	suppressedByLRU     uint64
	flushSuccessBatches uint64
	flushErrBatches     uint64
	flushedEvents       uint64

	// Flush buffer (drained by the goroutine). mu guards
	// concurrent absorb + flush.
	mu      sync.Mutex
	pending []observability.CountryBlockEvent
}

// NewDefaultCountryBlockSink constructs the production
// sink. The returned sink is NOT yet running — call Run on
// a goroutine to drain the ingress channel.
//
// Per brief, when cfg.SamplePct=0 the sink is "disabled":
// SubmitCountryBlock returns on the first PCT compare
// without touching any other resource. The constructor
// still allocates the LRU + PRNG + channel + buffer so a
// runtime toggle (admin endpoint flipping SamplePct,
// deferred) doesn't need re-construction.
//
// inserter may be nil (boot-failed observability — the
// flush path skips persistence silently); bus / enricher
// may NOT be nil (the geo-event publishing contract is
// load-bearing). logger may be nil (falls back to
// slog.Default).
func NewDefaultCountryBlockSink(
	bus *Bus,
	enricher *Enricher,
	inserter CountryBlockInserter,
	logger *slog.Logger,
	cfg CountryBlockSinkConfig,
) *DefaultCountryBlockSink {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.CacheCapacity <= 0 {
		cfg.CacheCapacity = defaultCBCacheCap
	}
	if cfg.ChannelBuffer <= 0 {
		cfg.ChannelBuffer = defaultCBChannelBuffer
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultCBFlushInterval
	}
	if cfg.FlushBatchSize <= 0 {
		cfg.FlushBatchSize = defaultCBFlushBatchSize
	}
	return &DefaultCountryBlockSink{
		bus:            bus,
		enricher:       enricher,
		inserter:       inserter,
		logger:         logger,
		samplePct:      cfg.SamplePct,
		cooldown:       cfg.Cooldown,
		cache:          newIPCooldownCache(cfg.CacheCapacity),
		flushInterval:  cfg.FlushInterval,
		flushBatchSize: cfg.FlushBatchSize,
		in:             make(chan observability.CountryBlockEvent, cfg.ChannelBuffer),
		done:           make(chan struct{}),
		pending:        make([]observability.CountryBlockEvent, 0, cfg.FlushBatchSize),
		prng:           rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0xD1B54A32D192ED03)),
	}
}

// SubmitCountryBlock applies the gates then publishes +
// enqueues. See the file-level comment for the gate
// sequence.
//
// Safe to call on a nil receiver (degraded-mode no-op).
// Safe to call concurrently from any goroutine.
func (s *DefaultCountryBlockSink) SubmitCountryBlock(
	ts time.Time, routeID, srcIP, country, mode, reason string, statusCode int,
) {
	if s == nil {
		return
	}
	// 1. Sampling gate — cheapest reject. samplePct=0 is
	//    the disabled state; samplePct=100 always passes.
	if s.samplePct <= 0 {
		return
	}
	if s.samplePct < 100 {
		s.prngMu.Lock()
		roll := s.prng.IntN(100)
		s.prngMu.Unlock()
		if roll >= s.samplePct {
			return
		}
	}

	// 2. Per-IP cooldown gate. Cooldown=0 disables this
	//    gate. The W.1 matcher already short-circuited
	//    RFC1918 sources, so we don't repeat that check
	//    here.
	if s.cooldown > 0 {
		now := time.Now()
		if last, ok := s.cache.peek(srcIP); ok && now.Sub(last) < s.cooldown {
			atomic.AddUint64(&s.suppressedByLRU, 1)
			return
		}
		s.cache.put(srcIP, now)
	}

	// 3. Bus publish. Synchronous because the Bus is
	//    ring-buffered + lock-free on the producer side
	//    (V.3 design). The /map page subscribers see the
	//    event on the next WS frame.
	if s.bus != nil && s.enricher != nil {
		event := s.enricher.EnrichCountryBlock(srcIP, routeID, country, mode, reason, statusCode)
		s.bus.Publish(event)
	}

	// 4. Enqueue for persistence. Non-blocking channel
	//    send — if the channel is full (flush goroutine
	//    is behind), drop with a counter bump. AC #13.
	row := observability.CountryBlockEvent{
		Ts:         ts.UTC(),
		RouteID:    routeID,
		SrcIP:      srcIP,
		Country:    country,
		Mode:       mode,
		StatusCode: statusCode,
		Reason:     reason,
	}
	select {
	case s.in <- row:
		atomic.AddUint64(&s.emitted, 1)
	default:
		atomic.AddUint64(&s.droppedByChannel, 1)
	}
}

// Run drives the sink's flush goroutine until ctx is
// cancelled. On cancellation, flushes whatever is pending.
// Wrapped in a recover so a panic inside logs + exits
// cleanly without bringing down the proxy.
//
// Per the WAF + throttle sink pattern; symmetric for
// operability.
func (s *DefaultCountryBlockSink) Run(ctx context.Context) {
	if s == nil {
		return
	}
	defer close(s.done)
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("country block: sink panic; emission disabled for the rest of this process",
				slog.Any("panic", r),
			)
		}
	}()

	tick := time.NewTicker(s.flushInterval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			// Drain any in-flight events from the ingress
			// channel into the pending buffer BEFORE the
			// final flush. Without this drain, a cancel
			// arriving between Submit's channel-send and
			// the goroutine's next loop iteration would
			// lose those events on shutdown.
			for {
				select {
				case e := <-s.in:
					s.absorb(e)
				default:
					goto drained
				}
			}
		drained:
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
func (s *DefaultCountryBlockSink) Done() <-chan struct{} {
	return s.done
}

// Close satisfies CountryBlockSink. No-op today (Run is
// owned by main.go via context cancellation); ships for
// interface symmetry with the V.1 NormalSink.
func (s *DefaultCountryBlockSink) Close() error {
	return nil
}

func (s *DefaultCountryBlockSink) absorb(e observability.CountryBlockEvent) {
	s.mu.Lock()
	s.pending = append(s.pending, e)
	shouldFlush := len(s.pending) >= s.flushBatchSize
	s.mu.Unlock()
	if shouldFlush {
		s.flush(context.Background())
	}
}

func (s *DefaultCountryBlockSink) flush(ctx context.Context) {
	s.mu.Lock()
	if len(s.pending) == 0 {
		s.mu.Unlock()
		return
	}
	batch := s.pending
	s.pending = make([]observability.CountryBlockEvent, 0, s.flushBatchSize)
	s.mu.Unlock()

	if s.inserter == nil {
		// Degraded-mode boot path. Drop silently with a
		// debug log so operators investigating an absent
		// activity-log row know where to look.
		s.logger.Debug("country block: flush skipped (no inserter — degraded mode)",
			slog.Int("dropped_events", len(batch)),
		)
		return
	}
	if err := s.inserter.InsertCountryBlockEventBatch(ctx, batch); err != nil {
		atomic.AddUint64(&s.flushErrBatches, 1)
		s.logger.Error("country block: flush failed; events lost",
			slog.String("err", err.Error()),
			slog.Int("lost_events", len(batch)),
		)
		return
	}
	atomic.AddUint64(&s.flushSuccessBatches, 1)
	atomic.AddUint64(&s.flushedEvents, uint64(len(batch)))
}

// --- Counters (test + ops introspection) -------------------

func (s *DefaultCountryBlockSink) Emitted() uint64 {
	return atomic.LoadUint64(&s.emitted)
}

func (s *DefaultCountryBlockSink) DroppedByChannel() uint64 {
	return atomic.LoadUint64(&s.droppedByChannel)
}

func (s *DefaultCountryBlockSink) SuppressedByLRU() uint64 {
	return atomic.LoadUint64(&s.suppressedByLRU)
}

func (s *DefaultCountryBlockSink) FlushSuccessBatches() uint64 {
	return atomic.LoadUint64(&s.flushSuccessBatches)
}

func (s *DefaultCountryBlockSink) FlushErrBatches() uint64 {
	return atomic.LoadUint64(&s.flushErrBatches)
}

func (s *DefaultCountryBlockSink) FlushedEvents() uint64 {
	return atomic.LoadUint64(&s.flushedEvents)
}

// SamplePct exposes the configured percentage for boot-log
// + healthz reporting. Mirror of the V.1 normal sink.
func (s *DefaultCountryBlockSink) SamplePct() int {
	if s == nil {
		return 0
	}
	return s.samplePct
}
