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
	"container/list"
	"math/rand/v2"
	"net"
	"sync"
	"time"
)

// Step V.1 — normal-traffic sink.
//
// Surfaces successful user traffic (D1: 2xx/3xx) as
// GeoEvent{category: "normal"} on the geo bus, so the
// /map page renders green arcs alongside the existing
// 4 threat colors (waf / throttle / crowdsec / auth).
//
// Three gates apply in sequence per spec §D9 (Option D):
//
//   1. Sampling gate — random %: math/rand/v2 PCG.
//      Cheap reject; runs before everything else.
//   2. RFC1918 gate — D2: LAN sources are counted in the
//      V.6 LAN pill (via LANCounter) and NOT emitted as
//      arcs. The Arenet marker's pulse already carries
//      the "you are here" signal; rendering RFC1918 sources
//      as arcs to the Arenet position itself would clutter
//      the homelab view where most traffic IS internal.
//   3. Per-IP cooldown gate — D9: hash(srcIP) → last-emit
//      timestamp LRU. If now - last < cooldown, drop. One
//      chatty client cannot dominate the green-arc layer.
//
// MMDB lookup runs ONLY after all 3 gates pass — saves the
// 1-5 µs warm / 50-200 µs cold per-event cost on the
// dropped 95% (per discovery §3.3 sample-before-lookup).
//
// Sink is nil-receiver-safe: (*DefaultNormalSink)(nil)
// .Submit(...) is a no-op. The wrap-at-install-time
// pattern (V.1.3 geoForwardingNormalSink) relies on this
// for AC #12 degraded mode.

// NormalSink is the seam V.1.2's RouteMetricsHandler
// middleware calls on every eligible successful request.
// Declared as an interface so V.1.2 + V.1.3 tests can
// substitute a stub without spinning up the LRU + PRNG +
// enricher dependencies.
type NormalSink interface {
	// Submit takes a single observation. Implementations
	// MUST be non-blocking (the middleware defer runs on
	// the request goroutine — must not stall the response).
	// Status is the final HTTP status (2xx/3xx per spec
	// §D1 gate; the middleware enforces this before
	// calling). srcIP is the trusted-proxy-resolved client
	// IP (via auth.IPExtractor). routeID identifies the
	// arenet route.
	Submit(status int, srcIP, routeID string)

	// Close releases any background resources. Idempotent.
	// Today's DefaultNormalSink has no background loop, so
	// Close is a no-op — but the interface ships it for
	// future-proofing (e.g. a background LRU pruner).
	Close() error
}

// LANCounter is the seam DefaultNormalSink uses to bump
// the V.6 LAN-events pill counter on the /map page when
// an RFC1918 source short-circuits arc emission. Declared
// as an interface so V.1.2 can wire the real counter from
// the page-level subscriber without coupling the sink to
// the frontend state model.
//
// V.1.1 ships the interface only — production wiring lands
// in V.1.3 alongside the geoForwardingNormalSink. The unit
// tests use a stub.
type LANCounter interface {
	Inc()
}

// NoopLANCounter is the default LANCounter when no real
// counter is wired (e.g. backend-only tests, or operator
// configurations where the V.6 LAN pill isn't surfaced).
// Inc is a no-op; allocation-free.
type NoopLANCounter struct{}

// Inc satisfies LANCounter.
func (NoopLANCounter) Inc() {}

// DefaultNormalSink is the production NormalSink.
type DefaultNormalSink struct {
	bus        *Bus
	enricher   *Enricher
	lanCounter LANCounter
	samplePct  int           // 0..100 — spec §D5
	cooldown   time.Duration // spec §D9
	cache      *ipCooldownCache

	// PRNG for the §D9 sample gate. math/rand/v2's PCG is
	// fast and per-process; the Mutex guards it because
	// rand.Rand isn't safe for concurrent use. A
	// sync.Pool of generators would be a microoptimization
	// not worth its complexity at homelab scale.
	prngMu sync.Mutex
	prng   *rand.Rand
}

// NormalSinkConfig groups the operator-tunable knobs from
// spec §5. Validation lives in the env-var parser at
// V.1.3 (NewDefaultNormalSink trusts its caller); this
// struct shape lets the parser produce the config once
// and hand it to the constructor.
type NormalSinkConfig struct {
	// SamplePct (0..100). 0 disables the sink — Submit
	// returns immediately on the cheap PCT compare,
	// triggering no LRU touch + no MMDB lookup. Per spec
	// §D5 master switch.
	SamplePct int
	// Cooldown is the per-IP rate cap. 0 disables the
	// cooldown gate (random sample alone). Per spec §D9.
	Cooldown time.Duration
	// CacheCapacity is the LRU max entries. Spec §D9
	// suggests 4096. Bound by the operator's RAM; a
	// homelab tab is unlikely to see 4096 distinct
	// public IPs in a cooldown window.
	CacheCapacity int
}

// NewDefaultNormalSink constructs the production sink.
// Caller is responsible for the bus + enricher lifecycle
// (both already provisioned by V.1-V.3 wiring in main.go);
// the sink only HOLDS references.
//
// lanCounter may be nil → NoopLANCounter substituted; that
// makes the sink self-contained for backend-only tests.
//
// Per spec §D5, when cfg.SamplePct=0 the sink is
// "disabled" — Submit returns on the first PCT compare
// without touching any other resource. The constructor
// still allocates the LRU + PRNG so a future operator
// toggle (e.g. an admin endpoint flipping SamplePct at
// runtime, deferred) doesn't need to re-construct the
// whole sink.
func NewDefaultNormalSink(bus *Bus, enricher *Enricher, lanCounter LANCounter, cfg NormalSinkConfig) *DefaultNormalSink {
	if lanCounter == nil {
		lanCounter = NoopLANCounter{}
	}
	capacity := cfg.CacheCapacity
	if capacity <= 0 {
		capacity = 4096
	}
	return &DefaultNormalSink{
		bus:        bus,
		enricher:   enricher,
		lanCounter: lanCounter,
		samplePct:  cfg.SamplePct,
		cooldown:   cfg.Cooldown,
		cache:      newIPCooldownCache(capacity),
		// Seed from time-based entropy. The PRNG is for
		// sampling, not cryptographic decisions — a
		// predictable seed would let an attacker craft
		// traffic that always lands on the "rejected" 95%,
		// but the threat model for an observability sink
		// doesn't include that adversary.
		prng: rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0x9E3779B97F4A7C15)),
	}
}

// Submit applies the 3 gates then publishes. See the
// file-level comment for the gate sequence rationale.
//
// Safe to call on a nil receiver (degraded mode no-op).
// Safe to call concurrently from any goroutine.
func (s *DefaultNormalSink) Submit(status int, srcIP, routeID string) {
	if s == nil {
		return
	}
	// 1. Sampling gate — fastest reject. samplePct=0 is
	//    the V.1 disabled state; samplePct=100 always
	//    passes.
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

	// 2. RFC1918 gate — count in LAN pill, no emit.
	//    isLAN handles nil + unspecified IPs (returns
	//    false → falls through to the normal path, where
	//    enrichBase produces an UNK event the frontend
	//    can still render).
	if ip := net.ParseIP(srcIP); ip != nil && isLAN(ip) {
		s.lanCounter.Inc()
		return
	}

	// 3. Per-IP cooldown gate. Cooldown=0 disables this
	//    gate (sampling alone bounds the rate).
	if s.cooldown > 0 {
		now := time.Now()
		if last, ok := s.cache.peek(srcIP); ok && now.Sub(last) < s.cooldown {
			return
		}
		s.cache.put(srcIP, now)
	}

	// 4. Enrich + publish. enrichBase tolerates a missing
	//    MMDB by returning a partial event with
	//    SourceCountry="UNK" and zero lat/lon — frontend
	//    renders a degraded arc rather than nothing
	//    (consistent with the V.2 behavior for the other
	//    4 categories).
	event := s.enricher.EnrichNormal(srcIP, routeID, status)
	s.bus.Publish(event)
}

// Close satisfies NormalSink. No background loops in V.1.1
// so this is a no-op; ships for interface symmetry.
func (s *DefaultNormalSink) Close() error {
	return nil
}

// SamplePct exposes the configured percentage for boot-log
// + healthz reporting. V.1.3 logs this at boot per the
// HF4 pattern.
func (s *DefaultNormalSink) SamplePct() int {
	if s == nil {
		return 0
	}
	return s.samplePct
}

// Cooldown exposes the configured cooldown for the same
// reason.
func (s *DefaultNormalSink) Cooldown() time.Duration {
	if s == nil {
		return 0
	}
	return s.cooldown
}

// Compile-time interface check.
var _ NormalSink = (*DefaultNormalSink)(nil)

// -------------------------------------------------------
// ipCooldownCache: tiny LRU+TTL for per-IP cooldown.
//
// Rationale for hand-rolling vs pulling hashicorp/golang-
// lru: the project has no LRU dep today (`grep lru go.mod`
// → empty). Adding a transitive dependency for ~70 LOC of
// straightforward map+linked-list code isn't justified at
// homelab scale. The implementation uses container/list
// (stdlib) for the doubly-linked-list backbone.
//
// API surface (peek + put) is tuned for the Submit path's
// pattern: read-then-conditional-write. peek does NOT
// move the entry to the front of the LRU (read-only),
// because the cooldown decision is based on the stored
// timestamp regardless of LRU ordering. put always moves
// the entry to the front so eviction targets the genuinely
// LRU entries.
//
// Concurrency: single sync.Mutex. Sharding deferred — the
// homelab scale (a handful of req/s post-sampling) won't
// see contention. The Submit path's other lock (prngMu)
// is held for nanoseconds; total per-event lock-acquired
// time is well under the MMDB lookup cost.

type ipCooldownCache struct {
	mu       sync.Mutex
	capacity int
	order    *list.List
	index    map[string]*list.Element
}

type cooldownEntry struct {
	key string
	ts  time.Time
}

func newIPCooldownCache(capacity int) *ipCooldownCache {
	if capacity <= 0 {
		capacity = 4096
	}
	return &ipCooldownCache{
		capacity: capacity,
		order:    list.New(),
		index:    make(map[string]*list.Element, capacity),
	}
}

// peek returns the stored timestamp for key without
// touching LRU order. Used by Submit's cooldown gate to
// answer "have we emitted for this IP recently?" without
// promoting the entry to MRU (the put on miss-or-stale
// handles promotion).
func (c *ipCooldownCache) peek(key string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	elt, ok := c.index[key]
	if !ok {
		return time.Time{}, false
	}
	return elt.Value.(*cooldownEntry).ts, true
}

// put inserts or updates key with the given timestamp.
// Promotes to MRU. If at capacity and key is new, evicts
// the LRU entry.
func (c *ipCooldownCache) put(key string, ts time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elt, ok := c.index[key]; ok {
		entry := elt.Value.(*cooldownEntry)
		entry.ts = ts
		c.order.MoveToFront(elt)
		return
	}
	if c.order.Len() >= c.capacity {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.index, oldest.Value.(*cooldownEntry).key)
		}
	}
	elt := c.order.PushFront(&cooldownEntry{key: key, ts: ts})
	c.index[key] = elt
}

// len returns the current number of entries. Test-only
// helper; not exposed via the NormalSink interface.
func (c *ipCooldownCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.index)
}
