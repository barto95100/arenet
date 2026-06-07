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
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingLANCounter is the stub LANCounter for tests.
type countingLANCounter struct{ n atomic.Uint64 }

func (c *countingLANCounter) Inc() { c.n.Add(1) }

// buildSink wires a real Bus + nil-Lookup Enricher (no
// MMDB needed — enrichBase tolerates a nil Lookup and
// returns a partial event with SourceCountry="UNK") plus
// the given config + LANCounter stub.
func buildSink(t *testing.T, cfg NormalSinkConfig, lan LANCounter) (*DefaultNormalSink, *Bus) {
	t.Helper()
	bus := NewBus(1024)
	enricher := NewEnricher(nil) // degraded MMDB — fine for unit tests
	return NewDefaultNormalSink(bus, enricher, lan, cfg), bus
}

// drainBus reads up to `cap` events from the bus snapshot.
func drainBus(b *Bus, cap int) []GeoEvent {
	return b.SnapshotLimited(cap)
}

// ---------- Sampling gate ----------

func TestSampling_ZeroPct_NoEmit(t *testing.T) {
	lan := &countingLANCounter{}
	s, bus := buildSink(t, NormalSinkConfig{SamplePct: 0, Cooldown: 0}, lan)
	for i := 0; i < 100; i++ {
		s.Submit(200, "8.8.8.8", "r-1")
	}
	if got := len(drainBus(bus, 100)); got != 0 {
		t.Errorf("SamplePct=0 must emit nothing, got %d events", got)
	}
	if got := lan.n.Load(); got != 0 {
		t.Errorf("SamplePct=0 must not touch LANCounter, got %d", got)
	}
}

func TestSampling_HundredPct_AlwaysEmit(t *testing.T) {
	// Use a unique source IP per call so the per-IP
	// cooldown isn't engaged. Cooldown=0 also disables it
	// but the public-IP gate must pass first.
	s, bus := buildSink(t, NormalSinkConfig{SamplePct: 100, Cooldown: 0}, &countingLANCounter{})
	const N = 50
	for i := 0; i < N; i++ {
		s.Submit(200, "203.0.113."+strconv.Itoa(i), "r-1")
	}
	if got := len(drainBus(bus, N+10)); got != N {
		t.Errorf("SamplePct=100 must emit every call, got %d/%d", got, N)
	}
}

func TestSampling_RoughProbabilityFloor(t *testing.T) {
	// Verify the random sample lands in a generous band
	// around the requested percentage. Generous bounds
	// (1% target, ±1% band over 10k iterations) keep this
	// test stable across PRNG seeds; the math says 3σ at
	// p=0.05 over n=10k is ±0.65%.
	const targetPct = 5
	const iterations = 10_000
	s, bus := buildSink(t, NormalSinkConfig{SamplePct: targetPct, Cooldown: 0}, &countingLANCounter{})
	for i := 0; i < iterations; i++ {
		// Unique IPs so cooldown doesn't interfere.
		s.Submit(200, "198.51.100."+strconv.Itoa(i%256), "r-1")
	}
	got := len(drainBus(bus, iterations))
	// Bus capacity is 1024 (buildSink). Cap the upper
	// bound at min(bus_cap, expected_upper) so the test
	// is honest about what we can observe.
	itf := float64(iterations)
	expectedLow := int(itf*0.03) - 100  // ~200
	expectedHigh := int(itf*0.07) + 100 // ~800
	if expectedHigh > 1024 {
		expectedHigh = 1024
	}
	if got < expectedLow || got > expectedHigh {
		t.Errorf("SamplePct=%d, iterations=%d → got %d events; want in [%d, %d]",
			targetPct, iterations, got, expectedLow, expectedHigh)
	}
}

// ---------- RFC1918 gate ----------

func TestRFC1918_CountsInLANPill_NoEmit(t *testing.T) {
	cases := []string{
		"10.0.0.1",
		"10.255.255.255",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.1.1",
		"127.0.0.1",
		"169.254.0.1",
		"::1",
		"fe80::1",
		"fc00::1",
	}
	for _, ip := range cases {
		t.Run(ip, func(t *testing.T) {
			lan := &countingLANCounter{}
			s, bus := buildSink(t, NormalSinkConfig{SamplePct: 100, Cooldown: 0}, lan)
			s.Submit(200, ip, "r-1")
			if got := len(drainBus(bus, 10)); got != 0 {
				t.Errorf("LAN ip %s: emitted %d events, want 0", ip, got)
			}
			if got := lan.n.Load(); got != 1 {
				t.Errorf("LAN ip %s: lanCounter.Inc called %d times, want 1", ip, got)
			}
		})
	}
}

func TestRFC1918_InvalidIP_FallsThroughToEnricher(t *testing.T) {
	// An invalid IP string isn't RFC1918 (ParseIP returns
	// nil), so the LAN gate doesn't trigger; the event
	// reaches enrichBase which produces a partial event
	// with empty country/coords. Operator sees a
	// SourceCountry=UNK arc — degraded mode, not a panic.
	lan := &countingLANCounter{}
	s, bus := buildSink(t, NormalSinkConfig{SamplePct: 100, Cooldown: 0}, lan)
	s.Submit(200, "not-an-ip", "r-1")
	if got := len(drainBus(bus, 10)); got != 1 {
		t.Errorf("invalid IP must still emit a degraded event, got %d events", got)
	}
	if got := lan.n.Load(); got != 0 {
		t.Errorf("invalid IP must not bump lanCounter, got %d", got)
	}
}

// ---------- Cooldown gate ----------

func TestCooldown_BlocksWithinWindow(t *testing.T) {
	s, bus := buildSink(t, NormalSinkConfig{
		SamplePct: 100,
		Cooldown:  time.Hour, // long window — second call always blocked
	}, &countingLANCounter{})
	s.Submit(200, "8.8.8.8", "r-1")
	s.Submit(200, "8.8.8.8", "r-1") // same IP, within cooldown
	if got := len(drainBus(bus, 10)); got != 1 {
		t.Errorf("cooldown must block second emission from same IP, got %d events", got)
	}
}

func TestCooldown_AllowsDifferentIPs(t *testing.T) {
	s, bus := buildSink(t, NormalSinkConfig{
		SamplePct: 100,
		Cooldown:  time.Hour,
	}, &countingLANCounter{})
	s.Submit(200, "8.8.8.8", "r-1")
	s.Submit(200, "1.1.1.1", "r-1")
	s.Submit(200, "9.9.9.9", "r-1")
	if got := len(drainBus(bus, 10)); got != 3 {
		t.Errorf("cooldown must not block distinct IPs, got %d events want 3", got)
	}
}

func TestCooldown_ZeroDisablesGate(t *testing.T) {
	s, bus := buildSink(t, NormalSinkConfig{
		SamplePct: 100,
		Cooldown:  0, // disabled
	}, &countingLANCounter{})
	for i := 0; i < 5; i++ {
		s.Submit(200, "8.8.8.8", "r-1")
	}
	if got := len(drainBus(bus, 10)); got != 5 {
		t.Errorf("Cooldown=0 must not gate, got %d events want 5", got)
	}
}

func TestCooldown_ExpiresAfterWindow(t *testing.T) {
	// Use a tiny cooldown so the test is fast. The
	// observation is: first emit lands, sleep > cooldown,
	// second emit also lands.
	s, bus := buildSink(t, NormalSinkConfig{
		SamplePct: 100,
		Cooldown:  20 * time.Millisecond,
	}, &countingLANCounter{})
	s.Submit(200, "8.8.8.8", "r-1")
	time.Sleep(35 * time.Millisecond)
	s.Submit(200, "8.8.8.8", "r-1")
	if got := len(drainBus(bus, 10)); got != 2 {
		t.Errorf("cooldown must expire after window, got %d events want 2", got)
	}
}

// ---------- LRU eviction ----------

func TestCooldown_LRUEviction_OldestEvicted(t *testing.T) {
	// Fill the LRU exactly, then add one more. The oldest
	// entry must be evicted; submitting again for the
	// oldest IP within the cooldown window MUST now emit
	// (cooldown state lost on eviction).
	const capacity = 4
	s, bus := buildSink(t, NormalSinkConfig{
		SamplePct:     100,
		Cooldown:      time.Hour,
		CacheCapacity: capacity,
	}, &countingLANCounter{})

	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}
	for _, ip := range ips {
		s.Submit(200, ip, "r-1")
	}
	if got := s.cache.len(); got != capacity {
		t.Fatalf("after fill, cache size = %d, want %d", got, capacity)
	}

	// Add a 5th — evicts "1.1.1.1" (LRU).
	s.Submit(200, "5.5.5.5", "r-1")
	if got := s.cache.len(); got != capacity {
		t.Errorf("after overflow, cache size = %d, want %d", got, capacity)
	}

	// Re-submit "1.1.1.1" — should now pass (its cooldown
	// entry was evicted) AND drain bus should show it
	// emitted again.
	beforeReSubmit := len(drainBus(bus, 10))
	s.Submit(200, "1.1.1.1", "r-1")
	afterReSubmit := len(drainBus(bus, 10))
	if afterReSubmit != beforeReSubmit+1 {
		t.Errorf("after LRU eviction, evicted IP should re-emit; before=%d after=%d", beforeReSubmit, afterReSubmit)
	}

	// "5.5.5.5" still in cache → re-submit must be blocked.
	beforeRepeat := afterReSubmit
	s.Submit(200, "5.5.5.5", "r-1")
	afterRepeat := len(drainBus(bus, 10))
	if afterRepeat != beforeRepeat {
		t.Errorf("freshly-inserted IP must still be cooldowned; before=%d after=%d", beforeRepeat, afterRepeat)
	}
}

// ---------- Nil-safety / degraded mode ----------

func TestNilReceiver_SafeNoOp(t *testing.T) {
	var s *DefaultNormalSink
	// MUST NOT panic.
	s.Submit(200, "8.8.8.8", "r-1")
	if got := s.SamplePct(); got != 0 {
		t.Errorf("nil sink SamplePct() = %d, want 0", got)
	}
	if got := s.Cooldown(); got != 0 {
		t.Errorf("nil sink Cooldown() = %d, want 0", got)
	}
}

func TestGeoIPDegraded_NoNilPanic(t *testing.T) {
	// Enricher built with nil Lookup (no MMDB). Submit
	// must complete cleanly and the event must reach the
	// bus with SourceCountry="UNK".
	s, bus := buildSink(t, NormalSinkConfig{SamplePct: 100, Cooldown: 0}, &countingLANCounter{})
	s.Submit(200, "8.8.8.8", "r-test")

	events := drainBus(bus, 10)
	if len(events) != 1 {
		t.Fatalf("degraded MMDB must still emit, got %d events", len(events))
	}
	if events[0].SourceCountry != "UNK" {
		t.Errorf("degraded MMDB → SourceCountry=%q, want UNK", events[0].SourceCountry)
	}
	if events[0].Category != CategoryNormal {
		t.Errorf("Category=%q, want %q", events[0].Category, CategoryNormal)
	}
	if events[0].StatusCode != 200 {
		t.Errorf("StatusCode=%d, want 200", events[0].StatusCode)
	}
	if events[0].RouteID != "r-test" {
		t.Errorf("RouteID=%q, want r-test", events[0].RouteID)
	}
}

func TestEnrichedEvent_CarriesCategoryNormal(t *testing.T) {
	// Pin the wire shape: every emitted event MUST have
	// Category="normal" so the frontend's V.6
	// CATEGORY_COLORS map paints it green
	// (var(--status-up)).
	s, bus := buildSink(t, NormalSinkConfig{SamplePct: 100, Cooldown: 0}, &countingLANCounter{})
	s.Submit(301, "203.0.113.42", "r-redirect")
	events := drainBus(bus, 10)
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].Category != CategoryNormal {
		t.Errorf("Category=%q, want %q", events[0].Category, CategoryNormal)
	}
	if events[0].StatusCode != 301 {
		t.Errorf("StatusCode=%d, want 301", events[0].StatusCode)
	}
}

// ---------- Close ----------

func TestClose_NoOp(t *testing.T) {
	s, _ := buildSink(t, NormalSinkConfig{SamplePct: 100, Cooldown: 0}, &countingLANCounter{})
	if err := s.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
	// Calling Submit after Close is still valid — the V.1
	// API doesn't define Close as terminal. (Future
	// background-pruner work may change this; the test
	// pins current behavior.)
	s.Submit(200, "8.8.8.8", "r-1")
}

// ---------- Concurrency ----------

func TestConcurrentSubmit_RaceFree(t *testing.T) {
	// Drive Submit from multiple goroutines under -race.
	// Each goroutine uses its own IP space so the LRU
	// + cooldown paths actually exercise (otherwise the
	// cooldown gate blocks most calls).
	s, bus := buildSink(t, NormalSinkConfig{
		SamplePct:     50,
		Cooldown:      time.Millisecond,
		CacheCapacity: 256,
	}, &countingLANCounter{})

	const goroutines = 8
	const perG = 250
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				ip := "10.0." + strconv.Itoa(gid) + "." + strconv.Itoa(i%200)
				// gid*256+i would be RFC1918 (10.x.x.x);
				// override to public so the test exercises
				// the cooldown + emit path.
				if ip[0:3] == "10." {
					ip = "203.0." + strconv.Itoa(gid) + "." + strconv.Itoa(i%200)
				}
				s.Submit(200, ip, "r-1")
			}
		}(g)
	}
	wg.Wait()

	// No assertions on event count — the sampling +
	// cooldown make the exact number non-deterministic.
	// The point is: the -race flag passes.
	_ = bus
}

// ---------- Interface satisfaction ----------

func TestNoopLANCounter_Inc(t *testing.T) {
	var c LANCounter = NoopLANCounter{}
	// MUST NOT panic.
	c.Inc()
	c.Inc()
}

// ---------- ipCooldownCache primitives ----------

func TestIPCooldownCache_PutPeek(t *testing.T) {
	c := newIPCooldownCache(10)
	ts := time.Now()
	c.put("a", ts)
	got, ok := c.peek("a")
	if !ok || !got.Equal(ts) {
		t.Errorf("peek after put: ok=%v ts=%v want ok=true ts=%v", ok, got, ts)
	}
}

func TestIPCooldownCache_PeekMissing(t *testing.T) {
	c := newIPCooldownCache(10)
	if _, ok := c.peek("nope"); ok {
		t.Errorf("peek on missing key returned ok=true")
	}
}

func TestIPCooldownCache_PutUpdates(t *testing.T) {
	c := newIPCooldownCache(10)
	t1 := time.Now()
	t2 := t1.Add(time.Second)
	c.put("a", t1)
	c.put("a", t2)
	got, _ := c.peek("a")
	if !got.Equal(t2) {
		t.Errorf("put-update: stored ts=%v want %v", got, t2)
	}
	if got := c.len(); got != 1 {
		t.Errorf("put-update should not grow: len=%d want 1", got)
	}
}

func TestIPCooldownCache_DefaultCapacity(t *testing.T) {
	c := newIPCooldownCache(0)
	if c.capacity != 4096 {
		t.Errorf("capacity=%d, want default 4096", c.capacity)
	}
}
