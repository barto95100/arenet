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
	"io"
	"log/slog"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/observability"
)

// W.4 — country-block sink tests. Mirror of the V.1
// normal_sink_test.go shape: sampling gate, cooldown gate,
// nil-receiver safety, race-free concurrent submit, bus
// publish + persistence dual-fan-out.

// recordingCBInserter captures every batch the sink flushes
// to the inserter seam. Thread-safe for the flush-goroutine
// + main-test-goroutine concurrent access.
type recordingCBInserter struct {
	mu     sync.Mutex
	events []observability.CountryBlockEvent
	calls  int
}

func (r *recordingCBInserter) InsertCountryBlockEventBatch(
	_ context.Context, events []observability.CountryBlockEvent,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	cp := make([]observability.CountryBlockEvent, len(events))
	copy(cp, events)
	r.events = append(r.events, cp...)
	return nil
}

func (r *recordingCBInserter) snapshot() []observability.CountryBlockEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]observability.CountryBlockEvent, len(r.events))
	copy(out, r.events)
	return out
}

func cbSilentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func buildCBSink(t *testing.T, cfg CountryBlockSinkConfig) (*DefaultCountryBlockSink, *Bus, *recordingCBInserter) {
	t.Helper()
	bus := NewBus(1024)
	enricher := NewEnricher(nil) // degraded MMDB — fine for unit tests
	inserter := &recordingCBInserter{}
	// Fast flush for tests — 5 ms tick is well below the
	// 250 ms production default but lets tests finish in
	// O(20 ms) per case instead of O(500 ms).
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 5 * time.Millisecond
	}
	s := NewDefaultCountryBlockSink(bus, enricher, inserter, cbSilentLogger(), cfg)
	return s, bus, inserter
}

// drainBusGeo is a small alias for clarity in the tests
// below — same shape as normal_sink_test.go's drainBus.
func drainBusGeo(b *Bus, cap int) []GeoEvent { return b.SnapshotLimited(cap) }

// runSink starts the flush goroutine and returns a cancel
// function the test calls in t.Cleanup to drain pending
// events before assertions.
func runSink(t *testing.T, s *DefaultCountryBlockSink) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	return func() {
		cancel()
		<-s.Done()
	}
}

// submitBlock is a 2-line shorthand — every test below
// passes the same canned BlockMatch fields except srcIP /
// route / country.
func submitBlock(s *DefaultCountryBlockSink, srcIP, country string) {
	s.SubmitCountryBlock(time.Now().UTC(), "r-1", srcIP, country, "deny", "deny-match", 403)
}

// ---------- Sampling gate ----------

// TestCountryBlockSink_SamplePct_Zero_NoEmit pins the disabled
// state: at SamplePct=0 the sink rejects every Submit before
// touching the bus / inserter / LRU.
func TestCountryBlockSink_SamplePct_Zero_NoEmit(t *testing.T) {
	s, bus, inserter := buildCBSink(t, CountryBlockSinkConfig{SamplePct: 0, Cooldown: 0})
	stop := runSink(t, s)
	for i := 0; i < 100; i++ {
		submitBlock(s, "203.0.113.5", "RU")
	}
	stop()
	if got := len(drainBusGeo(bus, 100)); got != 0 {
		t.Errorf("SamplePct=0 must emit nothing to bus; got %d", got)
	}
	if got := len(inserter.snapshot()); got != 0 {
		t.Errorf("SamplePct=0 must persist nothing; got %d", got)
	}
}

// TestCountryBlockSink_SamplePct_Hundred_AlwaysEmit pins
// the full-capture state at SamplePct=100. Use unique
// source IPs to bypass the per-IP cooldown.
func TestCountryBlockSink_SamplePct_Hundred_AlwaysEmit(t *testing.T) {
	s, bus, inserter := buildCBSink(t, CountryBlockSinkConfig{SamplePct: 100, Cooldown: 0})
	stop := runSink(t, s)
	const N = 50
	for i := 0; i < N; i++ {
		submitBlock(s, "203.0.113."+strconv.Itoa(i), "RU")
	}
	stop()
	if got := len(drainBusGeo(bus, N+10)); got != N {
		t.Errorf("SamplePct=100 must publish every Submit; got %d/%d", got, N)
	}
	if got := len(inserter.snapshot()); got != N {
		t.Errorf("SamplePct=100 must persist every Submit; got %d/%d", got, N)
	}
}

// ---------- Cooldown gate ----------

// TestCountryBlockSink_Cooldown_PreventsDuplicates pins
// the LRU rate-limit: within Cooldown, repeated Submits
// from the same source IP collapse to ONE persisted row.
func TestCountryBlockSink_Cooldown_PreventsDuplicates(t *testing.T) {
	s, bus, inserter := buildCBSink(t, CountryBlockSinkConfig{
		SamplePct: 100,
		Cooldown:  1 * time.Hour, // longer than the test
	})
	stop := runSink(t, s)
	for i := 0; i < 10; i++ {
		submitBlock(s, "203.0.113.5", "RU")
	}
	stop()
	if got := len(drainBusGeo(bus, 10)); got != 1 {
		t.Errorf("Cooldown collapse: bus should carry 1 event; got %d", got)
	}
	if got := len(inserter.snapshot()); got != 1 {
		t.Errorf("Cooldown collapse: persistence should carry 1 row; got %d", got)
	}
	// Counter for ops introspection.
	if got := s.SuppressedByLRU(); got != 9 {
		t.Errorf("SuppressedByLRU = %d; want 9 (one passed, nine collapsed)", got)
	}
}

// TestCountryBlockSink_Cooldown_AllowsDifferentIPs pins
// the per-IP scoping: different sources don't share a
// cooldown.
func TestCountryBlockSink_Cooldown_AllowsDifferentIPs(t *testing.T) {
	s, bus, _ := buildCBSink(t, CountryBlockSinkConfig{
		SamplePct: 100,
		Cooldown:  1 * time.Hour,
	})
	stop := runSink(t, s)
	submitBlock(s, "203.0.113.5", "RU")
	submitBlock(s, "203.0.113.6", "RU")
	submitBlock(s, "203.0.113.7", "RU")
	stop()
	if got := len(drainBusGeo(bus, 10)); got != 3 {
		t.Errorf("3 distinct IPs must each emit once; got %d", got)
	}
}

// ---------- Persistence shape ----------

// TestCountryBlockSink_EmitOnBlock_PersistsAllFields pins
// the row shape: every BlockMatch field round-trips into
// the persisted observability.CountryBlockEvent.
func TestCountryBlockSink_EmitOnBlock_PersistsAllFields(t *testing.T) {
	s, _, inserter := buildCBSink(t, CountryBlockSinkConfig{SamplePct: 100})
	stop := runSink(t, s)
	ts := time.Now().UTC().Truncate(time.Second)
	s.SubmitCountryBlock(ts, "route-abc", "203.0.113.42", "RU", "deny", "deny-match", 451)
	stop()

	rows := inserter.snapshot()
	if len(rows) != 1 {
		t.Fatalf("expected 1 persisted row; got %d", len(rows))
	}
	row := rows[0]
	if !row.Ts.Equal(ts) {
		t.Errorf("Ts = %v; want %v", row.Ts, ts)
	}
	if row.RouteID != "route-abc" {
		t.Errorf("RouteID = %q; want route-abc", row.RouteID)
	}
	if row.SrcIP != "203.0.113.42" {
		t.Errorf("SrcIP = %q; want 203.0.113.42", row.SrcIP)
	}
	if row.Country != "RU" {
		t.Errorf("Country = %q; want RU", row.Country)
	}
	if row.Mode != "deny" {
		t.Errorf("Mode = %q; want deny", row.Mode)
	}
	if row.StatusCode != 451 {
		t.Errorf("StatusCode = %d; want 451", row.StatusCode)
	}
	if row.Reason != "deny-match" {
		t.Errorf("Reason = %q; want deny-match", row.Reason)
	}
}

// TestCountryBlockSink_BusEventCarriesCountryBlockCategory
// pins the 6th-category contract: every published event
// has Category == CategoryCountryBlock.
func TestCountryBlockSink_BusEventCarriesCountryBlockCategory(t *testing.T) {
	s, bus, _ := buildCBSink(t, CountryBlockSinkConfig{SamplePct: 100})
	stop := runSink(t, s)
	submitBlock(s, "203.0.113.5", "RU")
	stop()

	events := drainBusGeo(bus, 10)
	if len(events) != 1 {
		t.Fatalf("expected 1 event on bus; got %d", len(events))
	}
	if events[0].Category != CategoryCountryBlock {
		t.Errorf("event Category = %q; want %q", events[0].Category, CategoryCountryBlock)
	}
	if events[0].RouteID != "r-1" {
		t.Errorf("event RouteID = %q; want r-1", events[0].RouteID)
	}
	if events[0].SourceCountry != "RU" {
		t.Errorf("event SourceCountry = %q; want RU (matcher's resolved value)", events[0].SourceCountry)
	}
	if events[0].StatusCode != 403 {
		t.Errorf("event StatusCode = %d; want 403", events[0].StatusCode)
	}
}

// TestCountryBlockSink_NilReceiver_SafeNoOp — calling
// SubmitCountryBlock on a nil *DefaultCountryBlockSink is
// a no-op (the W.1 module short-circuits on a nil global
// sink; we mirror that contract here for defense in depth).
func TestCountryBlockSink_NilReceiver_SafeNoOp(t *testing.T) {
	var s *DefaultCountryBlockSink
	// Must not panic.
	s.SubmitCountryBlock(time.Now(), "r-1", "1.2.3.4", "RU", "deny", "deny-match", 403)
	_ = s.Close()
	if got := s.SamplePct(); got != 0 {
		t.Errorf("nil receiver SamplePct = %d; want 0", got)
	}
}

// TestCountryBlockSink_NilInserter_DegradedMode_PublishesBus
// pins the AC #13 degraded-mode path: a boot-failed
// observability store means inserter==nil; the sink must
// still publish to the bus (so /map keeps rendering arcs)
// but skips persistence silently.
func TestCountryBlockSink_NilInserter_DegradedMode_PublishesBus(t *testing.T) {
	bus := NewBus(1024)
	enricher := NewEnricher(nil)
	s := NewDefaultCountryBlockSink(bus, enricher, nil, cbSilentLogger(), CountryBlockSinkConfig{
		SamplePct:     100,
		FlushInterval: 5 * time.Millisecond,
	})
	stop := runSink(t, s)
	submitBlock(s, "203.0.113.5", "RU")
	stop()

	if got := len(drainBusGeo(bus, 10)); got != 1 {
		t.Errorf("degraded mode must still publish to bus; got %d events", got)
	}
}

// TestCountryBlockSink_ConcurrentSubmit_RaceFree —
// stress-test the LRU + PRNG mutexes + channel send under
// concurrent goroutines. Run with -race to surface any
// missed synchronization.
func TestCountryBlockSink_ConcurrentSubmit_RaceFree(t *testing.T) {
	s, _, _ := buildCBSink(t, CountryBlockSinkConfig{
		SamplePct: 50,
		Cooldown:  10 * time.Millisecond,
	})
	stop := runSink(t, s)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				submitBlock(s, "203.0.113."+strconv.Itoa((seed*200+i)%256), "RU")
			}
		}(g)
	}
	wg.Wait()
	stop()
}
