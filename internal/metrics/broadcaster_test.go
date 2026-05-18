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

package metrics

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// quietLogger returns a logger discarding output. Used when log
// content is irrelevant to the test.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// captureLogger returns a logger whose output is collected into buf
// at Debug level (the level used by drop logs).
func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

func TestBroadcaster_Subscribe_AllocatesChannel(t *testing.T) {
	b := NewBroadcaster(quietLogger())
	s := b.Subscribe()
	if s == nil || s.Ch == nil {
		t.Fatal("Subscribe returned nil or no channel")
	}
	if cap(s.Ch) != SubscriberChanCap {
		t.Errorf("channel cap=%d want %d", cap(s.Ch), SubscriberChanCap)
	}
	if got := b.SubscriberCount(); got != 1 {
		t.Errorf("SubscriberCount=%d want 1", got)
	}
}

func TestBroadcaster_Unsubscribe_RemovesAndClosesChannel(t *testing.T) {
	b := NewBroadcaster(quietLogger())
	s := b.Subscribe()
	b.Unsubscribe(s)

	if got := b.SubscriberCount(); got != 0 {
		t.Errorf("SubscriberCount=%d want 0 after Unsubscribe", got)
	}
	// Reading from a closed channel returns the zero value with ok=false.
	if _, ok := <-s.Ch; ok {
		t.Error("expected closed channel after Unsubscribe")
	}
}

func TestBroadcaster_Unsubscribe_Idempotent(t *testing.T) {
	// Spec invariant: double Unsubscribe must not double-close
	// the channel.
	b := NewBroadcaster(quietLogger())
	s := b.Subscribe()
	b.Unsubscribe(s)
	// Second Unsubscribe must be a silent no-op.
	b.Unsubscribe(s)
	// And a third, just to be sure.
	b.Unsubscribe(s)
}

func TestBroadcaster_Unsubscribe_NilSafe(t *testing.T) {
	b := NewBroadcaster(quietLogger())
	b.Unsubscribe(nil) // must not panic
}

func TestBroadcaster_Publish_DeliversToActiveSubscribers(t *testing.T) {
	b := NewBroadcaster(quietLogger())
	s1 := b.Subscribe()
	s2 := b.Subscribe()

	snap := Snapshot{T: time.Now().UTC()}
	sent, dropped := b.Publish(snap)
	if sent != 2 || dropped != 0 {
		t.Errorf("sent=%d dropped=%d want 2/0", sent, dropped)
	}

	// Both subscribers must observe the snapshot.
	for i, s := range []*Subscriber{s1, s2} {
		select {
		case got := <-s.Ch:
			if !got.T.Equal(snap.T) {
				t.Errorf("subscriber %d received wrong snapshot", i)
			}
		case <-time.After(100 * time.Millisecond):
			t.Errorf("subscriber %d did not receive snapshot", i)
		}
	}
}

func TestBroadcaster_Publish_OnEmptyBroadcaster(t *testing.T) {
	// With no subscribers, Publish is a no-op and returns 0/0.
	b := NewBroadcaster(quietLogger())
	snap := Snapshot{T: time.Now().UTC()}
	sent, dropped := b.Publish(snap)
	if sent != 0 || dropped != 0 {
		t.Errorf("sent=%d dropped=%d want 0/0 on empty broadcaster", sent, dropped)
	}
}

func TestBroadcaster_Publish_DropsForFullChannel(t *testing.T) {
	b := NewBroadcaster(quietLogger())
	s := b.Subscribe()

	// First publish: enqueued, channel full now.
	sent, dropped := b.Publish(Snapshot{T: time.Now().UTC()})
	if sent != 1 || dropped != 0 {
		t.Fatalf("first publish sent=%d dropped=%d want 1/0", sent, dropped)
	}

	// Second publish without draining: must drop.
	sent, dropped = b.Publish(Snapshot{T: time.Now().UTC()})
	if sent != 0 || dropped != 1 {
		t.Errorf("second publish sent=%d dropped=%d want 0/1", sent, dropped)
	}

	// Drain the channel, then publish again: must be delivered.
	<-s.Ch
	sent, dropped = b.Publish(Snapshot{T: time.Now().UTC()})
	if sent != 1 || dropped != 0 {
		t.Errorf("post-drain publish sent=%d dropped=%d want 1/0", sent, dropped)
	}
}

func TestBroadcaster_Publish_DropLogIsRateLimited(t *testing.T) {
	// Spec §5.6: at most one debug log per DropLogInterval per
	// subscriber, even under sustained drops.
	var buf bytes.Buffer
	b := NewBroadcaster(captureLogger(&buf))
	_ = b.Subscribe() // intentionally never read

	// Fill the channel.
	b.Publish(Snapshot{T: time.Now().UTC()})

	// Now 100 consecutive Publish calls — they must all drop, but
	// only the FIRST should emit a log line (rate-limited).
	for i := 0; i < 100; i++ {
		b.Publish(Snapshot{T: time.Now().UTC()})
	}

	logged := strings.Count(buf.String(), "broadcaster dropped tick")
	if logged != 1 {
		t.Errorf("drop-log line count=%d want 1 (rate-limited within interval)", logged)
	}
}

func TestBroadcaster_DropLog_NoPlaintextPayload(t *testing.T) {
	// Security invariant: the drop log must NOT contain anything
	// from the snapshot payload (host, upstream, IDs of routes).
	// Logging snapshot content under a slow client would leak
	// internal route topology into debug logs.
	var buf bytes.Buffer
	b := NewBroadcaster(captureLogger(&buf))
	_ = b.Subscribe()

	secret := Snapshot{
		T: time.Now().UTC(),
		Routes: []RouteSnapshot{
			{
				ID:       "secret-route-id-xyz",
				Host:     "secret.example.com",
				Upstream: "http://10.0.0.42:9999",
			},
		},
	}
	b.Publish(secret) // fills channel
	b.Publish(secret) // drops, logs

	output := buf.String()
	for _, leak := range []string{
		"secret-route-id-xyz",
		"secret.example.com",
		"10.0.0.42",
	} {
		if strings.Contains(output, leak) {
			t.Errorf("drop log contains payload-derived value %q (PII leak)", leak)
		}
	}
}

func TestBroadcaster_ConcurrentSubscribeUnsubscribe(t *testing.T) {
	// Stress: many goroutines subscribing and unsubscribing while
	// Publish runs in parallel. Must complete without panic or race.
	b := NewBroadcaster(quietLogger())

	stop := make(chan struct{})

	// Publisher goroutine.
	var pubWg sync.WaitGroup
	pubWg.Add(1)
	go func() {
		defer pubWg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				b.Publish(Snapshot{T: time.Now().UTC()})
			}
		}
	}()

	// Workers subscribe and unsubscribe in tight loops.
	var workWg sync.WaitGroup
	for i := 0; i < 50; i++ {
		workWg.Add(1)
		go func() {
			defer workWg.Done()
			for k := 0; k < 100; k++ {
				s := b.Subscribe()
				// Drain whatever the publisher posted.
				select {
				case <-s.Ch:
				default:
				}
				b.Unsubscribe(s)
			}
		}()
	}
	workWg.Wait()
	close(stop)
	pubWg.Wait()

	// At end, only the publisher knows nothing; subscribers should
	// have all been removed.
	if got := b.SubscriberCount(); got != 0 {
		t.Errorf("leaked subscribers: %d", got)
	}
}

func TestBroadcaster_NewBroadcaster_NilLoggerOK(t *testing.T) {
	// nil logger MUST be replaced by slog.Default(), not panic.
	b := NewBroadcaster(nil)
	if b == nil || b.logger == nil {
		t.Fatal("NewBroadcaster(nil) returned nil or nil logger")
	}
	// Smoke: Subscribe + Publish must not panic.
	s := b.Subscribe()
	b.Publish(Snapshot{T: time.Now().UTC()})
	<-s.Ch
}

// --- Benchmarks ------------------------------------------------------------

func BenchmarkBroadcaster_Publish_10Subs(b *testing.B) {
	br := NewBroadcaster(quietLogger())
	subs := make([]*Subscriber, 10)
	// Drain each subscriber's channel in a goroutine so they stay
	// "fast" and Publish doesn't measure the drop path.
	stop := make(chan struct{})
	var drainWg sync.WaitGroup
	for i := range subs {
		subs[i] = br.Subscribe()
		drainWg.Add(1)
		go func(s *Subscriber) {
			defer drainWg.Done()
			for {
				select {
				case <-stop:
					return
				case <-s.Ch:
				}
			}
		}(subs[i])
	}
	snap := Snapshot{T: time.Now().UTC()}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		br.Publish(snap)
	}
	b.StopTimer()
	close(stop)
	drainWg.Wait()
}

func BenchmarkBroadcaster_PublishWithStuckSub(b *testing.B) {
	// Spec §9.3: 9 fast subscribers + 1 stuck one. The stuck sub
	// MUST NOT block the publish path, and per-publish cost stays
	// within 1.5× the all-fast scenario.
	br := NewBroadcaster(quietLogger())

	// One stuck subscriber: never drained.
	_ = br.Subscribe()

	// Nine fast subscribers: drained in background.
	stop := make(chan struct{})
	var drainWg sync.WaitGroup
	for i := 0; i < 9; i++ {
		s := br.Subscribe()
		drainWg.Add(1)
		go func(s *Subscriber) {
			defer drainWg.Done()
			for {
				select {
				case <-stop:
					return
				case <-s.Ch:
				}
			}
		}(s)
	}
	snap := Snapshot{T: time.Now().UTC()}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		br.Publish(snap)
	}
	b.StopTimer()
	close(stop)
	drainWg.Wait()
}
