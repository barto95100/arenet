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

func mkEvent(i int) GeoEvent {
	return GeoEvent{
		Timestamp: time.Unix(int64(i), 0).UTC(),
		Category:  CategoryWAF,
		SourceIP:  "1.2.3." + strconv.Itoa(i%256),
		Details:   strconv.Itoa(i),
	}
}

func TestNewBus_ZeroCapacityFallsBackToDefault(t *testing.T) {
	b := NewBus(0)
	if b.capacity != DefaultRingCapacity {
		t.Errorf("capacity = %d, want %d (default)", b.capacity, DefaultRingCapacity)
	}
}

func TestNewBus_NegativeCapacityFallsBackToDefault(t *testing.T) {
	b := NewBus(-1)
	if b.capacity != DefaultRingCapacity {
		t.Errorf("capacity = %d, want %d (default)", b.capacity, DefaultRingCapacity)
	}
}

func TestBus_PublishSnapshot_OldestFirst(t *testing.T) {
	b := NewBus(8)
	for i := 0; i < 5; i++ {
		b.Publish(mkEvent(i))
	}
	got := b.Snapshot()
	if len(got) != 5 {
		t.Fatalf("len = %d, want 5", len(got))
	}
	for i, ev := range got {
		if ev.Details != strconv.Itoa(i) {
			t.Errorf("oldest-first order broken at idx %d: got %s want %d", i, ev.Details, i)
		}
	}
}

func TestBus_RingBuffer_FIFOEviction(t *testing.T) {
	b := NewBus(4)
	for i := 0; i < 10; i++ {
		b.Publish(mkEvent(i))
	}
	got := b.Snapshot()
	if len(got) != 4 {
		t.Fatalf("len = %d, want 4 (capacity)", len(got))
	}
	// After 10 publishes into cap=4, the ring holds events 6,7,8,9.
	for i, want := 0, 6; i < 4; i, want = i+1, want+1 {
		if got[i].Details != strconv.Itoa(want) {
			t.Errorf("FIFO eviction broken at idx %d: got %s want %d", i, got[i].Details, want)
		}
	}
}

func TestBus_SnapshotLimited(t *testing.T) {
	b := NewBus(10)
	for i := 0; i < 8; i++ {
		b.Publish(mkEvent(i))
	}

	// limit < ring size: return the most recent `limit`, oldest-first.
	got := b.SnapshotLimited(3)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if got[0].Details != "5" || got[2].Details != "7" {
		t.Errorf("expected [5,6,7], got [%s,%s,%s]", got[0].Details, got[1].Details, got[2].Details)
	}

	// limit > ring size: clamp at size.
	got = b.SnapshotLimited(50)
	if len(got) != 8 {
		t.Fatalf("len = %d, want 8 (clamp at ring size)", len(got))
	}

	// limit > capacity: clamp at capacity.
	got = b.SnapshotLimited(1000)
	if len(got) != 8 {
		t.Fatalf("len = %d, want 8", len(got))
	}

	// limit <= 0: empty.
	if got := b.SnapshotLimited(0); got != nil {
		t.Errorf("limit=0 should return nil, got %v", got)
	}
	if got := b.SnapshotLimited(-1); got != nil {
		t.Errorf("limit=-1 should return nil, got %v", got)
	}
}

func TestBus_Snapshot_Empty(t *testing.T) {
	b := NewBus(4)
	if got := b.Snapshot(); got != nil {
		t.Errorf("empty bus Snapshot() = %v, want nil", got)
	}
}

func TestBus_Subscribe_ReceivesPostSubscribeEvents(t *testing.T) {
	b := NewBus(8)
	// Pre-subscribe events: should NOT reach this subscriber.
	b.Publish(mkEvent(0))
	b.Publish(mkEvent(1))

	ch, unsub := b.Subscribe(8)
	defer unsub()

	b.Publish(mkEvent(2))
	b.Publish(mkEvent(3))

	select {
	case ev := <-ch:
		if ev.Details != "2" {
			t.Errorf("first received = %s, want 2 (post-subscribe)", ev.Details)
		}
	case <-time.After(time.Second):
		t.Fatal("expected event 2 within 1s")
	}

	select {
	case ev := <-ch:
		if ev.Details != "3" {
			t.Errorf("second received = %s, want 3", ev.Details)
		}
	case <-time.After(time.Second):
		t.Fatal("expected event 3 within 1s")
	}
}

func TestBus_Subscribe_DropsWhenChannelFull(t *testing.T) {
	b := NewBus(64)
	ch, unsub := b.Subscribe(2) // tiny buffer
	defer unsub()

	// Publish 10 events without draining the channel — 2 land, 8 drop.
	for i := 0; i < 10; i++ {
		b.Publish(mkEvent(i))
	}

	stats := b.Stats()
	if stats.DroppedToSlowSub == 0 {
		t.Errorf("expected DroppedToSlowSub > 0, got %d", stats.DroppedToSlowSub)
	}
	// Drain what fits — channel must contain exactly 2 events
	// (capacity), then either close or be empty.
	count := 0
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				goto done
			}
			count++
		case <-time.After(50 * time.Millisecond):
			goto done
		}
	}
done:
	if count != 2 {
		t.Errorf("buffered events = %d, want 2 (chan cap)", count)
	}
}

func TestBus_Subscribe_UnsubscribeStopsDelivery(t *testing.T) {
	b := NewBus(8)
	ch, unsub := b.Subscribe(8)

	b.Publish(mkEvent(1))
	<-ch // receive the one event

	unsub()
	// Channel should be closed by now.
	if _, ok := <-ch; ok {
		t.Error("expected closed channel after unsubscribe")
	}

	// Publishing after unsubscribe must not panic or affect anything.
	b.Publish(mkEvent(2))
	if got := b.Stats().Subscribers; got != 0 {
		t.Errorf("subscribers = %d, want 0 after unsubscribe", got)
	}
}

func TestBus_Subscribe_UnsubscribeIdempotent(t *testing.T) {
	b := NewBus(8)
	_, unsub := b.Subscribe(8)
	unsub()
	unsub() // second call is no-op, must not panic or double-close.
}

func TestBus_MultipleSubscribers_AllReceive(t *testing.T) {
	b := NewBus(8)
	ch1, unsub1 := b.Subscribe(8)
	defer unsub1()
	ch2, unsub2 := b.Subscribe(8)
	defer unsub2()

	b.Publish(mkEvent(42))

	for i, ch := range []<-chan GeoEvent{ch1, ch2} {
		select {
		case ev := <-ch:
			if ev.Details != "42" {
				t.Errorf("subscriber %d received %s, want 42", i, ev.Details)
			}
		case <-time.After(time.Second):
			t.Errorf("subscriber %d timed out", i)
		}
	}
}

func TestBus_Stats(t *testing.T) {
	b := NewBus(5)
	_, unsub := b.Subscribe(2)
	defer unsub()

	for i := 0; i < 3; i++ {
		b.Publish(mkEvent(i))
	}

	stats := b.Stats()
	if stats.Subscribers != 1 {
		t.Errorf("Subscribers = %d, want 1", stats.Subscribers)
	}
	if stats.RingCapacity != 5 {
		t.Errorf("RingCapacity = %d, want 5", stats.RingCapacity)
	}
	if stats.RingSize != 3 {
		t.Errorf("RingSize = %d, want 3", stats.RingSize)
	}
	if stats.Published != 3 {
		t.Errorf("Published = %d, want 3", stats.Published)
	}
}

func TestBus_NilReceiver_SafeNoOps(t *testing.T) {
	var b *Bus
	b.Publish(mkEvent(1)) // must not panic
	if got := b.Snapshot(); got != nil {
		t.Errorf("nil bus Snapshot() = %v, want nil", got)
	}
	if got := b.SnapshotLimited(100); got != nil {
		t.Errorf("nil bus SnapshotLimited() = %v, want nil", got)
	}
	stats := b.Stats()
	if stats != (BusStats{}) {
		t.Errorf("nil bus Stats() = %+v, want zero", stats)
	}
	ch, unsub := b.Subscribe(8)
	if _, ok := <-ch; ok {
		t.Error("nil bus Subscribe channel should be closed")
	}
	unsub() // must not panic
}

func TestBus_Concurrent_PublishSubscribe(t *testing.T) {
	// Race-detector validates this.
	b := NewBus(64)
	const numPublishers = 4
	const numSubscribers = 4
	const eventsPerPublisher = 200

	var wgSubs sync.WaitGroup
	var receivedCounts [numSubscribers]uint64
	subs := make([]func(), numSubscribers)
	for i := 0; i < numSubscribers; i++ {
		ch, unsub := b.Subscribe(256)
		subs[i] = unsub
		wgSubs.Add(1)
		go func(idx int) {
			defer wgSubs.Done()
			for range ch {
				atomic.AddUint64(&receivedCounts[idx], 1)
			}
		}(i)
	}

	var wgPub sync.WaitGroup
	for p := 0; p < numPublishers; p++ {
		wgPub.Add(1)
		go func(pid int) {
			defer wgPub.Done()
			for i := 0; i < eventsPerPublisher; i++ {
				b.Publish(mkEvent(pid*10000 + i))
			}
		}(p)
	}
	wgPub.Wait()

	// Give subscribers a moment to drain.
	time.Sleep(100 * time.Millisecond)
	for _, u := range subs {
		u()
	}
	wgSubs.Wait()

	// Sanity: total published is numPublishers * eventsPerPublisher.
	if got, want := b.Stats().Published, uint64(numPublishers*eventsPerPublisher); got != want {
		t.Errorf("Published = %d, want %d", got, want)
	}
}
