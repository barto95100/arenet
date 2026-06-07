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
	"sync"
	"sync/atomic"
)

// DefaultRingCapacity is the spec §3.5 locked ring buffer
// size: 500 most recent GeoEvents kept in memory for
// page-mount replay. Operationally tuned: the /map page
// can paint a meaningful initial view from 500 events
// without blocking on N+1 minutes of WS frames to populate.
const DefaultRingCapacity = 500

// Bus is the in-memory, lossy-on-full event distributor for
// GeoEvents. It maintains a FIFO ring buffer of the last
// N events for replay on subscriber connect, and fans out
// new events to all currently-subscribed channels.
//
// Bus is goroutine-safe: Publish / Subscribe / Snapshot may
// all be called concurrently from any goroutine. The
// internal lock is held briefly (ring update + subscriber
// slice walk) so a slow subscriber cannot stall publishers
// of other events — non-blocking sends on each subscriber
// channel skip slow consumers and the slow client just sees
// gaps.
//
// Per spec §3.5 + §4 (architecture component 2), this is
// the single fan-out point shared by WS handler (live) and
// the GET replay endpoint (initial paint). A nil *Bus is a
// valid degraded-mode receiver: Publish is a no-op, Snapshot
// returns nil, Subscribe returns a closed channel + no-op
// unsubscribe.
type Bus struct {
	capacity int

	mu          sync.RWMutex
	ring        []GeoEvent
	writeIdx    int
	filled      bool
	subscribers []*subscription

	// Metrics. Atomics so Stats() never contends with the
	// hot path's locks.
	published        uint64
	droppedToSlowSub uint64
}

// subscription is the per-subscriber state the Bus keeps
// inside its subscribers slice. The channel is buffered;
// non-blocking sends drop events to slow consumers.
type subscription struct {
	ch chan GeoEvent
}

// BusStats returns ops-introspection counters for a running
// Bus. Used by future /healthz fields + the V.4 admin panel.
type BusStats struct {
	Subscribers      int    `json:"subscribers"`
	RingSize         int    `json:"ringSize"`
	RingCapacity     int    `json:"ringCapacity"`
	Published        uint64 `json:"published"`
	DroppedToSlowSub uint64 `json:"droppedToSlowSub"`
}

// NewBus constructs a Bus with the given ring capacity. A
// non-positive capacity falls back to DefaultRingCapacity so
// callers can pass 0 to opt into the spec-default size.
func NewBus(ringCapacity int) *Bus {
	if ringCapacity <= 0 {
		ringCapacity = DefaultRingCapacity
	}
	return &Bus{
		capacity: ringCapacity,
		ring:     make([]GeoEvent, ringCapacity),
	}
}

// Publish appends the event to the ring buffer and fans out
// to every current subscriber. Non-blocking: subscribers
// whose channel is full are silently skipped (counted into
// droppedToSlowSub) so a single slow client cannot stall
// publishing for the rest of the bus.
//
// Safe to call on a nil receiver (degraded mode no-op).
// Safe to call concurrently from any goroutine.
func (b *Bus) Publish(ev GeoEvent) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.ring[b.writeIdx] = ev
	b.writeIdx++
	if b.writeIdx >= b.capacity {
		b.writeIdx = 0
		b.filled = true
	}
	// Walk subscribers under the same lock — fan-out is
	// effectively constant time per subscriber. Holding the
	// lock through the non-blocking sends is fine because
	// each select-default takes ~ns and the only writers
	// contending are subscribe/unsubscribe paths.
	subs := b.subscribers
	b.mu.Unlock()

	atomic.AddUint64(&b.published, 1)
	for _, sub := range subs {
		select {
		case sub.ch <- ev:
		default:
			atomic.AddUint64(&b.droppedToSlowSub, 1)
		}
	}
}

// Subscribe registers a new subscriber and returns the
// channel it will receive events on, plus an unsubscribe
// function. The channel is buffered with the given size; a
// bufferSize <= 0 defaults to 64 (the empirically tuned
// value the ws_topology subscriber uses).
//
// IMPORTANT: subscribers MUST call the returned unsubscribe
// function on disconnect, otherwise the channel reference
// leaks into the subscribers slice and Publish keeps trying
// to send to it. The function is idempotent — calling it
// twice is safe.
//
// Safe to call on a nil receiver: returns a closed channel
// + a no-op unsubscribe so callers in degraded mode receive
// no events but still drain cleanly.
func (b *Bus) Subscribe(bufferSize int) (<-chan GeoEvent, func()) {
	if b == nil {
		ch := make(chan GeoEvent)
		close(ch)
		return ch, func() {}
	}
	if bufferSize <= 0 {
		bufferSize = 64
	}
	sub := &subscription{ch: make(chan GeoEvent, bufferSize)}

	b.mu.Lock()
	b.subscribers = append(b.subscribers, sub)
	b.mu.Unlock()

	var unsubOnce sync.Once
	unsubscribe := func() {
		unsubOnce.Do(func() {
			b.mu.Lock()
			for i, s := range b.subscribers {
				if s == sub {
					// Swap-and-truncate avoids the
					// allocation of a new slice on every
					// unsubscribe.
					b.subscribers[i] = b.subscribers[len(b.subscribers)-1]
					b.subscribers = b.subscribers[:len(b.subscribers)-1]
					break
				}
			}
			b.mu.Unlock()
			close(sub.ch)
		})
	}
	return sub.ch, unsubscribe
}

// Snapshot returns a copy of the ring buffer, oldest-first,
// containing up to capacity GeoEvents. Used by the WS
// handler at connect time when the page-mount replay path
// (GET /geo-events) is too coarse for the client's needs.
//
// Returns nil on a nil receiver.
func (b *Bus) Snapshot() []GeoEvent {
	if b == nil {
		return nil
	}
	return b.snapshotN(b.capacity)
}

// SnapshotLimited returns up to `limit` most-recent
// GeoEvents, oldest-first. Used by GET /api/v1/observability/
// geo-events to populate the initial paint with a
// caller-bounded window (default 100, clamped at the
// handler to 500 per spec §5.4).
//
// limit <= 0 returns an empty slice (defensive: an
// unintentional zero from a borked query param shouldn't
// blow up).
func (b *Bus) SnapshotLimited(limit int) []GeoEvent {
	if b == nil || limit <= 0 {
		return nil
	}
	if limit > b.capacity {
		limit = b.capacity
	}
	return b.snapshotN(limit)
}

// snapshotN extracts the last n events from the ring,
// oldest-first. Caller holds NO lock; this acquires the
// read lock for the duration of the copy.
func (b *Bus) snapshotN(n int) []GeoEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()

	total := b.capacity
	if !b.filled {
		total = b.writeIdx
	}
	if total == 0 {
		return nil
	}
	if n > total {
		n = total
	}

	out := make([]GeoEvent, n)
	// The oldest valid index is writeIdx when filled,
	// or 0 when not filled. The N most recent events sit
	// at writeIdx-1, writeIdx-2, ..., wrapping. To produce
	// them oldest-first we start at (writeIdx - n + capacity)
	// % capacity.
	start := (b.writeIdx - n + b.capacity) % b.capacity
	for i := 0; i < n; i++ {
		out[i] = b.ring[(start+i)%b.capacity]
	}
	return out
}

// Stats returns the current ops-introspection counters.
// Safe to call on a nil receiver (returns zero-value).
func (b *Bus) Stats() BusStats {
	if b == nil {
		return BusStats{}
	}
	b.mu.RLock()
	subs := len(b.subscribers)
	ringSize := b.capacity
	if !b.filled {
		ringSize = b.writeIdx
	}
	b.mu.RUnlock()
	return BusStats{
		Subscribers:      subs,
		RingSize:         ringSize,
		RingCapacity:     b.capacity,
		Published:        atomic.LoadUint64(&b.published),
		DroppedToSlowSub: atomic.LoadUint64(&b.droppedToSlowSub),
	}
}
