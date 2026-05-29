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

package waf

import (
	"container/list"
	"sync"
	"time"
)

// emitLRU rate-limits event emission per (routeID, srcIP,
// ruleID) triple. The spec §1.6.6 hazard: a sustained attack
// at 100 req/s emits 100 events/s × ~600 bytes; at the 30 d
// retention horizon that fills ~150 GB. The LRU caps the
// damage by emitting at most one event per triple per
// ttlSeconds (default 60s); the bucket counter on the
// aggregator side still increments on every block, so the
// dashboard sees the attack volume on the timeline.
//
// Cap defaults to 10k entries. When full, the oldest entry
// (LRU order) is evicted to make room.
//
// Thread-safe: ShouldEmit takes a write lock because both
// the read-and-decide and the bookkeeping-on-emit happen in
// the same critical section. The lock is held for an O(1)
// map lookup + list move; not a hot-path concern at the
// expected attack throughput.
type emitLRU struct {
	mu  sync.Mutex
	ll  *list.List               // LRU ordering, front = most recent
	idx map[string]*list.Element // key → list element
	cap int
	ttl time.Duration
	now func() time.Time // injectable for tests
}

type lruEntry struct {
	key string
	ts  time.Time
}

// newEmitLRU constructs an LRU rate-limiter. cap <= 0 means
// unlimited (used by tests that want pure TTL behaviour);
// production wiring passes 10_000.
func newEmitLRU(cap int, ttl time.Duration) *emitLRU {
	return &emitLRU{
		ll:  list.New(),
		idx: make(map[string]*list.Element, cap),
		cap: cap,
		ttl: ttl,
		now: func() time.Time { return time.Now() },
	}
}

// shouldEmit decides whether the caller should emit a fresh
// event row for this (routeID, srcIP, ruleID) triple AND
// records the decision so subsequent calls within ttl return
// false.
//
// Returns true on first sight or when the previous emit is
// older than ttl. Returns false when a recent emit already
// covered this triple — the caller should still increment its
// in-memory counter for the bucket aggregator (the LRU is
// purely about the event-table row, not the rolled-up count).
//
// Eviction policy: when at cap, the oldest entry is evicted
// to make room for the new one.
func (l *emitLRU) shouldEmit(routeID, srcIP, ruleID string) bool {
	key := routeID + "\x00" + srcIP + "\x00" + ruleID
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if elt, ok := l.idx[key]; ok {
		entry := elt.Value.(*lruEntry)
		if now.Sub(entry.ts) < l.ttl {
			// Recent — suppress this event row but bump the
			// entry's freshness so future emits stay
			// suppressed until ttl since this attempt.
			entry.ts = now
			l.ll.MoveToFront(elt)
			return false
		}
		// Stale — replace timestamp, move to front, allow emit.
		entry.ts = now
		l.ll.MoveToFront(elt)
		return true
	}

	// First sight of this triple — evict if needed, insert.
	if l.cap > 0 && l.ll.Len() >= l.cap {
		oldest := l.ll.Back()
		if oldest != nil {
			delete(l.idx, oldest.Value.(*lruEntry).key)
			l.ll.Remove(oldest)
		}
	}
	elt := l.ll.PushFront(&lruEntry{key: key, ts: now})
	l.idx[key] = elt
	return true
}

// len returns the current entry count. Test-only accessor.
func (l *emitLRU) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ll.Len()
}
