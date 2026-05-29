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

package throttle

import (
	"container/list"
	"strconv"
	"sync"
	"time"
)

// emitLRU rate-limits event emission per (srcIP, tier) tuple.
// Sustained credential-stuffing from a single IP would emit
// one event per block-decision; the LRU caps event rows to
// one per (srcIP, tier) per ttlSeconds (default 60s). The
// bucket counter on the aggregator side still ticks on every
// block decision (bump-then-suppress invariant, spec §1.6.5).
//
// Mirrors internal/waf/lru.go modulo the key shape: WAF uses
// a 3-tuple (route, src_ip, rule); throttle uses a 2-tuple
// (src_ip, tier) because the throttle event has no route or
// rule concept.
//
// Cap defaults to 10k entries. When full, LRU eviction
// kicks the oldest entry to make room.
//
// Thread-safe: shouldEmit takes a write lock because read-
// and-decide and bookkeeping-on-emit happen in the same
// critical section. Held briefly (map lookup + list move).
type emitLRU struct {
	mu  sync.Mutex
	ll  *list.List
	idx map[string]*list.Element
	cap int
	ttl time.Duration
	now func() time.Time // injectable for tests
}

type lruEntry struct {
	key string
	ts  time.Time
}

// newEmitLRU constructs an LRU rate-limiter. cap <= 0 means
// unlimited; production wiring passes 10_000.
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
// event row for this (srcIP, tier) tuple AND records the
// decision so subsequent calls within ttl return false.
//
// Returns true on first sight or when the previous emit is
// older than ttl. Returns false when a recent emit already
// covered this tuple — the caller still bumps its bucket
// counter (the LRU is purely about the event-table row, not
// the per-minute count).
//
// Eviction: when at cap, the oldest entry is evicted to make
// room.
func (l *emitLRU) shouldEmit(srcIP string, tier int) bool {
	key := srcIP + "\x00" + strconv.Itoa(tier)
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
		entry.ts = now
		l.ll.MoveToFront(elt)
		return true
	}

	// First sight — evict if needed, insert.
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

// len returns the current entry count. Test-only.
func (l *emitLRU) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ll.Len()
}
