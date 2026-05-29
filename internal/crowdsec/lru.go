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

package crowdsec

import (
	"container/list"
	"sync"
	"time"
)

// decisionLRU rate-limits decision_event row emission AND
// gates the bucket counter bump — see sink.go's absorb for
// the dedupe-BEFORE-bump invariant (Step N spec D4.A).
//
// STRUCTURAL DIFFERENCE FROM M/Q:
//
//   - M (internal/waf/lru.go) and Q (internal/throttle/lru.go)
//     LRUs are dedupe-AFTER-bump: the BlockCounter ticks on
//     EVERY absorb (including suppressed), the LRU only
//     controls the event-table row. The producer side is
//     synchronous (1 emit per block decision), so naive
//     bump-on-every-absorb has the right semantic.
//
//   - N's LRU is dedupe-BEFORE-bump: the CrowdSec StreamBouncer
//     re-emits every active decision on EVERY poll cycle.
//     Naive bump-on-every-absorb would inflate the bucket
//     counter by (active_count × polls_per_minute) every
//     minute. The LRU positioned BEFORE the BlockCounter
//     ensures the counter reflects "decisions ARRIVED this
//     minute" (new bans), not "decisions ACTIVE this minute".
//
// Per spec §3.2 and D4.A rationale-of-record.
//
// Keyed on the decision UUID (1-tuple). UUIDs are LAPI's
// stable cross-instance identifier; the same decision in
// multiple polls carries the same UUID, while a re-grant
// after a tombstone gets a fresh UUID and re-triggers emit.
//
// Cap 50_000 (5× the M/Q default) because CrowdSec's
// `?startup=true` first poll can return the entire active
// blocklist — community lists can carry tens of thousands of
// IPs. TTL 1h (60× M/Q's 60s) reflects the longest practical
// poll cadence + jitter (we poll at 60s per D7.A, so 1h is a
// 60-poll-cycle horizon that survives operator-paused stream
// recovery without spurious re-emission).
//
// Thread-safe under arbitrary concurrency. shouldEmit takes a
// write lock because read-and-decide-and-record happen in the
// same critical section.
type decisionLRU struct {
	mu  sync.Mutex
	ll  *list.List
	idx map[string]*list.Element
	cap int
	ttl time.Duration
	now func() time.Time // injectable for tests
}

type decisionLRUEntry struct {
	uuid string
	ts   time.Time
}

// newDecisionLRU constructs an LRU. cap <= 0 means unlimited;
// production wiring passes the constants in sink.go's
// SinkConfig defaults.
func newDecisionLRU(cap int, ttl time.Duration) *decisionLRU {
	return &decisionLRU{
		ll:  list.New(),
		idx: make(map[string]*list.Element, cap),
		cap: cap,
		ttl: ttl,
		now: func() time.Time { return time.Now() },
	}
}

// shouldEmit decides whether the caller should emit a fresh
// event row for this decision UUID AND records the decision so
// subsequent calls with the same UUID within ttl return false.
//
// Returns true on first sight or when the previous record is
// older than ttl. Returns false when a recent record already
// covered this UUID — and the caller MUST NOT bump the
// BlockCounter either (dedupe-before-bump; see absorb).
//
// Eviction: when at cap, the oldest entry is evicted to make
// room. With cap=50k and typical decision volume, eviction is
// rare in practice; the cap is a safety net against pathological
// LAPI behaviour.
func (l *decisionLRU) shouldEmit(uuid string) bool {
	if uuid == "" {
		// Empty UUID = LAPI returned a decision without a
		// stable identifier. Don't dedupe (let it through)
		// but also don't bump the LRU — would conflate
		// unrelated rows on the empty-string key. Logged
		// upstream in the consumer; this is the safer
		// defensive choice.
		return true
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if elt, ok := l.idx[uuid]; ok {
		entry := elt.Value.(*decisionLRUEntry)
		if now.Sub(entry.ts) < l.ttl {
			// Recent — suppress emit AND counter bump. Refresh
			// freshness so future re-polls of the same UUID
			// stay suppressed for a full ttl since this poll
			// (matches M/Q's freshness-refresh semantic).
			entry.ts = now
			l.ll.MoveToFront(elt)
			return false
		}
		// Past ttl — treat as a fresh decision (LAPI
		// re-published an old UUID after our entry expired).
		entry.ts = now
		l.ll.MoveToFront(elt)
		return true
	}

	// First sight — evict if needed, insert.
	if l.cap > 0 && l.ll.Len() >= l.cap {
		oldest := l.ll.Back()
		if oldest != nil {
			delete(l.idx, oldest.Value.(*decisionLRUEntry).uuid)
			l.ll.Remove(oldest)
		}
	}
	elt := l.ll.PushFront(&decisionLRUEntry{uuid: uuid, ts: now})
	l.idx[uuid] = elt
	return true
}

// forget removes the entry for uuid if present, freeing the
// slot. Called by the sink's Tombstone path when LAPI signals
// a decision was deleted (revoked or expired). After forget,
// a subsequent shouldEmit with the same UUID returns true
// (treated as a fresh first-sight).
//
// No-op when the UUID is not in the LRU (the entry may have
// already been evicted by capacity pressure, or the
// tombstone arrives for a decision we never saw — both are
// silently tolerated).
func (l *decisionLRU) forget(uuid string) {
	if uuid == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if elt, ok := l.idx[uuid]; ok {
		delete(l.idx, uuid)
		l.ll.Remove(elt)
	}
}

// len returns the current entry count. Test-only.
func (l *decisionLRU) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ll.Len()
}
