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

package automation

import (
	"sync"
	"time"
)

// dedupeTTL is the lifetime of a pre-push GET result in the
// dedupe LRU per spec §3.4. 60s matches the LAPI stream-poll
// ticker (a tombstone observed via the Sink fanout within
// the same minute will invalidate the cache entry; the TTL
// here is a defence against the rare case where LAPI's
// /v1/decisions changes without the stream surfacing the
// delete promptly).
const dedupeTTL = 60 * time.Second

// dedupeMaxEntries caps the dedupe LRU. The cache stores
// recent decisions Arenet has confirmed are active in LAPI
// (skipping a duplicate POST). 1024 is generous — a homelab
// rarely has more than dozens of distinct active auto-bans
// at once.
const dedupeMaxEntries = 1024

// dedupeKey mirrors cooldownKey's shape — composite for a
// single-allocation lookup with diagnostics-friendly fields.
type dedupeKey struct {
	Scope    string
	Value    string
	Scenario string
}

// dedupeEntry stores the result of the pre-push GET +
// timestamp for TTL. The ActiveInLAPI bool is the cached
// answer: true means "skip the push, LAPI already has an
// active decision for this (scope, value, scenario) tuple".
type dedupeEntry struct {
	ActiveInLAPI bool
	CheckedAt    time.Time
}

// dedupeLRU caches pre-push GET results per spec D4.B. A
// HIT (entry exists, not expired) skips the GET round-trip;
// a MISS performs the GET and stores the result.
//
// Invalidation is triggered by the §3.6 Sink tombstone
// listener: when a delete event lands for (scope, value),
// the corresponding dedupe entries (for every scenario) are
// cleared so the next push attempt re-queries LAPI fresh.
//
// Thread-safe. The clock is injectable for tests.
type dedupeLRU struct {
	mu      sync.Mutex
	entries map[dedupeKey]dedupeEntry
	maxSize int
	clock   func() time.Time
}

func newDedupeLRU() *dedupeLRU {
	return newDedupeLRUWithClock(time.Now)
}

func newDedupeLRUWithClock(clock func() time.Time) *dedupeLRU {
	return &dedupeLRU{
		entries: make(map[dedupeKey]dedupeEntry),
		maxSize: dedupeMaxEntries,
		clock:   clock,
	}
}

// Lookup returns the cached (ActiveInLAPI, true) if the
// entry is present and not expired; otherwise (false, false).
// The second return is "cache hit" — callers distinguish
// "miss → must GET LAPI" from "hit, value says LAPI has it".
func (l *dedupeLRU) Lookup(scope, value, scenario string) (active bool, hit bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := dedupeKey{Scope: scope, Value: value, Scenario: scenario}
	e, ok := l.entries[key]
	if !ok {
		return false, false
	}
	if l.clock().Sub(e.CheckedAt) > dedupeTTL {
		delete(l.entries, key)
		return false, false
	}
	return e.ActiveInLAPI, true
}

// Record stores a fresh GET result. Idempotent on re-record;
// updates the timestamp + active flag. Triggers cap-eviction
// when oversize.
func (l *dedupeLRU) Record(scope, value, scenario string, activeInLAPI bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := dedupeKey{Scope: scope, Value: value, Scenario: scenario}
	l.entries[key] = dedupeEntry{
		ActiveInLAPI: activeInLAPI,
		CheckedAt:    l.clock(),
	}
	if len(l.entries) > l.maxSize {
		l.evictOldestLocked()
	}
}

// Invalidate removes every entry matching (scope, value)
// across all scenarios. Called by the §3.6 tombstone listener
// when the LAPI stream reports a deletion: the cache must
// not say "active in LAPI" when LAPI just told us otherwise.
//
// Scope and value alone identify the IP/CIDR — scenarios are
// the operator's per-rule label. A single tombstone may
// affect multiple scenarios (e.g. an IP banned under both
// arenet/waf-sqli and arenet/throttle-tier2), so we sweep
// every scenario for the (scope, value) pair.
func (l *dedupeLRU) Invalidate(scope, value string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for k := range l.entries {
		if k.Scope == scope && k.Value == value {
			delete(l.entries, k)
		}
	}
}

// Size returns the current number of tracked entries.
func (l *dedupeLRU) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// evictOldestLocked removes the entry with the earliest
// CheckedAt. O(n); caller holds l.mu.
func (l *dedupeLRU) evictOldestLocked() {
	var oldestKey dedupeKey
	var oldestTs time.Time
	first := true
	for k, e := range l.entries {
		if first || e.CheckedAt.Before(oldestTs) {
			oldestKey = k
			oldestTs = e.CheckedAt
			first = false
		}
	}
	if !first {
		delete(l.entries, oldestKey)
	}
}
