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

// cooldownMaxEntries bounds the cooldown LRU defensively.
// On a homelab the steady-state size is dozens (the count
// of IPs the operator has unbanned in the last week); the
// cap is a defence against a pathological case (e.g. mass
// unban via cscli script). Same cap as the M/Q/N LRUs.
const cooldownMaxEntries = 10_000

// cooldownEntry is what we store per (src_ip, scenario) key:
// when the tombstone was observed + when the cooldown
// expires. The Until field is the only one the lookup path
// reads; ObservedAt is for diagnostics + boot-time seeding.
type cooldownEntry struct {
	ObservedAt time.Time
	Until      time.Time
}

// cooldownKey is the composite key. Defined as a struct so
// the map's hash function uses both fields atomically (vs a
// joined string which would need parsing on the lookup path
// for diagnostics).
type cooldownKey struct {
	SrcIP    string
	Scenario string
}

// cooldownLRU is the operator-tombstone guard per spec D5.A.
// When an operator unbans an IP that auto-classify banned,
// the (src_ip, scenario) pair lands here with a TTL set by
// the rule's Cooldown field. Within the cooldown, the
// trigger engine skips that pair.
//
// Thread-safe (the trigger engine + the tombstone-listener
// callback both write to it concurrently). The cap eviction
// + TTL expiry happen on each Record / HasCooldown call —
// no background goroutine, no separate timer. Lazy eviction
// is fine for this surface (the lookup is cheap, the map
// stays bounded, the worst case is one extra map iteration
// when the cap is reached).
type cooldownLRU struct {
	mu      sync.Mutex
	entries map[cooldownKey]cooldownEntry
	maxSize int
	// clock is injectable so tests can drive expiry with a
	// synthetic clock. Production wiring uses time.Now.
	clock func() time.Time
}

// newCooldownLRU returns an empty LRU with the default cap.
// Tests use newCooldownLRUWithClock to inject a synthetic
// clock for deterministic TTL coverage.
func newCooldownLRU() *cooldownLRU {
	return newCooldownLRUWithClock(time.Now)
}

func newCooldownLRUWithClock(clock func() time.Time) *cooldownLRU {
	return &cooldownLRU{
		entries: make(map[cooldownKey]cooldownEntry),
		maxSize: cooldownMaxEntries,
		clock:   clock,
	}
}

// Record adds a cooldown for (srcIP, scenario) with TTL =
// `ttl` from now. Idempotent on re-record: the latest call
// wins (extending the cooldown forward). Zero or negative
// ttl is treated as "no cooldown" and is a no-op.
//
// On cap saturation, we evict the OLDEST entry (lowest
// ObservedAt). This is O(n) — acceptable at 10k entries and
// cooldown re-records are rare events (tombstones happen at
// operator cadence, not request cadence).
func (l *cooldownLRU) Record(srcIP, scenario string, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock()
	key := cooldownKey{SrcIP: srcIP, Scenario: scenario}
	l.entries[key] = cooldownEntry{
		ObservedAt: now,
		Until:      now.Add(ttl),
	}

	if len(l.entries) > l.maxSize {
		l.evictOldestLocked()
	}
}

// HasCooldown reports whether (srcIP, scenario) is currently
// in cooldown. Expired entries are removed lazily on lookup.
//
// Two operations performed under the same lock so a
// concurrent Record can't race against the expiry check.
func (l *cooldownLRU) HasCooldown(srcIP, scenario string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := cooldownKey{SrcIP: srcIP, Scenario: scenario}
	e, ok := l.entries[key]
	if !ok {
		return false
	}
	if l.clock().After(e.Until) {
		delete(l.entries, key)
		return false
	}
	return true
}

// Size returns the current number of tracked entries.
// Exposed for metrics + diagnostics; not load-bearing for
// the engine logic.
func (l *cooldownLRU) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// evictOldestLocked removes the entry with the earliest
// ObservedAt. Caller must hold l.mu. Used only on cap
// saturation — rare in steady-state operation.
func (l *cooldownLRU) evictOldestLocked() {
	var oldestKey cooldownKey
	var oldestTs time.Time
	first := true
	for k, e := range l.entries {
		if first || e.ObservedAt.Before(oldestTs) {
			oldestKey = k
			oldestTs = e.ObservedAt
			first = false
		}
	}
	if !first {
		delete(l.entries, oldestKey)
	}
}
