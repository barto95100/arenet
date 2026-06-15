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

package alerting

import (
	"sync"
	"time"
)

// AL.2.b — Cooldown LRU per ADR D4.
//
// One entry per (rule_id, channel_id) pair, recording the
// wall-clock time the last fire was dispatched. OnCooldown
// returns true while now-firedAt < cooldown duration; once
// the window passes the entry is logically free again.
//
// EvictStale runs at the start of every watcher tick. It
// drops entries whose absolute age exceeds the eviction
// floor — defends against the LRU growing without bound
// when a rule is renamed or a channel is deleted while
// holding a stale cooldown entry. The eviction floor is
// generous (24h) so the steady-state working set is
// kept in memory; only truly forgotten entries are
// pruned.
//
// Concurrency: every method is safe for concurrent use.
// The watcher calls these methods sequentially per tick
// (D9 sequential eval V1) but Stop's Done() channel
// + the tick's per-call mutation pattern still need the
// mutex for the future parallel-eval V2 — keeping the
// guard now costs ~10ns per call vs the future code
// churn.
//
// V1 limitations (D4 ADR):
//   - In-memory only: cooldown resets on arenet restart.
//     V2 candidate: persist in BoltDB so a restart in
//     the middle of an outage doesn't re-page the
//     operator. Decision deferred until operator
//     feedback identifies the gap as real.

// CooldownLRU is the per-(rule, channel) cooldown table.
type CooldownLRU struct {
	mu      sync.Mutex
	entries map[cooldownKey]time.Time
	now     func() time.Time

	// evictionFloor caps the staleness of any retained
	// entry. Entries older than evictionFloor are dropped
	// even if their cooldown hasn't expired in principle —
	// a 24h cooldown that hasn't fired in 24+24h means the
	// rule is silent; the entry is dead weight.
	evictionFloor time.Duration
}

// cooldownKey is the LRU key. Kept as a value type so the
// map lookup is one allocation cheaper than a string-
// concatenation alternative.
type cooldownKey struct {
	RuleID    string
	ChannelID string
}

// DefaultEvictionFloor is the staleness ceiling
// EvictStale enforces. Matches ADR D4 "drop entries with
// fired_at older than 24h beyond their cooldown".
const DefaultEvictionFloor = 24 * time.Hour

// NewCooldownLRU constructs an empty cooldown table. now
// may be nil; production uses time.Now, tests inject a
// mock clock so cooldown-window passage doesn't require
// real-time sleeps.
func NewCooldownLRU(now func() time.Time) *CooldownLRU {
	if now == nil {
		now = time.Now
	}
	return &CooldownLRU{
		entries:       make(map[cooldownKey]time.Time),
		now:           now,
		evictionFloor: DefaultEvictionFloor,
	}
}

// OnCooldown reports whether the (rule, channel) pair is
// still inside its cooldown window. Returns false when no
// entry exists (first fire path).
func (c *CooldownLRU) OnCooldown(ruleID, channelID string, cooldown time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	firedAt, ok := c.entries[cooldownKey{RuleID: ruleID, ChannelID: channelID}]
	if !ok {
		return false
	}
	return c.now().Sub(firedAt) < cooldown
}

// Mark records a fire of (rule, channel) at the current
// wall-clock time. Overwrites any prior entry (a re-fire
// resets the window — the natural semantic operators
// expect).
func (c *CooldownLRU) Mark(ruleID, channelID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[cooldownKey{RuleID: ruleID, ChannelID: channelID}] = c.now()
}

// EvictStale drops entries older than evictionFloor AND
// entries whose RuleID is not in the keepRules set
// (cheap defense against rules being deleted while the
// watcher holds a cooldown reference). keepRules may be
// nil — only the staleness check runs.
//
// Returns the number of entries evicted (useful for the
// watcher's debug-level "evicted N stale cooldown
// entries" log).
func (c *CooldownLRU) EvictStale(keepRules map[string]struct{}) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	evicted := 0
	for k, firedAt := range c.entries {
		if now.Sub(firedAt) >= c.evictionFloor {
			delete(c.entries, k)
			evicted++
			continue
		}
		if keepRules != nil {
			if _, ok := keepRules[k.RuleID]; !ok {
				delete(c.entries, k)
				evicted++
			}
		}
	}
	return evicted
}

// Size returns the current entry count. Used by tests +
// the watcher's debug instrumentation.
func (c *CooldownLRU) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
