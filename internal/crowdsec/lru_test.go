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
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDecisionLRU_FirstSightAllowsEmit(t *testing.T) {
	lru := newDecisionLRU(100, time.Hour)
	if !lru.shouldEmit("uuid-1") {
		t.Fatal("first sight should allow emit")
	}
}

func TestDecisionLRU_RepeatWithinTTL_Suppresses(t *testing.T) {
	// Core invariant of the dedupe-before-bump pattern: the
	// SAME decision UUID re-emitted by LAPI on subsequent polls
	// MUST be suppressed for the full TTL window. This is what
	// stops `crowdsec_decision_count` from inflating by
	// (active × polls_per_minute) every minute.
	lru := newDecisionLRU(100, time.Hour)
	if !lru.shouldEmit("uuid-1") {
		t.Fatal("first sight should allow")
	}
	for i := 0; i < 60; i++ {
		if lru.shouldEmit("uuid-1") {
			t.Fatalf("repeat %d within TTL should be suppressed", i)
		}
	}
}

func TestDecisionLRU_DifferentUUIDs_Independent(t *testing.T) {
	// Each LAPI decision carries a unique UUID. Two distinct
	// decisions — even for the same IP / scenario — emit
	// independently.
	lru := newDecisionLRU(100, time.Hour)
	if !lru.shouldEmit("uuid-1") {
		t.Fatal("first UUID should allow")
	}
	if !lru.shouldEmit("uuid-2") {
		t.Fatal("different UUID should be independent")
	}
}

func TestDecisionLRU_AfterTTL_AllowsAgain(t *testing.T) {
	lru := newDecisionLRU(100, 100*time.Millisecond)
	var nowAt atomic.Int64
	nowAt.Store(time.Now().UnixNano())
	lru.now = func() time.Time { return time.Unix(0, nowAt.Load()) }

	if !lru.shouldEmit("uuid-1") {
		t.Fatal("first should allow")
	}
	if lru.shouldEmit("uuid-1") {
		t.Fatal("repeat within ttl should suppress")
	}
	nowAt.Add(int64(200 * time.Millisecond))
	if !lru.shouldEmit("uuid-1") {
		t.Fatal("after ttl elapsed should allow again")
	}
}

func TestDecisionLRU_FreshnessRefresh_KeepsSuppressing(t *testing.T) {
	// LAPI re-publishes the same active decision on every
	// 60s poll. The LRU refreshes the timestamp on every
	// suppression so a long-active decision NEVER re-emits
	// (the ttl window restarts on each suppress).
	lru := newDecisionLRU(100, time.Hour)
	var nowAt atomic.Int64
	nowAt.Store(time.Now().UnixNano())
	lru.now = func() time.Time { return time.Unix(0, nowAt.Load()) }

	if !lru.shouldEmit("uuid-1") {
		t.Fatal("first should allow")
	}
	for i := 0; i < 60; i++ {
		// Step the clock by 30s — well within the 1h ttl, but
		// stepping forward repeatedly to verify the refresh
		// resets the clock on the entry.
		nowAt.Add(int64(30 * time.Second))
		if lru.shouldEmit("uuid-1") {
			t.Fatalf("attempt %d (t+%ds, refresh chain) should be suppressed", i, (i+1)*30)
		}
	}
}

func TestDecisionLRU_EmptyUUID_AllowsButNotTracked(t *testing.T) {
	// Defensive path: empty UUID means LAPI returned a
	// malformed decision. Don't suppress (let it through so
	// the operator sees the bug in the dashboard) but don't
	// track in the LRU either (would conflate unrelated
	// rows on the empty-string key).
	lru := newDecisionLRU(100, time.Hour)
	if !lru.shouldEmit("") {
		t.Fatal("empty UUID should be allowed (not tracked)")
	}
	if !lru.shouldEmit("") {
		t.Fatal("repeated empty UUID should still be allowed (not tracked → no dedupe)")
	}
	if lru.len() != 0 {
		t.Errorf("LRU should not have tracked empty UUID, len=%d", lru.len())
	}
}

func TestDecisionLRU_EvictionWhenAtCap(t *testing.T) {
	lru := newDecisionLRU(3, time.Hour)
	for i := 0; i < 3; i++ {
		lru.shouldEmit(strconv.Itoa(i))
	}
	if got := lru.len(); got != 3 {
		t.Fatalf("len = %d, want 3", got)
	}
	lru.shouldEmit("3")
	if got := lru.len(); got != 3 {
		t.Fatalf("after eviction len = %d, want 3", got)
	}
	// Entry "0" evicted; new shouldEmit("0") looks fresh.
	if !lru.shouldEmit("0") {
		t.Fatal("evicted entry should look fresh")
	}
}

func TestDecisionLRU_Forget_FreesSlot(t *testing.T) {
	// Tombstone path: forget(uuid) drops the entry. A
	// subsequent shouldEmit with the same UUID is then
	// treated as first-sight.
	lru := newDecisionLRU(100, time.Hour)
	if !lru.shouldEmit("uuid-1") {
		t.Fatal("first should allow")
	}
	if lru.shouldEmit("uuid-1") {
		t.Fatal("repeat should suppress")
	}
	lru.forget("uuid-1")
	if lru.len() != 0 {
		t.Errorf("after forget, len = %d, want 0", lru.len())
	}
	if !lru.shouldEmit("uuid-1") {
		t.Fatal("after forget, same UUID should look fresh")
	}
}

func TestDecisionLRU_Forget_Unknown_Noop(t *testing.T) {
	// LAPI may signal deletion of a decision we never saw
	// (dropped on the channel via droppedByChannel, or the
	// LRU evicted it under cap pressure). forget on an
	// unknown UUID is silently tolerated.
	lru := newDecisionLRU(100, time.Hour)
	lru.forget("never-seen") // must not panic
	lru.forget("")           // empty-UUID case must not panic
	if lru.len() != 0 {
		t.Errorf("forget on unknown should not change len: got %d", lru.len())
	}
}

func TestDecisionLRU_ConcurrentSafe(t *testing.T) {
	lru := newDecisionLRU(1000, time.Hour)
	const workers = 16
	const perWorker = 1000
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				key := strconv.Itoa(w) + "-" + strconv.Itoa(i%50)
				lru.shouldEmit(key)
				if i%10 == 0 {
					lru.forget(key)
				}
			}
		}()
	}
	wg.Wait()
}
