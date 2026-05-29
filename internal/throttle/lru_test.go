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
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEmitLRU_FirstSightAllowsEmit(t *testing.T) {
	lru := newEmitLRU(100, time.Minute)
	if !lru.shouldEmit("1.2.3.4", 1) {
		t.Fatal("first sight should allow emit")
	}
}

func TestEmitLRU_RepeatWithinTTL_Suppresses(t *testing.T) {
	lru := newEmitLRU(100, time.Minute)
	lru.shouldEmit("1.2.3.4", 1)
	for i := 0; i < 100; i++ {
		if lru.shouldEmit("1.2.3.4", 1) {
			t.Fatalf("repeat %d within TTL should be suppressed", i)
		}
	}
}

func TestEmitLRU_DifferentTiers_AreIndependent(t *testing.T) {
	// Anti-regression on the (srcIP, tier) keying: same IP
	// hitting Tier 1 AND Tier 2 must produce TWO events, not
	// one. The Tier-1 event captures the initial block; the
	// Tier-2 event captures the escalation. Spec §1.3 D1.A.
	lru := newEmitLRU(100, time.Minute)
	if !lru.shouldEmit("1.2.3.4", 1) {
		t.Fatal("first Tier-1 should allow")
	}
	if !lru.shouldEmit("1.2.3.4", 2) {
		t.Fatal("same IP, different tier should be a fresh tuple")
	}
}

func TestEmitLRU_DifferentIPs_AreIndependent(t *testing.T) {
	lru := newEmitLRU(100, time.Minute)
	lru.shouldEmit("1.2.3.4", 1)
	if !lru.shouldEmit("5.6.7.8", 1) {
		t.Fatal("different IP should be a fresh tuple")
	}
}

func TestEmitLRU_AfterTTL_AllowsAgain(t *testing.T) {
	lru := newEmitLRU(100, 100*time.Millisecond)
	var nowAt atomic.Int64
	nowAt.Store(time.Now().UnixNano())
	lru.now = func() time.Time { return time.Unix(0, nowAt.Load()) }

	if !lru.shouldEmit("1.2.3.4", 1) {
		t.Fatal("first should allow")
	}
	if lru.shouldEmit("1.2.3.4", 1) {
		t.Fatal("repeat within ttl should suppress")
	}
	// Advance past ttl.
	nowAt.Add(int64(200 * time.Millisecond))
	if !lru.shouldEmit("1.2.3.4", 1) {
		t.Fatal("after ttl elapsed should allow again")
	}
}

func TestEmitLRU_FreshnessRefresh_KeepsSuppressing(t *testing.T) {
	// A sustained credential-stuffing attempt at 30 req/s for
	// 10 minutes should keep producing ONE row at the start,
	// not one every 60s. The LRU refreshes the timestamp on
	// every suppression so the ttl window restarts each time.
	lru := newEmitLRU(100, time.Minute)
	var nowAt atomic.Int64
	nowAt.Store(time.Now().UnixNano())
	lru.now = func() time.Time { return time.Unix(0, nowAt.Load()) }

	if !lru.shouldEmit("1.2.3.4", 1) {
		t.Fatal("first should allow")
	}
	for i := 0; i < 600; i++ {
		nowAt.Add(int64(time.Second))
		if lru.shouldEmit("1.2.3.4", 1) {
			t.Fatalf("attempt %d (t+%ds) should be suppressed", i, i+1)
		}
	}
}

func TestEmitLRU_EvictionWhenAtCap(t *testing.T) {
	lru := newEmitLRU(3, time.Hour)
	for i := 0; i < 3; i++ {
		lru.shouldEmit(strconv.Itoa(i), 1)
	}
	if got := lru.len(); got != 3 {
		t.Fatalf("len = %d, want 3", got)
	}
	// 4th entry — entry 0 (oldest) must be evicted.
	lru.shouldEmit("3", 1)
	if got := lru.len(); got != 3 {
		t.Fatalf("after eviction len = %d, want 3", got)
	}
	// Entry "0" should now look fresh again (it was evicted).
	if !lru.shouldEmit("0", 1) {
		t.Fatal("evicted entry should look fresh")
	}
}

func TestEmitLRU_ConcurrentSafe(t *testing.T) {
	// shouldEmit reached from the rate limiter's goroutine
	// (called per request); must be safe under arbitrary
	// concurrency.
	lru := newEmitLRU(100, time.Minute)
	const workers = 16
	const perWorker = 1000
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				lru.shouldEmit(strconv.Itoa(w)+"."+strconv.Itoa(i%5), (i%2)+1)
			}
		}()
	}
	wg.Wait()
	// No assertion on count — only that nothing raced.
}
