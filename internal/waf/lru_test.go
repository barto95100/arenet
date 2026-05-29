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
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEmitLRU_FirstSightAllowsEmit(t *testing.T) {
	lru := newEmitLRU(100, time.Minute)
	if !lru.shouldEmit("r1", "1.2.3.4", "942100") {
		t.Fatal("first sight should allow emit")
	}
}

func TestEmitLRU_RepeatWithinTTL_Suppresses(t *testing.T) {
	lru := newEmitLRU(100, time.Minute)
	lru.shouldEmit("r1", "1.2.3.4", "942100")
	for i := 0; i < 1000; i++ {
		if lru.shouldEmit("r1", "1.2.3.4", "942100") {
			t.Fatalf("repeat %d within TTL should be suppressed", i)
		}
	}
}

func TestEmitLRU_AfterTTL_AllowsAgain(t *testing.T) {
	lru := newEmitLRU(100, 100*time.Millisecond)
	// Use a synthetic clock so the test doesn't have to wait.
	var nowAt atomic.Int64
	nowAt.Store(time.Now().UnixNano())
	lru.now = func() time.Time { return time.Unix(0, nowAt.Load()) }

	if !lru.shouldEmit("r1", "1.2.3.4", "942100") {
		t.Fatal("first should allow")
	}
	if lru.shouldEmit("r1", "1.2.3.4", "942100") {
		t.Fatal("repeat within ttl should suppress")
	}
	// Advance past ttl.
	nowAt.Add(int64(200 * time.Millisecond))
	if !lru.shouldEmit("r1", "1.2.3.4", "942100") {
		t.Fatal("after ttl elapsed should allow again")
	}
}

func TestEmitLRU_DifferentTriples_Independent(t *testing.T) {
	// Anti-regression on the (routeID, srcIP, ruleID) keying:
	// changing ANY one should be treated as a fresh triple.
	lru := newEmitLRU(100, time.Minute)
	lru.shouldEmit("r1", "1.2.3.4", "942100")
	if !lru.shouldEmit("r2", "1.2.3.4", "942100") {
		t.Fatal("different routeID should be a fresh triple")
	}
	if !lru.shouldEmit("r1", "5.6.7.8", "942100") {
		t.Fatal("different srcIP should be a fresh triple")
	}
	if !lru.shouldEmit("r1", "1.2.3.4", "941100") {
		t.Fatal("different ruleID should be a fresh triple")
	}
}

func TestEmitLRU_EvictionWhenAtCap(t *testing.T) {
	// Cap at 3, fill, then add a 4th — the oldest must be
	// evicted (and so a NEW shouldEmit on it returns true
	// because it looks fresh to the LRU).
	lru := newEmitLRU(3, time.Hour)
	for i := 0; i < 3; i++ {
		lru.shouldEmit("r", strconv.Itoa(i), "rule")
	}
	if got := lru.len(); got != 3 {
		t.Fatalf("len = %d, want 3", got)
	}
	// Push the 4th entry — entry 0 (oldest) must be evicted.
	lru.shouldEmit("r", "3", "rule")
	if got := lru.len(); got != 3 {
		t.Fatalf("after eviction len = %d, want 3", got)
	}
	// Entry 0 should now look fresh again (it was evicted).
	if !lru.shouldEmit("r", "0", "rule") {
		t.Fatal("evicted entry should look fresh")
	}
}

func TestEmitLRU_FreshnessRefresh_KeepsSuppressing(t *testing.T) {
	// A burst at 30 req/s sustained for 10 minutes should
	// keep producing ONE row at the start, not one every
	// 60s. The LRU refreshes the timestamp on every
	// suppression so the ttl window restarts each time.
	lru := newEmitLRU(100, time.Minute)
	var nowAt atomic.Int64
	nowAt.Store(time.Now().UnixNano())
	lru.now = func() time.Time { return time.Unix(0, nowAt.Load()) }

	if !lru.shouldEmit("r1", "1.2.3.4", "942100") {
		t.Fatal("first should allow")
	}
	// 600 attempts spaced 1 s apart — total 10 minutes.
	for i := 0; i < 600; i++ {
		nowAt.Add(int64(time.Second))
		if lru.shouldEmit("r1", "1.2.3.4", "942100") {
			t.Fatalf("attempt %d (t+%ds) should be suppressed", i, i+1)
		}
	}
}

func TestEmitLRU_ConcurrentSafe(t *testing.T) {
	// AC anti-regression: shouldEmit must be safe to call
	// from many goroutines at once (it's reached from the
	// Caddy module's ServeHTTP, which runs concurrently per
	// request).
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
				lru.shouldEmit("r"+strconv.Itoa(w), "ip"+strconv.Itoa(i%5), "rule")
			}
		}()
	}
	wg.Wait()
	// No assertion on exact count — only that nothing
	// crashed or raced.
}
