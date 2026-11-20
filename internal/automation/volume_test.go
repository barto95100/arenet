// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestVolumeTracker_NoDedup is the core of the v2.83.1 fix: N identical events
// (same srcIP, same Source, same instant) are ALL retained and returned — the
// opposite of the WAF/throttle LRU, which collapsed them to one table row and
// starved the trigger's threshold count. If this ever returns 1 for a burst of
// 4, the bug is back.
func TestVolumeTracker_NoDedup(t *testing.T) {
	now := time.Now()
	tr := NewVolumeTracker(func() time.Time { return now })
	for i := 0; i < 4; i++ {
		tr.ObserveWafBlock("185.23.40.4", "RCE", now)
	}
	got, err := tr.QueryWafEvents(context.Background(), WafFilter{From: now.Add(-time.Minute), To: now.Add(time.Second)})
	if err != nil {
		t.Fatalf("QueryWafEvents: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d events for a 4-event burst, want 4 (no dedup)", len(got))
	}
	for _, e := range got {
		if e.Source != SourceWafRCE || e.SrcIP != "185.23.40.4" {
			t.Errorf("unexpected projected event: %+v", e)
		}
	}
}

// TestVolumeTracker_PerKeyCap pins the per-key ring bound: beyond
// maxEventsPerKey the oldest are dropped and the cap-key counter climbs, while
// the retained count never exceeds the cap (which stays >> any sane threshold).
func TestVolumeTracker_PerKeyCap(t *testing.T) {
	now := time.Now()
	tr := NewVolumeTracker(func() time.Time { return now })
	over := 5
	for i := 0; i < defaultMaxEventsPerKey+over; i++ {
		tr.Observe("1.2.3.4", SourceWafSQLi, now)
	}
	got, _ := tr.QueryWafEvents(context.Background(), WafFilter{From: now.Add(-time.Minute), To: now.Add(time.Second)})
	if len(got) != defaultMaxEventsPerKey {
		t.Fatalf("retained %d, want cap %d", len(got), defaultMaxEventsPerKey)
	}
	if s := tr.Stats(); s.DroppedCapKey != uint64(over) {
		t.Errorf("DroppedCapKey=%d, want %d", s.DroppedCapKey, over)
	}
}

// TestVolumeTracker_GlobalCap pins the distinct-key bound: beyond maxKeysGlobal
// the oldest key is evicted (LRU) and the cap-global counter climbs.
func TestVolumeTracker_GlobalCap(t *testing.T) {
	now := time.Now()
	tr := NewVolumeTracker(func() time.Time { return now })
	over := 10
	for i := 0; i < defaultMaxKeysGlobal+over; i++ {
		tr.Observe(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff), SourceWafSQLi, now)
	}
	if s := tr.Stats(); s.Keys != defaultMaxKeysGlobal {
		t.Errorf("Keys=%d, want cap %d", s.Keys, defaultMaxKeysGlobal)
	}
	if s := tr.Stats(); s.DroppedCapGlobal != uint64(over) {
		t.Errorf("DroppedCapGlobal=%d, want %d", s.DroppedCapGlobal, over)
	}
}

// TestVolumeTracker_PruneRetention pins that records older than the retention
// ceiling are pruned on query and the emptied key is removed.
func TestVolumeTracker_PruneRetention(t *testing.T) {
	now := time.Now()
	tr := NewVolumeTracker(func() time.Time { return now })
	tr.Observe("1.2.3.4", SourceWafSQLi, now.Add(-2*defaultRetention)) // well past the ceiling
	got, _ := tr.QueryWafEvents(context.Background(), WafFilter{})     // zero filter → all
	if len(got) != 0 {
		t.Fatalf("got %d, want 0 (pruned by retention)", len(got))
	}
	if s := tr.Stats(); s.Keys != 0 || s.PrunedWindow == 0 {
		t.Errorf("after prune: Keys=%d PrunedWindow=%d, want 0 / >0", s.Keys, s.PrunedWindow)
	}
}

// TestVolumeTracker_WindowFilter pins [From, To) selection.
func TestVolumeTracker_WindowFilter(t *testing.T) {
	now := time.Now()
	tr := NewVolumeTracker(func() time.Time { return now })
	tr.Observe("1.2.3.4", SourceWafSQLi, now.Add(-30*time.Second)) // in a 60s window
	tr.Observe("1.2.3.4", SourceWafSQLi, now.Add(-90*time.Second)) // out of a 60s window
	got, _ := tr.QueryWafEvents(context.Background(), WafFilter{From: now.Add(-60 * time.Second), To: now})
	if len(got) != 1 {
		t.Fatalf("got %d in-window, want 1", len(got))
	}
}

// TestVolumeTracker_SourceFamilySplit pins that the WAF reader never returns
// throttle events and vice versa (one tracker instance serves both surfaces).
func TestVolumeTracker_SourceFamilySplit(t *testing.T) {
	now := time.Now()
	tr := NewVolumeTracker(func() time.Time { return now })
	tr.Observe("1.2.3.4", SourceWafSQLi, now)
	tr.ObserveThrottle("1.2.3.4", 1, now)

	waf, _ := tr.QueryWafEvents(context.Background(), WafFilter{From: now.Add(-time.Minute), To: now.Add(time.Second)})
	if len(waf) != 1 || waf[0].Source != SourceWafSQLi {
		t.Errorf("WAF query = %+v, want one waf-sqli", waf)
	}
	thr, _ := tr.QueryThrottleEvents(context.Background(), ThrottleFilter{From: now.Add(-time.Minute), To: now.Add(time.Second)})
	if len(thr) != 1 || thr[0].Source != SourceThrottleTier1 {
		t.Errorf("throttle query = %+v, want one throttle-tier1", thr)
	}
}

// TestVolumeTracker_Concurrent exercises the mutex under -race: concurrent
// Observe + Query must not race or panic.
func TestVolumeTracker_Concurrent(t *testing.T) {
	now := time.Now()
	tr := NewVolumeTracker(func() time.Time { return now })
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ip := fmt.Sprintf("1.2.3.%d", g)
			for i := 0; i < 200; i++ {
				tr.Observe(ip, SourceWafRCE, now)
				_, _ = tr.QueryWafEvents(context.Background(), WafFilter{From: now.Add(-time.Minute), To: now.Add(time.Second)})
			}
		}(g)
	}
	wg.Wait()
}
