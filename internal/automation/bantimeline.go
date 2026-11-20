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
	"sort"
	"sync"
	"time"
)

// banTimeline is a bounded in-memory sliding-window ring of the timestamps of
// bans the writer successfully pushed, used to compute the in-UI
// "bans issued in the last 24h" activity gauge (D11, v2.84.0). It stores ONLY
// timestamps — the per-entry payload is a time.Time (24 B), so the cap bounds
// memory at ~cap*24 B (~48 KB at 2048) regardless of srcIP/scenario sizes; the
// "last ban" scenario/srcIP are single values held on the Engine, not here.
//
// In-memory on purpose (spec D11.a): the authoritative ban ledger is LAPI; this
// gauge resets on restart and rebuilds over the following 24h. Beyond `cap`
// bans inside the window, drop-oldest means the count under-reports (documented
// known limitation).
type banTimeline struct {
	mu   sync.Mutex
	ring []time.Time
	cap  int
	now  func() time.Time
}

// banTimelineCap bounds the ring. 2048 is generous for a homelab's realistic
// daily ban volume (the trigger's D8 re-emit guard collapses a flood from one
// vector to a single ban), and ~48 KB is negligible.
const banTimelineCap = 2048

// banWindow is the fixed reporting window for the UI gauge.
const banWindow = 24 * time.Hour

func newBanTimeline(now func() time.Time) *banTimeline {
	if now == nil {
		now = time.Now
	}
	return &banTimeline{cap: banTimelineCap, now: now}
}

// observe records one successful ban push at ts. Drop-oldest when at cap.
func (b *banTimeline) observe(ts time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ring = append(b.ring, ts)
	if len(b.ring) > b.cap {
		// Keep the newest cap entries (copy so the backing array stays bounded).
		trimmed := make([]time.Time, b.cap)
		copy(trimmed, b.ring[len(b.ring)-b.cap:])
		b.ring = trimmed
	}
}

// countSince prunes entries older than now-window and returns how many remain.
// Called by the HealthSnapshot read path (once per scrape), so pruning here is
// cheap and keeps the ring from holding >24h of stale entries.
func (b *banTimeline) countSince(window time.Duration) int {
	cutoff := b.now().Add(-window)
	b.mu.Lock()
	defer b.mu.Unlock()
	// Entries are appended in (near-)monotonic ts order in production; a sort
	// makes the prefix-drop correct even if a frozen-clock test appends out of
	// order. The ring is tiny (<= cap), so the sort is negligible.
	sort.Slice(b.ring, func(i, j int) bool { return b.ring[i].Before(b.ring[j]) })
	keep := 0
	for keep < len(b.ring) && !b.ring[keep].After(cutoff) {
		keep++
	}
	b.ring = b.ring[keep:]
	return len(b.ring)
}
