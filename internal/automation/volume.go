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
	"container/list"
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// VolumeTracker is the bounded, in-memory, sliding-window event counter that
// feeds the trigger engine's threshold check — the fix for the "auto-ban never
// fires from a single vector" bug (v2.83.1, spec
// docs/superpowers/specs/2026-11-20-automation-prelru-volume-design.md).
//
// Why it exists: the WAF and throttle observability sinks apply a 60 s sliding
// LRU dedup per (route/tier, srcIP, ruleID) BEFORE persisting to their event
// tables (internal/waf/lru.go, internal/throttle/lru.go), to cap storage. The
// trigger used to COUNT those deduplicated table rows, so a single attack
// vector contributed at most one row per 60 s and any Threshold >= 2 was
// unreachable. The tracker is fed from the PRE-LRU flux
// (geoForwardingWafSink.Emit / geoForwardingThrottleSink.Emit) and so sees true
// request volume. The tables stay the (deduplicated) forensic/UI record; the
// LRUs are untouched.
//
// It satisfies WafEventReader + ThrottleEventReader so it drops straight into
// the engine's existing read path in place of the DB-backed adapters. Querying
// a window [From, To) returns every retained event in that range (NOT
// deduplicated), which both fixes the primary bug and — because each tick
// re-reads the whole window rather than advancing a cursor past events — fixes
// the secondary per-tick/cross-tick accumulation bug (the trigger's D8 re-emit
// guard stops the lingering window from re-pushing).
//
// Bounds (spec §A): per-key ring capped at maxEventsPerKey (drop oldest),
// distinct (srcIP, Source) keys capped at maxKeysGlobal (LRU-evict oldest),
// records pruned to retention. Hard ceiling ~8 MB; < 100 KB idle. Single-vector
// persistent attackers (the automation target) are always captured; volumetric
// saturation is out of scope (bouncer + rate-limit own that).
type VolumeTracker struct {
	mu  sync.Mutex
	ll  *list.List                  // LRU ordering of keys; front = most recently observed
	idx map[volumeKey]*list.Element // key → element holding *volumeKeyState

	maxEventsPerKey int
	maxKeysGlobal   int
	retention       time.Duration
	now             func() time.Time

	droppedCapKey    atomic.Uint64
	droppedCapGlobal atomic.Uint64
	prunedWindow     atomic.Uint64
}

// Default bounds (spec §A). Package-level, no UI knob — tune via the
// arenet_automation_memcounter_* metrics if saturation shows.
const (
	defaultMaxEventsPerKey = 64
	defaultMaxKeysGlobal   = 4096
	// defaultRetention is a generous pruning ceiling for idle keys. The
	// per-key + global caps are the real memory bound; retention only
	// decides how long an untouched key lingers before a prune drops it.
	// Far above any sane rule Window (which has no upper bound in
	// validation, rules.go), so it never truncates a legitimate window.
	defaultRetention = time.Hour
)

type volumeKey struct {
	srcIP  string
	source Source
}

type volumeKeyState struct {
	key     volumeKey
	records []time.Time // ascending by observe order (append = newest)
}

// TrackerStats is a point-in-time read of the tracker's counters, surfaced via
// automation.HealthSnapshot for the Prometheus collector (spec §B).
type TrackerStats struct {
	Keys             int
	DroppedCapKey    uint64
	DroppedCapGlobal uint64
	PrunedWindow     uint64
}

// NewVolumeTracker builds a tracker with the default bounds. now may be nil
// (defaults to time.Now); tests inject a controllable clock.
func NewVolumeTracker(now func() time.Time) *VolumeTracker {
	if now == nil {
		now = time.Now
	}
	return &VolumeTracker{
		ll:              list.New(),
		idx:             make(map[volumeKey]*list.Element, defaultMaxKeysGlobal),
		maxEventsPerKey: defaultMaxEventsPerKey,
		maxKeysGlobal:   defaultMaxKeysGlobal,
		retention:       defaultRetention,
		now:             now,
	}
}

// isWafSource / isThrottleSource partition the Source space for the two reader
// surfaces. SourceAuthBurst belongs to neither (the audit reader is unaffected
// by any LRU and keeps reading its own store).
func isWafSource(s Source) bool {
	switch s {
	case SourceWafSQLi, SourceWafXSS, SourceWafRCE, SourceWafLFI, SourceWafProtocol, SourceWafOther:
		return true
	default:
		return false
	}
}

func isThrottleSource(s Source) bool {
	return s == SourceThrottleTier1 || s == SourceThrottleTier2
}

// ObserveWafBlock records one WAF BLOCK event (the caller gates on
// Action==BLOCK, preserving the v2.58.4 rule that detect-mode events must never
// contribute to a ban). category is the waf.Event category string; it maps to a
// Source via SourceFromWafCategory.
func (t *VolumeTracker) ObserveWafBlock(srcIP, category string, ts time.Time) {
	t.Observe(srcIP, SourceFromWafCategory(category), ts)
}

// ObserveThrottle records one throttle event. tier is the throttle.Event.Tier
// int (1 or 2); it maps to a Source via SourceFromThrottleTier.
func (t *VolumeTracker) ObserveThrottle(srcIP string, tier int, ts time.Time) {
	t.Observe(srcIP, SourceFromThrottleTier(tier), ts)
}

// Observe records one event for (srcIP, source) at ts. Bounded: per-key ring +
// global LRU eviction. A blank srcIP or an unknown source is dropped (nothing
// to ban / nowhere to count).
func (t *VolumeTracker) Observe(srcIP string, source Source, ts time.Time) {
	if srcIP == "" || !source.IsKnown() {
		return
	}
	k := volumeKey{srcIP: srcIP, source: source}

	t.mu.Lock()
	defer t.mu.Unlock()

	if elt, ok := t.idx[k]; ok {
		st := elt.Value.(*volumeKeyState)
		st.records = append(st.records, ts)
		if len(st.records) > t.maxEventsPerKey {
			// Drop oldest; copy so the backing array stays bounded.
			trimmed := make([]time.Time, t.maxEventsPerKey)
			copy(trimmed, st.records[len(st.records)-t.maxEventsPerKey:])
			st.records = trimmed
			t.droppedCapKey.Add(1)
		}
		t.ll.MoveToFront(elt)
		return
	}

	if t.maxKeysGlobal > 0 && t.ll.Len() >= t.maxKeysGlobal {
		if oldest := t.ll.Back(); oldest != nil {
			os := oldest.Value.(*volumeKeyState)
			delete(t.idx, os.key)
			t.ll.Remove(oldest)
			t.droppedCapGlobal.Add(1)
		}
	}
	st := &volumeKeyState{key: k, records: []time.Time{ts}}
	t.idx[k] = t.ll.PushFront(st)
}

// QueryWafEvents satisfies WafEventReader: every retained WAF-source event in
// [From, To), projected to SourceEvent, newest-last. Never deduplicated — that
// is the whole point.
func (t *VolumeTracker) QueryWafEvents(_ context.Context, filter WafFilter) ([]SourceEvent, error) {
	return t.query(filter.From, filter.To, filter.Limit, isWafSource), nil
}

// QueryThrottleEvents satisfies ThrottleEventReader.
func (t *VolumeTracker) QueryThrottleEvents(_ context.Context, filter ThrottleFilter) ([]SourceEvent, error) {
	return t.query(filter.From, filter.To, filter.Limit, isThrottleSource), nil
}

// query prunes expired records, then returns every record of a wanted source
// whose ts is in [from, to), as SourceEvent. Limit (> 0) caps the result set.
func (t *VolumeTracker) query(from, to time.Time, limit int, want func(Source) bool) []SourceEvent {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.pruneLocked(t.now())

	var out []SourceEvent
	for e := t.ll.Front(); e != nil; e = e.Next() {
		st := e.Value.(*volumeKeyState)
		if !want(st.key.source) {
			continue
		}
		for _, ts := range st.records {
			inFrom := from.IsZero() || ts.After(from) || ts.Equal(from)
			inTo := to.IsZero() || ts.Before(to)
			if !inFrom || !inTo {
				continue
			}
			ref := string(st.key.source) + "@" + strconv.FormatInt(ts.UTC().Unix(), 10)
			out = append(out, SourceEvent{
				ID:                ref,
				Ts:                ts,
				SrcIP:             st.key.srcIP,
				Source:            st.key.source,
				TriggeringEventID: ref,
			})
			if limit > 0 && len(out) >= limit {
				return out
			}
		}
	}
	return out
}

// pruneLocked drops records older than retention and removes emptied keys.
// Called under t.mu on every query (once per tick), so idle keys age out.
func (t *VolumeTracker) pruneLocked(now time.Time) {
	if t.retention <= 0 {
		return
	}
	cutoff := now.Add(-t.retention)
	for e := t.ll.Front(); e != nil; {
		next := e.Next()
		st := e.Value.(*volumeKeyState)
		w := 0
		for _, ts := range st.records {
			if ts.After(cutoff) {
				st.records[w] = ts
				w++
			} else {
				t.prunedWindow.Add(1)
			}
		}
		st.records = st.records[:w]
		if len(st.records) == 0 {
			delete(t.idx, st.key)
			t.ll.Remove(e)
		}
		e = next
	}
}

// Stats returns a point-in-time snapshot for the metrics collector.
func (t *VolumeTracker) Stats() TrackerStats {
	t.mu.Lock()
	keys := t.ll.Len()
	t.mu.Unlock()
	return TrackerStats{
		Keys:             keys,
		DroppedCapKey:    t.droppedCapKey.Load(),
		DroppedCapGlobal: t.droppedCapGlobal.Load(),
		PrunedWindow:     t.prunedWindow.Load(),
	}
}
