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

import "time"

// health.go exposes the auto-classify writer's state for external
// monitoring (the Prometheus /metrics endpoint in internal/api).
//
// Why this exists: the writer fails SILENTLY. A synchronous surface
// (Scenarios tab, manual ban) shows the operator an error; the
// asynchronous auto-classify writer only logs + bumps internal counters
// when the machine credential breaks, so an operator could stop banning
// attackers for weeks without a signal. These counters already live on
// the Engine (TotalPush*), and the sticky login-failed bit lives on the
// WatcherClient — this is the read-only view that stitches them into one
// snapshot a metrics collector can scrape.

// HealthSnapshot is a point-in-time read of the auto-classify writer.
// All fields are cheap reads; a collector takes one per scrape.
type HealthSnapshot struct {
	// WriterConfigured is false in the boot-degraded path (no watcher
	// credentials) — the writer is a no-op drain and the login-failed
	// gauge must read 0, not 1.
	WriterConfigured bool
	// WriterLoginFailed is the sticky flag: the last login to LAPI was
	// rejected (bad machine credential). This is THE silent-failure
	// signal — true means auto-banning has stopped until the operator
	// fixes the credential. Always false when WriterConfigured is false.
	WriterLoginFailed bool
	// PushSuccess / PushPermanent / PushDropped mirror the Engine's
	// cumulative push counters. Permanent is the one that rises on a
	// broken credential or a rejected payload (the drop that needs a
	// human); Dropped is retry-exhaustion against an unreachable LAPI.
	PushSuccess   uint64
	PushPermanent uint64
	PushDropped   uint64
	// LastPushAt is the time of the last successful push, or nil when
	// none has succeeded yet (v2.83 — the dashboard badge / API health).
	LastPushAt *time.Time
	// LastPushError is the message of the most recent failed push, or
	// nil. Non-nil means the most recent completed push failed (it is
	// cleared on the next success), so it is a recent error, not a
	// tombstone.
	LastPushError *string

	// D11 (v2.84.0) ban-activity view. TotalBansIssued24h is the in-memory
	// rolling count of bans the writer pushed in the last 24h (resets on
	// restart; LAPI is the ledger — see banTimeline known limitations).
	// LastBanScenario / LastBanSrcIP are the most recent ban's context,
	// stamped at the same instant as LastPushAt (which doubles as
	// "last ban issued at"); nil when none has been issued yet.
	TotalBansIssued24h int
	LastBanScenario    *string
	LastBanSrcIP       *string

	// Memcounter* are the pre-LRU volume tracker's stats (v2.83.1),
	// surfaced as arenet_automation_memcounter_* so an operator can see
	// the tracker's pressure and tune the caps. Keys is the current
	// retained (srcIP, source) key count; the Dropped* and Pruned are
	// cumulative since boot.
	MemcounterKeys             int
	MemcounterDroppedCapKey    uint64
	MemcounterDroppedCapGlobal uint64
	MemcounterPrunedWindow     uint64
}

// HealthReporter is the read-only surface a metrics collector asserts
// GetManager() to. *DefaultManager implements it; a fake in tests can
// too. Kept separate from the Manager interface (which is the
// operator-mutation surface) so a read-only consumer cannot reach the
// SetRules/SetCredentials mutators.
type HealthReporter interface {
	HealthSnapshot() HealthSnapshot
}

// HealthSnapshot reads the current writer + push counters. Safe for
// concurrent callers: the writer pointer is read under the same RWMutex
// SetCredentials/ClearCredentials write under, and the Engine counters
// are atomics.
func (m *DefaultManager) HealthSnapshot() HealthSnapshot {
	m.mu.RLock()
	w := m.writer
	m.mu.RUnlock()

	snap := HealthSnapshot{WriterConfigured: w != nil}
	if w != nil {
		snap.WriterLoginFailed = w.LoginFailed()
	}
	if m.engine != nil {
		snap.PushSuccess = m.engine.TotalPushSuccess()
		snap.PushPermanent = m.engine.TotalPushPermanent()
		snap.PushDropped = m.engine.TotalPushDropped()
		if ts, ok := m.engine.LastPushAt(); ok {
			snap.LastPushAt = &ts
		}
		if msg, ok := m.engine.LastPushError(); ok {
			snap.LastPushError = &msg
		}
		vs := m.engine.VolumeStats()
		snap.MemcounterKeys = vs.Keys
		snap.MemcounterDroppedCapKey = vs.DroppedCapKey
		snap.MemcounterDroppedCapGlobal = vs.DroppedCapGlobal
		snap.MemcounterPrunedWindow = vs.PrunedWindow

		snap.TotalBansIssued24h = m.engine.TotalBansIssued24h()
		if s, ok := m.engine.LastBanScenario(); ok {
			snap.LastBanScenario = &s
		}
		if ip, ok := m.engine.LastBanSrcIP(); ok {
			snap.LastBanSrcIP = &ip
		}
	}
	return snap
}

// Interface guard: the production manager is a HealthReporter.
var _ HealthReporter = (*DefaultManager)(nil)
