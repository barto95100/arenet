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
	"testing"
	"time"
)

// runWithTracker wires a tracker as BOTH the WAF and throttle reader (as
// production does), runs the engine until the writer sees an alert (or the
// deadline), then waits a little longer to catch any erroneous SECOND emit
// before cancelling. Returns the writer so the caller asserts the count.
func runWithTracker(t *testing.T, tr *VolumeTracker, rs RuleSet, clock func() time.Time, settle time.Duration) *fakeWriter {
	t.Helper()
	writer := &fakeWriter{}
	e, err := NewEngine(EngineConfig{
		Waf: tr, Throttle: tr, Audit: &fakeAuditReader{},
		Rules:        NewRuleSetHolder(rs),
		Writer:       writer,
		AuditEmitter: &fakeAuditEmitter{},
		Logger:       silentLogger(),
		TickInterval: 20 * time.Millisecond,
		Now:          clock,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && writer.alertCount() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(settle) // let several more ticks run to expose a re-emit (D8 guard)
	cancel()
	<-e.Done()
	return writer
}

// TestVolumeTrigger_WafBurst_BansOnce is G1: the exact bug scenario. Four
// identical RCE events (same srcIP, same instant) — which the LRU-deduped
// table collapsed to one row, leaving n=1 < threshold=2 and no ban — now go
// through the pre-LRU tracker, so the trigger counts 4 and bans EXACTLY once.
func TestVolumeTrigger_WafBurst_BansOnce(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	tr := NewVolumeTracker(clock)
	for i := 0; i < 4; i++ {
		tr.ObserveWafBlock("185.23.40.4", "RCE", now.Add(-time.Duration(i+1)*time.Second))
	}
	rs := enableRule(SourceWafRCE, 2, 60*time.Second, 4*time.Hour, 24*time.Hour)

	writer := runWithTracker(t, tr, rs, clock, 120*time.Millisecond)

	if writer.alertCount() != 1 {
		t.Fatalf("alertCount=%d, want exactly 1 (4 identical RCE, threshold 2)", writer.alertCount())
	}
	if a := writer.lastAlert(); a.Scenario != "arenet/waf-rce" || a.Source.Value != "185.23.40.4" {
		t.Errorf("alert=%+v, want scenario arenet/waf-rce from 185.23.40.4", a)
	}
}

// TestVolumeTrigger_WafBelowThreshold_NoBan: a single event under threshold
// never bans, even though the tracker retains it across many ticks.
func TestVolumeTrigger_WafBelowThreshold_NoBan(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	tr := NewVolumeTracker(clock)
	tr.ObserveWafBlock("185.23.40.4", "RCE", now.Add(-time.Second))
	rs := enableRule(SourceWafRCE, 2, 60*time.Second, 4*time.Hour, 24*time.Hour)

	writer := runWithTracker(t, tr, rs, clock, 120*time.Millisecond)

	if writer.alertCount() != 0 {
		t.Fatalf("alertCount=%d, want 0 (1 event < threshold 2)", writer.alertCount())
	}
}

// TestVolumeTrigger_ThrottleBurst_BansOnce is G2: the throttle sink carries the
// same LRU, so the same fix must hold for throttle events.
func TestVolumeTrigger_ThrottleBurst_BansOnce(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	tr := NewVolumeTracker(clock)
	for i := 0; i < 5; i++ {
		tr.ObserveThrottle("185.23.40.4", 1, now.Add(-time.Duration(i+1)*time.Second))
	}
	rs := enableRule(SourceThrottleTier1, 5, 60*time.Second, 15*time.Minute, 4*time.Hour)

	writer := runWithTracker(t, tr, rs, clock, 120*time.Millisecond)

	if writer.alertCount() != 1 {
		t.Fatalf("alertCount=%d, want exactly 1 (5 throttle-tier1, threshold 5)", writer.alertCount())
	}
	if a := writer.lastAlert(); a.Scenario != "arenet/throttle-tier1" {
		t.Errorf("scenario=%q, want arenet/throttle-tier1", a.Scenario)
	}
}

// TestVolumeTrigger_CrossTick_BansOnce is G3: two events that arrive in
// DIFFERENT ticks (the old cursor model counted each tick's batch in
// isolation, so 1+1 never reached 2) now accumulate over the window and ban —
// exactly once, proving the D8 re-emit guard holds while the window lingers.
func TestVolumeTrigger_CrossTick_BansOnce(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	tr := NewVolumeTracker(clock)
	rs := enableRule(SourceWafRCE, 2, 60*time.Second, 4*time.Hour, 24*time.Hour)

	writer := &fakeWriter{}
	e, err := NewEngine(EngineConfig{
		Waf: tr, Throttle: tr, Audit: &fakeAuditReader{},
		Rules: NewRuleSetHolder(rs), Writer: writer, AuditEmitter: &fakeAuditEmitter{},
		Logger: silentLogger(), TickInterval: 20 * time.Millisecond, Now: clock,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// One event before start: several ticks must NOT ban (1 < 2).
	tr.ObserveWafBlock("1.2.3.4", "RCE", now.Add(-time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)
	time.Sleep(80 * time.Millisecond)
	if writer.alertCount() != 0 {
		cancel()
		<-e.Done()
		t.Fatalf("banned with a single event (alertCount=%d)", writer.alertCount())
	}

	// Second event in a later tick: now 2 in the window → ban exactly once.
	tr.ObserveWafBlock("1.2.3.4", "RCE", now.Add(-2*time.Second))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && writer.alertCount() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(120 * time.Millisecond) // expose any re-emit
	cancel()
	<-e.Done()

	if writer.alertCount() != 1 {
		t.Fatalf("alertCount=%d, want exactly 1 (cross-tick accumulation, D8 guard)", writer.alertCount())
	}
}
