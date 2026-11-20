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
	"testing"
	"time"
)

// TestBanTimeline_CountSinceWindow is G1: the 24h count is a true sliding
// window — bans older than the window are pruned, not accumulated forever.
// Reinjecting a cumulative counter (no prune) fails this.
func TestBanTimeline_CountSinceWindow(t *testing.T) {
	now := time.Now()
	bt := newBanTimeline(func() time.Time { return now })
	bt.observe(now.Add(-26 * time.Hour)) // outside 24h → pruned
	bt.observe(now.Add(-2 * time.Hour))  // inside
	bt.observe(now.Add(-1 * time.Minute))
	bt.observe(now)
	if got := bt.countSince(banWindow); got != 3 {
		t.Fatalf("countSince(24h) = %d, want 3 (the 26h-old ban pruned)", got)
	}
}

// TestBanTimeline_Cap pins drop-oldest at the ring cap: the count never exceeds
// the cap even under a flood.
func TestBanTimeline_Cap(t *testing.T) {
	now := time.Now()
	bt := newBanTimeline(func() time.Time { return now })
	for i := 0; i < banTimelineCap+50; i++ {
		bt.observe(now)
	}
	if got := bt.countSince(banWindow); got != banTimelineCap {
		t.Fatalf("countSince = %d, want cap %d", got, banTimelineCap)
	}
}

// TestEngine_RecordBan wires the engine accessors: a recorded ban bumps the
// 24h count and stamps the last-ban scenario + srcIP.
func TestEngine_RecordBan(t *testing.T) {
	now := time.Now()
	e, err := NewEngine(EngineConfig{
		Waf: &fakeWafReader{}, Throttle: &fakeThrottleReader{}, Audit: &fakeAuditReader{},
		Rules: NewRuleSetHolder(DefaultRuleSet()), Logger: silentLogger(),
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if n := e.TotalBansIssued24h(); n != 0 {
		t.Fatalf("fresh engine: TotalBansIssued24h = %d, want 0", n)
	}
	if _, ok := e.LastBanScenario(); ok {
		t.Fatal("fresh engine: LastBanScenario set")
	}

	e.recordBan(now, "arenet/waf-rce", "185.23.40.4")
	e.recordBan(now, "arenet/waf-sqli", "1.2.3.4")

	if n := e.TotalBansIssued24h(); n != 2 {
		t.Errorf("TotalBansIssued24h = %d, want 2", n)
	}
	if s, ok := e.LastBanScenario(); !ok || s != "arenet/waf-sqli" {
		t.Errorf("LastBanScenario = %q/%v, want arenet/waf-sqli/true", s, ok)
	}
	if ip, ok := e.LastBanSrcIP(); !ok || ip != "1.2.3.4" {
		t.Errorf("LastBanSrcIP = %q/%v, want 1.2.3.4/true", ip, ok)
	}
}
