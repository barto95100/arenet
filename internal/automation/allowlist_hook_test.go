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
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAllowlistChecker satisfies AllowlistChecker with an injectable
// decision function and records whether it was consulted. No crowdsec /
// allowlist package import — that is the point of the interface
// (G_allowlist_no_crowdsec_dep).
type fakeAllowlistChecker struct {
	fn        func(srcIP string, cat Category) bool
	consulted atomic.Bool
}

func (f *fakeAllowlistChecker) IsAllowlisted(srcIP string, cat Category) bool {
	f.consulted.Store(true)
	if f.fn == nil {
		return false
	}
	return f.fn(srcIP, cat)
}

// recordingDedupeChecker records whether HasActiveDecision was called,
// so a test can prove the allowlist skip happens WITHOUT consulting the
// crowdsec mirror proxy.
type recordingDedupeChecker struct {
	consulted atomic.Bool
}

func (r *recordingDedupeChecker) HasActiveDecision(_ context.Context, _, _, _ string) (bool, time.Time, error) {
	r.consulted.Store(true)
	return false, time.Time{}, nil
}

// runTrigger spins the engine for a fixed window and returns once the
// deadline passes or wantAlerts have been pushed.
func runTrigger(t *testing.T, cfg EngineConfig, writer *fakeWriter, wantAlerts int) {
	t.Helper()
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) && writer.alertCount() < wantAlerts {
		time.Sleep(10 * time.Millisecond)
	}
	// Give any erroneous extra push a moment to land too.
	time.Sleep(60 * time.Millisecond)
	cancel()
	<-e.Done()
}

func wafBurst(ip string, src Source, now time.Time) *fakeWafReader {
	return &fakeWafReader{events: []SourceEvent{
		{ID: "1", Ts: now.Add(-20 * time.Second), SrcIP: ip, Source: src, TriggeringEventID: "1"},
		{ID: "2", Ts: now.Add(-10 * time.Second), SrcIP: ip, Source: src, TriggeringEventID: "2"},
	}}
}

// G_allowlist_match: an allowlisted IP whose scope covers the scenario's
// category has its intent skipped and an INFO "ban skipped (allowlisted)"
// line logged. RED before the hook: the alert is still pushed.
func TestAllowlistMatch_SkipsAndLogs_G(t *testing.T) {
	now := time.Now()
	waf := wafBurst("10.0.0.1", SourceWafRCE, now)
	rs := enableRule(SourceWafRCE, 2, 60*time.Second, 4*time.Hour, 24*time.Hour)
	writer := &fakeWriter{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	checker := &fakeAllowlistChecker{fn: func(ip string, cat Category) bool {
		return ip == "10.0.0.1" && cat == CategoryBlock
	}}

	runTrigger(t, EngineConfig{
		Waf: waf, Throttle: &fakeThrottleReader{}, Audit: &fakeAuditReader{},
		Rules: NewRuleSetHolder(rs), Writer: writer, AllowlistChecker: checker,
		Logger: logger, TickInterval: 20 * time.Millisecond,
		Now: func() time.Time { return now }, InitialCursorOffset: -1 * time.Hour,
	}, writer, 1)

	if writer.alertCount() != 0 {
		t.Errorf("alertCount = %d, want 0 (IP allowlisted for block)", writer.alertCount())
	}
	if !strings.Contains(buf.String(), "automation: ban skipped (allowlisted)") {
		t.Errorf("expected INFO 'ban skipped (allowlisted)'; buf=%q", buf.String())
	}
}

// G_allowlist_scope: an IP allowlisted for block ONLY must still be banned
// on a throttle-category scenario. Sibling guard — stays green; it bites if
// the hook ignores the category and skips everything.
func TestAllowlistScope_WrongCategory_NoSkip_G(t *testing.T) {
	now := time.Now()
	throttle := &fakeThrottleReader{events: []SourceEvent{
		{ID: "1", Ts: now.Add(-20 * time.Second), SrcIP: "10.0.0.2", Source: SourceThrottleTier1, TriggeringEventID: "1"},
		{ID: "2", Ts: now.Add(-10 * time.Second), SrcIP: "10.0.0.2", Source: SourceThrottleTier1, TriggeringEventID: "2"},
	}}
	rs := enableRule(SourceThrottleTier1, 2, 60*time.Second, 4*time.Hour, 24*time.Hour)
	writer := &fakeWriter{}
	checker := &fakeAllowlistChecker{fn: func(ip string, cat Category) bool {
		// allowlisted for block only
		return ip == "10.0.0.2" && cat == CategoryBlock
	}}

	runTrigger(t, EngineConfig{
		Waf: &fakeWafReader{}, Throttle: throttle, Audit: &fakeAuditReader{},
		Rules: NewRuleSetHolder(rs), Writer: writer, AllowlistChecker: checker,
		Logger: silentLogger(), TickInterval: 20 * time.Millisecond,
		Now: func() time.Time { return now }, InitialCursorOffset: -1 * time.Hour,
	}, writer, 1)

	if writer.alertCount() != 1 {
		t.Errorf("alertCount = %d, want 1 (allowlisted for block, scenario is throttle)", writer.alertCount())
	}
}

// G_allowlist_no_crowdsec_dep: the allowlist skip is a pure AreNET decision.
// When an IP is allowlisted, the trigger must NOT consult the crowdsec mirror
// proxy (ActiveDecisionChecker) at all — the two paths are independent by
// design. RED before the hook: dedupe is consulted, allowlist is not, alert
// pushed.
func TestAllowlistNoCrowdsecDep_SkipDoesNotConsultMirror_G(t *testing.T) {
	now := time.Now()
	waf := wafBurst("10.0.0.9", SourceWafRCE, now)
	rs := enableRule(SourceWafRCE, 2, 60*time.Second, 4*time.Hour, 24*time.Hour)
	writer := &fakeWriter{}
	dedupe := &recordingDedupeChecker{}
	allow := &fakeAllowlistChecker{fn: func(ip string, cat Category) bool { return true }}

	runTrigger(t, EngineConfig{
		Waf: waf, Throttle: &fakeThrottleReader{}, Audit: &fakeAuditReader{},
		Rules: NewRuleSetHolder(rs), Writer: writer,
		AllowlistChecker: allow, DedupeChecker: dedupe,
		Logger: silentLogger(), TickInterval: 20 * time.Millisecond,
		Now: func() time.Time { return now }, InitialCursorOffset: -1 * time.Hour,
	}, writer, 1)

	if writer.alertCount() != 0 {
		t.Errorf("alertCount = %d, want 0 (allowlisted)", writer.alertCount())
	}
	if !allow.consulted.Load() {
		t.Error("allowlist checker was never consulted")
	}
	if dedupe.consulted.Load() {
		t.Error("crowdsec mirror (dedupe) was consulted for an allowlisted IP — paths must be independent")
	}
}

// G_allowlist_category_map: Source.Category() implements the D4 mapping
// exactly. RED before the real mapping (stub returns CategoryBlock always).
func TestSourceCategory_Mapping_G(t *testing.T) {
	cases := map[Source]Category{
		SourceWafSQLi:       CategoryBlock,
		SourceWafXSS:        CategoryBlock,
		SourceWafRCE:        CategoryBlock,
		SourceWafLFI:        CategoryBlock,
		SourceWafProtocol:   CategoryBlock,
		SourceWafOther:      CategoryBlock,
		SourceThrottleTier1: CategoryThrottle,
		SourceThrottleTier2: CategoryThrottle,
		SourceAuthBurst:     CategoryAudit,
	}
	for src, want := range cases {
		if got := src.Category(); got != want {
			t.Errorf("Source(%q).Category() = %q, want %q", src, got, want)
		}
	}
}
