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

package automation

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- Fakes for the trigger engine ---------------------------------------

// fakeWafReader returns a static slice of events on every
// QueryWafEvents call (filtered by From / To).
type fakeWafReader struct {
	mu     sync.Mutex
	events []SourceEvent
}

func (f *fakeWafReader) QueryWafEvents(_ context.Context, filter WafFilter) ([]SourceEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []SourceEvent
	for _, e := range f.events {
		if (e.Ts.After(filter.From) || e.Ts.Equal(filter.From)) && e.Ts.Before(filter.To) {
			out = append(out, e)
		}
	}
	return out, nil
}

type fakeThrottleReader struct {
	mu     sync.Mutex
	events []SourceEvent
}

func (f *fakeThrottleReader) QueryThrottleEvents(_ context.Context, filter ThrottleFilter) ([]SourceEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []SourceEvent
	for _, e := range f.events {
		if (e.Ts.After(filter.From) || e.Ts.Equal(filter.From)) && e.Ts.Before(filter.To) {
			out = append(out, e)
		}
	}
	return out, nil
}

type fakeAuditReader struct {
	mu     sync.Mutex
	events []SourceEvent
}

func (f *fakeAuditReader) QueryAuthFailureEvents(_ context.Context, from, to time.Time, _ int) ([]SourceEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []SourceEvent
	for _, e := range f.events {
		if (e.Ts.After(from) || e.Ts.Equal(from)) && e.Ts.Before(to) {
			out = append(out, e)
		}
	}
	return out, nil
}

// fakeWriter records pushed alerts. Concurrent-safe.
type fakeWriter struct {
	mu      sync.Mutex
	alerts  []Alert
	pushErr error
}

func (f *fakeWriter) EnsureJWT(_ context.Context) (string, error) { return "fake-jwt", nil }
func (f *fakeWriter) LoginFailed() bool                           { return false }
func (f *fakeWriter) PushAlert(_ context.Context, a Alert) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pushErr != nil {
		return nil, f.pushErr
	}
	f.alerts = append(f.alerts, a)
	return []string{"alert-1"}, nil
}
func (f *fakeWriter) alertCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.alerts)
}
func (f *fakeWriter) lastAlert() Alert {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.alerts) == 0 {
		return Alert{}
	}
	return f.alerts[len(f.alerts)-1]
}

// fakeAuditEmitter records audit emission calls.
type fakeAuditEmitter struct {
	mu    sync.Mutex
	calls []struct {
		SrcIP, Scenario, EventID string
		Count, DurationSeconds   int
	}
}

func (f *fakeAuditEmitter) EmitDecisionPushed(srcIP, scenario, eventID string, count, dur int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, struct {
		SrcIP, Scenario, EventID string
		Count, DurationSeconds   int
	}{srcIP, scenario, eventID, count, dur})
}
func (f *fakeAuditEmitter) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// fakeDedupeChecker returns a hard-coded ActiveInLAPI value.
type fakeDedupeChecker struct {
	active atomic.Bool
}

func (f *fakeDedupeChecker) HasActiveDecision(_ context.Context, _, _, _ string) (bool, error) {
	return f.active.Load(), nil
}

// silentLogger discards log output during tests.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- Helpers -------------------------------------------------------------

// enableRule returns a RuleSet with one source enabled.
func enableRule(s Source, threshold int, window, duration, cooldown time.Duration) RuleSet {
	rs := DefaultRuleSet()
	r := rs.Rules[s]
	r.Enabled = true
	r.Threshold = threshold
	r.Window = window
	r.Duration = duration
	r.Cooldown = cooldown
	rs.Rules[s] = r
	return rs
}

// --- Tests ---------------------------------------------------------------

func TestNewEngine_RequiresAllReaders(t *testing.T) {
	holder := NewRuleSetHolder(DefaultRuleSet())
	_, err := NewEngine(EngineConfig{
		Throttle: &fakeThrottleReader{},
		Audit:    &fakeAuditReader{},
		Rules:    holder,
	})
	if err == nil {
		t.Error("expected error when WAF reader missing")
	}
}

func TestNewEngine_RequiresRulesHolder(t *testing.T) {
	_, err := NewEngine(EngineConfig{
		Waf:      &fakeWafReader{},
		Throttle: &fakeThrottleReader{},
		Audit:    &fakeAuditReader{},
	})
	if err == nil {
		t.Error("expected error when Rules holder missing")
	}
}

// TestTriggerEngine_AllDisabled_DoesNothing pins the spec
// §3.2 "AnyEnabled short-circuit": when no rule is enabled,
// the tick performs zero queries + emits zero intents.
func TestTriggerEngine_AllDisabled_DoesNothing(t *testing.T) {
	waf := &fakeWafReader{events: []SourceEvent{
		// Even with WAF events present, all-disabled =
		// nothing should happen.
		{ID: "1", Ts: time.Now(), SrcIP: "1.2.3.4", Source: SourceWafSQLi, TriggeringEventID: "1"},
	}}
	holder := NewRuleSetHolder(DefaultRuleSet()) // all disabled

	e, err := NewEngine(EngineConfig{
		Waf: waf, Throttle: &fakeThrottleReader{}, Audit: &fakeAuditReader{},
		Rules: holder, Logger: silentLogger(),
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)
	time.Sleep(50 * time.Millisecond) // let initial tick fire
	cancel()
	<-e.Done()

	if e.TotalIntentsEmit() != 0 {
		t.Errorf("TotalIntentsEmit = %d, want 0 (all rules disabled)", e.TotalIntentsEmit())
	}
}

// TestTriggerEngine_ThresholdNotMet_NoEmit verifies the
// aggregated-window model (D2.2.A): 1 event with threshold=2
// → no intent.
func TestTriggerEngine_ThresholdNotMet_NoEmit(t *testing.T) {
	now := time.Now()
	waf := &fakeWafReader{events: []SourceEvent{
		{ID: "1", Ts: now.Add(-10 * time.Second), SrcIP: "1.2.3.4", Source: SourceWafSQLi, TriggeringEventID: "1"},
	}}
	rs := enableRule(SourceWafSQLi, 2, 60*time.Second, 1*time.Hour, 24*time.Hour)
	holder := NewRuleSetHolder(rs)
	writer := &fakeWriter{}

	e, _ := NewEngine(EngineConfig{
		Waf: waf, Throttle: &fakeThrottleReader{}, Audit: &fakeAuditReader{},
		Rules: holder, Writer: writer, Logger: silentLogger(),
		TickInterval:        20 * time.Millisecond,
		Now:                 func() time.Time { return now },
		InitialCursorOffset: -1 * time.Hour,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)
	time.Sleep(80 * time.Millisecond)
	cancel()
	<-e.Done()

	if e.TotalIntentsEmit() != 0 {
		t.Errorf("TotalIntentsEmit = %d, want 0 (threshold not met)", e.TotalIntentsEmit())
	}
}

// TestTriggerEngine_ThresholdMet_Emits is the happy path:
// 2 SQLi events from the same IP within 60s, threshold=2 →
// 1 intent emitted, 1 alert pushed via writer, 1 audit row.
func TestTriggerEngine_ThresholdMet_Emits(t *testing.T) {
	now := time.Now()
	waf := &fakeWafReader{events: []SourceEvent{
		{ID: "1", Ts: now.Add(-20 * time.Second), SrcIP: "1.2.3.4", Source: SourceWafSQLi, TriggeringEventID: "1"},
		{ID: "2", Ts: now.Add(-10 * time.Second), SrcIP: "1.2.3.4", Source: SourceWafSQLi, TriggeringEventID: "2"},
	}}
	rs := enableRule(SourceWafSQLi, 2, 60*time.Second, 4*time.Hour, 24*time.Hour)
	holder := NewRuleSetHolder(rs)
	writer := &fakeWriter{}
	audit := &fakeAuditEmitter{}

	e, _ := NewEngine(EngineConfig{
		Waf: waf, Throttle: &fakeThrottleReader{}, Audit: &fakeAuditReader{},
		Rules:               holder,
		Writer:              writer,
		AuditEmitter:        audit,
		Logger:              silentLogger(),
		TickInterval:        20 * time.Millisecond,
		Now:                 func() time.Time { return now },
		InitialCursorOffset: -1 * time.Hour,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)
	// Wait for tick + writer to drain.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && writer.alertCount() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-e.Done()

	if writer.alertCount() != 1 {
		t.Fatalf("writer.alertCount = %d, want 1", writer.alertCount())
	}
	a := writer.lastAlert()
	if a.Scenario != "arenet/waf-sqli" {
		t.Errorf("Scenario = %q, want arenet/waf-sqli", a.Scenario)
	}
	if a.Source.Value != "1.2.3.4" {
		t.Errorf("Source.Value = %q, want 1.2.3.4", a.Source.Value)
	}
	if len(a.Decisions) != 1 || a.Decisions[0].Origin != "arenet" {
		t.Errorf("decisions: %+v, want one with Origin=arenet", a.Decisions)
	}
	if audit.callCount() != 1 {
		t.Errorf("audit.callCount = %d, want 1", audit.callCount())
	}
}

// TestTriggerEngine_CooldownHonoured pins D5.A: a cooldown
// entry for (src_ip, scenario) suppresses the intent.
func TestTriggerEngine_CooldownHonoured(t *testing.T) {
	now := time.Now()
	waf := &fakeWafReader{events: []SourceEvent{
		{ID: "1", Ts: now.Add(-20 * time.Second), SrcIP: "1.2.3.4", Source: SourceWafSQLi, TriggeringEventID: "1"},
		{ID: "2", Ts: now.Add(-10 * time.Second), SrcIP: "1.2.3.4", Source: SourceWafSQLi, TriggeringEventID: "2"},
	}}
	rs := enableRule(SourceWafSQLi, 2, 60*time.Second, 4*time.Hour, 24*time.Hour)
	holder := NewRuleSetHolder(rs)
	writer := &fakeWriter{}

	e, _ := NewEngine(EngineConfig{
		Waf: waf, Throttle: &fakeThrottleReader{}, Audit: &fakeAuditReader{},
		Rules: holder, Writer: writer, Logger: silentLogger(),
		TickInterval:        20 * time.Millisecond,
		Now:                 func() time.Time { return now },
		InitialCursorOffset: -1 * time.Hour,
	})

	// Pre-record a cooldown for (1.2.3.4, arenet/waf-sqli).
	e.cooldown.Record("1.2.3.4", "arenet/waf-sqli", 24*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-e.Done()

	if writer.alertCount() != 0 {
		t.Errorf("writer.alertCount = %d, want 0 (cooldown active)", writer.alertCount())
	}
}

// TestTriggerEngine_DedupeChecker_ActiveInLAPI_Skips pins
// D4.B: when the dedupe checker reports LAPI already has an
// active decision, the intent is skipped.
func TestTriggerEngine_DedupeChecker_ActiveInLAPI_Skips(t *testing.T) {
	now := time.Now()
	waf := &fakeWafReader{events: []SourceEvent{
		{ID: "1", Ts: now.Add(-20 * time.Second), SrcIP: "1.2.3.4", Source: SourceWafSQLi, TriggeringEventID: "1"},
		{ID: "2", Ts: now.Add(-10 * time.Second), SrcIP: "1.2.3.4", Source: SourceWafSQLi, TriggeringEventID: "2"},
	}}
	rs := enableRule(SourceWafSQLi, 2, 60*time.Second, 4*time.Hour, 24*time.Hour)
	holder := NewRuleSetHolder(rs)
	writer := &fakeWriter{}
	checker := &fakeDedupeChecker{}
	checker.active.Store(true)

	e, _ := NewEngine(EngineConfig{
		Waf: waf, Throttle: &fakeThrottleReader{}, Audit: &fakeAuditReader{},
		Rules: holder, Writer: writer, DedupeChecker: checker,
		Logger: silentLogger(), TickInterval: 20 * time.Millisecond,
		Now:                 func() time.Time { return now },
		InitialCursorOffset: -1 * time.Hour,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-e.Done()

	if writer.alertCount() != 0 {
		t.Errorf("writer.alertCount = %d, want 0 (LAPI already has decision)", writer.alertCount())
	}
}

// TestTriggerEngine_NoWriter_DrainsIntents pins AC #15:
// boot-degraded path where watcher creds are missing — the
// trigger engine still runs but the writer-side is a no-op
// drain. Intents emitted must not block.
func TestTriggerEngine_NoWriter_DrainsIntents(t *testing.T) {
	now := time.Now()
	waf := &fakeWafReader{events: []SourceEvent{
		{ID: "1", Ts: now.Add(-20 * time.Second), SrcIP: "1.2.3.4", Source: SourceWafSQLi, TriggeringEventID: "1"},
		{ID: "2", Ts: now.Add(-10 * time.Second), SrcIP: "1.2.3.4", Source: SourceWafSQLi, TriggeringEventID: "2"},
	}}
	rs := enableRule(SourceWafSQLi, 2, 60*time.Second, 4*time.Hour, 24*time.Hour)
	holder := NewRuleSetHolder(rs)

	e, _ := NewEngine(EngineConfig{
		Waf: waf, Throttle: &fakeThrottleReader{}, Audit: &fakeAuditReader{},
		Rules: holder, Writer: nil, // <- boot-degraded
		Logger: silentLogger(), TickInterval: 20 * time.Millisecond,
		Now:                 func() time.Time { return now },
		InitialCursorOffset: -1 * time.Hour,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-e.Done()

	// Intent emitted (the engine doesn't know writer is nil
	// at intent-emit time); writer-side no-op drain consumes
	// it silently. The metric counter confirms emission
	// happened.
	if e.TotalIntentsEmit() == 0 {
		t.Errorf("TotalIntentsEmit = 0, want >= 1 even with nil writer (boot-degraded)")
	}
}

// TestTriggerEngine_RuleChange_TakesEffectNextTick pins the
// §4 "rule change clobbers in-flight" mitigation: the engine
// reads the RuleSet snapshot at each tick, so changes take
// effect on the next tick. A mid-flight intent emitted under
// the old rules completes under those rules.
func TestTriggerEngine_RuleChange_TakesEffectNextTick(t *testing.T) {
	now := time.Now()
	waf := &fakeWafReader{events: []SourceEvent{
		{ID: "1", Ts: now.Add(-20 * time.Second), SrcIP: "1.2.3.4", Source: SourceWafSQLi, TriggeringEventID: "1"},
		{ID: "2", Ts: now.Add(-10 * time.Second), SrcIP: "1.2.3.4", Source: SourceWafSQLi, TriggeringEventID: "2"},
	}}
	rs := enableRule(SourceWafSQLi, 2, 60*time.Second, 4*time.Hour, 24*time.Hour)
	holder := NewRuleSetHolder(rs)
	writer := &fakeWriter{}

	e, _ := NewEngine(EngineConfig{
		Waf: waf, Throttle: &fakeThrottleReader{}, Audit: &fakeAuditReader{},
		Rules: holder, Writer: writer, Logger: silentLogger(),
		TickInterval:        50 * time.Millisecond,
		Now:                 func() time.Time { return now },
		InitialCursorOffset: -1 * time.Hour,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)
	// Wait for first emission.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && writer.alertCount() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if writer.alertCount() != 1 {
		t.Fatalf("first tick should emit: alertCount=%d", writer.alertCount())
	}

	// Now disable the rule. Subsequent ticks should NOT
	// emit even if events are still in the source.
	disabled := DefaultRuleSet() // all disabled
	holder.Set(disabled)

	time.Sleep(150 * time.Millisecond) // several more ticks
	cancel()
	<-e.Done()

	// Only the first emission counts; rule disable kicks in
	// on next tick.
	if writer.alertCount() > 1 {
		t.Errorf("after disable, additional emissions: alertCount=%d, want 1", writer.alertCount())
	}
}

// TestTriggerEngine_OnTombstone_RecordsCooldownAndInvalidatesDedupe
// pins the §3.6 D6.A entry point: the Step N Sink fanout
// translates UUID → (srcIP, scenario), then OnTombstone:
//  1. records a cooldown using the rule's Cooldown duration,
//  2. invalidates the dedupe LRU for (Ip, srcIP).
func TestTriggerEngine_OnTombstone_RecordsCooldownAndInvalidatesDedupe(t *testing.T) {
	rs := enableRule(SourceWafSQLi, 2, 60*time.Second, 4*time.Hour, 24*time.Hour)
	holder := NewRuleSetHolder(rs)
	e, _ := NewEngine(EngineConfig{
		Waf: &fakeWafReader{}, Throttle: &fakeThrottleReader{}, Audit: &fakeAuditReader{},
		Rules: holder, Logger: silentLogger(),
	})

	// Pre-populate the dedupe with two scenarios for the
	// same IP to exercise the "sweep across all scenarios"
	// invariant.
	e.dedupe.Record("Ip", "1.2.3.4", "arenet/waf-sqli", true)
	e.dedupe.Record("Ip", "1.2.3.4", "arenet/auth-burst", true)

	e.OnTombstone("1.2.3.4", "arenet/waf-sqli")

	if !e.cooldown.HasCooldown("1.2.3.4", "arenet/waf-sqli") {
		t.Error("OnTombstone should record a cooldown for (srcIP, scenario)")
	}
	// Dedupe invalidation is by (scope, value) — both
	// scenarios should be cleared.
	if _, hit := e.dedupe.Lookup("Ip", "1.2.3.4", "arenet/waf-sqli"); hit {
		t.Error("OnTombstone should invalidate dedupe for (1.2.3.4, waf-sqli)")
	}
	if _, hit := e.dedupe.Lookup("Ip", "1.2.3.4", "arenet/auth-burst"); hit {
		t.Error("OnTombstone should invalidate dedupe for (1.2.3.4, auth-burst) too (same IP)")
	}
}

// TestTriggerEngine_OnTombstone_OrphanScenario_InvalidatesDedupeOnly
// pins the orphan-tombstone path: a tombstone for a scenario
// arenet never auto-classified (e.g. operator pushed via
// cscli with the "arenet/" prefix manually) invalidates the
// dedupe but does NOT record a cooldown (no rule duration to
// read from).
func TestTriggerEngine_OnTombstone_OrphanScenario_InvalidatesDedupeOnly(t *testing.T) {
	rs := DefaultRuleSet() // all disabled
	holder := NewRuleSetHolder(rs)
	e, _ := NewEngine(EngineConfig{
		Waf: &fakeWafReader{}, Throttle: &fakeThrottleReader{}, Audit: &fakeAuditReader{},
		Rules: holder, Logger: silentLogger(),
	})

	e.dedupe.Record("Ip", "1.2.3.4", "arenet/waf-sqli", true)
	// A non-matching scenario (e.g. crowdsecurity/http-probing)
	// should still invalidate the dedupe for the same IP
	// because the dedupe key includes the scenario but the
	// tombstone semantic is "this IP is now unbanned in LAPI"
	// — affects every scenario for that IP.
	e.OnTombstone("1.2.3.4", "crowdsecurity/http-probing")

	if _, hit := e.dedupe.Lookup("Ip", "1.2.3.4", "arenet/waf-sqli"); hit {
		t.Error("orphan tombstone should still invalidate dedupe for the IP")
	}
	if e.cooldown.HasCooldown("1.2.3.4", "crowdsecurity/http-probing") {
		t.Error("orphan tombstone (non-arenet scenario) should NOT record cooldown")
	}
}

// TestRuleSetHolder_Set_AtomicSwap pins thread-safety of the
// RuleSet swap: concurrent Get calls during a Set must see
// either the old or the new snapshot, never a torn read.
func TestRuleSetHolder_Set_AtomicSwap(t *testing.T) {
	h := NewRuleSetHolder(DefaultRuleSet())

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Reader goroutines.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				rs := h.Get()
				// Sanity: the map must have a known count
				// of sources at every read.
				if len(rs.Rules) != len(AllSources()) {
					t.Errorf("torn read: rule count = %d, want %d",
						len(rs.Rules), len(AllSources()))
				}
			}
		}()
	}

	// Swap repeatedly.
	for i := 0; i < 100; i++ {
		next := DefaultRuleSet()
		r := next.Rules[SourceWafSQLi]
		r.Enabled = i%2 == 0
		next.Rules[SourceWafSQLi] = r
		h.Set(next)
	}
	close(stop)
	wg.Wait()
}
