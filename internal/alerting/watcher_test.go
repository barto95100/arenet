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

package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

// AL.2.b — Watcher pinning tests. Coverage per the
// operator's brief.

// --- test fakes ------------------------------------------

type fakeRuleStore struct {
	mu              sync.Mutex
	rules           []storage.AlertRule
	evalUpdates     []evalCall
	firedUpdates    []firedCall
	listErr         error
}

type evalCall struct {
	id     string
	at     time.Time
	hasErr bool
	errMsg string
}
type firedCall struct {
	id string
	at time.Time
}

func (f *fakeRuleStore) ListAlertRules(_ context.Context) ([]storage.AlertRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]storage.AlertRule, len(f.rules))
	copy(out, f.rules)
	return out, nil
}
func (f *fakeRuleStore) UpdateAlertRuleEvalState(_ context.Context, id string, at time.Time, evalErr error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := evalCall{id: id, at: at, hasErr: evalErr != nil}
	if evalErr != nil {
		c.errMsg = evalErr.Error()
	}
	f.evalUpdates = append(f.evalUpdates, c)
	return nil
}
func (f *fakeRuleStore) UpdateAlertRuleFiredState(_ context.Context, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.firedUpdates = append(f.firedUpdates, firedCall{id: id, at: at})
	return nil
}

type fakeDispatcher struct {
	mu    sync.Mutex
	calls []dispatchCall
	// failFor causes Dispatch to return Failed for the
	// listed channelIDs.
	failFor map[string]string
}
type dispatchCall struct {
	evt        AlertEvent
	channelIDs []string
}

func (f *fakeDispatcher) Dispatch(_ context.Context, evt AlertEvent, ids []string) DispatchResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, dispatchCall{evt: evt, channelIDs: append([]string{}, ids...)})
	result := DispatchResult{
		Fired:   []string{},
		Failed:  map[string]string{},
		Skipped: map[string]string{},
	}
	for _, id := range ids {
		if reason, fail := f.failFor[id]; fail {
			result.Failed[id] = reason
			continue
		}
		result.Fired = append(result.Fired, id)
	}
	return result
}

type fakeSource struct {
	name      string
	readErr   error
	readValue SourceValue
	calls     int32
	mu        sync.Mutex
}

func (f *fakeSource) Name() string                              { return f.name }
func (f *fakeSource) ValidateParams(_ json.RawMessage) error    { return nil }
func (f *fakeSource) Read(_ context.Context, _ json.RawMessage) (SourceValue, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.readErr != nil {
		return SourceValue{}, f.readErr
	}
	return f.readValue, nil
}

type fakeLookup struct {
	known map[string]Source
}

func (f *fakeLookup) Get(name string) (Source, bool) {
	s, ok := f.known[name]
	return s, ok
}

func mustRule(t *testing.T, r storage.AlertRule) storage.AlertRule {
	t.Helper()
	if r.SourceParams == nil {
		r.SourceParams = json.RawMessage(`{}`)
	}
	if r.EvalParams == nil {
		r.EvalParams = json.RawMessage(`{"operator":">","value":0}`)
	}
	return r
}

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- helpers ---------------------------------------------

func runOneTick(t *testing.T, cfg WatcherConfig) {
	t.Helper()
	w, err := NewWatcher(cfg)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	// Drive a single tick synchronously via the package-
	// internal tick method. Avoids the ticker goroutine
	// + the close(w.started) race in the per-tick
	// assertions.
	w.tick(context.Background())
}

func baseRule(id, name string, channels []string) storage.AlertRule {
	return storage.AlertRule{
		ID:           id,
		Name:         name,
		Enabled:      true,
		Kind:         RuleKindThreshold,
		Severity:     int(SeverityWarning),
		Category:     "waf",
		Source:       "stub",
		SourceParams: json.RawMessage(`{}`),
		EvalParams:   json.RawMessage(`{"operator":">","value":0}`),
		Channels:     channels,
		CooldownSecs: 300,
	}
}

// --- tests -----------------------------------------------

func TestWatcher_NewWatcher_MissingDeps(t *testing.T) {
	if _, err := NewWatcher(WatcherConfig{}); err == nil {
		t.Errorf("nil err with empty config; want error")
	}
}

func TestWatcher_DisabledRuleSkipped(t *testing.T) {
	r := mustRule(t, baseRule("r-1", "disabled", []string{"ch-1"}))
	r.Enabled = false

	store := &fakeRuleStore{rules: []storage.AlertRule{r}}
	src := &fakeSource{name: "stub", readValue: FloatValue(100)}
	disp := &fakeDispatcher{}
	runOneTick(t, WatcherConfig{
		Store:      store,
		Sources:    &fakeLookup{known: map[string]Source{"stub": src}},
		Dispatcher: disp,
		Cooldown:   NewCooldownLRU(nil),
		Logger:     silentLogger(),
	})
	if len(disp.calls) != 0 {
		t.Errorf("dispatch calls = %d; want 0 on disabled rule", len(disp.calls))
	}
	if src.calls != 0 {
		t.Errorf("source reads = %d; want 0 on disabled rule", src.calls)
	}
}

func TestWatcher_SourceNotFound_PersistsError(t *testing.T) {
	r := mustRule(t, baseRule("r-1", "ghost-src", []string{"ch-1"}))
	r.Source = "ghost"

	store := &fakeRuleStore{rules: []storage.AlertRule{r}}
	disp := &fakeDispatcher{}
	runOneTick(t, WatcherConfig{
		Store:      store,
		Sources:    &fakeLookup{known: map[string]Source{}},
		Dispatcher: disp,
		Cooldown:   NewCooldownLRU(nil),
		Logger:     silentLogger(),
	})
	if len(disp.calls) != 0 {
		t.Errorf("dispatch calls = %d; want 0 on missing source", len(disp.calls))
	}
	if len(store.evalUpdates) != 1 {
		t.Fatalf("eval updates = %d; want 1", len(store.evalUpdates))
	}
	if !store.evalUpdates[0].hasErr {
		t.Errorf("eval update missing error; want 'source not registered'")
	}
}

func TestWatcher_SourceReadError_PersistsErrorNoFire(t *testing.T) {
	r := mustRule(t, baseRule("r-1", "src-err", []string{"ch-1"}))
	store := &fakeRuleStore{rules: []storage.AlertRule{r}}
	src := &fakeSource{name: "stub", readErr: errors.New("timeout")}
	disp := &fakeDispatcher{}
	runOneTick(t, WatcherConfig{
		Store:      store,
		Sources:    &fakeLookup{known: map[string]Source{"stub": src}},
		Dispatcher: disp,
		Cooldown:   NewCooldownLRU(nil),
		Logger:     silentLogger(),
	})
	if len(disp.calls) != 0 {
		t.Errorf("dispatch calls = %d; want 0", len(disp.calls))
	}
	if len(store.evalUpdates) != 1 || !store.evalUpdates[0].hasErr {
		t.Errorf("expected one eval update with err; got %+v", store.evalUpdates)
	}
	if !strings.Contains(store.evalUpdates[0].errMsg, "timeout") {
		t.Errorf("err msg = %q; want timeout substring", store.evalUpdates[0].errMsg)
	}
}

func TestWatcher_EvalError_PersistsErrorNoFire(t *testing.T) {
	r := mustRule(t, baseRule("r-1", "eval-err", []string{"ch-1"}))
	// Source returns a non-numeric value; threshold
	// evaluator fails because Float is nil.
	store := &fakeRuleStore{rules: []storage.AlertRule{r}}
	src := &fakeSource{name: "stub", readValue: StringValue("foo")}
	disp := &fakeDispatcher{}
	runOneTick(t, WatcherConfig{
		Store:      store,
		Sources:    &fakeLookup{known: map[string]Source{"stub": src}},
		Dispatcher: disp,
		Cooldown:   NewCooldownLRU(nil),
		Logger:     silentLogger(),
	})
	if len(disp.calls) != 0 {
		t.Errorf("dispatch calls = %d; want 0", len(disp.calls))
	}
	if len(store.evalUpdates) != 1 || !store.evalUpdates[0].hasErr {
		t.Errorf("expected eval update with err; got %+v", store.evalUpdates)
	}
}

func TestWatcher_HappyPath_DispatchesAlertEvent(t *testing.T) {
	r := mustRule(t, baseRule("r-1", "happy", []string{"ch-1"}))
	store := &fakeRuleStore{rules: []storage.AlertRule{r}}
	src := &fakeSource{name: "stub", readValue: FloatValue(50)}
	disp := &fakeDispatcher{}
	runOneTick(t, WatcherConfig{
		Store:      store,
		Sources:    &fakeLookup{known: map[string]Source{"stub": src}},
		Dispatcher: disp,
		Cooldown:   NewCooldownLRU(nil),
		Logger:     silentLogger(),
	})
	if len(disp.calls) != 1 {
		t.Fatalf("dispatch calls = %d; want 1", len(disp.calls))
	}
	got := disp.calls[0]
	if got.evt.RuleID != "r-1" {
		t.Errorf("evt.RuleID = %q; want r-1", got.evt.RuleID)
	}
	if got.evt.RuleName != "happy" {
		t.Errorf("evt.RuleName = %q; want happy", got.evt.RuleName)
	}
	if !strings.Contains(got.evt.Subject, "happy") {
		t.Errorf("default subject missing rule name; got %q", got.evt.Subject)
	}
	// Eval state heartbeat must be written even when the
	// rule fires.
	if len(store.evalUpdates) != 1 || store.evalUpdates[0].hasErr {
		t.Errorf("eval update missing or has unexpected err: %+v", store.evalUpdates)
	}
	if len(store.firedUpdates) != 1 {
		t.Errorf("fired update count = %d; want 1", len(store.firedUpdates))
	}
}

func TestWatcher_MultiChannel_DispatchesToEachSeparately(t *testing.T) {
	r := mustRule(t, baseRule("r-1", "multi", []string{"ch-a", "ch-b", "ch-c"}))
	store := &fakeRuleStore{rules: []storage.AlertRule{r}}
	src := &fakeSource{name: "stub", readValue: FloatValue(50)}
	disp := &fakeDispatcher{}
	runOneTick(t, WatcherConfig{
		Store:      store,
		Sources:    &fakeLookup{known: map[string]Source{"stub": src}},
		Dispatcher: disp,
		Cooldown:   NewCooldownLRU(nil),
		Logger:     silentLogger(),
	})
	if len(disp.calls) != 3 {
		t.Fatalf("dispatch calls = %d; want 3 (one per channel)", len(disp.calls))
	}
	gotChannels := map[string]bool{}
	for _, c := range disp.calls {
		if len(c.channelIDs) != 1 {
			t.Errorf("channelIDs len = %d; want 1 (each Dispatch carries one ID)", len(c.channelIDs))
		}
		gotChannels[c.channelIDs[0]] = true
	}
	for _, want := range []string{"ch-a", "ch-b", "ch-c"} {
		if !gotChannels[want] {
			t.Errorf("channel %q not dispatched; got %v", want, gotChannels)
		}
	}
}

func TestWatcher_CooldownRespectedWithinWindow(t *testing.T) {
	r := mustRule(t, baseRule("r-1", "cd", []string{"ch-1"}))
	r.CooldownSecs = 600 // 10 min

	store := &fakeRuleStore{rules: []storage.AlertRule{r}}
	src := &fakeSource{name: "stub", readValue: FloatValue(50)}
	disp := &fakeDispatcher{}
	clk := newClockMock(time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC))
	cooldown := NewCooldownLRU(clk.Now)
	cfg := WatcherConfig{
		Store:      store,
		Sources:    &fakeLookup{known: map[string]Source{"stub": src}},
		Dispatcher: disp,
		Cooldown:   cooldown,
		Now:        clk.Now,
		Logger:     silentLogger(),
	}
	runOneTick(t, cfg)
	clk.Advance(2 * time.Minute) // still well inside the 10-min cooldown
	runOneTick(t, cfg)

	if len(disp.calls) != 1 {
		t.Errorf("dispatch calls = %d; want 1 (second tick suppressed by cooldown)", len(disp.calls))
	}
}

func TestWatcher_CooldownExpiresAfterWindow(t *testing.T) {
	r := mustRule(t, baseRule("r-1", "cd-expire", []string{"ch-1"}))
	r.CooldownSecs = 60

	store := &fakeRuleStore{rules: []storage.AlertRule{r}}
	src := &fakeSource{name: "stub", readValue: FloatValue(50)}
	disp := &fakeDispatcher{}
	clk := newClockMock(time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC))
	cooldown := NewCooldownLRU(clk.Now)
	cfg := WatcherConfig{
		Store:      store,
		Sources:    &fakeLookup{known: map[string]Source{"stub": src}},
		Dispatcher: disp,
		Cooldown:   cooldown,
		Now:        clk.Now,
		Logger:     silentLogger(),
	}
	runOneTick(t, cfg)    // tick 1 → dispatch
	clk.Advance(30 * time.Second)
	runOneTick(t, cfg)    // tick 2 → suppressed
	clk.Advance(40 * time.Second) // total 70s > 60s window
	runOneTick(t, cfg)    // tick 3 → re-dispatch

	if len(disp.calls) != 2 {
		t.Errorf("dispatch calls = %d; want 2 (1 + 0 + 1)", len(disp.calls))
	}
}

func TestWatcher_HeartbeatHonouredWhenNotFired(t *testing.T) {
	// Source returns 0, evaluator > 50 ⇒ no fire. The
	// heartbeat (UpdateAlertRuleEvalState with nil err)
	// MUST still be written.
	r := mustRule(t, baseRule("r-1", "no-fire", []string{"ch-1"}))
	r.EvalParams = json.RawMessage(`{"operator":">","value":50}`)
	store := &fakeRuleStore{rules: []storage.AlertRule{r}}
	src := &fakeSource{name: "stub", readValue: FloatValue(10)}
	disp := &fakeDispatcher{}
	runOneTick(t, WatcherConfig{
		Store:      store,
		Sources:    &fakeLookup{known: map[string]Source{"stub": src}},
		Dispatcher: disp,
		Cooldown:   NewCooldownLRU(nil),
		Logger:     silentLogger(),
	})
	if len(disp.calls) != 0 {
		t.Errorf("dispatch calls = %d; want 0 (condition not met)", len(disp.calls))
	}
	if len(store.evalUpdates) != 1 || store.evalUpdates[0].hasErr {
		t.Errorf("eval heartbeat not written cleanly; got %+v", store.evalUpdates)
	}
	if len(store.firedUpdates) != 0 {
		t.Errorf("fired update written without fire; got %+v", store.firedUpdates)
	}
}

func TestWatcher_DispatcherFailure_NoFiredStateWrite(t *testing.T) {
	r := mustRule(t, baseRule("r-1", "fail-disp", []string{"ch-1"}))
	store := &fakeRuleStore{rules: []storage.AlertRule{r}}
	src := &fakeSource{name: "stub", readValue: FloatValue(50)}
	disp := &fakeDispatcher{failFor: map[string]string{"ch-1": "boom"}}
	runOneTick(t, WatcherConfig{
		Store:      store,
		Sources:    &fakeLookup{known: map[string]Source{"stub": src}},
		Dispatcher: disp,
		Cooldown:   NewCooldownLRU(nil),
		Logger:     silentLogger(),
	})
	if len(disp.calls) != 1 {
		t.Fatalf("dispatch calls = %d; want 1", len(disp.calls))
	}
	if len(store.firedUpdates) != 0 {
		t.Errorf("fired update written despite dispatch failure; got %+v", store.firedUpdates)
	}
}

func TestWatcher_RunStartStopNoLeak(t *testing.T) {
	// End-to-end lifecycle smoke. Drive Start in a
	// goroutine, wait for the Started signal, cancel
	// the ctx, await Done within 2s.
	r := mustRule(t, baseRule("r-1", "lifecycle", []string{"ch-1"}))
	store := &fakeRuleStore{rules: []storage.AlertRule{r}}
	src := &fakeSource{name: "stub", readValue: FloatValue(0)}
	disp := &fakeDispatcher{}
	w, err := NewWatcher(WatcherConfig{
		Store:           store,
		Sources:         &fakeLookup{known: map[string]Source{"stub": src}},
		Dispatcher:      disp,
		Cooldown:        NewCooldownLRU(nil),
		PollingInterval: 50 * time.Millisecond,
		Logger:          silentLogger(),
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()
	select {
	case <-w.Started():
	case <-time.After(2 * time.Second):
		t.Fatalf("Started() not signalled within 2s — first tick stuck")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Run() did not return within 2s after cancel — goroutine leak")
	}
}

func TestWatcher_TickImmediateAtStart(t *testing.T) {
	// PollingInterval = 1h; if we observe a dispatch
	// within 100ms of Start, the immediate first tick
	// (D3) fired.
	r := mustRule(t, baseRule("r-1", "imm", []string{"ch-1"}))
	store := &fakeRuleStore{rules: []storage.AlertRule{r}}
	src := &fakeSource{name: "stub", readValue: FloatValue(50)}
	disp := &fakeDispatcher{}
	w, _ := NewWatcher(WatcherConfig{
		Store:           store,
		Sources:         &fakeLookup{known: map[string]Source{"stub": src}},
		Dispatcher:      disp,
		Cooldown:        NewCooldownLRU(nil),
		PollingInterval: time.Hour,
		Logger:          silentLogger(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	select {
	case <-w.Started():
	case <-time.After(2 * time.Second):
		t.Fatalf("Started() never fired — first tick didn't run synchronously at Run entry")
	}
	disp.mu.Lock()
	got := len(disp.calls)
	disp.mu.Unlock()
	if got != 1 {
		t.Errorf("dispatch calls at Started = %d; want 1 (immediate first tick)", got)
	}
}
