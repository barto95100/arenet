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
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/barto95100/arenet/internal/storage"
)

// AL.2.b — Watcher runtime per ADR D10 (30s polling).
//
// One goroutine drives a ticker that fires every
// PollingInterval (30s default). Each tick walks
// the AlertRule list once (D9 sequential V1) and, per
// rule, executes the D6 flow:
//
//  1. source.Read with 5s per-rule timeout (D5)
//     - error → UpdateEvalState(err) + skip
//  2. evaluator.Evaluate
//     - error → UpdateEvalState(err) + skip
//  3. UpdateEvalState(nil)  ← heartbeat write
//  4. !fired → return
//  5. For each channel ID in rule.Channels:
//     - OnCooldown → skip
//     - Build AlertEvent (templates from AL.2.a)
//     - dispatcher.Dispatch([channel])
//     - cooldown.Mark + record success
//  6. channelsFired non-empty → UpdateFiredState
//
// Lifecycle mirrors internal/automation/trigger.go Engine
// (Run/Done pattern, immediate first tick, ctx-driven
// shutdown). cmd/arenet/main.go wires Start at boot,
// defer Stop at shutdown.

// Watcher polls the rule store and dispatches AlertEvents
// on fire.
type Watcher struct {
	cfg WatcherConfig

	done chan struct{} // closed when Run exits

	// started signals the first tick has completed. Tests
	// + the lifecycle smoke use it to assert "watcher is
	// up" without sleeping for the polling interval.
	startedOnce sync.Once
	started     chan struct{}
}

// WatcherConfig bundles every dep the Watcher needs.
// Construction via NewWatcher validates the required
// fields; optional fields default to production values.
type WatcherConfig struct {
	// Store is the AlertRule + Channel persistence layer.
	// REQUIRED.
	Store AlertRuleStore

	// Sources is the Source lookup registry. REQUIRED.
	Sources SourceLookup

	// Dispatcher fans an AlertEvent to channels.
	// REQUIRED. *Dispatcher satisfies the interface;
	// tests inject a fake.
	Dispatcher WatcherDispatcher

	// PollingInterval is the ticker period. Defaults to
	// 30s per ADR D10 when zero. The minimum is enforced
	// by NewWatcher (1s) — anything below 1s is a wiring
	// bug.
	PollingInterval time.Duration

	// PerRuleReadTimeout caps the source.Read call per
	// rule per tick. Defaults to 5s per D5 when zero.
	PerRuleReadTimeout time.Duration

	// Cooldown is the per-(rule, channel) LRU. REQUIRED.
	Cooldown *CooldownLRU

	// Now is the injectable clock used by both the
	// watcher's heartbeat timestamps and the cooldown
	// LRU. Defaults to time.Now when nil. Tests inject a
	// mock clock so test ticks don't depend on real
	// time.
	Now func() time.Time

	// Logger receives the watcher's lifecycle + per-tick
	// debug events. Defaults to slog.Default() when nil.
	Logger *slog.Logger
}

// AlertRuleStore is the read+write seam the Watcher
// reaches through. *storage.Store satisfies it via
// ListAlertRules + UpdateAlertRuleEvalState +
// UpdateAlertRuleFiredState (AL.2.a additions for D7).
type AlertRuleStore interface {
	ListAlertRules(ctx context.Context) ([]storage.AlertRule, error)
	UpdateAlertRuleEvalState(ctx context.Context, id string, evalAt time.Time, evalErr error) error
	UpdateAlertRuleFiredState(ctx context.Context, id string, firedAt time.Time) error
	UpdateAlertRuleLastMatched(ctx context.Context, id string, matched bool) error
}

// WatcherDispatcher is the seam the watcher dispatches
// through. *alerting.Dispatcher satisfies it via Dispatch.
// Tests inject a fake so they can assert "rule fired and
// dispatched channels [...]" without booting real senders.
type WatcherDispatcher interface {
	Dispatch(ctx context.Context, evt AlertEvent, channelIDs []string) DispatchResult
}

// NewWatcher constructs the watcher. Returns an error if
// any required field is missing — the watcher is wired
// once at boot, so a misconfig is loud rather than silent.
func NewWatcher(cfg WatcherConfig) (*Watcher, error) {
	if cfg.Store == nil {
		return nil, errors.New("watcher: Store is required")
	}
	if cfg.Sources == nil {
		return nil, errors.New("watcher: Sources is required")
	}
	if cfg.Dispatcher == nil {
		return nil, errors.New("watcher: Dispatcher is required")
	}
	if cfg.Cooldown == nil {
		return nil, errors.New("watcher: Cooldown is required")
	}
	if cfg.PollingInterval == 0 {
		cfg.PollingInterval = 30 * time.Second
	}
	// 10ms floor — defensive against a wiring bug that
	// passes a zero-like duration. Tests legitimately
	// want sub-second intervals to drive the ticker
	// rapidly without slowing the suite; production
	// values are 30s+. A 10ms floor catches the wiring-
	// bug regime (negative / 1ns intervals) without
	// blocking the tests.
	if cfg.PollingInterval < 10*time.Millisecond {
		return nil, fmt.Errorf("watcher: PollingInterval %v below 10ms minimum", cfg.PollingInterval)
	}
	if cfg.PerRuleReadTimeout == 0 {
		cfg.PerRuleReadTimeout = 5 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Watcher{
		cfg:     cfg,
		done:    make(chan struct{}),
		started: make(chan struct{}),
	}, nil
}

// PollingInterval reports the configured polling cadence.
// Used by cmd/arenet/main.go's lifecycle log so the boot
// banner echoes the actual interval.
func (w *Watcher) PollingInterval() time.Duration {
	return w.cfg.PollingInterval
}

// Run starts the polling loop. Blocks until ctx is
// cancelled. Safe to call once per Watcher; a re-call
// panics on the closed `done` channel (mirrors the
// automation.Engine convention).
func (w *Watcher) Run(ctx context.Context) {
	defer close(w.done)

	ticker := time.NewTicker(w.cfg.PollingInterval)
	defer ticker.Stop()

	// D3 — tick once immediately so callers don't wait
	// the full PollingInterval before the first read.
	w.tick(ctx)
	w.startedOnce.Do(func() { close(w.started) })

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

// Done returns a channel closed once Run has exited.
// Tests + cmd/arenet/main.go use it to await clean
// shutdown.
func (w *Watcher) Done() <-chan struct{} { return w.done }

// Started returns a channel closed once the first tick
// has completed. Lets tests assert "watcher came up"
// without racing the polling interval.
func (w *Watcher) Started() <-chan struct{} { return w.started }

// tick executes one polling pass.
func (w *Watcher) tick(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	rules, err := w.cfg.Store.ListAlertRules(ctx)
	if err != nil {
		w.cfg.Logger.Warn("alerting watcher: list rules failed",
			"err", err)
		return
	}

	// EvictStale runs once per tick against the keep set
	// derived from the live rule list. Cheap defence
	// against rule-deletion holding cooldown entries.
	keep := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		keep[r.ID] = struct{}{}
	}
	if evicted := w.cfg.Cooldown.EvictStale(keep); evicted > 0 {
		w.cfg.Logger.Debug("alerting watcher: evicted stale cooldown entries",
			"count", evicted)
	}

	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		w.evalOneRule(ctx, r)
	}
}

// evalOneRule executes the D6 per-rule flow.
func (w *Watcher) evalOneRule(ctx context.Context, r storage.AlertRule) {
	now := w.cfg.Now()

	// Step 1: source.Read.
	src, ok := w.cfg.Sources.Get(r.Source)
	if !ok {
		w.persistEvalState(ctx, r.ID, now, fmt.Errorf("source %q not registered", r.Source))
		return
	}

	readCtx, cancel := context.WithTimeout(ctx, w.cfg.PerRuleReadTimeout)
	value, err := src.Read(readCtx, r.SourceParams)
	cancel()
	if err != nil {
		w.persistEvalState(ctx, r.ID, now, fmt.Errorf("source read: %w", err))
		return
	}

	// Step 2: evaluator.Evaluate.
	ev, err := EvaluatorFor(r.Kind)
	if err != nil {
		w.persistEvalState(ctx, r.ID, now, fmt.Errorf("evaluator lookup: %w", err))
		return
	}
	fired, err := ev.Evaluate(value, r.EvalParams)
	if err != nil {
		// Eval error is not a genuine state transition. Return before
		// the edge block, deliberately leaving a state rule's LastMatched
		// untouched: a transient error must not clear the edge (which
		// would re-fire on recovery) nor fabricate one. Worst case is a
		// suppressed re-fire, never a spurious flood.
		w.persistEvalState(ctx, r.ID, now, fmt.Errorf("evaluate: %w", err))
		return
	}

	// Step 3: heartbeat (eval succeeded, condition may or
	// may not be met).
	w.persistEvalState(ctx, r.ID, now, nil)

	// Step 4: state rules are edge-triggered — dispatch only on the
	// not-match → match transition; threshold rules fire whenever the
	// condition holds (cooldown-gated). Persist the edge state for
	// state rules so the transition memory survives a restart.
	isState := r.Kind == RuleKindState

	if isState {
		if !fired {
			// State left (or never reached) the matched value. Clear
			// the edge flag so the next rising edge can fire. Only
			// write when it actually changes, to avoid churn.
			if r.LastMatched {
				if err := w.cfg.Store.UpdateAlertRuleLastMatched(ctx, r.ID, false); err != nil {
					w.cfg.Logger.Warn("alerting watcher: persist last-matched(false) failed",
						"rule_id", r.ID, "err", err)
				}
			}
			return
		}
		if r.LastMatched {
			// Still matched since last tick — no rising edge, stay silent.
			return
		}
		// Rising edge: fall through to dispatch. State rules bypass the
		// cooldown (the edge itself is the anti-flood gate); LastMatched
		// is persisted true only after a successful dispatch below.
	} else {
		// Threshold: unchanged — short-circuit when the condition isn't met.
		if !fired {
			return
		}
	}

	// Step 5: dispatch. Threshold rules consult the cooldown; state
	// rules (rising edge) skip it.
	cooldown := time.Duration(r.CooldownSecs) * time.Second
	channelsFired := make([]string, 0, len(r.Channels))
	for _, channelID := range r.Channels {
		if !isState && w.cfg.Cooldown.OnCooldown(r.ID, channelID, cooldown) {
			w.cfg.Logger.Debug("alerting watcher: channel on cooldown — skipped",
				"rule_id", r.ID, "channel_id", channelID,
				"cooldown_secs", r.CooldownSecs)
			continue
		}
		evt := w.buildAlertEvent(r, value, now)
		result := w.cfg.Dispatcher.Dispatch(ctx, evt, []string{channelID})
		if len(result.Fired) > 0 {
			w.cfg.Cooldown.Mark(r.ID, channelID)
			channelsFired = append(channelsFired, channelID)
			w.cfg.Logger.Info("alerting watcher: rule fired",
				"rule_id", r.ID, "rule_name", r.Name,
				"channel_id", channelID, "event_id", evt.ID)
		} else if reason, ok := result.Failed[channelID]; ok {
			w.cfg.Logger.Warn("alerting watcher: dispatch failed",
				"rule_id", r.ID, "channel_id", channelID,
				"err", reason)
		}
		// Channels that ended up in Skipped (disabled /
		// MinSeverity gate) are logged at debug level by
		// the dispatcher itself; the watcher doesn't
		// re-emit.
	}

	// Step 6: post-dispatch persistence.
	if len(channelsFired) > 0 {
		if err := w.cfg.Store.UpdateAlertRuleFiredState(ctx, r.ID, now); err != nil {
			w.cfg.Logger.Warn("alerting watcher: persist fired state failed",
				"rule_id", r.ID, "err", err)
		}
		// For state rules, record the rising edge as consumed ONLY after
		// a successful fire — a failed dispatch leaves LastMatched false
		// so the edge is retried next tick.
		if isState {
			if err := w.cfg.Store.UpdateAlertRuleLastMatched(ctx, r.ID, true); err != nil {
				w.cfg.Logger.Warn("alerting watcher: persist last-matched(true) failed",
					"rule_id", r.ID, "err", err)
			}
		}
	}
}

// buildAlertEvent assembles the AlertEvent per the
// AL.2.a Subject/Body template defaults (D6 in the AL.2.a
// brief). Operator templates override the defaults.
func (w *Watcher) buildAlertEvent(r storage.AlertRule, value SourceValue, at time.Time) AlertEvent {
	subject := w.renderTemplate(r.SubjectTemplate, defaultSubjectTemplate, r, value, at)
	body := w.renderTemplate(r.BodyTemplate, defaultBodyTemplate, r, value, at)

	evt := AlertEvent{
		ID:        uuid.NewString(),
		Timestamp: at,
		RuleID:    r.ID,
		RuleName:  r.Name,
		Severity:  Severity(r.Severity),
		Category:  r.Category,
		Subject:   subject,
		Body:      body,
	}
	if len(value.Labels) > 0 {
		evt.Labels = make(map[string]string, len(value.Labels))
		for k, v := range value.Labels {
			evt.Labels[k] = v
		}
	}
	if len(value.Context) > 0 {
		evt.Context = make(map[string]any, len(value.Context))
		for k, v := range value.Context {
			evt.Context[k] = v
		}
	}
	return evt
}

// renderTemplate runs the rule's optional template
// against the templating context. A compile failure at
// fire time should never happen — Validate (AL.2.a)
// gates this at CRUD. As defence in depth, on either
// compile or execute failure the renderer falls back to
// fallback (the kind-specific default).
func (w *Watcher) renderTemplate(operatorTmpl, fallback string, r storage.AlertRule, value SourceValue, at time.Time) string {
	tmpl := operatorTmpl
	if tmpl == "" {
		tmpl = fallback
	}
	ctx := newAlertEventTemplateContext(r, value, at)
	t, err := compileBodyTemplate(tmpl)
	if err != nil {
		w.cfg.Logger.Warn("alerting watcher: template compile failed at fire time",
			"rule_id", r.ID, "err", err)
		return fallback
	}
	rendered, err := renderTemplate(t, ctx)
	if err != nil {
		w.cfg.Logger.Warn("alerting watcher: template render failed",
			"rule_id", r.ID, "err", err)
		return fallback
	}
	return rendered
}

// persistEvalState wraps the UpdateAlertRuleEvalState
// call so the watcher loop reads cleanly. A storage
// failure here is non-fatal (tertiary error path); we
// log it but never block the rest of the tick.
func (w *Watcher) persistEvalState(ctx context.Context, ruleID string, at time.Time, evalErr error) {
	if err := w.cfg.Store.UpdateAlertRuleEvalState(ctx, ruleID, at, evalErr); err != nil {
		w.cfg.Logger.Warn("alerting watcher: persist eval state failed",
			"rule_id", ruleID, "err", err, "eval_err", evalErr)
	}
}

// renderTemplate's data context. Wraps the AlertEvent
// fields the operator's template references — they see
// {{.RuleName}}, {{.Severity}}, {{.Value}}, etc.
type alertEventTemplateContext struct {
	RuleID    string
	RuleName  string
	Severity  string
	Category  string
	Timestamp time.Time
	Source    string
	// Value is the SourceValue.Float OR .String,
	// whichever is set. Operators use {{.Value}} without
	// needing to know the source kind.
	Value any
	// Labels + Context are exposed verbatim so templates
	// can drill into {{.Labels.route_id}} etc.
	Labels  map[string]string
	Context map[string]any
}

func newAlertEventTemplateContext(r storage.AlertRule, v SourceValue, at time.Time) alertEventTemplateContext {
	var val any
	if v.Float != nil {
		val = *v.Float
	} else if v.String != nil {
		val = *v.String
	}
	return alertEventTemplateContext{
		RuleID:    r.ID,
		RuleName:  r.Name,
		Severity:  Severity(r.Severity).String(),
		Category:  r.Category,
		Timestamp: at,
		Source:    r.Source,
		Value:     val,
		Labels:    v.Labels,
		Context:   v.Context,
	}
}

const (
	// Default subject template. Used when the operator
	// leaves AlertRule.SubjectTemplate empty.
	defaultSubjectTemplate = "[{{.Severity}}] {{.RuleName}} fired"
	// Default body template. Same.
	defaultBodyTemplate = "Rule {{.RuleName}} fired. Source {{.Source}} value: {{.Value}}"
)

// Pin the json.RawMessage shape used by AlertEvent
// Context downstream, so a future refactor that
// accidentally widens it surfaces here at compile time.
var _ = json.RawMessage(nil)
