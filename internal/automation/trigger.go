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
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// tickInterval is the trigger engine's polling cadence per
// spec D2.1.A. 5s is well inside the 60s LAPI ticker ceiling
// so the auto-classify latency contribution is invisible
// end-to-end.
const tickInterval = 5 * time.Second

// writerChanBuffer is the buffered-channel cap for the
// trigger → writer pipeline per spec D7.A. Drop-on-full when
// the writer can't keep up (LAPI down + backlog accumulating);
// the source events remain in their durable tables for
// forensics.
const writerChanBuffer = 1024

// writerBackoffInitial / writerBackoffMax frame the writer's
// exponential retry on ErrLAPIUnavailable. Linear-ish growth
// (×2 each attempt) until a 30s ceiling; persistent failures
// just retry at 30s intervals.
const (
	writerBackoffInitial = 500 * time.Millisecond
	writerBackoffMax     = 30 * time.Second
	writerMaxRetries     = 5
)

// Intent is the trigger engine's emission shape — a request
// to push a LAPI decision. Materialised into an Alert by the
// writer goroutine just before the HTTP push.
type Intent struct {
	// SrcIP is the source IP for the auto-ban.
	SrcIP string

	// Source is the trigger-engine category. Used to look
	// up the rule's Duration + to compute the scenario via
	// Source.Scenario().
	Source Source

	// TriggeringEventID is the ID of one of the events that
	// crossed the threshold. Carried into the audit row so
	// the operator can drill from "auto-ban audit entry" to
	// "the WAF event row that triggered it".
	TriggeringEventID string

	// TriggeringEventCount is the number of events that
	// counted toward the threshold trip. Reported in the
	// audit message field for operator clarity.
	TriggeringEventCount int

	// DurationSeconds is the ban duration. Pulled from the
	// rule at trigger time so a mid-flight rule change can't
	// retroactively shorten / extend an already-emitted
	// intent.
	DurationSeconds int
}

// AuditEmitter is the callback the writer goroutine invokes
// after a successful PushAlert to record the auto-classify
// audit event (spec AC #10). Decoupled as an interface so
// the engine doesn't import audit (preserves the unidirectional
// dependency direction documented in §3.9).
type AuditEmitter interface {
	EmitDecisionPushed(srcIP, scenario string, triggeringEventID string, triggeringEventCount int, durationSeconds int)
}

// Writer is the abstract write surface — production wiring
// passes a *WatcherClient; tests pass a fake to assert the
// alert shape without spinning up an HTTP server. The two
// methods mirror the WatcherClient API exactly.
type Writer interface {
	EnsureJWT(ctx context.Context) (string, error)
	PushAlert(ctx context.Context, alert Alert) ([]string, error)
	LoginFailed() bool
}

// ActiveDecisionChecker is the surface the dedupe layer uses
// to ask "does LAPI already have an active decision for this
// (scope, value, scenario)?" per spec D4.B. In production
// this is satisfied by a thin Step N crowdsec.Sink wrapper
// that reads the local decision_event mirror table — the
// mirror is updated by the StreamBouncer within ~60s of LAPI
// state changes, so it's the right source-of-truth proxy
// without adding an extra LAPI GET round-trip.
//
// Returning (true, nil) tells the writer to skip the push.
// Returning (false, nil) means "go ahead". Returning an error
// is treated as "go ahead with the push" — defensive: a
// dedupe failure shouldn't BLOCK an auto-ban, only suppress
// duplicates.
//
// Note: the spec §1.3 D4 rationale named "pre-push GET" as
// the design; reading the local mirror is the implementation
// because the mirror IS the cached LAPI state (Step N's
// purpose). Same source-of-truth semantics, zero extra LAPI
// round-trips.
type ActiveDecisionChecker interface {
	HasActiveDecision(ctx context.Context, scope, value, scenario string) (bool, error)
}

// WriterProvider is the recreate-and-swap accessor for the
// engine's writer (P.3 wiring). At each intent the writer
// loop calls Writer() to fetch the CURRENT WatcherClient —
// nil disables the push (no-op drain). The production
// implementation (*DefaultManager) atomically swaps the
// underlying *WatcherClient when the operator updates
// credentials via PUT /settings/automation/credentials, so
// the next intent picks up the new client without restarting
// the writer goroutine. Sticky loginFailed flag on the old
// client is discarded with the old client (P.2 commit-body
// checklist item #3, recreate-and-swap arbitrated path).
//
// Tests + the boot path that doesn't yet need recreation can
// still pass a static Writer via EngineConfig.Writer; the
// engine prefers WriterProvider when both are set.
type WriterProvider interface {
	Writer() Writer
}

// EngineConfig holds the trigger engine's wiring. The three
// Reader interfaces are required (the engine can't tick
// without them); Writer + AuditEmitter + ActiveDecisionChecker
// may be nil for unit tests that don't exercise the push
// path. Logger is required (production passes slog.Default;
// tests pass a discarding logger).
type EngineConfig struct {
	Waf      WafEventReader
	Throttle ThrottleEventReader
	Audit    AuditEventReader

	// Writer is the static writer (test path + the
	// pre-P.3 wiring). When set, EngineConfig.Writer is
	// used for every intent.
	Writer Writer
	// WriterProvider (P.3) is the recreate-and-swap
	// accessor. When set, takes precedence over Writer.
	// Production wiring passes the DefaultManager here.
	WriterProvider WriterProvider

	AuditEmitter  AuditEmitter
	DedupeChecker ActiveDecisionChecker

	Rules  *RuleSetHolder
	Logger *slog.Logger

	// Now is the clock source for the engine (cursors +
	// LRU TTLs). Tests inject a controllable clock;
	// production wiring leaves it nil to default to
	// time.Now.
	Now func() time.Time

	// TickInterval overrides the default 5s for tests that
	// want to drive ticks faster. Production wiring leaves
	// it 0 → defaults to tickInterval.
	TickInterval time.Duration

	// InitialCursorOffset shifts the boot cursor backward
	// from Now() by this duration. Zero = the production
	// posture (cursor starts at now; only events from boot
	// forward are considered, so a restart doesn't re-emit
	// historical events). Tests pass a negative-Duration
	// equivalent (e.g. -1*time.Hour to read events from
	// the past hour). The value is added to Now() on
	// initialisation; negative values move the cursor back.
	InitialCursorOffset time.Duration
}

// RuleSetHolder wraps a RuleSet behind a thread-safe getter
// so the API layer's PUT /settings/automation can atomically
// swap the engine's active rule set without race. The engine
// reads the snapshot at each tick (spec §4 "rule change
// clobbers" mitigation: a tick under the OLD rules completes;
// the next tick uses the NEW rules).
type RuleSetHolder struct {
	mu sync.RWMutex
	rs RuleSet
}

// NewRuleSetHolder returns a holder seeded with the given
// RuleSet. Production wiring loads from BoltDB at boot; an
// empty / unconfigured store seeds DefaultRuleSet().
func NewRuleSetHolder(rs RuleSet) *RuleSetHolder {
	return &RuleSetHolder{rs: rs}
}

// Get returns the current snapshot. Cheap (RLock + map copy
// is unnecessary — callers read fields but don't mutate the
// returned value).
func (h *RuleSetHolder) Get() RuleSet {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.rs
}

// Set atomically replaces the active RuleSet. Caller (the
// API PUT handler) has already validated the new set.
func (h *RuleSetHolder) Set(rs RuleSet) {
	h.mu.Lock()
	h.rs = rs
	h.mu.Unlock()
}

// Engine is the trigger goroutine. Created via NewEngine,
// started via Run(ctx), stopped via context cancellation.
// Thread-safe metrics counters; the tick loop runs on one
// goroutine, the writer on another.
type Engine struct {
	cfg EngineConfig

	cursor   map[Source]time.Time // per-source last-seen ts; advances each tick
	cursorMu sync.Mutex           // protects cursor (engine tick + boot init both write it)

	cooldown *cooldownLRU
	dedupe   *dedupeLRU

	intents chan Intent
	done    chan struct{}

	// Counters (exposed via methods, atomic so the
	// metrics handler in P.3 can read concurrently).
	totalTicks         atomic.Uint64
	totalIntentsEmit   atomic.Uint64
	totalIntentsDrop   atomic.Uint64
	totalPushSuccess   atomic.Uint64
	totalPushPermanent atomic.Uint64
	totalPushDropped   atomic.Uint64
	loginFailures      atomic.Uint64
}

// NewEngine validates the config + returns an Engine. Does
// NOT start the goroutines (caller invokes Run).
func NewEngine(cfg EngineConfig) (*Engine, error) {
	if cfg.Waf == nil || cfg.Throttle == nil || cfg.Audit == nil {
		return nil, errors.New("automation.NewEngine: WAF / Throttle / Audit readers all required")
	}
	if cfg.Rules == nil {
		return nil, errors.New("automation.NewEngine: Rules holder required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.TickInterval <= 0 {
		cfg.TickInterval = tickInterval
	}
	return &Engine{
		cfg:      cfg,
		cursor:   make(map[Source]time.Time),
		cooldown: newCooldownLRUWithClock(cfg.Now),
		dedupe:   newDedupeLRUWithClock(cfg.Now),
		intents:  make(chan Intent, writerChanBuffer),
		done:     make(chan struct{}),
	}, nil
}

// Run starts the trigger tick + the writer goroutine. Blocks
// until ctx is cancelled. Safe to call once per Engine; a
// re-call panics on the closed `done` channel.
func (e *Engine) Run(ctx context.Context) {
	defer close(e.done)

	// Initialise cursors to "now" (+ optional offset for
	// tests) so the first tick reads events from this point
	// forward. A boot-time cursor at zero would re-emit the
	// full historical event set — exactly the operator-loop
	// footgun we don't want after a restart (the active
	// LAPI decisions are already in place; the StreamBouncer
	// keeps the bouncer cache warm).
	startTs := e.cfg.Now().Add(e.cfg.InitialCursorOffset)
	e.cursorMu.Lock()
	for _, s := range AllSources() {
		e.cursor[s] = startTs
	}
	e.cursorMu.Unlock()

	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		e.writerLoop(ctx)
	}()

	ticker := time.NewTicker(e.cfg.TickInterval)
	defer ticker.Stop()

	// Tick once immediately so callers don't wait the
	// full tickInterval before the first read.
	e.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			writerWG.Wait()
			return
		case <-ticker.C:
			e.tick(ctx)
		}
	}
}

// Done returns a channel closed once Run has exited. Tests
// + callers use it to await clean shutdown.
func (e *Engine) Done() <-chan struct{} { return e.done }

// SetWriterProvider injects the recreate-and-swap writer
// accessor at boot time. Used by cmd/arenet/main.go to wire
// the DefaultManager — the Engine reads currentWriter() per
// intent, so the swap takes effect without restarting the
// writer goroutine. nil clears the provider (engine falls
// back to the static cfg.Writer).
func (e *Engine) SetWriterProvider(p WriterProvider) {
	// Engine reads cfg.WriterProvider lock-free in
	// currentWriter() — concurrent reads happen on every
	// intent. A mutex would add overhead per-intent; instead
	// we rely on the boot-time-only semantics: this method
	// is called ONCE during wireAutomation, before Run()
	// starts. Setting after Run starts is a programmer
	// error.
	e.cfg.WriterProvider = p
}

// tick performs one polling pass: query each enabled source,
// group events by (src_ip, source), check thresholds, apply
// cooldown + dedupe, emit intents. Errors per source are
// logged + swallowed (AC #13 boot-degraded posture — one
// flaky source MUST NOT pause the others).
func (e *Engine) tick(ctx context.Context) {
	e.totalTicks.Add(1)
	rs := e.cfg.Rules.Get()
	if !rs.AnyEnabled() {
		// All rules disabled → zero queries. The cursor
		// stays put; if the operator enables a rule mid-
		// flight, the next tick after the enable reads
		// from the now-out-of-date cursor (events
		// accumulated since the last all-disabled tick).
		// That's fine — those events are old enough that
		// the threshold-in-window check naturally
		// suppresses them.
		return
	}

	now := e.cfg.Now()

	// One read pass per source-type (WAF, throttle, audit).
	// Each pass returns []SourceEvent already projected to
	// the engine's normalised shape.
	var events []SourceEvent
	events = append(events, e.readWaf(ctx, now)...)
	events = append(events, e.readThrottle(ctx, now)...)
	events = append(events, e.readAudit(ctx, now)...)

	if len(events) == 0 {
		return
	}

	// Group by (src_ip, source) for the threshold check.
	type groupKey struct {
		SrcIP  string
		Source Source
	}
	groups := make(map[groupKey][]SourceEvent)
	for _, ev := range events {
		k := groupKey{SrcIP: ev.SrcIP, Source: ev.Source}
		groups[k] = append(groups[k], ev)
	}

	for k, groupEvents := range groups {
		rule, ok := rs.Rules[k.Source]
		if !ok || !rule.Enabled {
			continue
		}
		if len(groupEvents) < rule.Threshold {
			continue
		}
		// Window check: count events whose Ts is within
		// `rule.Window` of `now`. Defensive against a
		// long-cursor backlog where old events would
		// satisfy the threshold without being recent.
		recentCount := 0
		var triggeringID string
		windowStart := now.Add(-rule.Window)
		for _, ev := range groupEvents {
			if ev.Ts.After(windowStart) || ev.Ts.Equal(windowStart) {
				recentCount++
				if triggeringID == "" {
					triggeringID = ev.TriggeringEventID
				}
			}
		}
		if recentCount < rule.Threshold {
			continue
		}

		scenario := k.Source.Scenario()

		// Cooldown check (D5.A).
		if e.cooldown.HasCooldown(k.SrcIP, scenario) {
			e.cfg.Logger.Debug("automation: skipping intent (cooldown)",
				"src_ip", k.SrcIP, "scenario", scenario)
			continue
		}

		// Dedupe check (D4.B).
		active, hit := e.dedupe.Lookup("Ip", k.SrcIP, scenario)
		if !hit && e.cfg.DedupeChecker != nil {
			a, err := e.cfg.DedupeChecker.HasActiveDecision(ctx, "Ip", k.SrcIP, scenario)
			if err != nil {
				e.cfg.Logger.Warn("automation: dedupe check failed, proceeding with push",
					"err", err, "src_ip", k.SrcIP, "scenario", scenario)
				// Don't cache — error path stays in cache miss state.
			} else {
				e.dedupe.Record("Ip", k.SrcIP, scenario, a)
				active = a
			}
		}
		if active {
			e.cfg.Logger.Debug("automation: skipping intent (already active in LAPI)",
				"src_ip", k.SrcIP, "scenario", scenario)
			continue
		}

		intent := Intent{
			SrcIP:                k.SrcIP,
			Source:               k.Source,
			TriggeringEventID:    triggeringID,
			TriggeringEventCount: recentCount,
			DurationSeconds:      int(rule.Duration / time.Second),
		}
		select {
		case e.intents <- intent:
			e.totalIntentsEmit.Add(1)
		default:
			// Buffer full → drop. AC #13 / D7.A. The
			// source events stay in their tables.
			e.totalIntentsDrop.Add(1)
		}
	}
}

// readWaf executes the WAF event read for this tick. Cursor
// advances to max(event.Ts) so the next tick reads only
// new events.
func (e *Engine) readWaf(ctx context.Context, now time.Time) []SourceEvent {
	e.cursorMu.Lock()
	cursor := e.cursor[SourceWafSQLi] // any waf source shares the cursor — they share the table
	if cursor.IsZero() {
		// Defensive: an enum extension that adds a new
		// source without re-init should still tick.
		cursor = now.Add(-tickInterval)
	}
	e.cursorMu.Unlock()

	events, err := e.cfg.Waf.QueryWafEvents(ctx, WafFilter{
		From:  cursor,
		To:    now,
		Limit: queryLimit,
	})
	if err != nil {
		e.cfg.Logger.Warn("automation: waf read failed", "err", err)
		return nil
	}

	// Advance cursor to the latest event ts we observed.
	// If we hit the queryLimit, leave the cursor at the
	// observed-max — next tick reads the remainder.
	if len(events) > 0 {
		var maxTs time.Time
		for _, ev := range events {
			if ev.Ts.After(maxTs) {
				maxTs = ev.Ts
			}
		}
		e.cursorMu.Lock()
		for _, src := range []Source{
			SourceWafSQLi, SourceWafXSS, SourceWafRCE,
			SourceWafLFI, SourceWafProtocol, SourceWafOther,
		} {
			if maxTs.After(e.cursor[src]) {
				e.cursor[src] = maxTs
			}
		}
		e.cursorMu.Unlock()
	} else {
		e.advanceCursor(SourceWafSQLi, now)
		e.advanceCursor(SourceWafXSS, now)
		e.advanceCursor(SourceWafRCE, now)
		e.advanceCursor(SourceWafLFI, now)
		e.advanceCursor(SourceWafProtocol, now)
		e.advanceCursor(SourceWafOther, now)
	}
	return events
}

func (e *Engine) readThrottle(ctx context.Context, now time.Time) []SourceEvent {
	e.cursorMu.Lock()
	cursor := e.cursor[SourceThrottleTier1]
	if cursor.IsZero() {
		cursor = now.Add(-tickInterval)
	}
	e.cursorMu.Unlock()

	events, err := e.cfg.Throttle.QueryThrottleEvents(ctx, ThrottleFilter{
		From:  cursor,
		To:    now,
		Limit: queryLimit,
	})
	if err != nil {
		e.cfg.Logger.Warn("automation: throttle read failed", "err", err)
		return nil
	}

	if len(events) > 0 {
		var maxTs time.Time
		for _, ev := range events {
			if ev.Ts.After(maxTs) {
				maxTs = ev.Ts
			}
		}
		e.cursorMu.Lock()
		for _, src := range []Source{SourceThrottleTier1, SourceThrottleTier2} {
			if maxTs.After(e.cursor[src]) {
				e.cursor[src] = maxTs
			}
		}
		e.cursorMu.Unlock()
	} else {
		e.advanceCursor(SourceThrottleTier1, now)
		e.advanceCursor(SourceThrottleTier2, now)
	}
	return events
}

func (e *Engine) readAudit(ctx context.Context, now time.Time) []SourceEvent {
	e.cursorMu.Lock()
	cursor := e.cursor[SourceAuthBurst]
	if cursor.IsZero() {
		cursor = now.Add(-tickInterval)
	}
	e.cursorMu.Unlock()

	events, err := e.cfg.Audit.QueryAuthFailureEvents(ctx, cursor, now, queryLimit)
	if err != nil {
		e.cfg.Logger.Warn("automation: audit read failed", "err", err)
		return nil
	}

	if len(events) > 0 {
		var maxTs time.Time
		for _, ev := range events {
			if ev.Ts.After(maxTs) {
				maxTs = ev.Ts
			}
		}
		e.cursorMu.Lock()
		if maxTs.After(e.cursor[SourceAuthBurst]) {
			e.cursor[SourceAuthBurst] = maxTs
		}
		e.cursorMu.Unlock()
	} else {
		e.advanceCursor(SourceAuthBurst, now)
	}
	return events
}

func (e *Engine) advanceCursor(src Source, ts time.Time) {
	e.cursorMu.Lock()
	if ts.After(e.cursor[src]) {
		e.cursor[src] = ts
	}
	e.cursorMu.Unlock()
}

// writerLoop drains the intents channel + pushes to LAPI.
// Three error classes from WatcherClient.PushAlert:
//   - nil: success → audit + increment totalPushSuccess.
//   - ErrLAPIUnavailable: transient → exponential backoff retry.
//     After writerMaxRetries we drop + increment totalPushDropped.
//   - ErrLoginFailed: permanent (operator must fix) →
//     increment totalPushPermanent, log, drop. Don't loop on
//     these — the next intent retries fresh (the operator may
//     have fixed the issue between).
//
// The writer is resolved per-intent via currentWriter() so
// the P.3 recreate-and-swap path (DefaultManager) reaches the
// engine without restarting any goroutine.
func (e *Engine) writerLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case intent := <-e.intents:
			w := e.currentWriter()
			if w == nil {
				// AC #15 boot-degraded path or post-PUT
				// ClearCredentials. Drain silently — the
				// intent was a valid threshold trip but
				// the operator has explicitly disabled
				// the writer.
				continue
			}
			e.processIntent(ctx, w, intent)
		}
	}
}

// currentWriter returns the active writer. Prefers the
// WriterProvider (recreate-and-swap path) over the static
// Writer config field, so a Manager swap takes effect
// immediately.
func (e *Engine) currentWriter() Writer {
	if e.cfg.WriterProvider != nil {
		return e.cfg.WriterProvider.Writer()
	}
	return e.cfg.Writer
}

func (e *Engine) processIntent(ctx context.Context, writer Writer, intent Intent) {
	scenario := intent.Source.Scenario()
	alert := buildAlert(intent, e.cfg.Now())

	backoff := writerBackoffInitial
	for attempt := 1; attempt <= writerMaxRetries; attempt++ {
		_, err := writer.PushAlert(ctx, alert)
		if err == nil {
			e.totalPushSuccess.Add(1)
			// Record success in dedupe so the next tick
			// for the same (src_ip, scenario) within
			// dedupeTTL skips a duplicate push.
			e.dedupe.Record("Ip", intent.SrcIP, scenario, true)
			if e.cfg.AuditEmitter != nil {
				e.cfg.AuditEmitter.EmitDecisionPushed(
					intent.SrcIP, scenario,
					intent.TriggeringEventID,
					intent.TriggeringEventCount,
					intent.DurationSeconds,
				)
			}
			return
		}

		if errors.Is(err, ErrLoginFailed) {
			e.totalPushPermanent.Add(1)
			e.loginFailures.Add(1)
			e.cfg.Logger.Warn("automation: push permanent failure (creds bad or alert shape rejected) — dropping intent",
				"src_ip", intent.SrcIP, "scenario", scenario, "err", err)
			return
		}

		if errors.Is(err, ErrLAPIUnavailable) {
			e.cfg.Logger.Warn("automation: push transient failure — retrying",
				"src_ip", intent.SrcIP, "scenario", scenario,
				"attempt", attempt, "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > writerBackoffMax {
				backoff = writerBackoffMax
			}
			continue
		}

		// Unknown error class — log + drop. Don't loop on
		// these (could be a programming error we don't want
		// to amplify with retries).
		e.totalPushPermanent.Add(1)
		e.cfg.Logger.Error("automation: push unknown error class — dropping intent",
			"src_ip", intent.SrcIP, "scenario", scenario, "err", err)
		return
	}

	// All retries exhausted → drop.
	e.totalPushDropped.Add(1)
	e.cfg.Logger.Warn("automation: push retries exhausted — dropping intent",
		"src_ip", intent.SrcIP, "scenario", scenario)
}

// buildAlert materialises an Intent into the LAPI Alert wire
// shape. The required-but-not-operator-meaningful fields
// (capacity, leakspeed, scenario_hash, ...) are populated
// with sensible non-empty defaults so LAPI's validator
// accepts the alert (see watcher_client.go Alert doc).
func buildAlert(intent Intent, now time.Time) Alert {
	scenario := intent.Source.Scenario()
	startAt := now.UTC().Format(time.RFC3339)
	return Alert{
		Scenario: scenario,
		Source: AlertSource{
			Scope: "Ip",
			Value: intent.SrcIP,
			IP:    intent.SrcIP,
		},
		Decisions: []AlertDecision{{
			Duration: (time.Duration(intent.DurationSeconds) * time.Second).String(),
			Origin:   "arenet",
			Scenario: scenario,
			Scope:    "Ip",
			Type:     "ban",
			Value:    intent.SrcIP,
		}},
		Message:         "auto-classified by arenet",
		Capacity:        0,
		EventsCount:     intent.TriggeringEventCount,
		Leakspeed:       "0s",
		ScenarioHash:    "",
		ScenarioVersion: "",
		Simulated:       false,
		StartAt:         startAt,
		StopAt:          startAt,
		Events:          []map[string]any{},
	}
}

// OnTombstone is the §3.6 / §3.7 D6.A entry point — installed
// by the cmd/arenet/main.go wiring as the Step N
// crowdsec.Sink tombstone listener. Resolution from UUID →
// (src_ip, scenario) is the responsibility of the caller (a
// thin adapter in main.go that reads the observability
// decision_event mirror); this method just consumes the
// (srcIP, scenario, cooldown duration) tuple.
//
// Invalidates the dedupe LRU for the (Ip, srcIP) key across
// all scenarios so the next push attempt re-checks LAPI
// fresh.
//
// Records the cooldown using the rule's Cooldown duration
// for the matching Source. If no rule matches the scenario
// (orphan tombstone — possible if the operator unbans an IP
// that arenet never auto-classified) we still invalidate the
// dedupe but do NOT record a cooldown (no rule to read
// duration from).
func (e *Engine) OnTombstone(srcIP, scenario string) {
	e.dedupe.Invalidate("Ip", srcIP)

	// Translate scenario back to Source to get the rule's
	// cooldown duration. Scenario = "arenet/<source>".
	if len(scenario) > len("arenet/") && scenario[:len("arenet/")] == "arenet/" {
		src := Source(scenario[len("arenet/"):])
		if src.IsKnown() {
			rule, ok := e.cfg.Rules.Get().Rules[src]
			if ok && rule.Cooldown > 0 {
				e.cooldown.Record(srcIP, scenario, rule.Cooldown)
				return
			}
		}
	}
	// Orphan tombstone — dedupe already invalidated, no
	// cooldown to record.
}

// Metric accessors (P.3 will surface these on /metrics/summary).

func (e *Engine) TotalTicks() uint64         { return e.totalTicks.Load() }
func (e *Engine) TotalIntentsEmit() uint64   { return e.totalIntentsEmit.Load() }
func (e *Engine) TotalIntentsDrop() uint64   { return e.totalIntentsDrop.Load() }
func (e *Engine) TotalPushSuccess() uint64   { return e.totalPushSuccess.Load() }
func (e *Engine) TotalPushPermanent() uint64 { return e.totalPushPermanent.Load() }
func (e *Engine) TotalPushDropped() uint64   { return e.totalPushDropped.Load() }
func (e *Engine) LoginFailures() uint64      { return e.loginFailures.Load() }
