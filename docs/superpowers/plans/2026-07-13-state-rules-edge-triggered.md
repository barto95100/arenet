# Edge-Triggered State Alerting Rules — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `state`-kind alerting rules edge-triggered — fire once on the not-match → match transition, silent while the state persists — fixing the notification flood from `update_available` (and any state rule).

**Architecture:** Add a persisted `LastMatched bool` to `AlertRule` (no migration — JSON `omitempty`). In the watcher's `evalOneRule`, state rules dispatch only on the rising edge (`fired && !LastMatched`), bypassing the cooldown; `LastMatched=true` is persisted only after a successful dispatch. Threshold rules are unchanged.

**Tech Stack:** Go 1.25, BoltDB (bbolt), stdlib `log/slog`, table tests.

**Spec:** `docs/superpowers/specs/2026-07-13-state-rules-edge-triggered-design.md`

## Global Constraints

- `gofmt -s` clean; `go vet ./...` and `staticcheck ./...` clean; no `panic` outside `main`.
- `ctx context.Context` first arg on I/O methods; wrap errors `fmt.Errorf("...: %w", err)`; `slog` for logging.
- AGPL header already present on all touched files (no new files).
- `LastMatched` addition must not break existing stored rules (JSON `omitempty` → deserializes to `false`).
- Backend build/test: `go build ./...`, `go test ./internal/storage/ ./internal/alerting/`.

---

### Task 1: Storage — `LastMatched` field, updater, PUT-preservation

**Files:**
- Modify: `internal/storage/alert_rule.go`
- Modify: `internal/storage/alert_rule_test.go`

**Interfaces:**
- Produces (consumed by Task 2):
  - `AlertRule.LastMatched bool` (JSON `last_matched,omitempty`)
  - `func (s *Store) UpdateAlertRuleLastMatched(ctx context.Context, id string, matched bool) error`
- Also modifies `UpdateAlertRule` to preserve `LastMatched` from the stored copy on every operator PUT.

- [ ] **Step 1: Write the failing tests**

Add to `internal/storage/alert_rule_test.go`. Use the existing helpers in that file: `newStoreForTest(t)` (temp-dir `Store`) and `sampleRule(id, name)` (a valid rule builder — threshold kind, cooldown 300, channels `["ch-1"]`).

```go
func TestUpdateAlertRuleLastMatched_RoundTrip(t *testing.T) {
	store := newStoreForTest(t)
	created, err := store.CreateAlertRule(context.Background(), sampleRule("rule-1", "lm"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// default is false
	got, err := store.GetAlertRule(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.LastMatched {
		t.Fatalf("fresh rule LastMatched = true; want false")
	}
	// set true, read back
	if err := store.UpdateAlertRuleLastMatched(context.Background(), created.ID, true); err != nil {
		t.Fatalf("update last matched: %v", err)
	}
	got, _ = store.GetAlertRule(context.Background(), created.ID)
	if !got.LastMatched {
		t.Fatalf("LastMatched = false after set true")
	}
}

func TestUpdateAlertRule_PreservesLastMatched(t *testing.T) {
	store := newStoreForTest(t)
	created, _ := store.CreateAlertRule(context.Background(), sampleRule("rule-1", "lm"))
	if err := store.UpdateAlertRuleLastMatched(context.Background(), created.ID, true); err != nil {
		t.Fatalf("set last matched: %v", err)
	}
	// operator PUT that carries LastMatched=false (as the API layer would)
	edit := created
	edit.LastMatched = false
	edit.Name = "lm-edited"
	if _, err := store.UpdateAlertRule(context.Background(), edit); err != nil {
		t.Fatalf("update rule: %v", err)
	}
	got, _ := store.GetAlertRule(context.Background(), created.ID)
	if !got.LastMatched {
		t.Fatalf("operator PUT reset LastMatched to false; want preserved true")
	}
}
```

Back-compat note: `sampleRule` doesn't set `LastMatched`, so a freshly-created rule already exercises the "field absent → deserializes false" path (the first assertion above). No separate legacy-blob test needed.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/storage/ -run 'LastMatched' -v`
Expected: compile error / FAIL — `UpdateAlertRuleLastMatched` undefined and `AlertRule.LastMatched` undefined.

- [ ] **Step 3: Add the field**

In `internal/storage/alert_rule.go`, add to the `AlertRule` struct (after `LastErrorAt`, ~line 79):

```go
	LastMatched bool `json:"last_matched,omitempty"`
```

- [ ] **Step 4: Preserve it in `UpdateAlertRule`**

In `UpdateAlertRule` (`alert_rule.go`, in the preserve-watcher-owned-fields block ~lines 250-262, right after the `LastError`/`LastErrorAt` preservation), add:

```go
		// LastMatched is watcher-owned edge state. A bool's zero
		// value is indistinguishable from a deliberate false, so
		// (unlike the pointer fields above) always copy it from the
		// stored rule — the operator API never sets it.
		r.LastMatched = existing.LastMatched
```

- [ ] **Step 5: Add the updater**

In `internal/storage/alert_rule.go`, add after `UpdateAlertRuleFiredState` (~line 399), copying that method's structure:

```go
// UpdateAlertRuleLastMatched persists the state-rule edge-detection
// flag (whether the rule's condition was met at the last evaluation).
// Watcher-owned; the operator API never writes it. Bumps UpdatedAt.
func (s *Store) UpdateAlertRuleLastMatched(ctx context.Context, id string, matched bool) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if id == "" {
		return errors.New("alert_rule: id must not be empty")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketAlertRules))
		raw := b.Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		var r AlertRule
		if err := json.Unmarshal(raw, &r); err != nil {
			return fmt.Errorf("unmarshal alert_rule: %w", err)
		}
		r.LastMatched = matched
		r.UpdatedAt = time.Now().UTC()
		buf, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal alert_rule: %w", err)
		}
		return b.Put([]byte(id), buf)
	})
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/storage/ -run 'LastMatched' -v`
Expected: PASS. Then the whole package: `go test ./internal/storage/` → PASS (no regression).

- [ ] **Step 7: gofmt + vet + commit**

```bash
gofmt -s -w internal/storage/alert_rule.go internal/storage/alert_rule_test.go
go vet ./internal/storage/
git add internal/storage/alert_rule.go internal/storage/alert_rule_test.go
git commit -m "feat(storage): add AlertRule.LastMatched + UpdateAlertRuleLastMatched

Watcher-owned edge-detection flag for state rules. omitempty (no
migration; existing rules read as false). UpdateAlertRule always
preserves it from the stored copy so an operator PUT can't reset the
edge state (bool zero-value is ambiguous, unlike the pointer Last* fields)."
```

---

### Task 2: Watcher — edge-trigger for state rules

**Files:**
- Modify: `internal/alerting/watcher.go`
- Modify: `internal/alerting/watcher_test.go`

**Interfaces:**
- Consumes (from Task 1): `AlertRule.LastMatched`, `Store.UpdateAlertRuleLastMatched`.
- Adds `UpdateAlertRuleLastMatched(ctx, id string, matched bool) error` to the `AlertRuleStore` interface (`watcher.go:117`).

- [ ] **Step 1: Extend the fake store, then write the failing tests**

First, in `internal/alerting/watcher_test.go`, extend `fakeRuleStore` (struct ~line 38) to satisfy the new interface method AND — critically — to **mutate `f.rules` in place** so a later tick re-reads the updated `LastMatched` (the existing `UpdateAlertRuleFiredState` fake only records the call; the edge-trigger tests need the state to actually change between ticks):

```go
// add to fakeRuleStore struct:
	lastMatchedUpdates []lastMatchedCall

// add type:
type lastMatchedCall struct {
	id      string
	matched bool
}

// add method — records the call AND mutates the stored rule so the
// next ListAlertRules reflects the new edge state:
func (f *fakeRuleStore) UpdateAlertRuleLastMatched(_ context.Context, id string, matched bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastMatchedUpdates = append(f.lastMatchedUpdates, lastMatchedCall{id: id, matched: matched})
	for i := range f.rules {
		if f.rules[i].ID == id {
			f.rules[i].LastMatched = matched
		}
	}
	return nil
}
```

Then add the edge-trigger tests. Reuse the file's existing helpers:
`baseRule(id, name, channels)` (threshold-kind fixture) + `mustRule(t, r)`
(fills default params), `fakeLookup{known: map[string]Source{...}}`,
`silentLogger()`, `NewCooldownLRU(nil)`, and the `FloatValue`/`StringValue`
`SourceValue` constructors. These tests need **multiple ticks on the same
watcher**, so build it once with `NewWatcher(cfg)` and call `w.tick(ctx)`
repeatedly (the existing `runOneTick` helper builds a fresh watcher per
call — not usable here; but it's fine to construct `WatcherConfig` the same
way it does). A state rule is a `baseRule` with `Kind` set to
`RuleKindState` and `EvalParams` `{"expected":"available"}`. The source's
`readValue` field is read without a lock in `Read`, so between synchronous
ticks a test can reassign `src.readValue = …` directly.

```go
func stateRule(id string, channels []string) storage.AlertRule {
	r := baseRule(id, "state-"+id, channels)
	r.Kind = RuleKindState
	r.EvalParams = json.RawMessage(`{"expected":"available"}`)
	return mustRule(nil, r) // mustRule only fills nil params; r already has them
}

func newWatcherFor(t *testing.T, store *fakeRuleStore, disp *fakeDispatcher, src *fakeSource) *Watcher {
	t.Helper()
	w, err := NewWatcher(WatcherConfig{
		Store:      store,
		Sources:    &fakeLookup{known: map[string]Source{"stub": src}},
		Dispatcher: disp,
		Cooldown:   NewCooldownLRU(nil),
		Logger:     silentLogger(),
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	return w
}

func TestWatcher_StateRule_FiresOnceWhileMatched(t *testing.T) {
	src := &fakeSource{name: "stub", readValue: StringValue("available")}
	store := &fakeRuleStore{rules: []storage.AlertRule{stateRule("r-1", []string{"ch-1"})}}
	disp := &fakeDispatcher{}
	w := newWatcherFor(t, store, disp, src)
	ctx := context.Background()
	w.tick(ctx)
	w.tick(ctx)
	w.tick(ctx)
	if got := len(disp.calls); got != 1 {
		t.Fatalf("dispatch calls = %d; want 1 (edge-triggered)", got)
	}
	if len(store.lastMatchedUpdates) == 0 || !store.lastMatchedUpdates[len(store.lastMatchedUpdates)-1].matched {
		t.Fatalf("LastMatched not persisted true after fire")
	}
}

func TestWatcher_StateRule_RefiresAfterReturningToMatch(t *testing.T) {
	src := &fakeSource{name: "stub", readValue: StringValue("available")}
	store := &fakeRuleStore{rules: []storage.AlertRule{stateRule("r-1", []string{"ch-1"})}}
	disp := &fakeDispatcher{}
	w := newWatcherFor(t, store, disp, src)
	ctx := context.Background()
	w.tick(ctx)                            // available → fire (1)
	src.readValue = StringValue("up_to_date") // leaves match; persists LastMatched=false
	w.tick(ctx)                            // no fire
	src.readValue = StringValue("available")  // returns to match
	w.tick(ctx)                            // rising edge again → fire (2)
	if got := len(disp.calls); got != 2 {
		t.Fatalf("dispatch calls = %d; want 2", got)
	}
}

func TestWatcher_StateRule_RetriesWhenDispatchFails(t *testing.T) {
	src := &fakeSource{name: "stub", readValue: StringValue("available")}
	store := &fakeRuleStore{rules: []storage.AlertRule{stateRule("r-1", []string{"ch-1"})}}
	disp := &fakeDispatcher{failFor: map[string]string{"ch-1": "boom"}}
	w := newWatcherFor(t, store, disp, src)
	ctx := context.Background()
	w.tick(ctx) // rising edge, dispatch fails → LastMatched stays false
	for _, u := range store.lastMatchedUpdates {
		if u.matched {
			t.Fatalf("LastMatched set true despite failed dispatch")
		}
	}
	disp.failFor = nil // recover
	w.tick(ctx)        // still matched, still an edge (LastMatched false) → retry succeeds
	if got := len(disp.calls); got != 2 {
		t.Fatalf("dispatch calls = %d; want 2 (retry after failure)", got)
	}
}

func TestWatcher_ThresholdRule_UnchangedFiresEachTick(t *testing.T) {
	// regression guard: a threshold rule over its limit still fires on
	// successive ticks, proving edge logic is scoped to state rules.
	// Cooldown default (300s) would suppress the 2nd fire, so use a
	// cooldown of 0 to isolate "does the edge logic touch threshold?".
	src := &fakeSource{name: "stub", readValue: FloatValue(100)}
	r := mustRule(t, baseRule("r-1", "thr", []string{"ch-1"}))
	r.CooldownSecs = 0
	store := &fakeRuleStore{rules: []storage.AlertRule{r}}
	disp := &fakeDispatcher{}
	w := newWatcherFor(t, store, disp, src)
	ctx := context.Background()
	w.tick(ctx)
	w.tick(ctx)
	if got := len(disp.calls); got != 2 {
		t.Fatalf("threshold dispatch calls = %d; want 2 (unchanged)", got)
	}
}
```

Helper reuse: `baseRule`, `mustRule`, `fakeLookup`, `silentLogger`,
`NewCooldownLRU`, `FloatValue`, `StringValue`, `fakeSource`,
`fakeDispatcher` all already exist in this file — the two small local
helpers `stateRule`/`newWatcherFor` above just compose them. Note the
threshold test sets `CooldownSecs = 0`; storage's ≥30 min applies to the
API layer, not to a fixture handed straight to the watcher, so 0 is fine
here and isolates the edge-vs-threshold behavior.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/alerting/ -run 'StateRule|ThresholdRule_Unchanged' -v`
Expected: FAIL — the state tests currently fire every tick (3 dispatches, not 1), because the edge logic doesn't exist yet. The threshold test may already pass (it documents current behavior); that's fine — it's the regression guard.

- [ ] **Step 3: Implement the edge-trigger in `evalOneRule`**

In `internal/alerting/watcher.go`:

First add to the `AlertRuleStore` interface (after `UpdateAlertRuleFiredState`, ~line 120):

```go
	UpdateAlertRuleLastMatched(ctx context.Context, id string, matched bool) error
```

Then rework Step 4-6 of `evalOneRule` (the block from `if !fired { return }` through the fired-state write, ~lines 286-326). Replace with:

```go
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
```

Keep the existing `persistEvalState` heartbeat call (Step 3, ~line 284) exactly as-is, before this block.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/alerting/ -run 'StateRule|ThresholdRule_Unchanged' -v`
Expected: all PASS. Then the whole package: `go test ./internal/alerting/` → PASS (no regression in existing watcher/evaluator/cooldown tests).

- [ ] **Step 5: gofmt + vet + staticcheck + commit**

```bash
gofmt -s -w internal/alerting/watcher.go internal/alerting/watcher_test.go
go vet ./internal/alerting/
staticcheck ./internal/alerting/ || true   # report, don't block if the tool isn't installed
git add internal/alerting/watcher.go internal/alerting/watcher_test.go
git commit -m "fix(alerting): edge-trigger state rules to stop the notification flood

State rules (e.g. update_available) fired every tick while their
condition held, throttled only by the cooldown — flooding the panel with
duplicate events for one stable state. Now state rules fire only on the
not-match → match rising edge, tracked via the persisted LastMatched flag,
and bypass the cooldown (the edge is the gate). LastMatched is set true
only after a successful dispatch, so a failed send is retried, never
swallowed. Threshold rules are unchanged."
```

---

### Task 3: Runtime verification

**Files:** none (observation only).

- [ ] **Step 1: Build**

Run: `go build ./... && cd web/frontend && npm run build && cd ../.. && go build -o arenet ./cmd/arenet`
Expected: clean build.

- [ ] **Step 2: Drive the watcher (verify skill)**

Run the binary with an update-available state and a configured `update_available` state rule + a channel. Watch the logs across several polling ticks (the watcher default is 30s; wait ~2-3 ticks). Confirm:
- Exactly **one** `alerting watcher: rule fired` line for the rule, then silence while the state stays `available`.
- No new `alert_event` rows accrue after the first (check `/alerting` → History, or the events count).
- Restart the binary while the update is still available → **no** new fire on the first post-restart tick (the persisted `LastMatched=true` suppresses it).

- [ ] **Step 3: Capture evidence + report PASS/FAIL** per the verify skill (log excerpt showing one fire then quiet ticks; and the no-refire-after-restart observation).

---

## Self-Review

**Spec coverage:** `LastMatched` field + updater + PUT-preservation → Task 1. Edge-trigger in `evalOneRule` + cooldown bypass + write ordering → Task 2 Step 3. Interface method → Task 2 Step 3. Watcher tests (fires-once, refire-on-return, retry-on-failure, threshold-unchanged) → Task 2 Step 1; storage tests (round-trip incl. default-false back-compat, PUT-preserves) → Task 1 Step 1. Runtime + no-refire-after-restart → Task 3. All spec sections covered.

**Placeholder scan:** No TBD/TODO. All test code uses the file's real existing helpers (`newStoreForTest`, `sampleRule`, `baseRule`, `mustRule`, `fakeLookup`, `silentLogger`, `NewCooldownLRU`, `FloatValue`, `StringValue`), verified present; the only new symbols are the two composing wrappers `stateRule`/`newWatcherFor` defined inline in the plan.

**Type consistency:** `UpdateAlertRuleLastMatched(ctx, id string, matched bool) error` identical in the `Store` method (Task 1), the `AlertRuleStore` interface (Task 2), and the fake (Task 2). `LastMatched bool` / json `last_matched` consistent across storage struct, fake mutation, and tests. `RuleKindState`/`RuleKindThreshold` are the existing constants. The fake's in-place `f.rules` mutation is the load-bearing detail that makes the multi-tick edge tests meaningful — called out explicitly in Task 2 Step 1.
