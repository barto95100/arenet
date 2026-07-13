# State Alerting Rules — Edge-Triggered Firing — Design

**Date:** 2026-07-13
**Status:** Approved (design validated by operator)

## Problem

An alerting rule of kind `state` (e.g. `update_available`) re-fires on
**every watcher tick** for as long as its condition holds, throttled only
by the per-(rule, channel) cooldown (default 300 s). Because "an update is
available" is a **stable state** — not a recurring event — the rule fires
every ~5 minutes indefinitely, producing a stream of identical
`alert_event` rows. In the sidebar notification panel each distinct
event timestamp becomes its own unread item, so the operator sees a growing
red badge count for a single available update.

**Observed (operator VM):** ~15 `update / Info / system / "[info] update
fired"` events spaced ~5-6 min apart, one unread badge each.

### Root cause (empirically confirmed)

- `internal/alerting/source_update_available.go:42` — `Read()` correctly
  returns the current state (`"available"` while an update exists).
- `internal/alerting/evaluator.go:184` — `StateEvaluator.Evaluate` returns
  `*value.String == p.Expected`, i.e. `true` **every tick** the state
  matches. It has no memory of the previous tick — no transition detection.
- `internal/alerting/watcher.go:252` `evalOneRule` — on `fired == true`,
  the only gate before dispatch is `Cooldown.OnCooldown` (watcher.go:295).
  With the default 300 s cooldown and a state that stays matched, the rule
  fires once per cooldown window forever.

This affects **all** `state`-kind rules, not just `update_available`.

## Goal

Make `state` rules **edge-triggered**: fire once when the condition
transitions from not-met → met, and stay silent while it remains met.
Re-fire only if the state leaves the matched value and returns to it later
(e.g. operator upgrades, then a newer release appears). `threshold` rules
are unchanged.

## Decisions (from brainstorming)

1. **Edge-triggered semantics** for `state` rules: fire only on
   not-match → match transition.
2. **Persist the last-matched state in BoltDB** (a field on `AlertRule`),
   so the transition memory survives an Arenet restart — a restart while an
   update is already available must NOT re-fire.
3. **Edge-trigger replaces cooldown for `state` rules** (see §2 rationale).
4. **No purge of already-accumulated events** — the shipped
   "Mark all read" (localStorage `lastSeen`) clears the badge; the fix
   prevents recurrence. No throwaway purge code (YAGNI).

---

## Section 1 — Transition detection

Add a persisted field to the rule recording whether its condition was met
at the previous evaluation:

```go
// internal/storage/alert_rule.go — AlertRule struct
LastMatched bool `json:"last_matched,omitempty"`
```

`omitempty` + JSON-serialized struct storage means this is
**backward-compatible with no migration**: existing rules deserialize it as
`false` (the safe default — a rule whose state is already matched at first
post-upgrade tick will fire once, which is the correct "first observation"
behavior).

**`LastMatched` is watcher-owned and must survive an operator PUT.**
`UpdateAlertRule` (`alert_rule.go:225`) already preserves the other
watcher-owned fields (`LastFiredAt`, `LastEvalAt`, `LastError` /
`LastErrorAt`) from the stored copy when the caller didn't set them
(lines 250-262). `LastMatched` must get the same treatment — but because
it is a `bool`, its zero value (`false`) is indistinguishable from a
deliberate `false`, so the "caller didn't set it" test used for the pointer
fields does not work. Instead, **always** copy `LastMatched` from the
stored `existing` rule in `UpdateAlertRule` (the operator-facing API never
sets it; only the watcher's `UpdateAlertRuleLastMatched` does). This
prevents an operator edit from silently resetting the edge state and
re-firing.

In `evalOneRule` (`internal/alerting/watcher.go`), after `Evaluate`
produces `fired`:

- **Threshold rules** (`r.Kind == RuleKindThreshold`): unchanged — dispatch
  when `fired`, gated by cooldown, exactly as today.
- **State rules** (`r.Kind == RuleKindState`): dispatch only when
  `fired && !r.LastMatched` (the rising edge). When `fired == r.LastMatched`
  (state unchanged), skip dispatch.
- Persist the new `fired` value into `LastMatched` — see §2 for the exact
  write ordering.

Effect on the reported case:
- `up_to_date → available`: `fired=true`, `LastMatched=false` → **fire once**.
- `available → available`: `fired=true`, `LastMatched=true` → no dispatch.
- restart with state already `available`: `LastMatched=true` was persisted
  → no re-fire.
- `available → up_to_date → available` (upgrade then newer release):
  second rising edge → fires again (correct).

## Section 2 — Cooldown interaction and write ordering

Once state rules are edge-triggered, the cooldown is redundant for them and
introduces a **transition-swallow hazard**: if a transition is detected but
the cooldown is still active from a prior fire, the dispatch would be
skipped while `LastMatched` flips to `true` — consuming the edge without
notifying.

**Decision:** for `state` rules, the edge-trigger **replaces** the
cooldown. Do NOT call `OnCooldown` for state rules. (Threshold rules keep
`OnCooldown` intact — it is their only anti-flood gate.)

**Write ordering — never consume a transition without notifying:**

- If `fired == false`: persist `LastMatched = false` unconditionally (the
  state has left the matched value; the next rising edge must be able to
  fire).
- If `fired == true` and it's a rising edge (`!LastMatched`): dispatch
  first; persist `LastMatched = true` **only if ≥1 channel fired
  successfully**. If dispatch fails on all channels, leave `LastMatched =
  false` so the transition is retried on the next tick.
- If `fired == true` and not a rising edge (`LastMatched` already true): no
  dispatch, no write needed (idempotent).

This guarantees a failed dispatch never silently swallows the edge — worst
case is a retry next tick, never a missed alert.

The heartbeat write (`persistEvalState`, watcher.go:284) is unchanged and
still runs every tick regardless.

## Section 3 — Storage method, tests, non-goals

### Storage

Add, mirroring the existing `UpdateAlertRuleFiredState`
(`internal/storage/alert_rule.go:370`):

```go
// UpdateAlertRuleLastMatched persists the state-rule edge-detection flag.
func (s *Store) UpdateAlertRuleLastMatched(ctx context.Context, id string, matched bool) error
```

Add the method to the watcher's `AlertRuleStore` interface
(`internal/alerting/watcher.go`, alongside `UpdateAlertRuleFiredState`).

### Tests (TDD)

`internal/alerting/watcher_test.go`:
1. **Edge-trigger holds:** a state rule whose source stays matched across 3
   consecutive ticks dispatches **once** (tick 1), not 3×. (This is the
   test that would have caught the bug.)
2. **Re-fire on return:** `matched → not-matched → matched` fires again on
   the second rising edge.
3. **Failed dispatch retries:** on a rising edge where all channels fail,
   `LastMatched` is not set to true, and the next tick (still matched)
   re-attempts the dispatch.
4. **Threshold unchanged (regression guard):** a threshold rule that stays
   over its limit still fires on successive ticks (subject to cooldown),
   proving the edge logic is scoped to `state` only.

`internal/storage/alert_rule_test.go`:
5. **Round-trip + back-compat:** `UpdateAlertRuleLastMatched` persists and
   reads back; a rule stored without the field deserializes as
   `LastMatched == false`.
6. **Operator PUT preserves the flag:** set `LastMatched=true` via the
   watcher method, then call `UpdateAlertRule` with a rule value that has
   `LastMatched=false` (as an operator edit would) → the stored rule keeps
   `LastMatched == true`.

### Runtime verification

Rebuild; configure an `update_available` state rule with a channel; run
against a build that reports an update. Observe the logs across several
watcher ticks: exactly **one** `alerting watcher: rule fired` line, then
silence while the state stays `available`. Confirm no new `alert_event`
rows accrue after the first.

### Non-goals (YAGNI)

- No purge of historical `alert_event` rows (the Mark-all-read + the fix
  suffice).
- No periodic re-reminder for persistent state (operator chose pure
  edge-trigger).
- No change to threshold-rule behavior, the cooldown LRU itself, the
  sources, or the notification panel.

## Files summary

| Action | File |
| --- | --- |
| Modify | `internal/storage/alert_rule.go` (add `LastMatched` field + `UpdateAlertRuleLastMatched`; preserve `LastMatched` from stored copy in `UpdateAlertRule`) |
| Modify | `internal/storage/alert_rule_test.go` (round-trip + back-compat test; operator-PUT-preserves-LastMatched test) |
| Modify | `internal/alerting/watcher.go` (edge-trigger in `evalOneRule`; add store-interface method) |
| Modify | `internal/alerting/watcher_test.go` (edge-trigger + regression tests) |

## Global constraints (from CLAUDE.md)

- AGPL header already present on all touched files (no new files).
- `gofmt -s` clean, `go vet ./...`, `staticcheck ./...` clean.
- `ctx context.Context` first arg on the new I/O method; wrap errors with
  `fmt.Errorf("...: %w", err)`; `slog` for any logging; no panics.
- The `LastMatched` field addition must not break existing stored rules
  (verified: JSON `omitempty`, deserializes to `false`).
