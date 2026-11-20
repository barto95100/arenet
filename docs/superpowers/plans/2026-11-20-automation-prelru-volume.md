<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Plan — pre-LRU volume signal for the automation threshold

Spec: `docs/superpowers/specs/2026-11-20-automation-prelru-volume-design.md`.
Branch: `fix/automation-prelru-volume`. Discipline: `[[guard]]` — the G1 test is
written and seen to **fail on the table-count path first**, then the fix makes
it pass, then the defect is reinjected (`cp`, never `git checkout`).

## T0 — Guard golden / failing test first (no production change)

- Add `internal/automation/volume_trigger_test.go`:
  - **G1**: a harness that feeds N identical WAF `(srcIP, rule, route, ts≈now)`
    events, drives one (or a few) ticks, and asserts exactly one intent when
    `N ≥ Threshold`, none when `N < Threshold`.
  - Written against the **current** engine first (fake reader returning the
    LRU-deduped 1 row) → watch it FAIL (n=1 < threshold). Commit the red test
    shape in its own commit so the diff proves the defect.
- No `-update`, no production edit in this commit.

## T1 — The volume tracker (`internal/automation/volume.go`)

- `type volumeTracker` — thread-safe, injectable clock (`now func() time.Time`).
- Per-key `(srcIP, Source)` ring of recent event records
  `{ts, triggeringRef}`; **per-key cap K** (drop oldest), **global key cap**
  with LRU eviction, prune entries older than the tracker's configured retention
  (= `maxEnabledWindow`, refreshed from the rule set each tick).
- API:
  - `Observe(srcIP string, source Source, ts time.Time, ref string)`
  - `Query(now time.Time, within time.Duration) []SourceEvent` — every retained
    event newer than `now-within`, projected to the engine's `SourceEvent`
    shape with the synthetic `TriggeringEventID` (D6).
  - `SetRetention(d time.Duration)` / prune.
- Unit tests: TTL expiry, per-key cap, global LRU eviction, concurrency
  (`-race`). This is **G4**.

## T2 — Feed the tracker from the pre-LRU tap (`cmd/arenet`)

- Define a narrow observer interface the engine satisfies, e.g.
  `WafVolumeObserver{ ObserveWafBlock(srcIP, category string, ts time.Time) }`
  and `ThrottleVolumeObserver{ ObserveThrottle(srcIP, tier string, ts time.Time) }`
  (category→Source and tier→Source mapping stays in `automation`).
- `geoForwardingWafSink`: add the observer field; in `Emit`, when
  `e.Action == waf.ActionBlock`, call `ObserveWafBlock(e.SrcIP, string(e.Category), e.Ts)`.
  Nil-safe (degraded wiring).
- `geoForwardingThrottleSink`: same, `ObserveThrottle(e.SrcIP, <tier>, e.Ts)`.
  **Implementation check:** confirm `throttle.Event` exposes the tier field the
  storage row carries; if the field name differs, adapt the mapping only.
- Wire the engine's observer into both forwarders in `main.go` (after
  `wireAutomation` returns the engine, or expose the tracker from it).

## T3 — Trigger reads the tracker (`internal/automation/trigger.go`)

- `readWaf` / `readThrottle`: replace the `QueryWafEvents` / `QueryThrottleEvents`
  DB calls with `tracker.Query(now, maxEnabledWindow)` filtered to the WAF /
  throttle source families. **Drop the cursor** for these two (keep `readAudit`
  and its cursor exactly as-is).
- `tick()`: unchanged group → per-rule window recount → cooldown → dedupe → emit.
- **D8 re-emit guard**: immediately after a successful `e.intents <- intent`,
  call `e.dedupe.Record("Ip", srcIP, scenario, true)` so the next tick (events
  still inside `Window`) does not re-emit before the LAPI mirror updates.
- Each tick, refresh `tracker.SetRetention(maxEnabledWindow(rs))`.
- Remove the now-dead `automationWafReader` / `automationThrottleReader` DB
  wiring **only if** nothing else uses them; otherwise leave them and just stop
  calling them from the trigger (decide during impl, note in the commit).

## T4 — Reinject + sibling isolation (`[[guard]]`)

- Reinject the table-count read behind `readWaf` (via `cp` backup), run G1/G2/G3
  → confirm they fail; restore; `diff -q` RESTORED.
- Confirm G1 (WAF) and G2 (throttle) fail **independently** — one reinjection
  must not fail the other's assertion (one mechanism, one test).

## T5 — Full suite + non-regression (G6)

- `go build ./... && go vet ./...`
- `go test -race -count=1 ./internal/automation/... ./internal/waf/... ./internal/throttle/... ./cmd/arenet/...`
- Confirm the audit/auth-failure path and the automation **health block**
  (v2.83.0) are untouched; `/healthz` contract intact.

## T6 — Docs / smoke

- `docs/smoke-test-automation-prelru-volume.md`: the G5 dogfood procedure
  (4-curl burst → exactly one `arenet/` decision at `threshold=2`), plus the
  memory-bound sanity note.
- Update memory `automation-threshold-per-tick-bug` to the confirmed root cause
  (LRU-before-table starves the count; fix = pre-LRU tracker) and this spec/plan.

## PR / tag

- PR `fix/automation-prelru-volume` → `main`. No `Co-Authored-By`, no 🤖 footer
  (operator standing rule).
- Operator tags **v2.83.1** after review; dogfood gate **G5** before closing.
- Operator drops `diag/automation-trigger-trace` (no merge).

## Open points for operator sign-off (before T1)

1. Scope **WAF + throttle** (vs WAF-only) — recommended both (identical bug).
2. **Replace** the WAF/throttle DB read in the trigger (vs supplement) —
   recommended replace (also fixes the cross-tick bug).
3. Target tag **v2.83.1** (patch) — recommended.
