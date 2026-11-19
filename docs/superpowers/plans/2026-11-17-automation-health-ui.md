<!-- Arenet implementation plan. CC-BY-SA-4.0 for docs; code AGPL-3.0. -->

# Plan — auto-classify health in API + badge (v2.83.0)

Companion to `specs/2026-11-17-automation-health-ui-design.md`. Bite-sized,
TDD where the logic is load-bearing. Target tag **v2.83.0** (feature).

## Task 1 — Engine: record last push success/error (trigger.go)

- Add to `Engine`: `lastPushSuccessNano atomic.Int64`,
  `lastPushErr atomic.Pointer[string]`.
- In `processIntent`:
  - success path (~:650): store `cfg.Now().UnixNano()`, store `nil` error.
  - `ErrLoginFailed` (~:667), unknown-class (~:693): store `err.Error()`.
  - retries-exhausted drop (~:700): store the last transient err's message.
- Getters: `LastPushAt() (time.Time, bool)`, `LastPushError() (string, bool)`.

## Task 2 — Engine test first (trigger_test.go)

- `TestEngine_LastPushRecord`: drive a fake Writer that returns nil, then
  `ErrLoginFailed`, then nil again; assert `LastPushAt` advances on
  success, `LastPushError` is set after the failure and **cleared** after
  the next success.
- Run → watch it fail against Task 1 not-yet-written, then implement.
- **Guard:** reinject "don't clear error on success" → test fails; restore
  via `cp` (never `git checkout`).

## Task 3 — HealthSnapshot (health.go)

- Add `LastPushAt *time.Time`, `LastPushError *string`.
- Populate in `HealthSnapshot()` from the Task 1 getters (nil when the
  bool is false). Extend `health_test.go`.

## Task 4 — API handler (automation_handlers.go)

- `automationHealth` struct with the six JSON fields (D1/D2/D3/D4).
- In `getAutomation`: after resolving `mgr`, if `mgr != nil` and it
  asserts to `automation.HealthReporter`, fill from the snapshot;
  `writerHealthy = WriterConfigured && !WriterLoginFailed`; format
  `LastPushAt` as RFC3339 UTC. Always emit the object (zero when nil).

## Task 5 — API tests (automation_handlers_test.go)

- `TestGetAutomation_HealthWhenConfigured` (gate 2): fake manager +
  HealthReporter → health block reflects the snapshot.
- `TestGetAutomation_HealthZeroWhenUnconfigured` (gate 3): no manager →
  health present, zero/null, 200 not 500. **Guard** for the "no 500".

## Task 6 — /healthz byte-identity guard (health_test.go)

- If no such test exists, add `TestHealthz_ByteIdentical` pinning
  `{"status":"ok","uptime_seconds":N}`. Confirms the non-goal.

## Task 7 — OpenAPI (settings.yaml)

- New `SettingsAutomationHealth` schema; add `health` to
  `SettingsAutomation` (and document the pre-existing `engineRunning`).
- Run the full `internal/api` package so `TestOpenAPI_*` validate.

## Task 8 — Frontend types (types.ts)

- `AutomationHealth` interface; `health?: AutomationHealth` on
  `AutomationResponse` (optional — tolerate an older backend).

## Task 9 — Frontend badge (+page.svelte)

- Load `res.health` into state in `loadAutomation`.
- `$derived` badge state: not-configured / inactive / degraded / active
  (§4.2 table). "inactive" = no `rule.enabled`.
- Render the right `<Badge variant>` + i18n label; wrap in a `<span
  title={tooltip}>` with counters + lastPushAt + lastPushError.

## Task 10 — i18n (en.json + fr.json)

- Keys: `settings.automation.badge.{active,degraded,inactive,notConfigured}`
  and `settings.automation.health.tooltip.*`. Both locales. Parity test.

## Task 11 — Frontend test (page.test.ts)

- Gate 5: four payloads → correct label + variant. Guard: degraded payload
  must not render "Active".

## Task 12 — Gates + docs + PR

- `gofmt -s -l`, `go vet ./...`, `go build ./...`.
- `go test -race -count=1 ./internal/automation/... ./internal/api/...`
  (capture real exit — no pipe-to-tail, per the go-test-pipe-masks-exit
  lesson).
- `cd web/frontend && npm run check && npm test`.
- Reinject the two load-bearing guards (Task 2, Task 5 gate 3).
- `docs/operations/monitoring.md` one-liner for the in-UI badge.
- Commit (no Co-Authored-By per project rule), push, open PR → v2.83.0.

## Flake note

`TestOpenAPI_RolesMatchTheRouter` can panic intermittently under parallel
load (`topology_snapshot.go:112`, nil store in the test harness) — a
pre-existing flake, not introduced here. If it surfaces in CI, re-run;
don't mistake it for a regression from this lot.
