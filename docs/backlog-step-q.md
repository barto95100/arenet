# Step Q — Backlog

Items deferred from Step Q work. Same convention as
`docs/backlog-step-m.md`.

## 1. Pre-existing flakes surfaced during Q work

### Finding #Q-1 — `TestMetricsSummary_4xxAnd5xxAreIndependent` flakes on minute boundary

`internal/api/metrics_handlers_test.go:344` —
`TestMetricsSummary_4xxAnd5xxAreIndependent` (and its sibling
`TestMetricsSummary_5xxOnly_4xxStaysZero`) flakes when the
wall-clock minute ticks between the test's seed step and the
handler's read step.

**Mechanism.** The test computes the seed timestamp as
`time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)` and
seeds a row at that bucket. The /metrics/summary handler then
recomputes the same expression — but if the wall clock has
crossed a minute boundary in between, the two values differ by
one minute and the handler reads an empty bucket. Surface:
`TotalFourXxPerMin = 0, want 7` plus `TotalReqPerMin = 0, want 50`.

**Surfaced.** During the Q.3 step-5 `go test -race ./...` full
gate (2026-05-29). The race binary's longer build + test wall
time makes the boundary-crossing window wider than the un-raced
run, so the flake is more visible there. Re-running the test in
isolation 5× was green; rerunning the full /api race once after
the fail was also green.

**Why not fix during Q.3.** The defect is pre-existing (predates
Q work — likely from M.2 when the M field was added), and the
fix requires capturing a single shared `now` between the test
seed and the handler observation. The cleanest path is to thread
a clock injector through the summary handler (mirror of the
aggregator's `SetClock`) — non-trivial enough to warrant its own
focused change, NOT a side-load on a feature commit.

**Fix sketch.**

1. Add `func (h *Handler) SetNow(now func() time.Time)` to the
   API handler, defaulting to `time.Now`.
2. Replace the two literal `time.Now().UTC()` calls in
   `metricsSummary` with `h.now().UTC()`.
3. In `TestMetricsSummary_4xxAnd5xxAreIndependent` (+ siblings),
   pin a synthetic clock to a fixed `time.Time` and use it for
   both the seed and the handler.

**Triage.** Latent flake, low blast radius (one test class), not
a regression introduced by Q. Pick up as a standalone refactor
in a later step.

### Finding #Q-2 — Pre-existing gofmt drift on `internal/api/oidc.go`

`gofmt -l -s ./internal/api/` reports `oidc.go` as drifted on a
clean Q branch. Not Q-induced (the file is unchanged by Q
work). Mentioned here so it doesn't reappear in a future
gate-output as "Q-introduced". Fix as a separate one-line
`gofmt -w` commit when convenient.

**Triage.** Cosmetic, non-blocking.
