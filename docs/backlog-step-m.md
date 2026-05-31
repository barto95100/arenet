# Step M — Backlog

Items deferred from Step M work. Same convention as
`docs/backlog-step-l.md`.

## 1. From M.5 smoke (2026-05-29)

### Finding #M.5-1 — `--dev` mode serves a splash for SPA paths

The boot flag `--dev` makes arenet serve a small dev splash
at routes that aren't part of the admin API (the operator is
expected to run Vite at `:5173` for the real SPA). As a
result, live `curl` tests against `/security` and
`/security/<id>` hit the splash, not the page.

This is by design and matches the pattern Step L lived with —
the bundle build (`npm run build`) + `svelte-check` cover the
SPA quality bar, not the smoke harness. The smoke can opt into
a stronger live render check in a future pass by either:

- (a) running arenet WITHOUT `--dev` so the embedded SPA is
  served from the static bundle, or
- (b) bringing up Vite in parallel during the smoke and
  curling `:5173/security` instead.

**Triage**: not a regression, not blocking. Note here so the
next smoke author can make the explicit choice rather than
re-discovering the splash mid-run.

### Finding #M.5-2 — `/metrics/summary` only surfaces the just-closed minute

The M.2 wire shape aggregates over `[now-1min, now)`. An
operator opening the dashboard 5 minutes after an attack burst
sees zeros on the headline cards even though the burst is
clearly visible on the 24h timeline chart 1-2 cards below. The
`topAttackedRoute` headline + the `wafBlocksByCategory` strip
also vanish from the summary as soon as the bucket rolls past.

The timeline charts remain authoritative (24h / 30d windows).
For the v1.0 ship this is acceptable — the cards answer "what
is happening *right now*" which IS a useful question; longer
windows live in the chart. But a UX improvement for a later
step: optionally compute summary over the last N minutes
(default 1, configurable for an operator who prefers a
5-minute pulse).

**Triage**: UX-only, non-blocking. The M.4 drill-down's
timeline + per-rule table already cover the longer window.
Possible Step Q candidate alongside the rate-limit-events
audit work.

### Finding #M.5-3 — Crash-recovery not re-validated in M.5 (declared L-covered)

The L.5 smoke validated the SIGKILL crash-recovery path against
the L counter buckets. Step M adds `waf_block_count` (rides the
same aggregator path → same `bucket_1m` flush cycle) + the
`waf_event` table (per-event rows persisted by the sink's
batched flush, distinct from the aggregator).

The waf_event path's crash semantic: events buffered in the
sink's in-memory channel + pending slice are lost on SIGKILL —
same shape as L's "at most the in-memory accumulation for the
current window". Unit-tested by `TestSink_CleanShutdownFlushesPending`
(SIGTERM-style ctx-cancel triggers a final flush) but NOT
re-asserted live in M.5.

**Triage**: defer to L+M consolidation smoke. The invariant is
documented and unit-tested; the live re-validation cost
(restart arenet during a burst, count event-loss bound) is high
for low marginal evidence. Pick up if Step Q's rate-limit
events work touches the sink shape.

**Status (post-O sweep 2026-05-31).** Resolved at unit level
across all three event-table sinks. Step Q's throttle sink +
Step N's decision sink both inherit the same batched-channel-
flush shape, so the consolidation is now properly L+M+Q+N (O
adds no new sink). Three new tests landed, identically named
`TestSink_CrashLossBound_FlushedEventsPersist_PendingLost` in
`internal/{waf,throttle,crowdsec}/sink_test.go`. Each test
pins the FLIP SIDE of the existing clean-shutdown contract:
events flushed pre-crash → on disk; events still in the
pending slice → lost. The bound is at-most (FlushBatchSize -
1) events + the unbuffered channel residue.

Live full-restart smoke deliberately NOT added — the live
infra cost vs unit-test coverage is now well-balanced, and
the per-sink invariant tests are deterministic + isolated.

---

## 2. Closed

No items closed yet in Step M.
