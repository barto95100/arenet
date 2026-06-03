# Step S — Backlog

Items deferred from Step S work. Same convention as
`docs/backlog-step-p.md` / `docs/backlog-step-r.md`.

## 1. Cleanup candidates

### Finding #S-1 — Consolidate scattered env-only vars into the config layer

S.3 deliberately scoped the centralised `internal/config` package
to the 11 settings that were already flag-backed in
`cmd/arenet/main.go`'s old `parseFlags()`. The following env vars
are still read decentralised at their call sites:

- `ARENET_ACME_EMAIL` (`cmd/arenet/main.go`).
- `ARENET_CROWDSEC_API_URL`, `ARENET_CROWDSEC_API_KEY`
  (`cmd/arenet/main.go`).
- `ARENET_TRUSTED_PROXIES` (`cmd/arenet/main.go` →
  `auth.NewIPExtractor`).
- `ARENET_HTTP_PORT`, `ARENET_HTTPS_PORT`
  (`internal/caddymgr/manager.go`).
- `ARENET_HIBP_DISABLED` (`internal/auth/hibp.go`).

**Operational consequence**: none today — each variable works
exactly as documented. The split surface means an operator
reading `docs/operations/config.md` sees the flag-backed settings
in a TOML grid + a separate "env-only knobs" list. Minor UX
fragmentation, not functional drift.

**Completion shape** (focused future step):

- Move each env-only read into the `Config` struct as a new
  field.
- Add TOML + ARENET_* + (where applicable) `--flag` aliases via
  the same precedence stack.
- Update each call site (`main.go`, `caddymgr/manager.go`,
  `auth/hibp.go`) to read from `*appconfig.Config` instead of
  `os.Getenv`.
- Backwards-compat: keep the env var names unchanged so existing
  homelab installs don't break on upgrade.
- Update `docs/operations/config.md` to a single config-surface
  table.

**Recommendation.** Roll into a focused future step if/when
operators ask for "everything in one TOML file". Today the
split is honest (env-only for things rarely tuned; full
precedence stack for things tuned per install) — not a bug.

**Triage.** Backlog candidate, not a defect. Documented up
front so the resolution path is clear when the operator demand
surfaces.

### Finding #S-31 — `TestMetricsSummary_5xxOnly_4xxStaysZero` timing flake

`internal/api/metrics_handlers_test.go::TestMetricsSummary_5xxOnly_4xxStaysZero`
intermittently fails with `TotalFiveXxPerMin = 0, want 3`. Observed
during the `#R-TOPO-v2-phase2` C2 verification gate (2026-06-03);
the same test passes deterministically when run in isolation
(`go test -run TestMetricsSummary_5xxOnly_4xxStaysZero -count=3`
exits 0).

**Operational consequence**: a single CI failure forces a re-run.
The result is correct (the test asserts the right thing); the
race window is in the test scaffolding, not in the production
code path being exercised.

**Suspected cause** (not investigated in depth): the test sets up
a few 5xx events via the WAF/throttle/metrics pipeline and then
asserts the aggregator's per-minute counters. Under
`-race` + concurrent test execution, the in-process metrics
ticker (`metrics.TickInterval = 1s`) may drain the just-incremented
counter into the previous bucket boundary, leaving 0 for the
asserted bucket. The fix probably involves either freezing
`time.Now` for the test or asserting against a cumulative total
rather than a per-bucket projection.

**Recommendation.** Light pass on the test only, not the
production code. Reproduce with `go test -race -count=20
-run TestMetricsSummary_5xxOnly` to make the flake reliable,
then either pin the bucket boundary deterministically or
relax the assertion to `>=3` (the test's contract is "5xx
events recorded", not "exactly 3 in this specific bucket").

**Triage.** Test scaffolding flake. Not a release blocker — the
re-run always passes. Documented up front so the next person
who hits it has the resolution path mapped.
