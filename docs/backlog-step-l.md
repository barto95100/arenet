# Step L — Backlog

Items deferred from Step L work. Inspired by the per-step backlog
convention used in `docs/backlog-step-j.md`.

## 1. From L.2 review (2026-05-28)

### Finding #L.2-1 — Pre-existing staticcheck warning: `oidc.go pathJoin` unused — RESOLVED in M.0 sweep (2026-05-28)

**Status**: RESOLVED in M.0 sweep (2026-05-28).

Surfaced by the L.2 close-out `staticcheck ./internal/api/...`
run. Predates Step L (introduced in commit `1d7bc19d`, Step K.2
work). Not touched in L.2 because it was outside the L.2 surface;
deferred to verify cosmetic vs URL-encoding bug.

**Symptom:**

```
internal/api/oidc.go:1006:6: func pathJoin is unused (U1000)
```

**Resolution.** Inspected every URL-construction site in
`internal/api/oidc.go`. The two `IssuerURL` consumers
(`oidc.NewProvider` and the OIDCConfig hash for cache
invalidation) both pass the URL verbatim — `go-oidc`
constructs the `.well-known/openid-configuration` path
internally, and the API edge strips that suffix server-side
before persistence. No call site uses string concatenation
that should have routed through `pathJoin`. **Function is
genuinely dead code; removed in the M.0 sweep commit.**

### Finding #L.5-1 — main.go log line hardcoded :8080 — RESOLVED in M.0 sweep (2026-05-28)

**Status**: RESOLVED in M.0 sweep (2026-05-28).

Surfaced by the L.5 smoke (2026-05-28). The "Arenet listening
http=:8080" log line in `cmd/arenet/main.go` was hardcoded and
ignored the `ARENET_HTTP_PORT` / `ARENET_HTTPS_PORT` override
that the prereq commit `7650802` had wired into Caddy. Caddy
itself bound the right port; only this one cosmetic log line
was wrong.

**Resolution.** Exported `caddymgr.HTTPListen()` and
`caddymgr.HTTPSListen()` accessors; main.go now reads from them
so the log line matches the actual bind, including under env
override. Verified by reading the new `Arenet listening` line
during the M.0 sweep smoke.

### Finding #L.2-2 — Last bucket of historical timeline lags up to 1 minute — RESOLVED inline in L.3 (2026-05-28)

**Status**: RESOLVED inline in L.3 (2026-05-28).

By design: the aggregator flushes at the minute boundary, so
the current (in-progress) minute is not yet persisted to
`bucket_1m`. The `/metrics/timeseries` endpoint returns the
dense window ending at the next bucket boundary — the very
last slot would be gap-filled (0 or null) until the next
flush.

**Resolution.** The L.3 dashboard + L.4 drill-down each call
`trimTrailing(resp)` which does `resp.points.slice(0, -1)` on
every timeseries before passing to the chart. The phantom
near-zero point at the right edge is dropped client-side. The
L.5 smoke verified live that data lands correctly and no fake
zero-cliff renders on the chart's right edge.

The live `reqPerSec` WebSocket pipeline (Step E topology view)
remains real-time and unaffected — the dashboard is
historical-only by design.

---

## 2. Closed

All three findings logged above are resolved. No open Step L
backlog items at this time. Future Step L work would re-open
this doc; Step M starts with a clean slate.
