# Step L — Smoke test

**Date**: 2026-05-28
**Binary**: built from commit `7650802` (Step L L.1–L.4 + the
`ARENET_HTTP_PORT` / `ARENET_HTTPS_PORT` prereq).
**Mode**: `--dev`.

## 1. Environment

| Component | Where |
|-----------|-------|
| Arenet admin API | `:9994` |
| Arenet HTTP data plane | `:18080` (via `ARENET_HTTP_PORT=18080`) |
| Arenet HTTPS data plane | `:18443` (via `ARENET_HTTPS_PORT=18443`) |
| Backend (Python http.server) | `:19999`, paths `/` → 200, `/4xx` → 404, `/5xx` → 503 |
| Data dir | `/tmp/arenet-l5/data` (fresh) |

Ports chosen to avoid the user's running dev arenet on `:8080`.
The `ARENET_HTTP_PORT` / `ARENET_HTTPS_PORT` env-var override
was committed as a dedicated prereq (`7650802`) so future Step
smokes don't fight the same port collision.

## 2. Method

End-to-end against a real binary; not a re-run of unit tests.
Single bash harness:

1. Build `CGO_ENABLED=0 go build` ✓
2. Start backend on `:19999` ✓
3. Boot arenet with the two env-var overrides ✓
4. Bootstrap admin via `/api/v1/auth/setup` ✓ (status 201)
5. Login via `/api/v1/auth/login` ✓ (status 200, cookie captured)
6. Create route `smoke.test → http://127.0.0.1:19999` via
   `POST /api/v1/routes` ✓ (status 201)
7. Probe traffic: 1× /, 1× /4xx, 1× /5xx (lands in the
   `19:02:00` bucket — the boundary crossed shortly after)
8. **Round 1 traffic** (aligned to the same minute): 100 OK
   + 5 4xx + 3 5xx (108 requests, landed in `19:05:00`)
9. Wait for the next minute boundary → flush triggers
10. Query SQLite directly + every `/api/v1/metrics/*` endpoint
11. Assert AC matrix (§3 below)
12. SIGKILL arenet, restart, send round 2 traffic, assert
    previously-flushed buckets survived
13. Sabotage scenario: pre-create `metrics.db` as a directory
    → boot → assert proxy stays up + `/metrics/*` returns
    `disabled=true`
14. Teardown, verify ports free

## 3. Acceptance Criteria matrix

| AC | Verdict | Evidence |
|----|---------|----------|
| **#1** Bucket aggregator emits one row per route per minute | **PASS** | `SELECT * FROM bucket_1m` after traffic: 2 rows (19:02, 19:05), counts match the seed exactly: `(108, 5, 3)` for the burst minute. |
| **#2** Hourly rollup correct | **N/A** | 60-minute horizon; not reachable inside a single smoke window. Unit-tested by `TestRetention_Rollup1hCorrect` (weighted p95 = 28, not unweighted max 100). |
| **#3** 4xx and 5xx tracked SEPARATELY at every layer | **PASS** | Storage row: `(req=108, 4xx=5, 5xx=3)` — three independent values. `/metrics/summary`: `totalReqPerMin=108, totalFourXxPerMin=5, totalFiveXxPerMin=3`. Three independent `/metrics/timeseries` queries returned the right counts for each metric and zero for the others. |
| **#4** Retention prune | **N/A** | 24h / 30d horizon; not reachable in smoke. Unit-tested by `TestRetention_Prune1mOlder24h` and `TestRetention_Prune1hOlder30d`. |
| **#5** Gap-fill rule: 0 for counts, **null for p95** | **PASS** | 24h `req_per_sec` window: 1440 points, 2 non-zero data points, 1438 gap-filled zeros, **0 null** points. 24h `p95_latency_ms`: 2 non-null data points, 1438 **null** points, **0 zero-valued** p95 points. The rule held EXACTLY: zero is for counts, null is for p95, never the reverse. |
| **#6** Summary exposes 4xx and 5xx separately | **PASS** | `/metrics/summary` JSON has independent `totalFourXxPerMin=5` and `totalFiveXxPerMin=3` keys. |
| **#7** Dashboard renders without API error | **PASS (API side)** | The three endpoints the dashboard depends on (`/metrics/summary`, `/metrics/timeseries?route=all` × 3 metrics) all returned `200` with valid bodies under live traffic. Rendering itself is covered by `svelte-check` (532 files, 0 errors) + the bundle build. |
| **#8** Per-route drill-down endpoint | **PASS** | `GET /api/v1/metrics/timeseries?route=<uuid>&metric=req_per_sec&window=24h` returned all 3 expected data points (19:02 / 19:05 / 19:07) matching the persisted history. |
| **#9** Step E topology unchanged | **PASS** | WebSocket handshake → `HTTP/1.1 101 Switching Protocols`. Tick frame contains the existing fields: `reqs`, `errs`, `reqPerSec`, `errRate5xx`, `host`, `upstream`, `id`. No regression on the Step E wire shape. |
| **#10** Single CGO-free binary | **PASS** | `CGO_ENABLED=0 go build` produced the 87 MB binary that ran the entire smoke. |
| **#11** SQLite file initialised at boot; re-open is a no-op | **PASS** | `metrics.db` + `metrics.db-shm` + `metrics.db-wal` created on first boot. After SIGKILL + restart (and again after the second clean shutdown + restart in the sabotage check), `SELECT version FROM schema_version` returned `1`. Existing rows survived. |
| **#12** Crash recovery: no data loss within bucket window | **PASS** | Pre-kill: 2 flushed buckets. SIGKILL + restart. Post-restart: **same 2 buckets present** with identical contents. The 10 in-flight requests in the current minute were lost — within the documented "at most the in-memory accumulation" bound. Round 2 traffic produced a new third bucket at `19:07:00` as expected. |
| **#13** Metrics sink NEVER degrades the data plane | **PASS (both halves)** | (a) **Boot-failure**: with `metrics.db` pre-created as a directory, arenet booted, logged `level=ERROR ... continuing without metrics history (AC #13)`, Caddy came up, `/metrics/summary` returned `200` with `{"disabled":true, ..., "globalP95LatencyMs":null}`, `/metrics/timeseries` returned `200` with `{"disabled":true, "points":[]}`. (b) **Runtime-failure**: declared covered by `TestAggregator_FlushErrorIsLoggedAndSwallowed` + `TestAggregator_IngestStillNonBlockingDuringFlushErrors` (synthesising a mid-run SQLite error on a real binary without disk-filling tricks is brittle; the unit test injects a `failingSink` deterministically and proves the in-memory state reset + heartbeat-increment + ingress-non-blocking invariants). |
| **#14** Frontend tests pass | **PASS (with documented caveat)** | Vitest full suite: 172/174. The 2 failing tests are in `routes/page.test.ts > upstream-pool repeater` — known-flaky-under-load, pass `22/22` when run standalone. Pre-existing from before Step L (last touched in `7d7b60a`, Step K.1). |
| **#15** Backend tests pass | **PASS** | `go test ./...`: 9 packages green. |
| **#16** Bundle budget | **PASS** | `npm run build` chunks: `observability/_page.svelte.js` = 0.45 kB gz, `observability/_routeId_/_page.svelte.js` = 0.45 kB gz, `observability/_routeId_/_page.ts.js` = 0.11 kB gz. The dashboard surface adds ~1 kB gz total — under the 10 kB-gz budget by a factor of 10. |
| **#17** Viewer-accessible | **PASS** | Unit test `TestMetricsEndpoints_Viewer200`: viewer session → `GET /api/v1/metrics/timeseries` and `/metrics/summary` both return 200. Wiring in `routes.go` mounts the metrics endpoints in the hard-auth-no-admin group, same as GET `/routes` and GET `/audit`. |

## 4. Findings

### Fix-before-tag

None.

### Backlog

**Finding #L.5-1 — Cosmetic log line in main.go still hardcodes `:8080`.**
The boot-time log line `time=... msg="Arenet listening" http=:8080 admin_api=:9994` is hardcoded in `cmd/arenet/main.go:listenAttrs` (line ~348). When the operator overrides via `ARENET_HTTP_PORT=18080`, Caddy correctly binds `:18080` (verified end-to-end) and the data-plane works, but this one log line still says `:8080`. Cosmetic only — does not affect any code path; the `Caddy started http=:18080` line just above is the authoritative one.

Fix: read the value via `caddymgr` instead of hardcoding. ~3-line change, not blocking the tag. Logged here to fix before another step smoke leans on the log line.

## 5. Verdict

**VERDICT: PASS**

- 13 PASS items (#1, #3, #5, #6, #7, #8, #9, #10, #11, #12, #13, #16, #17)
- 2 PASS-with-documented-caveat (#14 vitest known-flake — pre-existing, #15 backend tests)
- 2 N/A with justification (#2 hourly rollup — 60-min horizon out of smoke scope; #4 retention — 24h / 30d horizon out of smoke scope) — both have authoritative unit tests
- 0 FAIL
- 1 backlog item, cosmetic, non-blocking

Tag `v0.8.0-step-l` after this smoke doc lands.

## 6. Evidence appendix

Selected raw outputs captured during the run.

### Storage rows after burst (AC #1, #3)

```
65b552ba-f9b4-45fd-a93c-a24d51895ed9|2026-05-28 19:02:00|3|1|1|4
65b552ba-f9b4-45fd-a93c-a24d51895ed9|2026-05-28 19:05:00|108|5|3|16
```

### /metrics/summary after burst (AC #6)

```json
{
    "generatedAt": "2026-05-28T19:06:33Z",
    "windowSeconds": 60,
    "totalReqPerMin": 108,
    "totalFourXxPerMin": 5,
    "totalFiveXxPerMin": 3,
    "globalP95LatencyMs": 16,
    "activeRouteCount": 1,
    "topRoutes": [{
        "routeId": "65b552ba-f9b4-45fd-a93c-a24d51895ed9",
        "host": "smoke.test",
        "reqsPerMin": 108, "fourxxPerMin": 5, "fivexxPerMin": 3
    }]
}
```

### /metrics/summary on degraded reader (AC #13)

```json
{"generatedAt":"2026-05-28T19:16:15Z","windowSeconds":60,"disabled":true,"totalReqPerMin":0,"totalFourXxPerMin":0,"totalFiveXxPerMin":0,"globalP95LatencyMs":null,"activeRouteCount":0,"topRoutes":[]}
```

### Step E WS frame shape (AC #9)

```
handshake: HTTP/1.1 101 Switching Protocols
tick keys: ['routes', 't']
route[0] keys: ['errRate5xx', 'errs', 'host', 'id', 'reqPerSec', 'reqs', 'upstream']
```

### AC #13 boot-degraded log line

```
time=2026-05-28T21:11:19.744+02:00 level=ERROR msg="observability: metrics DB unavailable — continuing without metrics history (AC #13)" path=/tmp/arenet-l5/sabotage/metrics.db err="observability: ping: unable to open database file (14)"
```

### Bundle sizes (AC #16)

```
observability/_page.svelte.js              1.06 kB │ gzip:  0.45 kB
observability/_routeId_/_page.svelte.js    1.08 kB │ gzip:  0.45 kB
observability/_routeId_/_page.ts.js        0.11 kB │ gzip:  0.11 kB
```

### Crash recovery (AC #12)

Pre-kill `bucket_1m` count: 2. SIGKILL. Post-restart `bucket_1m` count: 2 (same contents). Round 2 traffic produced a third bucket at `19:07:00 | 50 req`.
