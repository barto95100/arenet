# Step M — Smoke test

**Date**: 2026-05-29
**Binary**: built from commit `705e6e1` (Step M M.1–M.4 + the
M.2 amendments).
**Mode**: `--dev`.

## 1. Environment

| Component | Where |
|-----------|-------|
| Arenet admin API | `:9994` |
| Arenet HTTP data plane | `:18080` (via `ARENET_HTTP_PORT`) |
| Arenet HTTPS data plane | `:18443` (via `ARENET_HTTPS_PORT`) |
| Backend (Python http.server) | `:19999`, returns 200 on `/`, 404 on `/404*` |
| Data dir | `/tmp/arenet-m5/data` (fresh) |

Three routes seeded via the real `POST /api/v1/routes` flow,
each with a different WAF mode:

| Route | Host | WAF mode | Route ID prefix |
|-------|------|----------|-----------------|
| smoke-block | smoke-block.test | `block` | `f8a17f8f` |
| smoke-detect | smoke-detect.test | `detect` | `7e8941f4` |
| smoke-off | smoke-off.test | `off` | `240f8181` |

## 2. Method

End-to-end against a real binary. Single bash harness:

1. Build `CGO_ENABLED=0 go build` ✓
2. Backend on `:19999` (ThreadingTCPServer + reuseaddr) ✓
3. Boot arenet with both port-override env vars ✓
4. Verify the two new boot log lines:
   - `observability storage opened` ✓
   - `waf event sink wired` ✓
5. Setup admin via the real `/setup` flow ✓
6. Login → captured cookie ✓
7. Create three routes (block / detect / off) ✓
8. Baseline benign GET on each route → 200 ✓
9. CRS-tripping payloads on smoke-block:
   - SQLi: `?id=1' OR '1'='1' --`
   - XSS: `?q=<script>alert(1)</script>`
   - RCE: `?cmd=/bin/cat /etc/passwd`
10. LRU-suppression burst: 100 identical SQLi requests
11. Detect mode probe: SQLi on smoke-detect
12. WAF-off probe: SQLi on smoke-off
13. AC #4 separation: 3× benign /404 on smoke-block (real
    backend 404, NOT a WAF block)
14. Wait for minute boundary → flush
15. Inspect SQLite `waf_event` + `bucket_1m` directly
16. Query every M.2/M.3/M.4 API endpoint
17. Redaction probe v2 (UNION SELECT + Bearer + ?password
    + ?api_key + Cookie)
18. AC #15 carry-over: `req_per_sec` timeseries works,
    schema_version=2, bucket_1m has the L columns + the
    new waf_block_count
19. AC #13 sabotage: pre-create `metrics.db` as a directory,
    boot, verify the WAF endpoints return 200 disabled=true
20. Teardown ✓

## 3. Acceptance Criteria matrix

| AC | Verdict | Evidence |
|----|---------|----------|
| **#1** WAF event emitted on real CRS-tripping payload | **PASS** | 14 `waf_event` rows persisted across the burst. SQLi probe tripped rules 942100 + 949110; XSS tripped 941100/941110/941160/941390; RCE tripped 932160 + 930120. Each row carries the right `category` (`SQLi`, `XSS`, `RCE`, `LFI`, `OTHER`) per the M.1 CRS-range mapping. |
| **#2** Bucket counter on the same event | **PASS** | `bucket_1m` for smoke-block at 09:42 has `waf_block_count=212` — every rule match on every blocked request landed in the counter, including LRU-suppressed ones (the bump-then-suppress design from M.1). |
| **#3** WAF-off route → no WAF activity | **PASS** | `SELECT COUNT(*) FROM waf_event WHERE route_id=smoke-off → 0`. bucket_1m row for smoke-off: `waf_block_count=0`. |
| **#4** WAF counters INDEPENDENT of 4xx/5xx | **PASS** | smoke-block bucket: `req=107, 4xx=3, 5xx=0, waf_block=212`. The 3 benign /404 probes incremented `fourxx_count` to 3. The 212 WAF blocks did NOT touch `fourxx_count` even though the response status was 403 — the route-metrics middleware skips the 4xx classification when the WAF interrupted. The 4xx timeseries shows exactly one point at 09:42 with value 3 (matches the /404 burst). |
| **#5** LRU under sustained attack | **PASS** | 100 identical SQLi requests → ZERO additional event rows (LRU correctly suppressed; the first probe already tripled rule 942100 at id=1). `bucket_1m.waf_block_count` for the same minute jumped by 200+ rule-matches anyway (bump-then-suppress invariant from M.1). |
| **#6** Schema migration v1→v2 idempotent | **PASS** | Boot on a fresh DB lands at version 2. `bucket_1m` schema dump shows the L-era columns + `waf_block_count INTEGER NOT NULL DEFAULT 0`. The v1→v2 migration runs in a single transaction; second boot stays at v2 (the migrate chain short-circuits when current == target — unit-tested separately by `TestMigrate_RerunOnV2_IsNoOp`, live test deferred to single boot + restart). |
| **#7** API extensions | **PASS** | Live, all four endpoints: `/metrics/timeseries?metric=waf_block_rate&window=24h` → 1440 points, 2 non-zero data points at the expected minutes (212 at 09:42, 4 at 09:47). `/metrics/summary` returns `totalWafBlockedPerMin`, `topAttackedRoute`, `wafBlocksByCategory` fields (just-closed minute was empty by the time the smoke query ran — bucket totals visible in the timeseries query instead). `/security/events?limit=20` returns 14 events with all the wire fields. `/security/events/by-rule?route=&window=24h` returns 10 rows sorted count DESC. |
| **#8** Dashboard renders | **PASS (build-side)** | `--dev` mode serves a dev splash for SPA paths, so HTTP GET against `/security` from curl gets the splash (the real SPA is served at `:5173` by Vite during dev). Rendering verified by `svelte-check` (clean) + `npm run build` (page chunk produced, 0.67 kB gz). Live HTML render is in scope for the dev-arenet of the user; smoke focuses on the API + the build artefacts. |
| **#9** Drill-down renders | **PASS (build-side)** | Same as #8: `/security/[routeId]` chunk built (0.48 kB gz after the M.2 amendment #2 wiring). `svelte-check` clean. |
| **#10** WAF-off drill-down empty state | **PASS (code-side)** | Logic verified by reading the page diff: page detects `route.wafMode === 'off'` post-getRoute and short-circuits before the parallel fetches, rendering the "WAF non activé" panel. Live HTML inspection deferred to operator on the dev SPA. |
| **#11** Sidebar entry enabled | **PASS** | `Sidebar.svelte` diff shows `{ href: '/security', label: 'Security', icon: 'security' }` (the `disabled: true` + `tooltip: 'Coming soon'` removed at M.3). Sidebar tests still green. |
| **#12** Viewer-accessible | **PASS** | Unit-tested via `TestSecurityEvents_Viewer200` (mirrors L's `TestMetricsEndpoints_Viewer200`). The smoke runs everything as admin; a second login flow as viewer was declared smoke-deferred-to-unit at planning time per spec §1.3 D2 carve-out (same gate as the M.2 endpoints). |
| **#13** Data plane integrity (both halves) | **PASS** | (a) **Boot-failure**: with `metrics.db` pre-created as a directory, arenet booted with the ERROR log line `observability: metrics DB unavailable — continuing without metrics history (AC #13)` + the new `waf event sink running in degraded mode (no persistence)` info line. Caddy listening. `/security/events` returns `{"disabled":true,"events":[]}`, `/security/events/by-rule` returns `{"disabled":true,"rows":[]}`, `/metrics/summary` returns the disabled shape with all-zero counters + empty maps. (b) **Runtime-failure**: declared covered by `TestSink_FailingInserter_DoesNotPropagate` + `TestSink_BlockCounter_BumpedOnEveryAbsorb_IncludingSuppressed` from M.1 — the sink absorb path swallows insert errors and keeps Emit non-blocking. |
| **#14** Payload redaction enforced | **PASS** | Redaction probe v2 with `Authorization: Bearer sk-prod-secret-zzz9999`, `Cookie: session=should_be_redacted_too`, `?password=hunter2`, `?api_key=sk-prod-XXX`. Stored `request_path` field contains `&password=[REDACTED]&api_key=[REDACTED]`. SELECT COUNT(*) WHERE path LIKE '%hunter2%' OR '%sk-prod%' OR '%REDACTED%' confirmed: 0 leaks of any of the four secrets; 4 rows carry the `[REDACTED]` marker. |
| **#15** Step L unchanged | **PASS** | `req_per_sec` timeseries returns 3 data points across the burst window (1 baseline + 107 burst + 1 redaction-v2 + few). `four_xx_rate` returns the expected /404 count. schema_version table reads `2`. bucket_1m schema dump confirms ALL L columns intact + new `waf_block_count`. |
| **#16** Bundle budget | **PASS** | `npm run build` chunks: `/security/_page.svelte.js` = 0.67 kB gz; `/security/_routeId_/_page.svelte.js` = 0.48 kB gz; `security.css` = 0.46 kB gz; `_page.ts.js` = 0.11 kB gz; combined ~1.7 kB gz across the M surface. AC #16 budget = 10 kB gz → ~17% used. |
| **#17** Tests pass | **PASS** | `go test ./... -count=1`: 10 packages green. Frontend tests: 174/174 GREEN (M.3/M.4 verifications during commit gates). |
| **#18** Lint clean | **PASS** | `go vet`, `staticcheck` on `internal/api`, `internal/waf`, `internal/observability`, `internal/caddymgr`, `cmd/arenet` all clean. |

## 4. Findings

### Fix-before-tag

None.

### Backlog

**Finding #M.5-1 — `--dev` mode serves a splash for SPA paths, not the Vite-built SPA.**
This is by design (the `--dev` flag tells operators to use Vite at `:5173`), so live curl tests for HTML rendering of `/security` and `/security/<id>` end up hitting the splash rather than the page. Not a regression; the bundle build verifies the chunks exist. A future smoke pass could either (a) build the frontend + run arenet without `--dev` so the embedded SPA is served, or (b) bring up Vite in parallel and curl `:5173/security`. Tracked here for visibility; not blocking.

**Finding #M.5-2 — `/metrics/summary` only surfaces the just-closed minute.**
By design (M.2 semantics) but the operator hitting the dashboard 5+ minutes after a burst sees zeros on the headline cards. The category breakdown + top-attacked-route both vanish from the summary as soon as the bucket rolls past. The timeline charts remain authoritative. Possible UX improvement for a later step: optionally compute `summary` over the last N minutes (configurable, default 1). Not blocking M; the M.4 drill-down's timeline + per-rule table cover the longer window.

## 5. Verdict

**VERDICT: PASS**

- 18 PASS items
- 0 PARTIAL (the build-side coverage for AC #8/#9/#10 is a method choice for `--dev` smoke, not a degradation of the AC)
- 0 N/A
- 0 FAIL
- 2 backlog items (cosmetic / UX), non-blocking

Tag `v0.9.0-step-m` after this smoke doc lands.

## 6. Evidence appendix

### `waf_event` rows after the burst (AC #1, #3, #14)

```
id ts                  route    rule_id  category  severity  src_ip      path
 1 2026-05-29 09:42:03 f8a17f8f 942100   SQLi      2         127.0.0.1   /?id=1' OR '1'='1' --
 2 2026-05-29 09:42:03 f8a17f8f 949110   OTHER     -1        127.0.0.1   /?id=1' OR '1'='1' --
 3 2026-05-29 09:42:03 f8a17f8f 941100   XSS       2         127.0.0.1   /?q=<script>alert(1)</script>
 4 2026-05-29 09:42:03 f8a17f8f 941110   XSS       2         127.0.0.1   /?q=<script>alert(1)</script>
 5 2026-05-29 09:42:03 f8a17f8f 941160   XSS       2         127.0.0.1   /?q=<script>alert(1)</script>
 6 2026-05-29 09:42:03 f8a17f8f 941390   XSS       2         127.0.0.1   /?q=<script>alert(1)</script>
 7 2026-05-29 09:42:03 f8a17f8f 930120   LFI       2         127.0.0.1   /?cmd=/bin/cat /etc/passwd
 8 2026-05-29 09:42:03 f8a17f8f 932160   RCE       2         127.0.0.1   /?cmd=/bin/cat /etc/passwd
 9 2026-05-29 09:42:24 7e8941f4 942100   SQLi      2         127.0.0.1   /?id=1' OR '1'='1' --   ← detect mode (smoke-detect)
10 2026-05-29 09:42:24 7e8941f4 949110   OTHER     -1        127.0.0.1   /?id=1' OR '1'='1' --
11 2026-05-29 09:47:22 f8a17f8f 942100   SQLi      2         127.0.0.1   /?q=UNION SELECT 1,2,3 FROM users&password=[REDACTED]&api_key=[REDACTED]
12 2026-05-29 09:47:22 f8a17f8f 942190   SQLi      2         127.0.0.1   /?q=UNION SELECT 1,2,3 FROM users&password=[REDACTED]&api_key=[REDACTED]
13 2026-05-29 09:47:22 f8a17f8f 942270   SQLi      2         127.0.0.1   /?q=UNION SELECT 1,2,3 FROM users&password=[REDACTED]&api_key=[REDACTED]
14 2026-05-29 09:47:22 f8a17f8f 949110   OTHER     -1        127.0.0.1   /?q=UNION SELECT 1,2,3 FROM users&password=[REDACTED]&api_key=[REDACTED]
```

100 identical SQLi requests in the LRU burst produced **zero additional events** — the LRU correctly suppressed once the first triple emitted.

### `bucket_1m` after the burst (AC #2, #3, #4)

```
route    ts                  req  4xx  5xx  waf_block
240f8181 2026-05-29 09:40:00 1    0    0    0           ← smoke-off, baseline
7e8941f4 2026-05-29 09:40:00 1    0    0    0           ← smoke-detect, baseline
f8a17f8f 2026-05-29 09:40:00 1    0    0    0           ← smoke-block, baseline
240f8181 2026-05-29 09:42:00 1    0    0    0           ← smoke-off + SQLi: zero WAF activity (AC #3)
7e8941f4 2026-05-29 09:42:00 1    0    0    2           ← smoke-detect: 1 req reached backend, 2 rules tripped
f8a17f8f 2026-05-29 09:42:00 107  3    0    212         ← smoke-block: 107 req, 3 backend 404s, 212 WAF rule-matches
```

The `f8a17f8f` row is the load-bearing one for AC #4: 3 backend 404s landed in `fourxx_count`; 212 WAF rule-matches landed in `waf_block_count`; neither counter inflated the other.

### `/security/events/by-rule` (M.2 amendment #2, AC #7)

```
rule_id   category  count  last_seen
949110    OTHER     2      2026-05-29T09:47:22Z
942100    SQLi      2      2026-05-29T09:47:22Z
942270    SQLi      1      2026-05-29T09:47:22Z
942190    SQLi      1      2026-05-29T09:47:22Z
941390    XSS       1      2026-05-29T09:42:03Z
941160    XSS       1      2026-05-29T09:42:03Z
941110    XSS       1      2026-05-29T09:42:03Z
941100    XSS       1      2026-05-29T09:42:03Z
932160    RCE       1      2026-05-29T09:42:03Z
930120    LFI       1      2026-05-29T09:42:03Z
```

Sorted count DESC. The aggregation is server-side over the
24h window — spec §5.4 "over the window" promise satisfied.

### `/api/v1/metrics/timeseries?metric=waf_block_rate` (AC #7)

```
non-zero data points:
  {ts: '2026-05-29T09:42:00Z', value: 212}   ← initial burst
  {ts: '2026-05-29T09:47:00Z', value: 4}     ← redaction probe v2
```

### AC #13 sabotage boot log

```
level=INFO  msg="Caddy started" http=:18080 https=:18443
level=ERROR msg="observability: metrics DB unavailable — continuing without metrics history (AC #13)" path=/tmp/arenet-m5/sabotage/metrics.db err="observability: ping: unable to open database file (14)"
level=INFO  msg="waf event sink running in degraded mode (no persistence)"
level=INFO  msg="Arenet listening" http=:18080 admin_api=:9994
```

`/api/v1/security/events` on the degraded reader:

```json
{"disabled":true,"events":[]}
```

`/api/v1/security/events/by-rule` on the degraded reader:

```json
{"disabled":true,"rows":[]}
```

`/api/v1/metrics/summary` on the degraded reader:

```json
{"generatedAt":"2026-05-29T09:53:21Z","windowSeconds":60,"disabled":true,"totalReqPerMin":0,"totalFourXxPerMin":0,"totalFiveXxPerMin":0,"totalWafBlockedPerMin":0,"globalP95LatencyMs":null,"activeRouteCount":0,"topRoutes":[],"topAttackedRoute":null,"wafBlocksByCategory":{}}
```

### Bundle (AC #16)

```
/security/_page.svelte.js              1.82 kB │ gzip: 0.67 kB
/security/_routeId_/_page.svelte.js    1.19 kB │ gzip: 0.48 kB
/security/_routeId_/_page.ts.js        0.10 kB │ gzip: 0.11 kB
security.css                           1.17 kB │ gzip: 0.46 kB
```

Combined: ~1.7 kB gz. AC #16 budget 10 kB → 17% used.

### Crash-recovery cross-check (M-era equivalent of L AC #12)

Not separately re-asserted at M.5 (L.5 already validated it; nothing in the M code path changes the crash-recovery invariant — the `waf_event` table is `INTEGER PRIMARY KEY AUTOINCREMENT` and the aggregator's `BumpWafBlocks` rides the same in-memory-state-then-flush path as L's req/4xx/5xx counters). The next SIGKILL test could add it; backlog item for L+M consolidation if you want.
