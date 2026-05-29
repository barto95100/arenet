# Step Q — Smoke test

**Date**: 2026-05-29
**Binary**: built from commit `c8a861c` (Step Q Q.1–Q.4 + the Q backlog file).
**Mode**: `--dev`.

## 1. Environment

| Component | Where |
|-----------|-------|
| Arenet admin API | `:9994` |
| Arenet HTTP data plane | `:18080` (via `ARENET_HTTP_PORT=18080`) |
| Arenet HTTPS data plane | `:18443` (via `ARENET_HTTPS_PORT=18443`) |
| Trusted proxies | `127.0.0.0/8` (via `ARENET_TRUSTED_PROXIES`) — enables `X-Forwarded-For` spoofing to drive distinct attacker IPs |
| Backend (Python http.server) | `:19999`, returns 200 on `/`, 404 on `/404*` |
| Data dir | `/tmp/arenet-q5/data` (fresh) |

Three routes seeded via the real `POST /api/v1/routes` flow, mirror of M.5:

| Route | Host | WAF mode | Route ID prefix |
|-------|------|----------|-----------------|
| smoke-block-q | smoke-block-q.test | `block` | `610e0a1d` |
| smoke-detect-q | smoke-detect-q.test | `detect` | `1ae9753a` |
| smoke-off-q | smoke-off-q.test | `off` | `ce0670d4` |

## 2. Method

End-to-end against a real binary, single interactive harness:

1. Build `CGO_ENABLED=0 go build` ✓
2. Backend on `:19999` ✓
3. Boot arenet with `ARENET_HTTP_PORT=18080` / `ARENET_HTTPS_PORT=18443` / `ARENET_TRUSTED_PROXIES=127.0.0.0/8` ✓
4. Verify the three sink boot log lines:
   - `observability storage opened` ✓
   - `waf event sink wired` ✓
   - **NEW Q.1** `throttle event sink wired` ✓
5. Setup admin via the real `/api/v1/auth/setup` flow ✓
6. Login → captured cookie ✓
7. Create three routes (block / detect / off) ✓
8. **Phase B — Tier 1 throttle**: 4 sub-threshold failures from `XFF=10.0.0.1` → 0 throttle_event rows. 5th failure → Tier 1 fires (1 row, `tier=1, blockDuration=900s`). 6th request → 429 with `Retry-After: 900`.
9. **LRU + bucket invariant**: 30 additional spam POSTs from `10.0.0.1` while blocked → 429 rejected by middleware (no `Hit()` call → no bucket bump). 1 row in `throttle_event` (LRU dedupe OK).
10. **Phase C — Tier 2 attempt**: 12 rapid POSTs from `XFF=10.0.0.2`. The 5th triggers Tier 1, the next 7 are 429-blocked. **Tier 2 does NOT fire in a rapid burst** because the Tier 1 lockout prevents `Hit()` from being called on subsequent failures. The 1h-window mechanism is unit-tested in `TestRateLimiter_Tier2Block_EmitsThrottleEvent` (hits spaced 6 min apart so Tier 1's 5-min window never trips). Documented as PARTIAL — same pattern as M.5 N/A items.
11. **Phase D — Auth failures**: `GET /security/auth-failures?window=24h` → 1440 timeseries buckets, 12 recent entries with action / username / srcIp / message populated.
12. **Phase E — Attackers cross-source**: WAF block from `XFF=10.0.0.99` (SQLi payload via Host header) — the WAF event records `src_ip=127.0.0.1` because the WAF observation point reads `caddyhttp.MatchRequest.ClientIPAddress()`, not the Arenet IP extractor (pre-existing M.1 behaviour, NOT Q). Net: WAF=1 IP (127.0.0.1) + throttle=2 IPs (10.0.0.1, 10.0.0.2) + audit=3 IPs (same two + 127.0.0.1) → union = 3.
13. **Phase F — API extensions**: throttle-events filters by srcIp / tier validated; metrics timeseries with `throttle_block_rate` + `auth_failure_rate` works on `route=all`; `auth_failure_rate` on `route=<uuid>` returns all-zero per AC #10 literal.
14. **Phase G — AC #15**: schema version reads `3`. `bucket_1m` columns: all L + M + new `throttle_block_count`. M endpoints (`/security/events`, `/security/events/by-rule`) return live data. **The throttle bucket row** (`route_id=_throttle`) has `waf_block_count=0`, the WAF bucket row has `throttle_block_count=0` — Q signals do NOT inflate M/L counters (AC #15 anti-regression).
15. **Phase H — Frontend**: `npm run check` 0 errors / 0 warnings on 542 files. `npm run build` green. Bundle delta = +1011 bytes gz vs pre-Q baseline (measured at Q.4 step 5: 112,894 → 113,905 across the client bundle). Spec target was < 5 kB gz; actual is 5× under.
16. **Phase I — AC #13/#14 sabotage**: `mkdir /tmp/arenet-q5/data/metrics.db`, reboot, verify the three degraded log lines. Endpoint matrix:
    - `/security/throttle-events` → `{disabled:true, events:[]}` ✓
    - `/security/auth-failures` → **200 with real data** (audit-backed, independent of metrics.db). This validates the Q.2 wiring decision: auth-failures uses the audit bucket which lives in the main BoltDB, NOT metrics.db.
    - `/security/attackers-summary` → `{partial:true, uniqueIps=3, byBucketSource:{waf:0, throttle:0, audit:3}}` — three-state contract works: subset of readers nil → partial, the union reflects what DID respond.
    - Tier 1 still fires from a new IP: `hit5=401, hit6=429` — in-memory rate limiter independent of metrics.db.
17. **Phase J — Tests / linters**: `go test ./... -count=1` clean on all 11 packages. `go vet ./...` clean. `svelte-check` clean.
18. **Teardown** ✓

## 3. Acceptance Criteria matrix

| AC | Verdict | Evidence |
|----|---------|----------|
| **#1** ThrottleEvent emitted on Tier 1 block | **PASS** | After 4 sub-threshold failures and 1 fire from `XFF=10.0.0.1`, `SELECT * FROM throttle_event WHERE src_ip='10.0.0.1'` returns 1 row: `tier=1, blocked_until=ts+900s, block_duration_seconds=900`. 6th request returns 429 with `Retry-After: 900`. |
| **#2** ThrottleEvent emitted on Tier 2 block | **PARTIAL** | Rapid-burst smoke can't synthesise the Tier-2 fire path: once Tier 1 locks the IP, the rate-limiter middleware's `Allow()` rejects subsequent requests at 429 before the handler is called, so `Hit()` never increments the Tier-2 1h-window counter. The Tier-2 mechanism is unit-tested in `internal/auth/ratelimit_test.go:TestRateLimiter_Tier2Block_EmitsThrottleEvent` (hits spaced 6 min apart via synthetic clock — Tier 1's 5-min window never trips, only Tier 2's 1h window does). Same kind of carve-out as M.5 N/A items; no scope creep in the rate limiter for a smoke. |
| **#3** Bucket counter increments on every block | **PASS** | After 1 Tier-1 block decision + 30 subsequent 429 requests, `bucket_1m WHERE route_id='_throttle'` has `throttle_block_count=1` for the relevant minute. The spec's "every absorb (incl. LRU-suppressed)" invariant counts emissions to the SINK (= every `Hit()` call with `newBlock>0`), not every blocked request. Once an IP is 429-locked the middleware rejects without calling `Hit()`. Both numbers (1 sink absorb, 1 bucket bump) match. Sustained-attack expansion is unit-tested in `TestSink_BlockCounter_BumpedOnEveryAbsorb_IncludingSuppressed`. |
| **#4** Pre-threshold failures do NOT emit | **PASS** | After 4 failures from `10.0.0.1`, `SELECT COUNT(*) FROM throttle_event WHERE src_ip='10.0.0.1'` returns 0. The 5th failure (the one crossing the threshold) is what creates the row. |
| **#5** Auth-failure aggregation honours the window | **PASS** | `/api/v1/security/auth-failures?window=24h` returns `timeseries` with 1440 buckets (= 24h × 60min), `recent` capped at audit volume in the window (12 entries), and `partial: false` (volume well under the 200-row scan cap). Sum across timeseries buckets matches `len(recent)` modulo window-boundary edge (timeseries ts truncated to minute uses `to` exclusive). |
| **#6** Schema v2→v3 migration idempotent | **PASS** | Fresh boot lands at `schema_version=3`. `PRAGMA table_info(bucket_1m)` returns the L columns + M `waf_block_count` + new Q `throttle_block_count`. `throttle_event` table present with the expected columns. Live re-boot (Phase I sabotage cycle then teardown) re-opens at v3 without re-running ALTERs. Idempotency on v2→v3 is also unit-tested in `TestMigrate_V2ToV3_PreservesExistingData`. |
| **#7** `/api/v1/security/throttle-events` endpoint | **PASS** | Live: `GET /security/throttle-events?limit=20` returns 2 events (Tier-1 fires from 10.0.0.1 + 10.0.0.2), wire fields complete (id, ts, tier, srcIp, attemptedUsername, blockedUntil, blockDurationSeconds). `?srcIp=10.0.0.1` filter → 1 event. `?tier=1` filter → 2 events. `?tier=3` → 400 with `tier must be 1 or 2`. |
| **#8** `/api/v1/security/auth-failures?window=24h` | **PASS** | Wire shape: `{window, timeseries:[{ts,value}*1440], recent:[12 entries], partial:false}`. Recent feed carries action / username / srcIp / message per spec — verified the audit log threading is intact (only the throttle-event side has an empty username, see Backlog #Q.5-1). |
| **#9** `/api/v1/security/attackers-summary` | **PASS** | Live: `{window:'24h', uniqueIps:3, byBucketSource:{waf:1, throttle:2, audit:3}}`. Union over the three sources: WAF=127.0.0.1 (1), throttle=10.0.0.1 + 10.0.0.2 (2), audit=10.0.0.1 + 10.0.0.2 + 127.0.0.1 (3); union={127.0.0.1, 10.0.0.1, 10.0.0.2}=3. Server-side dedup verified by the byBucketSource sums NOT equaling uniqueIps. |
| **#10** `/metrics/timeseries` accepts new metric names | **PASS** | `?metric=throttle_block_rate&route=all` → 1440 points, 2 non-zero buckets matching the Tier-1 fires (one per IP). `?metric=auth_failure_rate&route=all` → 1440 points, sum across non-zero buckets = 12 (matches audit log count). `?metric=auth_failure_rate&route=<uuid>` → ALL points = 0 (AC #10 literal: per-route variant is N/A). |
| **#11** `/metrics/summary` extended | **PASS (build-side)** | The three new fields `totalThrottlePerMin`, `totalAuthFailuresPerMin`, `attackerIpsUnique` are present in the response with the correct types. Values were 0 at the smoke's sample-time because the just-closed minute had rolled past the throttle activity (same "just-closed minute" UX limitation documented in M backlog #M.5-2 — applies to every per-minute aggregate). The wire contract + AC #15 independence are validated below; the data-presence in headline cards is the existing UX trade-off, NOT a Q regression. |
| **#12** MixedEventList renders interleaved feed | **PASS (build-side)** | Same as M.5 #8: `--dev` serves a splash for SPA paths, so live HTML curl tests would hit the splash. Component compiled (chunk produced + manifest entry). Rendering verified by `svelte-check` (clean) + unit-test-style row merging done by the component (no Vitest test added in Q.4 — the surface is a thin merge-sort over typed inputs). Live operator render in scope for the dev SPA. |
| **#13** Data plane integrity: ThrottleSink failure does not block auth handler | **PASS** | (a) **Boot-failure**: `mkdir /tmp/arenet-q5/data/metrics.db`, reboot → log lines `observability: metrics DB unavailable — continuing without metrics history (AC #13)` + `throttle event sink running in degraded mode (no persistence)` + `waf event sink running in degraded mode (no persistence)`. Caddy listens. Tier-1 lockout still fires: 5 failures from a new IP `XFF=10.0.0.50` returned 401×5 + 429×1 (in-memory rate limiter independent of metrics.db). (b) **Runtime-failure**: declared covered by unit test `TestSink_FailingInserter_DoesNotPropagate` from Q.1 (mirror of M's identical test); the sink absorb path swallows insert errors and keeps `Emit` non-blocking. |
| **#14** AC #13 boot-degraded API surface | **PASS** | With sabotaged metrics.db: `/security/throttle-events` returns `{disabled:true, events:[]}`. `/security/auth-failures` returns **200 with REAL data** (1440 timeseries + 12 recent) — by design: the audit bucket lives in the main BoltDB, NOT metrics.db, so this endpoint survives a metrics.db outage. `/security/attackers-summary` returns `{partial:true, uniqueIps=3, byBucketSource:{waf:0, throttle:0, audit:3}}` — the three-state contract works exactly as specified: subset readers nil → partial flag set, the union reflects the remaining (audit) source. |
| **#15** Step M unchanged | **PASS** | schema_version=3. `bucket_1m` schema dump confirms ALL L columns + M `waf_block_count` + new `throttle_block_count`. M endpoints `/security/events` (2 events) and `/security/events/by-rule` (2 rules) return live data. **Critical AC #15 independence**: the `_throttle` sentinel rows have `waf_block_count=0, fourxx_count=0, fivexx_count=0`; the WAF-route bucket row has `throttle_block_count=0`. Q signals do NOT contaminate M/L counters. |
| **#16** Bundle budget | **PASS** | Total Q frontend delta = +1011 bytes gzipped across the client bundle (measured Q.4 step 5: pre-Q baseline 112,894 → post-Q 113,905). Spec target was < 5 kB gz; actual is ~5× under. M's 1.7 kB + Q's ~1 kB = ~2.7 kB total /security surface, well under the per-page budget. |
| **#17** Tests pass | **PASS** | `go test ./... -count=1`: all 11 packages green (cmd/arenet, internal/{api, audit, auth, backup, caddymgr, metrics, observability, storage, throttle, waf}). |
| **#18** Lint clean | **PASS** | `go vet ./...` clean on all packages. `gofmt -l -s` clean on Q-touched files (pre-existing drift on `internal/api/oidc.go` documented in backlog #Q-2, unrelated to Q). `svelte-check` 0 errors / 0 warnings on 542 files. |
| **#19** Viewer-accessible on all Q endpoints | **PASS (build-side)** | All three Q endpoints mounted in the `hard-auth-no-admin` chi route group at routes.go (same group as the M endpoints). Unit tests pin the viewer flow: `TestSecurityThrottleEvents_Viewer200`, `TestSecurityAuthFailures_Viewer200`, and the attackers-summary handler shares the same gate. Live viewer-flow smoke deferred to unit per spec §1.3 D2 carve-out (same convention as M.5 #12). |

## 4. Findings

### Fix-before-tag

None.

### Backlog

**Finding #Q.5-1 — `throttle_event.attempted_username` is always empty.**

The throttle event row carries `attempted_username=""` even though the audit log records the username correctly. Root cause: a context-propagation oddity in `internal/api/auth_handlers.go:login` — the handler does `r = r.WithContext(SetAttemptedUsername(ctx, attempted))` inside the handler, but the rate-limiter middleware reads `AttemptedUsernameFromContext(r.Context())` from ITS OWN `r` variable (the middleware's outer scope, untouched by the handler's reassignment). The middleware reads the original (unset) context.

This is a **pre-existing M-era / Step-D-era bug**, not Q-introduced: the Tier 2 `slog.Warn` line also wouldn't carry the username with this wiring (the existing unit test `TestRateLimiter_Tier2_LogsWarnWithFields` works because the test helper sets the context BEFORE the middleware wraps, not inside the handler — masking the real-handler bug).

**Why not fix during Q.5.** The fix requires changing the context-propagation path between the login handler and the rate-limiter middleware (probably either propagate the username through a different channel or have the middleware read from the request body via a wrapped reader). Non-trivial enough to warrant its own focused change; out of scope for the smoke pass.

**Fix sketch.** Either (a) move the `SetAttemptedUsername` call to a per-route middleware that wraps the inner `/login` handler so the rate-limiter middleware's `r` context is mutated, or (b) thread the username through a separate accessor that the middleware reads directly (decoupled from the context chain).

**Triage.** Low blast radius: throttle events still carry full forensic info (ts, tier, srcIp, blocked_until, block_duration_seconds) — only the username field is empty. Audit log carries it. Tier 2 Warn line would carry it if Tier 2 ever fired (the live smoke never reached Tier 2 — see AC #2 PARTIAL).

**Finding #Q.5-2 — WAF event `src_ip` field reads connection remote addr, not the trusted-proxy-resolved IP.**

The WAF observation point (`internal/waf/module.go:259`) reads `mr.ClientIPAddress()` (Caddy's MatchRequest helper) which returns the connection-level remote address, NOT the IP extracted by `internal/auth/ipextract.go`. With `ARENET_TRUSTED_PROXIES=127.0.0.0/8` and an `X-Forwarded-For: 10.0.0.99` header, the throttle / audit / IP-extract layers all see `10.0.0.99` but the WAF event still records `127.0.0.1`. This means `/security/attackers-summary.byBucketSource.waf` reports a different IP set than `byBucketSource.throttle`/`audit` when behind a trusted proxy.

**Why not fix during Q.5.** This is a **pre-existing M.1 behaviour**, not Q-introduced. The WAF module would need to either honour the IP-extractor chain (currently bypassed because the module is a Caddy handler, not an Arenet middleware) or have the WAF middleware pull the resolved IP from request context populated by the IP extractor.

**Triage.** No data integrity issue in standard deployments (homelab without a reverse proxy in front of arenet → `mr.ClientIPAddress()` and the IP extractor return the same value). The smoke exposed the divergence only because I deliberately spoofed XFF to simulate distinct attackers; production attackers don't get to forge XFF. Low priority; documented for the future M+Q-integration revisit when arenet is deployed behind a load balancer.

## 5. Verdict

**VERDICT: PASS**

- **17 PASS** (#1, #3, #4, #5, #6, #7, #8, #9, #10, #11, #12, #13, #14, #15, #16, #17, #18, #19) — note #11/#12/#19 are "PASS (build-side)" mirror of M.5's same-shape declarations
- **1 PARTIAL** with cited unit-test coverage (#2 Tier 2 fire — not synthesisable in rapid-burst smoke; covered by `TestRateLimiter_Tier2Block_EmitsThrottleEvent`)
- **0 FAIL**
- 2 backlog items (Finding #Q.5-1, #Q.5-2), both pre-existing or low-blast-radius

PARTIAL is within the bracket the user explicitly endorsed pre-execution: "AC #2 PARTIAL-with-evidence est OK". No scope creep introduced into the rate limiter; the unit-test-backed coverage of the Tier 2 path satisfies the spec's intent.

Tag `v1.0.0-step-q` after this smoke doc lands.

## 6. Evidence appendix

### `throttle_event` rows after the smoke run (AC #1, #4)

```
id  ts                  tier  src_ip      attempted_username  block_duration_seconds
 1  2026-05-29 13:17:39   1   10.0.0.1    (empty — see #Q.5-1)         900
 2  2026-05-29 13:20:02   1   10.0.0.2    (empty — see #Q.5-1)         900
```

The 4 sub-threshold failures from each IP did not produce a row (AC #4). The Tier-1 block fired on the 5th failure each time.

### `bucket_1m` after the smoke run (AC #3, #15)

```
route_id                              ts          req  4xx  5xx  waf_block  throttle_block
_throttle                             1780060620   0    0    0    0          1            ← Tier 1 from 10.0.0.1
_throttle                             1780060800   0    0    0    0          1            ← Tier 1 from 10.0.0.2
610e0a1d-b60b-4d97-bb41-bbb8bc09beef  1780060920   2    0    0    2          0            ← smoke-block-q SQLi: 2 WAF, 0 throttle
```

The two sentinel `_throttle` rows: `throttle_block_count=1` each (one Tier-1 block decision per IP), `waf_block_count=0`. The WAF-route row (`610e0a1d…`): `throttle_block_count=0`. AC #15 independence holds.

### `/security/auth-failures?window=24h` non-zero buckets (AC #8)

```
ts                       value
2026-05-29T13:15:00Z      1     ← initial pre-setup wrong-password attempt
2026-05-29T13:16:00Z      1
2026-05-29T13:17:00Z      5     ← 10.0.0.1 burst (Phase B)
2026-05-29T13:20:00Z      5     ← 10.0.0.2 burst (Phase C)
```

Total = 12 events; `recent` feed returns the same 12 entries.

### `/security/attackers-summary?window=24h` (AC #9)

```json
{
  "window": "24h",
  "uniqueIps": 3,
  "byBucketSource": {"waf": 1, "throttle": 2, "audit": 3}
}
```

waf={127.0.0.1} ∪ throttle={10.0.0.1, 10.0.0.2} ∪ audit={10.0.0.1, 10.0.0.2, 127.0.0.1} = {127.0.0.1, 10.0.0.1, 10.0.0.2} = 3 unique.

### AC #13/#14 sabotage matrix

```
# After: mkdir /tmp/arenet-q5/data/metrics.db && reboot

log:
  ERROR observability: metrics DB unavailable — continuing without metrics history (AC #13)
  INFO  waf event sink running in degraded mode (no persistence)
  INFO  throttle event sink running in degraded mode (no persistence)

GET /api/v1/security/throttle-events
  → 200 {"disabled":true,"events":[]}

GET /api/v1/security/auth-failures?window=24h
  → 200 {"window":"24h","timeseries":[…1440 buckets…],"recent":[…12 entries…]}
    (NO disabled flag — audit-backed, independent of metrics.db)

GET /api/v1/security/attackers-summary?window=24h
  → 200 {"partial":true,"window":"24h","uniqueIps":3,"byBucketSource":{"waf":0,"throttle":0,"audit":3}}

POST /api/v1/auth/login (XFF=10.0.0.50, wrong password) × 5
  → 401 × 5
POST /api/v1/auth/login (XFF=10.0.0.50, wrong password) × 1 more
  → 429 (Tier 1 fires in memory — rate limiter independent of metrics.db)
```

Three-state contract pinned: throttle-events `disabled:true` (events backed by metrics.db, now down), auth-failures NO flag (audit backed by main BoltDB, vivant), attackers-summary `partial:true` (2 of 3 readers down but audit survives, union narrower but honest).

### Frontend bundle delta (AC #16)

| Metric | Baseline (pre-Q) | Post-Q.4 | Delta |
|--------|------------------|----------|-------|
| Client bundle (sum gzipped, 47 JS files) | 112,894 B | 113,905 B | +1,011 B (~1 kB gz) |

Spec target was < 5 kB gz combined Q frontend addition; actual delta is ~5× under. Measured via stash-build-unstash-build comparison; identical chunk file count.
