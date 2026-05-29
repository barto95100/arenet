# Step Q — Rate-limit + auth-failure events

**Status:** FROZEN — tag `v1.0.0-step-q-spec` on 2026-05-29.
**Target spec-freeze tag:** `v1.0.0-step-q-spec`.
**Target implementation tag:** `v1.0.0-step-q` after the Q.5 smoke
verdict PASS.
**Author:** Claude + Ludovic Ramos.
**Draft date:** 2026-05-29.

> Closes the THROTTLE + auth-failure feed signals in the Step M
> dashboard mocks. Builds DIRECTLY on the M foundation (waf.Sink
> shape, schema migration chain, dashboard chrome) — Step Q is
> the "second turn of the crank" on the security-events plumbing
> M already built. CrowdSec remains **Step N** (deferred since
> spec freeze), unchanged.
>
> The version bump to v1.0.x marks Q as the **completion of the
> Phase 2 Security & Threat dashboard** roadmap item; the next
> major bump moves to Phase 3.

---

## 1.1 Goal

Two security event sources still produce data the dashboard
ignores:

1. **Rate-limiter** — `internal/auth/ratelimit.go` blocks IPs
   after Tier 1 (5 failures / 5 min → 15 min block) and Tier 2
   (10 failures / 1 h → 1 h block) thresholds. Tier 2 fires a
   single `slog.Warn` line; Tier 1 fires silently. Nothing
   surfaces on the dashboard. The mock feed shows `THROTTLE`
   entries alongside WAF events; an operator under credential-
   stuffing attack sees the spike WAY before Tier 2 trips IF the
   feed shows Tier 1 too.
2. **Auth failures** — `ActionLoginFailure` /
   `ActionUnlockFailure` / `ActionOIDCLoginRejected` /
   `ActionOIDCCallbackInvalid` already land in the audit table.
   The mock feed wants them on the same timeline as WAF events
   (one place to look during an incident).

Step Q surfaces both. The signal is **complementary** to the WAF
log: WAF catches payload-level attacks (SQLi, XSS, RCE) on
business routes; the rate-limiter + auth-failure catch
credential-stuffing on the **admin surface**. Both belong on the
`/security` dashboard.

---

## 1.2 Scope

Five sub-tasks, mirror Step M's M.1–M.5 cadence:

| Sub-task | Surface       | Subject |
|----------|---------------|---------|
| Q.1      | backend       | Rate-limit event capture: extend the limiter to emit on EVERY block decision (Tier 1 + Tier 2). New event type + sink reuse + schema migration v2→v3 (new column `throttle_block_count` on `bucket_1m`/`bucket_1h` + new `throttle_event` table). |
| Q.2      | backend       | Auth-failure timeline: derive from existing audit log (no new sink). New `/api/v1/security/auth-failures` endpoint surfacing per-minute counts over a window + recent events feed. |
| Q.3      | backend       | REST API: extend `/metrics/timeseries` with `throttle_block_rate` + `auth_failure_rate`; extend `/metrics/summary` with `totalThrottlePerMin` + `totalAuthFailuresPerMin`; new `/api/v1/security/throttle-events` endpoint. |
| Q.4      | frontend      | Extend `/security` dashboard: 3 new stat cards (THROTTLE/min, AUTH-FAIL/min, ATTACKER IPs unique), 2 new timeline charts (throttle, auth-fail), recent-events feed widened to MIXED feed (WAF + THROTTLE + AUTH) with category badge per type. Per-route drill-down unchanged in M.4 (the new signals are not per-route — they're per-IP). |
| Q.5      | smoke + doc   | Live smoke. Real credential-stuffing burst against `/api/v1/auth/login` → verify Tier 1 → Tier 2 events both land; throttle bucket counter ticks; auth-failure events surface; dashboard stat cards + mixed feed populate. Tag `v1.0.0-step-q`. |

---

## 1.3 Locked decisions

(All decisions arbitrated 2026-05-29; rationale of record preserved.)

### D1 — Rate-limit event emission point → **A (every block decision, Tier 1 + Tier 2)**

**Constraint.** The rate limiter is on the auth handler's hot
path. Its current shape is "fast atomic-protected map of IP →
failure list + block-until ts". Adding per-block event capture
must not slow the auth path measurably.

**Options:**

- **D1.A — Emit on every BLOCK decision (Tier 1 OR Tier 2).**
  Wherever `newBlock > 0` triggers in `Record()`, push a
  `ThrottleEvent{tier, ip, attemptedUsername, blockedUntil,
  blockDuration}` onto a new ThrottleSink (mirror of waf.Sink).
  The hot path adds ONE non-blocking channel send (~50 ns under
  contention; drops on full, like the WAF sink). Tier 1 events
  are emitted alongside Tier 2 — that's the mock-feed promise.
- **D1.B — Emit on every FAILURE (not just block).**
  Every `Record()` call emits an event regardless of whether
  it crossed a threshold. Bigger volume (every typoed
  password from a legitimate user creates a row). Operator
  signal is louder but noisier; storage growth concern.
- **D1.C — Emit on Tier 2 only (current Warn-line surface).**
  Status quo. Tier 1 stays silent. Rejected by the user's
  earlier feedback ("Tier 1 = building up, Tier 2 = cliff;
  feed should show the build-up").

**Decision: A.** Tier 1 + Tier 2 = the block-decision signal
the mock wants. Successful auths and pre-threshold failures
stay invisible (the audit log already carries them as
`ActionLoginSuccess` / `ActionLoginFailure` for forensic
review). Volume bound: the per-IP LRU (see D9 + §1.6.5)
suppresses repeats within 60s, same shape as M's WAF sink.

**Rejected — D1.B:** every-failure emission. Adds legitimate
typed-password typos to the dashboard, which the operator
mostly wants to ignore. The audit log already records them.

**Rejected — D1.C:** Tier 2 only. Today's behaviour. The
mock feed needs the Tier 1 build-up visible BEFORE the
Tier 2 cliff — otherwise an operator only learns about
credential-stuffing once it's already crossed the deeper
threshold.

### D2 — Auth-failure timeline source → **B (server-side audit-bucket scan)**

**Constraint.** `ActionLoginFailure` etc. already land in the
audit table. The dashboard wants per-minute counts + a recent
events feed. Two paths:

- **D2.A — Derive client-side from the existing audit endpoint.**
  Frontend calls `/api/v1/audit?action=login_failure,...&since=...`,
  groups client-side. Pros: zero new code. Cons: (1) requires
  pagination cursors for a 24h/30d window, (2) every dashboard
  load re-aggregates client-side, (3) doesn't match the
  performance shape of M's bucket aggregator (M.4's drill-
  down's per-rule table was a similar trap — fixed in M.2
  amendment #2 by going server-side).
- **D2.B — New server-side aggregate endpoint, derived from
  audit at query time.** `GET /api/v1/security/auth-failures?
  window=24h` returns `{timeseries: [...], recent: [...]}`
  populated from a SINGLE bbolt scan over the audit bucket,
  filtered to the auth-failure action set. Pros: respects the
  M.2 amendment #2 lesson (server-side aggregation honours
  the window cleanly). Cons: bbolt audit is event-shaped,
  not bucketed — the query scans the audit bucket for the
  window and groups in-Go. At 100 failures/sec for 24h that's
  8.6M rows — way more than realistic auth-failure volume
  but still worth a cap.
- **D2.C — Mirror audit-failure events into the
  `metrics.db` event-sink pattern.**
  Audit handler emits to a new AuthFailureSink alongside the
  existing `audit.Append`. Sink writes to a new
  `auth_failure_event` table in metrics.db with the same
  shape as `waf_event`. Pros: query is identical to the WAF
  pattern; storage is uniform; M.3/M.4 dashboard widgets
  reuse 1:1. Cons: data duplication (event in BOTH audit
  table AND metrics.db); two stores to maintain.

**Decision: B.** The audit table is the source of truth for
auth events. Introducing a parallel store (D2.C) for the same
data is redundant + creates a sync-drift hazard. Client-side
aggregation (D2.A) doesn't scale beyond ~1 hour windows and
re-pays the cost on every dashboard load.

**Implementation contract** (forced by D2.B):

- New `audit.Store.QueryByActionRange(ctx, actions []Action,
  from, to time.Time, limit int) ([]Event, error)` method
  that walks the audit bucket in reverse-ts order, stops at
  `limit` rows scanned OR `to` boundary, returns rows whose
  action ∈ `actions`. Bounded scan, never reads the full
  bucket; the audit storage layer already exposes `List`
  with filtering — the new method is a narrow variant that
  filters by an **action set** (the existing API filters by
  a single action; adding multi-action filter at the storage
  layer avoids N parallel calls in the api handler).
- **Hard cap** of 50,000 rows scanned per call. Beyond that
  the handler returns a `partial: true` flag in the wire
  response + a recommendation to narrow the window. Rationale:
  bbolt iteration over a giant audit bucket is single-threaded;
  a runaway query could block the audit hot path. The cap is
  defence-in-depth on top of the natural smallness of
  auth-failure volume.
- Auth-failure ACTION SET (from `internal/audit/actions.go`):
  `login_failure`, `unlock_failure`, `oidc_login_rejected`,
  `oidc_callback_invalid`. NOT `password_compromised_detected`
  (that's HIBP signal, not an authentication attempt).
  NOT `setup_admin_created` (that's a success). The set is
  pinned in `internal/api/security_handlers.go` as
  `authFailureActions`; future audit actions can opt in by
  joining the slice.

**Rejected — D2.A** (client-side scan): pagination cursor
required for 24h, every dashboard load re-aggregates. The
M.2 amendment #2 lesson explicitly warned against this
shape.

**Rejected — D2.C** (parallel sink mirror): double-write
+ two sources of truth for the same data + sink-failure-
drift hazard (sink-side row count diverges from audit row
count under load). The audit volume is small enough that
server-side scan is the cheapest correct answer.

### D3 — Throttle schema → **A (bucket counter + event table, mirror M)**

If D1.A is chosen, Q.1 needs the migration chain to bump
again:

- **D3.A — Extend `bucket_1m` / `bucket_1h` with
  `throttle_block_count INTEGER NOT NULL DEFAULT 0`.**
  AND create a new `throttle_event` table for per-event
  detail (IP, attempted_username, tier, blocked_until_ts).
  Indexes on `ts`, `(src_ip, ts)`.
- **D3.B — Skip the bucket column; keep ThrottleEvents
  ONLY in their own table.**
  Counter for the dashboard is derived from
  `SELECT COUNT(*) FROM throttle_event WHERE ts >= …` per
  bucket. Simpler schema; per-tick aggregator doesn't need a
  new counter. Cons: dashboard timeline = 1440 COUNT
  queries on 24h window (or one big GROUP BY).

**Decision: A.** Mirror the M.1 shape. Dashboard timeline
reads the bucket counter (fast scan over the existing
bucket index); recent-events widget reads the event table.

**Concrete schema for v2 → v3 (inside the existing migrate-
chain in `internal/observability/migrate.go`):**

```sql
ALTER TABLE bucket_1m ADD COLUMN throttle_block_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bucket_1h ADD COLUMN throttle_block_count INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS throttle_event (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  tier INTEGER NOT NULL,               -- 1 or 2
  src_ip TEXT NOT NULL,
  attempted_username TEXT NOT NULL,    -- verbatim per D8.A; may be empty
  blocked_until INTEGER NOT NULL,      -- unix seconds
  block_duration_seconds INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_throttle_event_ts        ON throttle_event (ts);
CREATE INDEX IF NOT EXISTS idx_throttle_event_src_ip_ts ON throttle_event (src_ip, ts);

UPDATE schema_version SET version = 3;
```

Single transaction, idempotent re-open. Default 0 on the
new column means existing rows from pre-Q deployments
remain readable.

**Rejected — D3.B** (event-table-only): 1440 `COUNT(*) WHERE
ts BETWEEN ...` queries per timeline view, OR one big GROUP
BY ts that doesn't use any existing index. The bucket counter
is the canonical fast path; we already paid the migration
cost in M.1.

### D4 — Auth-failure aggregation in the bucket layer? → **B (no, audit-scan only)**

A parallel question for D2.B: should auth-failure counts also
land in `bucket_1m` / `bucket_1h` as a column (so the timeline
chart reads from buckets, matching the WAF pattern)?

- **D4.A — Yes, mirror M.1.** Add
  `auth_failure_count INTEGER NOT NULL DEFAULT 0` to the
  bucket tables. The Q.2 endpoint queries audit at request
  time but ALSO writes a per-minute count into bucket_1m
  for the timeline chart. Two sources of truth, the audit
  table is canonical.
- **D4.B — No, audit-only.** The timeline endpoint scans
  the audit table per-request and groups by minute on the
  fly. No bucket counter, no second write path. Simpler;
  one source of truth.

**Decision: B.** Auth-failure volume on a homelab is tiny
(a handful per day in normal operation; bursts during
credential-stuffing but capped by the rate limiter itself).
The audit-bucket scan handles it cleanly. Avoid the
double-write D4.A would introduce — same drift hazard as
D2.C, just with smaller blast radius.

**Implementation contract:**

- Auth-failure timeline is computed by the Q.3 endpoint
  `GET /api/v1/security/auth-failures?window=24h` on the
  fly from a single audit-bucket scan (per D2.B).
- The endpoint returns BOTH a per-minute timeseries (for
  the `/security` dashboard's chart) AND the most-recent
  N rows (for the mixed-feed widget) in one response —
  one scan, two projections.
- The `/metrics/timeseries?metric=auth_failure_rate`
  endpoint (Q.3) is implemented as a thin redirect to the
  same audit-scan path, projected to the metrics wire
  shape with gap-fill rule = 0 for missing buckets. NOT
  served from `bucket_1m`.

**Trade-off acknowledged.** Two distinct timeline data
sources on the same dashboard (`bucket_1m`-backed for
WAF/throttle/req/4xx/5xx; audit-scan-backed for
auth-failures). The frontend doesn't care — both return
`{points: [{ts, value}, ...]}`. The operator doesn't see
the asymmetry.

**Rejected — D4.A:** double-write hazard outweighs the
performance win for a metric whose volume is, in practice,
single-digit per minute.

### D5 — Mixed event feed → **A (one MixedEventList)**

The dashboard mock shows a single feed with WAF / THROTTLE /
AUTH entries interleaved. The current `WafEventList` shows
only WAF. Two paths:

- **D5.A — One MixedEventList widget.** Replace WafEventList
  on the dashboard with a new MixedEventList that fetches
  from the three endpoints in parallel + merges sorted by ts.
  Per-row category badge identifies the source. Drill-down
  page (M.4) keeps WafEventList unchanged (per-route view is
  WAF-specific; throttle/auth are not per-route).
- **D5.B — Three SEPARATE event widgets.** Dashboard shows
  three stacked widgets (WAF Events / Throttle Events / Auth
  Failures). Operator sees them clustered visually, but loses
  the time-interleaving that makes "burst across the system"
  obvious.

**Decision: A.** New `MixedEventList.svelte` widget on the
`/security` dashboard replaces the existing `WafEventList`.
Fetches the three event sources in parallel + merges sorted
by `ts` desc. Per-row category badge identifies the source
(WAF / THROTTLE / AUTH).

**Drill-down page (M.4) stays on `WafEventList`** — the
per-route view is intentionally WAF-only (throttle + auth
failures are per-IP, not per-route; routing them into the
per-route drill-down would mis-attribute attacker IPs to
whichever route they happened to hit first).

**Rejected — D5.B:** three stacked widgets. Loses the
time-interleaving that makes "system-wide burst" obvious.

### D6 — Unique attacker IPs stat → **A (server-side union)**

The mock has an "ATTACKER IPs unique" stat card. Three event
sources contribute IPs: `waf_event.src_ip`,
`throttle_event.src_ip`, `audit.Event.ip`. Stat card needs
the **union** count over the window.

- **D6.A — Compute server-side**, new handler
  `/api/v1/security/attackers-summary` doing the union scan
  over the three tables.
- **D6.B — Compute client-side** from the three feeds the
  dashboard already fetches.

**Decision: A.** New endpoint
`GET /api/v1/security/attackers-summary?window=24h` returns
`{uniqueIps: <int>, byBucketSource: {waf: N, throttle: N, audit: N}}`.
Server-side union over the three event sources: scan
`waf_event.src_ip DISTINCT`, `throttle_event.src_ip DISTINCT`,
and the audit-bucket auth-failure IPs (via the audit-scan
path from D2.B) — union those into a Go `map[string]struct{}`
and return the count.

The `byBucketSource` breakdown is a bonus for the dashboard
to show "12 unique attackers (WAF: 8, THROTTLE: 3, AUTH: 5)"
if useful; primary value is the union count. Honest "over
the window" semantics.

**Rejected — D6.B:** client-side union pays the
window-derived re-aggregation cost on every dashboard load.

### D7 — Sink emit position in the rate limiter → **A (outside mutex)**

A subtle concern. Today's `Record()` is `O(failures-list-length)`
under a single mutex. Adding a sink emit:

- **D7.A — Emit OUTSIDE the mutex** (after Unlock), like the
  existing Tier-2 Warn line. Same shape, well-tested pattern.
- **D7.B — Emit INSIDE the mutex.** Simpler control flow but
  serialises behind contention.

**Decision: A.** `Record()` releases the mutex first (already
the pattern for the Tier-2 Warn line — see
`internal/auth/ratelimit.go` lines ~244-254), then emits to
the throttle sink. Same shape as M's `waf.Sink.Emit`: channel
send + default-case drop. Auth handler's hot path takes ONE
extra atomic-bounded operation (~50 ns); no blocking under
contention.

### D8 — `attempted_username` exposure → **A (verbatim, parity with audit log)**

The rate limiter already accepts `attemptedUsername` and logs
it in the Tier-2 Warn. Putting it in a queryable event row
raises a small privacy question: an attacker spraying
"admin", "root", "guest" credentials produces those usernames
in the dashboard. That's the signal we WANT (operator sees
"someone is guessing valid usernames"). But a legitimate
typo also produces the typed username — a one-off audit log
entry was fine; a dashboard widget surfacing it 24h later
is louder.

- **D8.A — Capture verbatim** (same as the audit's existing
  behaviour). Operator-visible. Mitigation: the dashboard
  shows the username inside the THROTTLE entry, not as a
  standalone column. Operator can correlate but it's not
  prominent.
- **D8.B — Capture, but redact on display** if the username
  matches a known existing user (anti-typo policy). Complex;
  introduces an authorisation-flavoured leak ("if redacted,
  it WAS a real user"). Rejected as worse than transparent.
- **D8.C — Capture hashed.** Operator sees a hash; can
  correlate across events but not read the literal value.
  Reduces noise but defeats the "someone is spraying
  'admin'" signal.

**Decision: A.** Stored verbatim in `throttle_event.
attempted_username`. The audit log already exposes it via
`ActionLoginFailure.ActorUsernameAttempted` (Step K.2's
operator-attempt tracking); Step Q maintains parity. The
"someone is spraying 'admin'" signal is the value of the
field.

§1.6 documents this as the deliberate exposure. The redaction
pass from `internal/waf/redact.go` is NOT applied to
`attempted_username` — it's not a credential, it's the
username portion of a credential attempt.

**Rejected — D8.B** (redact-if-real-user): introduces an
authorization-flavoured leak ("if redacted, the user
exists"). Worse than transparent.

**Rejected — D8.C** (hash): defeats the spray signal.

### D9 — Throttle retention → **A (30d like M waf_event)**

- **D9.A — Same as M waf_event:** 30d at row granularity for
  `throttle_event`; bucket counter rides the existing 24h/30d
  retention.
- **D9.B — Longer for throttle.** Credential-stuffing
  forensics matter weeks later (the post-incident "did we see
  this IP last month?" question). Could push to 90d.

**Decision: A.** `throttle_event` rides the same retention
prune as `waf_event` (30d at row granularity, hourly prune
loop). The bucket counter on the existing bucket tables
inherits L's 24h / 30d retention. New constant
`RetainThrottleEvents = 30 * 24 * time.Hour` in
`internal/observability/retention.go`. New prune step in
`RetentionRunner.tick()`.

**Rejected — D9.B** (longer retention for security forensics):
operators who need >30d snapshot `metrics.db` externally,
same answer as M.

---

## 1.4 Out of scope

- **CrowdSec integration** → Step N (still deferred, unchanged
  from M).
- **WAF per-rule severity tuning** → Step Q does NOT touch the
  WAF surface from M.
- **Network-level IP-block enforcement.** Q's "ATTACKER IPs"
  stat card surfaces the data; acting on it (firewall, fail2ban
  hand-off, CrowdSec push) is Step N.
- **Alerting / notifications** on threshold crossings → Phase 3.
- **Audit log full-text search.** The Q endpoints filter audit
  events by action+time; arbitrary search stays out of scope.
- **Per-route auth-failure attribution.** A failed login is
  against the admin surface, not a route — Q does NOT add
  per-route auth-failure stats. The dashboard's existing M
  per-route drill-down stays WAF-only.

---

## 1.5 Range of change

**New backend package: `internal/throttle/`** (mirrors
`internal/waf/` minus the Caddy module, since the throttle
event source is the auth handler, not Caddy):

| Path | Touch |
|------|-------|
| `internal/throttle/event.go` (NEW) | `Event` type (Ts, Tier, SrcIP, AttemptedUsername, BlockedUntil, BlockDurationSeconds). |
| `internal/throttle/sink.go` (NEW) | `EventSink` interface + `BlockCounter` interface + production `Sink` (channel-buffered, batched flush, recover-on-panic). Direct copy of `waf/sink.go`'s shape with the WAF-specific bits stripped — same AC #13 invariants, same Inserter/BlockCounter split. |
| `internal/throttle/lru.go` (NEW) | Per-(SrcIP, Tier) LRU, 10k cap, 60s TTL. Mirrors `waf/lru.go` with a 2-keyed tuple (the throttle event doesn't have a rule_id concept). |
| `internal/throttle/global.go` (NEW) | `SetGlobalSink` / `getGlobalSink` package singleton, mirrors `waf/global.go`. Allows the rate limiter to emit without a constructor-injected sink (the rate limiter is itself a singleton created at boot before the sink). |
| `internal/throttle/*_test.go` (NEW) | Unit tests per file. LRU concurrency-safety test. Sink: AC #13 paths (nil inserter, failing inserter, panic recovery), block-counter bump-on-every-absorb, clean-shutdown flush. |

**Backend — existing files extended:**

| Path | Touch |
|------|-------|
| `internal/auth/ratelimit.go` | + sink emit OUTSIDE the mutex (per D1.A + D7.A) on every block decision (Tier 1 or Tier 2). Re-uses the existing `tier2Triggered` / `logBlockedUntil` plumbing — adds a `tier1Triggered` counterpart for symmetry. The Tier-2 slog.Warn line stays (operator log retention path). |
| `internal/audit/store.go` (or `internal/audit/query.go` NEW) | + `QueryByActionRange(ctx, actions []Action, from, to time.Time, limit int) ([]Event, error)` method per D2.B. Walks the audit bucket reverse-ts. **Hard cap 50,000 rows scanned**. The audit package already has `List(ctx, filter)`; this new method is the multi-action-set variant. |
| `internal/observability/migrate.go` | v2→v3 migration step (per D3.A): ALTER bucket_1m + bucket_1h to add `throttle_block_count`, CREATE TABLE `throttle_event` + indexes, bump `schema_version` to 3. Same single-transaction shape as v1→v2. |
| `internal/observability/storage.go` | + `ThrottleEvent` type + `ThrottleEventFilter` + `InsertThrottleEventBatch` + `QueryThrottleEvents` + `PruneThrottleEventsOlderThan`. Bucket InsertBatch / Query / QueryAggregated extended with the new column. |
| `internal/observability/bucket.go` | + `ThrottleBlockCount int64` on `MetricBucket`. |
| `internal/observability/aggregator.go` | + `BumpThrottleBlocks(srcIP string)` method on `Aggregator` that satisfies `throttle.BlockCounter`. The aggregator's per-route bump keys on `routeID`; this new bump is per-IP (no route concept), so it lands in a NEW global-totals slot rather than the per-route routeState. Spec implementation detail in §3.5. |
| `internal/observability/retention.go` | + `RetainThrottleEvents = 30 * 24 * time.Hour` constant; + prune step in `RetentionRunner.tick()` for the new table; + sum on hourly rollup. |
| `internal/api/handler.go` | + `ThrottleEventReader` interface (`QueryThrottleEvents`, `AggregateThrottleEventsByTier`). + `AuthFailureReader` interface (`QueryAuthFailures`, `AggregateAuthFailuresOverWindow`). + matching setters. |
| `internal/api/security_handlers.go` | + `securityThrottleEvents` handler (GET `/security/throttle-events`). + `securityAuthFailures` handler (GET `/security/auth-failures`). + `securityAttackersSummary` handler (GET `/security/attackers-summary`). + extended `metricsSummary` with `totalThrottlePerMin`, `totalAuthFailuresPerMin`, `attackerIpsUnique`. |
| `internal/api/metrics_handlers.go` | + `throttle_block_rate` + `auth_failure_rate` to `metricName` enum; + `pickMetricValue` routes `throttle_block_rate` to `bucket.ThrottleBlockCount`; `auth_failure_rate` is special-cased to detour through the audit-scan path (per D4.B). |
| `internal/api/routes.go` | Mount three new endpoints in the hard-auth-no-admin group (viewer-accessible). |
| `cmd/arenet/main.go` | + `throttle.NewSink(throttleInserterAdapter{obsStore}, obsAggregator, logger, throttle.SinkConfig{})` + `throttle.SetGlobalSink`. + `auditFailureReaderAdapter` wiring on `apiHandler`. AC #13 degraded path: nil store → no-op sink (mirror of M wiring). |

**Frontend:**

| Path | Touch |
|------|-------|
| `web/frontend/src/lib/api/types.ts` | + `ThrottleEvent`, `AuthFailureEvent`, `AttackersSummary` types; + new `MetricName` literals (`throttle_block_rate`, `auth_failure_rate`); + new `SummaryResponse` fields (`totalThrottlePerMin`, `totalAuthFailuresPerMin`, `attackerIpsUnique`). |
| `web/frontend/src/lib/api/security.ts` | + `fetchThrottleEvents`, `fetchAuthFailures`, `fetchAttackersSummary` typed wrappers. |
| `web/frontend/src/lib/components/MixedEventList.svelte` (NEW) | Interleaved feed: parallel fetch of 3 event sources, merge sort by ts desc, per-row category badge. Reuses the M.3 category-color mapping for WAF; new colours for THROTTLE (status-warn) + AUTH (status-info). |
| `web/frontend/src/routes/security/+page.svelte` | + 3 new stat cards (THROTTLE/min, AUTH-FAIL/min, ATTACKER IPs unique), + 2 new timeline charts (throttle, auth-fail), replace `WafEventList` with `MixedEventList`. Layout grows: 5 → 8 stat cards (wraps to 2 rows). |
| `web/frontend/src/routes/security/[routeId]/+page.svelte` | **No change.** Per-route drill-down stays WAF-only (per D5 carve-out: throttle + auth are per-IP, not per-route). |

**Docs / smoke:**

| Path | Touch |
|------|-------|
| `docs/smoke-test-step-q.md` (NEW) | Q.5 evidence + verdict. |
| `docs/backlog-step-q.md` (NEW, if findings accumulate). |

---

## 1.6 Threat model deltas vs Step M

### 1.6.1 Attempted-username exposure (D8.A)

Documented as deliberate. Dashboard exposes the attempted
username inside the THROTTLE event row, mirroring the audit
log's existing behaviour. Operator visibility on
credential-stuffing patterns is the signal we want; the audit
log already gives an attacker who reads it the same data, so
Q.4 doesn't introduce a new disclosure.

### 1.6.2 Source-IP exposure: same contract as M

`src_ip` on ThrottleEvent + AuthFailureEvent is verbatim from
the request's remote address (after the trusted-proxy chain
resolution). Same operator note as M §1.6.3: behind an
internal LAN, expect RFC1918 addresses in the feed.

### 1.6.3 No new redaction surface

ThrottleEvents don't carry payload bodies — the rate limiter
sees only IP + attempted username. No `[REDACTED]` work needed
beyond what M already does for waf_event.

### 1.6.4 Hot-path safety on the auth handler (D7.A invariant)

Sink emit happens AFTER `mu.Unlock()` in `Record()`. The
emit's `select { case ch <- evt: default: drop }` is O(1) and
never blocks the auth path. A full channel drops the event;
the audit log row still lands (audit.Append is the source of
truth for forensics).

### 1.6.5 Storage growth bound

ThrottleSink reuses the LRU per (src_ip, tier) — same shape
as M's per-(route,ip,rule) LRU but two-keyed. 60s TTL; under
sustained attack a single attacker IP emits one Tier-1 row +
one Tier-2 row per 60s, regardless of failure count. Bucket
counter ticks every block decision (not LRU-filtered), so
volume signal stays accurate.

---

## 2. Acceptance Criteria

Numbered, each PASS / PARTIAL / N/A at Q.5 smoke time.

**AC #1 — ThrottleEvent emitted on Tier 1 block.**
5 failed POST `/api/v1/auth/login` within `Tier1Window` from
a single source IP triggers a 15-minute block (existing
behaviour). Q adds: a `throttle_event` row with `tier=1`,
populated `src_ip`, `attempted_username`, `blocked_until`,
`block_duration_seconds`. Smoke verification: live curl
burst against `/auth/login` → `SELECT * FROM throttle_event
WHERE tier=1` returns the expected row.

**AC #2 — ThrottleEvent emitted on Tier 2 block.**
The existing Tier-2 slog.Warn line continues to fire (no
regression on operator-log integrations). Q adds: a
`throttle_event` row with `tier=2` AND the bucket counter
ticks. Verification: continue the AC #1 burst to 10 failures
within `Tier2Window` → assert a second `throttle_event` row
+ Warn line still in arenet.log.

**AC #3 — Bucket counter increments on every block.**
Mirror of M AC #5: the LRU may suppress repeated `throttle_
event` rows for the same (src_ip, tier) within 60s, but
`bucket_1m.throttle_block_count` ticks on every block
decision (bump-then-suppress invariant). Smoke verification:
sustained attack 100 failures from one IP → 1 event row in
the steady state + bucket counter += 1 per block decision.

**AC #4 — Pre-threshold failures do NOT emit.**
The first 4 failed logins within `Tier1Window` produce zero
`throttle_event` rows (no threshold crossed). The audit log
still records each via `ActionLoginFailure` — the divide is
"audit = every failure for forensics; throttle event = every
block decision for the dashboard signal."

**AC #5 — Auth-failure aggregation honours the window.**
`GET /api/v1/security/auth-failures?window=30d` returns
events older than 24h alongside recent ones. The audit-scan
path (D2.B) walks the full window correctly. M.2 amendment
#2 lesson carried: never silently truncate to "most-recent N
events" when the contract says "over the window".

**AC #6 — Schema v2→v3 migration idempotent.**
Boot on a pre-Q `metrics.db` (Step M era, schema_version=2)
runs the migration in one transaction: `bucket_1m` +
`bucket_1h` gain `throttle_block_count`; new `throttle_event`
table created. Existing waf_event rows + Step-M data
preserved. Re-opening a v3 DB is a no-op (no second ALTER).
Verified live by snapshotting an M-era metrics.db and booting
Q against it.

**AC #7 — `/api/v1/security/throttle-events` endpoint.**
Wire shape:
```json
{
  "events": [
    {"id": 1, "ts": "2026-...", "tier": 1, "srcIp": "1.2.3.4",
     "attemptedUsername": "admin", "blockedUntil": "2026-...",
     "blockDurationSeconds": 900}
  ],
  "disabled": true | false
}
```
Optional filters: `limit` (capped server-side at 100),
`srcIp`, `tier`. Viewer-accessible. AC #14 boot-disabled +
503-on-query-error paths match the M.2 pattern.

**AC #8 — `/api/v1/security/auth-failures?window=24h`.**
Wire shape: `{timeseries: [{ts, value}, ...], recent: [{ts,
action, srcIp, attemptedUsername}, ...], partial?: true,
disabled?: true}`. Single audit-scan, two projections (per
D2.B + D4.B). `partial: true` set if the scan hit the 50k
row cap before reaching the window's `from`.

**AC #9 — `/api/v1/security/attackers-summary`.**
Wire shape: `{uniqueIps: <int>, byBucketSource: {waf: N,
throttle: N, audit: N}, disabled?: true}`. Server-side
union over the three sources (D6.A).

**AC #10 — `/metrics/timeseries` accepts the new metric
names.** `throttle_block_rate` reads from `bucket_1m.
throttle_block_count` (gap-fill = 0 for missing buckets,
same shape as `waf_block_rate`). `auth_failure_rate` reads
from the audit-scan path (per D4.B), projected to the
`{points: [{ts, value}]}` wire shape with gap-fill = 0.
Both metrics support `route=all` (the per-route variant is
N/A — neither signal is per-route, so `route=<uuid>` returns
all-zero).

**AC #11 — `/metrics/summary` extended.** Adds three new
fields: `totalThrottlePerMin: <int>`, `totalAuthFailures
PerMin: <int>`, `attackerIpsUnique: <int>`. The L/M fields
stay unchanged.

**AC #12 — MixedEventList renders interleaved feed.**
`/security` dashboard widget shows WAF + THROTTLE + AUTH
rows sorted ts desc. Each row carries a category badge
identifying the source. Three event sources fetched in
parallel; merge happens client-side after the fetches
resolve.

**AC #13 — Data plane integrity: ThrottleSink failure does
not block the auth handler.**
- (a) **Boot-failure**: nil `metrics.db` → throttle sink in
  no-op mode (events drop). Auth handler still serves
  login requests. Smoke verifies the `level=INFO
  msg="throttle event sink running in degraded mode"`
  log line + login still works.
- (b) **Runtime-failure**: declared covered by the unit
  test `TestSink_FailingInserter_DoesNotPropagate`
  (mirror of M's same-named test, mechanical port).

**AC #14 — AC #13 boot-degraded API surface.**
With sabotaged `metrics.db`, the three new endpoints
(`/throttle-events`, `/auth-failures`, `/attackers-summary`)
return 200 with `disabled: true` and empty bodies. Same
contract as the M endpoints under sabotage.

**AC #15 — Step M unchanged.** Re-run the M.5 matrix subset
at Q.5: `/api/v1/security/events` works, `/security/events/
by-rule` works, WAF block on a payload still produces a
`waf_event` row + `bucket_1m.waf_block_count` tick.
Schema version reads `3`. Bucket schema dump shows all M
columns + new `throttle_block_count`.

**AC #16 — Bundle budget.** Combined `/security/*`
frontend surface adds < 5 kB gz on top of M's 1.7 kB. Total
security surface < 10 kB gz, well under the per-page
budget. (The M.4 drill-down chunk is unchanged.)

**AC #17 — Tests pass.** `go test ./... -count=1` clean
across all packages (existing + new `internal/throttle`).
Vitest baseline 174/174 (or higher if Q adds tests).

**AC #18 — Lint clean.** `go vet`, `staticcheck` clean on
the Q surface. `svelte-check` clean (no new errors / warnings).

**AC #19 — Viewer-accessible on all Q endpoints.**
The three new endpoints sit in the hard-auth-no-admin group
(same as the M endpoints). Anti-regression test mirroring
`TestSecurityEvents_Viewer200`: a viewer-role user can read
the new endpoints; anon receives 401.

---

## 3. Architecture impact

### 3.1 Domain model deltas

```go
// internal/throttle/event.go (NEW)
type Event struct {
    Ts                   time.Time
    Tier                 int    // 1 or 2
    SrcIP                string
    AttemptedUsername    string // verbatim per D8.A
    BlockedUntil         time.Time
    BlockDurationSeconds int
}

// internal/observability/storage.go — extend MetricBucket
type MetricBucket struct {
    RouteID            string
    Ts                 time.Time
    ReqCount           int64
    FourxxCount        int64
    FivexxCount        int64
    WafBlockCount      int64
    ThrottleBlockCount int64 // ← NEW, Step Q
    LatencyP95Ms       int32
}

// internal/observability/storage.go — new persisted type
type ThrottleEvent struct {
    ID                   int64
    Ts                   time.Time
    Tier                 int
    SrcIP                string
    AttemptedUsername    string
    BlockedUntil         time.Time
    BlockDurationSeconds int
}
```

### 3.2 Rate-limiter integration (Q.1)

`internal/auth/ratelimit.go`'s `Record()` currently emits a
single slog.Warn line on Tier 2 (lines ~246-253). Q extends:

```go
// After mu.Unlock() in Record(), before returning:
if tier1Triggered {
    if sink := throttle.GetGlobalSink(); sink != nil {
        sink.Emit(throttle.Event{
            Ts:                   now,
            Tier:                 1,
            SrcIP:                ip,
            AttemptedUsername:    attemptedUsername,
            BlockedUntil:         logBlockedUntil,
            BlockDurationSeconds: int(Tier1Block.Seconds()),
        })
    }
}
if tier2Triggered {
    // existing slog.Warn line stays
    if sink := throttle.GetGlobalSink(); sink != nil {
        sink.Emit(throttle.Event{Tier: 2, ...})
    }
}
```

`tier1Triggered` is the new symmetry-with-tier2 boolean
captured under the mutex; the emit happens outside the mutex
per D7.A. **Auth hot path adds ONE channel send per block
decision; never blocks.**

### 3.3 Event sink

```go
// internal/throttle/sink.go (NEW)
type EventSink interface {
    Emit(Event)
}

type BlockCounter interface {
    BumpThrottleBlocks(srcIP string)
}

type Inserter interface {
    InsertThrottleEventBatch(ctx context.Context, events []Event) error
}

type Sink struct { ... }  // mirror of waf.Sink
```

Direct mechanical port of `internal/waf/sink.go` minus the
WAF-specific bits. Same Run / absorb / flush shape, same AC
#13 invariants, same LRU rate-limit pattern.

### 3.4 REST API

**Extended endpoints:**

- `/api/v1/metrics/timeseries` — new metric names
  `throttle_block_rate`, `auth_failure_rate`.
- `/api/v1/metrics/summary` — new fields per AC #11.

**New endpoints (Q.3):**

- `GET /api/v1/security/throttle-events?limit=&srcIp=&tier=` —
  pure event log read, mirrors `/security/events`.
- `GET /api/v1/security/auth-failures?window=` — combined
  timeseries + recent feed, single audit-scan.
- `GET /api/v1/security/attackers-summary?window=` —
  server-side union IP count.

All viewer-accessible, all AC #13-degraded-friendly.

### 3.5 Aggregator per-IP slot (subtle)

L/M's `observability.Aggregator` tracks per-route state via
`routeState`. Throttle events are per-IP, not per-route —
they have NO routeID concept. Question: where does
`BumpThrottleBlocks(srcIP)` increment?

**Decision (forced by the data model):** the throttle bump
goes into a NEW per-bucket-row slot keyed by the synthetic
route ID `"_throttle"` (a sentinel that never collides with a
real route — UUIDs don't have an underscore prefix). The
existing aggregator infrastructure (per-route map, per-minute
flush) handles it without modification — same code path,
different key.

The frontend dashboard's "throttle/min" stat card reads
`bucket_1m WHERE route_id='_throttle'` aggregated, OR
equivalently `SUM(throttle_block_count) WHERE
route_id='_throttle'`. Either query is cheap.

**Alternative considered:** add a new top-level aggregator
slot (not via routeState). Rejected because the existing
flush path's transactional shape is already correct; piggy-
backing on routeID="_throttle" is the smaller change.

Documented in §1.6 as the load-bearing convention: the
sentinel `"_throttle"` is reserved at the storage layer.

### 3.6 Schema migration

```sql
-- internal/observability/migrate.go (v2→v3)
ALTER TABLE bucket_1m ADD COLUMN throttle_block_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bucket_1h ADD COLUMN throttle_block_count INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS throttle_event (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  tier INTEGER NOT NULL,
  src_ip TEXT NOT NULL,
  attempted_username TEXT NOT NULL,
  blocked_until INTEGER NOT NULL,
  block_duration_seconds INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_throttle_event_ts        ON throttle_event (ts);
CREATE INDEX IF NOT EXISTS idx_throttle_event_src_ip_ts ON throttle_event (src_ip, ts);

UPDATE schema_version SET version = 3;
```

Wrapped in a single transaction (same shape as v1→v2).

### 3.7 Retention

`RetentionRunner` gains a third prune step:

```go
// Delete throttle_event rows older than RetainThrottleEvents (30d).
DELETE FROM throttle_event WHERE ts < ?
```

Runs on the existing hourly cadence alongside the M
`waf_event` prune.

---

## 4. Sub-tasks (ordered)

| # | Title | Surface | Commit |
|---|-------|---------|--------|
| Q.1 | ThrottleSink + rate-limit emit + schema v2→v3 | backend | 1 |
| Q.2 | AuthFailureReader + audit-scan timeline | backend | 1 |
| Q.3 | REST API extensions + 3 new endpoints | backend | 1 |
| Q.4 | Dashboard mixed feed + stat cards + charts | frontend | 1 |
| Q.5 | Smoke + tag `v1.0.0-step-q` | smoke + doc | 1 + tag |

---

## 5. Per-sub-task design

### 5.1 Q.1 — ThrottleSink + rate-limit emit + schema v2→v3

**New files:**
- `internal/throttle/event.go` — `Event` struct (no
  truncation needed — fields are bounded by definition;
  IP / username are short, ts is timestamp, durations
  are ints).
- `internal/throttle/sink.go` — `EventSink` +
  `BlockCounter` + `Inserter` interfaces; production
  `Sink` mirroring `waf.Sink`.
- `internal/throttle/lru.go` — Per-(SrcIP, Tier) LRU,
  10k cap, 60s TTL. Tuple key = `srcIp + "|" + strconv.
  Itoa(tier)`.
- `internal/throttle/global.go` — `SetGlobalSink` /
  `GetGlobalSink` (exported this time — the rate
  limiter is in a different package and the
  conventional getter shape is the cleanest path).
- Tests for each: round-trip Emit → Inserter, AC #13
  paths (nil inserter, failing inserter), LRU
  rate-limit per tuple, BlockCounter bump on every
  absorb (incl. suppressed), panic-recovery on Run.

**Migration:**
- `internal/observability/migrate.go` gains a
  `migrateV2toV3` step. Bumps `currentSchemaVersion`
  to 3. Per-step tests mirror the v1→v2 tests
  (idempotent, preserves data, creates the new table
  + indexes).

**Storage:**
- `internal/observability/storage.go` gains
  `InsertThrottleEventBatch`, `QueryThrottleEvents`
  (filter: SrcIP, Tier, From, To, Limit cap 100),
  `PruneThrottleEventsOlderThan`. Bucket
  InsertBatch / Query / QueryAggregated extended with
  the new `throttle_block_count` column.
- `internal/observability/bucket.go` gains
  `ThrottleBlockCount int64`.
- `internal/observability/aggregator.go` gains
  `BumpThrottleBlocks(srcIP string)` method (per
  §3.5 sentinel pattern).
- `internal/observability/retention.go` gains
  `RetainThrottleEvents` constant + prune step + sum
  on hourly rollup.

**Rate limiter:**
- `internal/auth/ratelimit.go` `Record()` extended
  with `tier1Triggered` symmetry + emit OUTSIDE the
  mutex (per D7.A). Existing Tier-2 Warn line stays.

**Tests:**
- `TestRateLimit_EmitOnTier1Block`: 5 failures → 1
  throttle_event row with tier=1.
- `TestRateLimit_EmitOnTier2Block`: 10 failures →
  additional throttle_event with tier=2.
- `TestRateLimit_NoEmitBeforeThreshold`: 4 failures
  → 0 throttle_event rows.
- `TestRateLimit_SinkNil_DoesNotPanic`: nil global
  sink → Record() still works.
- Existing rate-limit tests stay green.

### 5.2 Q.2 — AuthFailureReader + audit-scan timeline

**New files (or extensions):**
- `internal/audit/store.go` (or split into
  `internal/audit/query.go`) — `QueryByActionRange(
  ctx, actions []Action, from, to time.Time, limit
  int) ([]Event, hitCap bool, error)`. Walks the bucket
  reverse-ts; stops at limit OR from boundary. Returns
  `hitCap = true` when limit hit before from.

**API:**
- `internal/api/handler.go` gains `AuthFailureReader`
  interface (`QueryAuthFailures`) — separate from
  the audit reader to keep the API layer's mock
  surface narrow.
- `internal/api/security_handlers.go` gains
  `securityAuthFailures` handler: pulls the audit
  scan, projects to timeseries + recent feed in one
  pass.

**Tests:**
- `TestAudit_QueryByActionRange_FilterByActionSet`:
  seed audit events with mixed actions; verify only
  the auth-failure subset is returned.
- `TestAudit_QueryByActionRange_HitsCap`: seed >
  cap events; verify hitCap=true + the slice is
  capped.
- `TestSecurityAuthFailures_TimeseriesGapFill`:
  verify the per-minute groupBy with gap-fill = 0
  for empty minutes.
- `TestSecurityAuthFailures_RecentFeedSortedDesc`:
  verify the recent feed is ts-desc.
- AC #14 paths (nil reader, scan error).

### 5.3 Q.3 — REST API extensions + 3 new endpoints

**Touched files:**
- `internal/api/metrics_handlers.go` — extend
  `MetricName` enum with `throttle_block_rate` +
  `auth_failure_rate`; `pickMetricValue` routes
  `throttle_block_rate` to `bucket.ThrottleBlockCount`;
  `auth_failure_rate` is special-cased in the
  timeseries handler to detour through the
  AuthFailureReader.
- `internal/api/security_handlers.go` — three new
  handlers (`securityThrottleEvents`,
  `securityAuthFailures`, `securityAttackersSummary`).
- `internal/api/handler.go` — three new interfaces +
  setters.
- `internal/api/routes.go` — three new routes mounted.
- `cmd/arenet/main.go` — wire the three readers (all
  satisfied by `*observability.Store` + the audit
  store).

**Tests:**
- `TestSecurityThrottleEvents_*`: anon 401, viewer
  200, nil 200-disabled, error 503, validation 400,
  filter by srcIp / tier, limit cap.
- `TestSecurityAuthFailures_*`: same gates +
  window-mapping (24h/30d) + partial-flag handling.
- `TestSecurityAttackersSummary_*`: server-side
  union correctness (seed 3 sources with overlapping
  IPs, verify the count + the breakdown).
- `TestMetricsTimeseries_ThrottleBlockRate`: verify
  the new metric flows through the existing handler.
- `TestMetricsTimeseries_AuthFailureRate`: verify
  the special-cased audit-scan detour.
- `TestMetricsSummary_NewFields`: verify
  totalThrottlePerMin + totalAuthFailuresPerMin +
  attackerIpsUnique are populated.
- `TestMetricsSummary_NewFields_IndependentFromM`:
  AC #15 anti-regression — Q burst doesn't inflate
  M fields and vice versa.

### 5.4 Q.4 — Dashboard mixed feed + stat cards + charts

**Touched files:**
- `web/frontend/src/lib/api/types.ts` — new types per
  §1.5.
- `web/frontend/src/lib/api/security.ts` — three new
  typed wrappers.
- `web/frontend/src/lib/components/MixedEventList.svelte`
  (NEW) — parallel fetch + merge.
- `web/frontend/src/routes/security/+page.svelte`:
  - 3 new stat cards (THROTTLE/min, AUTH-FAIL/min,
    ATTACKER IPs unique). Layout wraps to 2 rows on
    narrow screens, 8 cards visible on wide.
  - 2 new timeline charts (throttle, auth-fail).
  - Replace `WafEventList` with `MixedEventList`.
- `web/frontend/src/routes/security/[routeId]/+page.svelte`:
  **No change.** Per-route drill-down stays WAF-only.

**Bundle target:** combined Q frontend additions < 5 kB
gz. M shipped at 1.7 kB gz total; Q should add ~3 kB gz
in the worst case (the new widget + the 3 new endpoints'
typed wrappers).

### 5.5 Q.5 — Smoke + tag

Mirror Step M.5 smoke. Differences:
- **Credential-stuffing burst**: 11+ POST `/api/v1/auth/
  login` with bad password from a single source IP. Tier
  1 fires at 5, Tier 2 at 10. Verify both events land +
  bucket counter ticks + Warn line still fires.
- **Auth failures**: verify `/security/auth-failures`
  returns the timeseries + recent feed from the audit
  log.
- **Attackers summary**: trip a WAF block on a CRS payload
  + a throttle block on credential-stuffing from DIFFERENT
  IPs → expect uniqueIps=2 with byBucketSource breakdown.
- **Mixed feed**: verify the dashboard's `MixedEventList`
  interleaves the three sources by ts.
- **AC #13 sabotage**: mkdir at metrics.db, boot, assert
  `/throttle-events` + `/auth-failures` + `/attackers-
  summary` all return 200 disabled=true.
- **AC #15 carry-over**: re-run M.5 matrix subset to
  prove no regression on WAF / observability.

---

## 6. Migration strategy

`metrics.db` schema v2 → v3 via the existing migrate-chain
pattern. Two ALTERs (`bucket_1m`, `bucket_1h` get
`throttle_block_count`) + one CREATE (`throttle_event` table).
No bbolt schema change — the audit bucket stays as-is.

---

## 7. Smoke test plan (skeleton, filled at Q.5)

Mirror Step M smoke. Differences:

- **Trigger Tier-1**: 5 failed POST `/api/v1/auth/login` with
  bad password within 5 minutes from a single source IP →
  expect ThrottleEvent(tier=1) row + bucket counter += 1.
- **Trigger Tier-2**: keep going to 10 failures within 1h →
  expect ThrottleEvent(tier=2) row + bucket counter += 1 +
  the existing slog.Warn line still fires.
- **Auth-failure feed**: verify `/security/auth-failures`
  returns the expected events sorted ts-desc.
- **Mixed feed**: verify the MixedEventList shows WAF +
  THROTTLE + AUTH rows interleaved by ts.
- **AC #15**: re-run M.5 matrix subset to prove no regression.
- **AC #13 sabotage**: mkdir at metrics.db, boot, /security/*
  endpoints still 200-disabled=true.

---

## 8. Tag plan

Spec freeze: `v1.0.0-step-q-spec` after arbitration.
Implementation tag `v1.0.0-step-q` after Q.5 PASS. Same
discipline as M.

**Version bump justification.** Q closes the Phase 2 Security
& Threat dashboard roadmap item (CLAUDE.md). Phase 1
(observability + WAF dashboard) ships under 0.8.x / 0.9.x;
Q's completion of the security feed marks the natural 1.0
milestone. Phase 3 features will bump to 1.x as they land.

---

## 9. Spec freeze tag

Same convention as M (spec doc §9): freeze with
`v1.0.0-step-q-spec`. Subsequent amendments land as in-doc
"Spec-1 §11" sections + a refreshed `v1.0.0-step-q-spec-N`
tag near Q.5 if anything material shifts.

---

## 10. Decisions resolved (2026-05-29)

Arbitration outcome, captured here for future readers:

| ID | Decision | Rationale (short) |
|----|----------|-------------------|
| D1 | **A** — emit on every block (Tier 1 + Tier 2) | Mock feed needs Tier-1 build-up visible; LRU bounds the noise. |
| D2 | **B** — server-side audit-bucket scan | Single source of truth (the audit table); no double-write. 50k row scan cap. |
| D3 | **A** — bucket counter + event table | Mirror M.1 shape; fast timeline chart + per-event forensics. |
| D4 | **B** — no auth-failure bucket column, audit-scan only | Volume small enough; double-write avoided. |
| D5 | **A** — one MixedEventList widget | Interleaved matches the mock + reflects ops reality. |
| D6 | **A** — server-side union for attacker IPs | "Over the window" semantics; M.2-amendment-#2 lesson. |
| D7 | **A** — sink emit outside the mutex | Mirrors existing Tier-2 Warn-line pattern; non-blocking. |
| D8 | **A** — attempted_username verbatim | Parity with audit log; "someone is spraying 'admin'" IS the signal. |
| D9 | **A** — 30d retention on throttle_event | Cohérent avec M. |

Spec freeze tag `v1.0.0-step-q-spec` lands on the commit that
introduces this doc in its final form. Subsequent amendments
follow the §9 Spec-1 pattern (in-doc §11 amendments section
+ refreshed `v1.0.0-step-q-spec-N` tag near Q.5 if anything
material shifts).
