# Step L — Observability (per-route metrics history)

**Status:** FROZEN — tag `v0.8.0-step-l-spec` on 2026-05-28.
**Target implementation tag:** `v0.8.0-step-l` after the L.5 smoke verdict PASS.
**Author:** Claude + Ludovic Ramos.
**Date frozen:** 2026-05-28.

---

## 1.1 Goal

Step L closes the **observability** roadmap item from the Step J
backlog (`docs/backlog-step-j.md` — observability stub, commit
`adba91e`). Today the admin UI surfaces only the live `reqPerSec`
tick (Step E WebSocket pipeline) — no history, no aggregates,
no trend. An operator who wants to know "what happened on this
route Tuesday at 14h" has no answer.

Step L ships **per-route metrics with rolling history**, exposed
as timeline graphs in two surfaces:

1. **`/observability` dashboard** — global aggregated view : top
   routes by traffic, total req/min, total 5xx/min, latency
   global percentile. The first place an operator lands when
   asked "is the proxy healthy?".
2. **Per-route drill-down** — historical panel attached to each
   route's detail surface, with the same metrics scoped to that
   route only.

Four metrics are tracked in v1.0: **req/sec**, **4xx rate**,
**5xx rate**, and **latency p95**. The 4xx is tracked separately
from 5xx (different operational signal: 4xx is a security /
exposure tell when Arenet faces the internet — scanning,
credential-stuffing, fuzzing). Bytes in-out / per-upstream
breakdown / upstream health history are **explicitly out of
scope** (§1.4).

The other roadmap candidates (Phase 2 Security & Threat dashboard,
domain-level wildcard certs, WAF tuning UI) remain unscheduled
post-L.

## 1.2 Scope

Five sub-tasks. L.5 is the live smoke + tag (not optional —
mirror Step K K.4 discipline).

| Sub-task | Surface       | Subject |
|----------|---------------|---------|
| L.1      | backend       | SQLite schema + driver wiring + bucket aggregator in-process. Step E pipeline gains a "buckets sink" alongside its existing WebSocket sink. |
| L.2      | backend       | REST API `/api/v1/metrics/timeseries?route=<id>&metric=<name>&window=<24h|30d>`. Returns the bucket rows for the requested window. |
| L.3      | frontend      | `/observability` dashboard page (global aggregated view). D3.js timeline graphs. |
| L.4      | frontend      | Per-route historical drill-down panel (mounted in the existing route detail surface). |
| L.5      | smoke + tag   | Live smoke test plan + `v0.8.0-step-l` release. |

Each named sub-task is one commit per the §8 plan (same
convention as Steps J/K).

## 1.3 Locked decisions

The 11 decisions arbitrated at spec time. Numbered to ease
post-spec cross-reference.

1. **Metrics tracked in v1.0: req/sec + 4xx rate + 5xx rate +
   p95 latency.**
   - **req/sec**: count of HTTP requests handled by the route's
     Caddy handler chain, per second. Same counter Step E reads
     for the live WS tick.
   - **4xx rate**: count of responses whose status code is in
     `[400, 500)`. Tracked separately from 5xx because the
     operational signal differs — 4xx is the security /
     exposure tell when Arenet faces the internet (scanning,
     credential-stuffing, path-fuzzing). A homelab-only
     instance may see this as noise; an internet-exposed one
     needs it.
   - **5xx rate**: count of responses whose status code is in
     `[500, 600)`. Server-side problems — upstream down, WAF
     block, gateway timeout. Different visual signal from 4xx;
     they must be plotted separately, not summed.
   - **p95 latency**: 95th percentile of upstream-response
     duration over the bucket. Sourced from a histogram-like
     Go aggregator (linear buckets coarse enough for SQLite
     storage: 10/25/50/100/250/500/1000/2500/5000/10000 ms,
     same shape Caddy's Prometheus exporter uses, cf.
     `caddy_http_request_duration_seconds`).

   **NOT tracked in v1.0** (explicit backlog):
   - Request / response byte volumes.
   - Per-upstream breakdown inside a route's pool (J.1 multi-
     pool — adds a dimension that multiplies row count).
   - Upstream health history (live data is already in Step E
     WS, persisting the history is a separate concern).
   - Per-status-code drill (502 vs 504 vs 500 collapse into
     "5xx"; 401 vs 404 vs 429 collapse into "4xx").

2. **Bucket sizes + retention: 1min/24h + 1h/30d.**
   - 1-minute buckets retained for the last 24 h. Granular
     enough to debug a recent incident.
   - 1-hour buckets retained for the last 30 d. Trend view.
   - For 50 routes: ~108k rows total, ~5 MB SQLite file.
     Negligible.
   - Older data (> 30 d) is pruned by the retention goroutine
     (§4.6).

3. **Pipeline source: in-process Step E counters, NOT scrape of
   the Caddy Prometheus endpoint.**
   - Step E (`internal/metrics`) already maintains atomic Go
     counters per route + a 1-second broadcaster. Step L adds a
     second consumer of those counters: a "bucket aggregator"
     that accumulates 60 ticks then flushes one row to SQLite.
   - The scrape-Caddy alternative was rejected: it would add a
     redundant network round-trip inside Arenet itself and
     decouple two pipelines that share one source. The atomic
     counter model gives perfect read consistency at the cost
     of one shared struct.

4. **SQLite file location: `<data-dir>/metrics.db` (flat).**
   - Separate file from `arenet.db` (bbolt). bbolt is single-
     writer; mixing in SQLite would either contend the writer
     lock or require a sub-process — neither is desirable.
   - Same data-dir as bbolt for hygiene (one mount, one
     backup boundary).

5. **SQLite driver: `modernc.org/sqlite` (pure-Go, no cgo).**
   - Preserves the Arenet single-binary posture (cross-
     compile clean on macOS / Linux / Windows / FreeBSD without
     a C toolchain).
   - The `mattn/go-sqlite3` driver is 2-3× faster on heavy
     writes but our workload is ~50 writes/min (= 0.83/sec);
     the perf delta is irrelevant here.

6. **API: REST for historical queries, WebSocket Step E
   unchanged for live ticks.**
   - `GET /api/v1/metrics/timeseries?route=<id>&metric=<name>&window=24h|30d`
     returns the bucket rows for the window. Pull-on-demand,
     cacheable, classic.
   - The Step E WebSocket pipeline stays as-is (1 broadcast/sec
     for the live Topology view). Step L doesn't extend it.

7. **UI surface: dashboard `/observability` + drill-down per
   route.**
   - **Dashboard** (`/observability`): global view. Top N routes
     by traffic, total req/min, total 5xx/min, p95 latency
     globally. Lands the operator on the first answer to "is
     the proxy healthy?".
   - **Drill-down**: per-route historical panel reused inside
     the existing route detail surface (Routes page expanded
     row, or modal). Same three metrics, scoped to one route.

8. **Charts library: D3.js (already in the dependency tree from
   Step E).**
   - No new dependency. Reuses the SVG-rendering know-how
     accumulated for the Topology view.

9. **Bucket flush cadence: aggregator-side, matches bucket size.**
   - For 1-minute buckets: accumulate 60 ticks in Go memory,
     write 1 row per route to SQLite at the rollover.
   - For 1-hour rollups: the retention goroutine derives them
     from the 1-minute buckets at the hour boundary (no second
     in-Go aggregator).
   - Crash boundary: max 1 minute of unflushed data lost on
     abrupt shutdown. Acceptable.

10. **Retention: goroutine + DELETE every hour.**
    - Background goroutine in `internal/metrics` (or new
      `internal/observability`) runs every 60 minutes:
      ```sql
      DELETE FROM bucket_1m WHERE ts < (now - 24h);
      DELETE FROM bucket_1h WHERE ts < (now - 30d);
      ```
    - Plus the hourly rollup: read the 60 latest 1-minute
      buckets per route, aggregate (sum req, sum 5xx,
      compute weighted p95), insert into `bucket_1h`.
    - SQLite triggers were considered and rejected: harder to
      reason about, harder to test.

11. **Step E pipeline is NOT refactored.**
    - The existing `Registry` + `Broadcaster` keep their
      contract verbatim. Step L greffe un second sink (the
      bucket aggregator) on the same atomic counters via an
      additive interface.
    - The broadcaster's per-second tick continues to feed the
      Topology WebSocket exactly as today. Drill-down's
      historical view is a parallel data path.

## 1.4 Out of scope

- **Per-upstream breakdown.** J.1 introduced multi-upstream
  pools per route. Drilling down to "which upstream in the
  pool generated the 5xx" multiplies row count by pool size,
  and requires a Caddy handler hook the current Step E doesn't
  have. Defer.
- **Bytes in / out.** Useful for capacity planning, not
  critical for homelab health. Defer.
- **Upstream health history.** Step E already exposes the
  live healthy/unhealthy state via WS; persisting history is
  a separate observation concern (status timeline, incident
  view).
- **Per-status-code drill-down.** v1.0 collapses everything
  ≥500 into "5xx". A future iteration may split (502 vs 504
  vs 500 carry different operational signals).
- **Alerting / webhooks.** The dashboard is purely informative.
  Outbound notifications belong to the Phase 2 Security &
  Threat dashboard (different step entirely).
- **Multi-tenant isolation.** Single-admin observable scope
  per Arenet instance, like every other Phase 1 feature.
- **Metric export.** Operator can read the SQLite file directly
  (`metrics.db`) — there's no `/metrics` Prometheus endpoint
  exposed by Arenet itself. Caddy's internal `:2019/metrics`
  is admin-only and stays as-is.

## 1.5 Range of change

| Area | Change |
|------|--------|
| `internal/metrics` (existing, Step E) | Additive: new `BucketAggregator` consumes the same atomic counters as `Broadcaster`. Existing types/methods unchanged. |
| `internal/observability` (new) | SQLite open/close lifecycle, schema migration, retention goroutine, bucket flush goroutine, query helpers. |
| `internal/api` | New handler `metricsTimeseries` + route wiring under `/api/v1/metrics/*`. Admin auth chain (soft-auth + RequireAdmin? — see §3.3 / Q4 below). |
| `internal/caddymgr` | One hook to expose `request_duration_seconds` to the metrics package (Caddy admin endpoint already exposes it via Prometheus; we use the same in-process telemetry source). |
| `cmd/arenet/main.go` | Open the SQLite DB at boot, pass into `internal/observability` constructor, start the flush + retention goroutines. |
| Frontend `lib/api/metrics.ts` | New API wrapper. |
| Frontend `routes/observability/+page.svelte` | New dashboard page. |
| Frontend per-route surface | New `<RouteMetricsPanel>` component embedded in the existing route detail. |
| Sidebar | New "Observability" entry (icon, position between Topology and Settings — see Q4 below for the auth gate). |
| Frontend deps | None new (D3.js already present from Step E). |
| Go deps | `modernc.org/sqlite v1.x` (pure Go) added to `go.mod`. |
| Storage | New file `<data-dir>/metrics.db`. No change to `arenet.db`. |

## 1.6 Threat model deltas vs Step K

Minimal. Step L is a read-only data feature.

- **Δ1 — SQLite file readable post-compromise.** A reader who
  gains filesystem access to `metrics.db` can reconstruct the
  route traffic timeline. This is the same risk surface as
  `arenet.db` (which already contains routes + secrets). Same
  filesystem-permissions boundary applies.

- **Δ2 — Metrics endpoint enumeration.** `GET /api/v1/metrics/
  timeseries?route=<id>` requires a valid session. Unauthenticated
  enumeration of route IDs is already covered by the existing
  hard-auth gate; Step L doesn't widen the surface.

- **Δ3 — No new secret surfaces.** Metrics rows contain only
  IDs + timestamps + integer counters. No PII, no IPs (cf.
  spec K.2 audit-message hygiene, mirror here).

- **Δ4 — Disk-full vulnerability.** A misconfigured retention
  goroutine (bug or stopped goroutine) could fill the disk
  over weeks. Mitigation: the goroutine writes a heartbeat to
  slog every hour. Operational, not a code-level guarantee.

## 2. Acceptance Criteria

Numbered AC items. Each must be PASS / PARTIAL with documented
caveat / N/A with justification at L.5 smoke time.

**AC #1 — Bucket aggregator emits one row per route per minute.**
After a route has received at least one request, exactly one
`bucket_1m` row exists per minute boundary, with `route_id`,
`ts` (rounded to the minute), and the four counters populated
(`req_count`, `fourxx_count`, `fivexx_count`, `latency_p95_ms`).

**AC #2 — Hourly rollup correct.** The `bucket_1h` row for any
hour H equals the **exact** sum of the 60 `bucket_1m` rows
within H for the same route, independently for `req_count`,
`fourxx_count`, and `fivexx_count`. The hourly `latency_p95_ms`
is the **weighted-by-req-count percentile-of-percentiles
approximation** across the 60 per-minute samples — NOT an
exact p95 over the underlying raw observations (raw
observations are not persisted; only per-minute p95s are).
Tested as approximation, not equality: the L.5 smoke compares
the hourly p95 to the max of the 60 minute p95s and asserts
it sits within that envelope, not against a recomputed exact
p95.

**AC #3 — 4xx and 5xx are tracked SEPARATELY at every layer.**
The atomic counter, the SQLite columns, the REST API metric
enum, the dashboard cards, the drill-down charts ALL keep
4xx and 5xx as independent series. Pinned anti-regression: a
test asserts that a synthetic 4xx burst does NOT increment
the 5xx counter, and reciprocally. (Step L UX/security
invariant: 4xx surfaces scanning / credential-stuffing
patterns when Arenet faces the internet; collapsing it into
"errors" would erase that signal.)

**AC #4 — Retention prune deletes old data.** After 25 hours of
running, `bucket_1m` rows with `ts < now - 24h` are absent.
After 31 days, `bucket_1h` rows with `ts < now - 30d` are
absent. Verified via in-process test with injected timestamps
(L.5 smoke checks live rotation on a single rollover window
only, not the full 24h/30d range — see §7).

**AC #5 — REST API returns the requested window.**
`GET /api/v1/metrics/timeseries?route=<id>&metric=<name>&window=24h`
returns the 1-minute buckets covering the last 24 hours, in
timestamp-ascending order. Same shape for `window=30d`
returning the 1-hour buckets. Accepts all four metric names
independently: `req_per_sec` / `four_xx_rate` / `five_xx_rate`
/ `p95_latency_ms`.

**Missing-bucket gap-fill rule** (anti-regression — a "0 ms
p95" would render as a fake latency dip on the chart):
- For **count metrics** (`req_per_sec`, `four_xx_rate`,
  `five_xx_rate`): missing buckets are emitted as rows with
  `value: 0` — a route that received zero traffic in a window
  is a real "0 req/sec" signal.
- For **`p95_latency_ms`**: missing buckets are emitted as rows
  with `value: null` — there is no latency without traffic.
  The frontend MUST render `null` as a gap (no data point), not
  as a 0 ms value.

**AC #6 — Summary endpoint exposes 4xx and 5xx separately.**
`GET /api/v1/metrics/summary` returns `totalReqPerMin`,
`totalFourXxPerMin`, `totalFiveXxPerMin`, `globalP95LatencyMs`,
and the top 5 routes by traffic. Anti-regression on the
4xx/5xx split.

**AC #7 — Dashboard renders without API error.** Loading
`/observability` shows: 5 stat cards (req/min, 4xx/min,
5xx/min, p95, # active routes), top 5 routes by traffic
chart, and three independent timeline charts (req/min,
4xx/min, 5xx/min) over 24h. Empty state (zero routes
configured) is handled gracefully.

**AC #8 — Per-route drill-down renders historical timeline.**
Clicking on a route in the dashboard or in the Routes page
opens a panel showing the four metrics over the selected
window (default 24h, 30d toggle). The 4xx and 5xx panels are
rendered as separate charts (not stacked, not overlaid).

**AC #9 — Step E topology view unchanged.** No regression on
the existing live `reqPerSec` WebSocket broadcast. The
topology page renders the live tick at exactly the same
interval, with the same data shape.

**AC #10 — Single-binary build preserved.** `go build ./cmd/arenet`
produces a static binary with no cgo dependency
(`go env CGO_ENABLED=0 && go build ./...` succeeds).

**AC #11 — SQLite file initialised at boot.** First boot
creates `<data-dir>/metrics.db` with the schema applied. Re-
opening an existing file is a no-op (no destructive migration).

**AC #12 — Crash recovery: no data loss within bucket window.**
Killing Arenet with `SIGKILL` during a bucket window loses at
most the in-memory accumulation for that window (~1 minute of
data). The next start resumes cleanly from the last persisted
bucket.

**AC #13 — Metrics sink NEVER degrades the data plane.**
Critical invariant for an internet-exposed proxy: failures in
the metrics subsystem must not block, fail, or slow request
proxying. Specifically:
- **At boot** — if `metrics.db` cannot be opened (permission
  denied, disk full, file corrupted, schema-migration error,
  underlying sqlite driver init failure), Arenet starts in a
  degraded mode: the Caddy data plane comes up and serves
  traffic; the metrics subsystem logs the error (`slog.Error`)
  and is disabled for the lifetime of the process. The Step E
  live WebSocket pipeline keeps working (in-memory only).
- **At runtime** — every write to the bucket aggregator and
  every SQLite flush is best-effort: errors are logged at most
  once per tick (rate-limited to avoid log flood) and the
  request path never sees them. A locked/full/corrupt DB makes
  the relevant bucket(s) lost, not the request.
- **No panic anywhere on the metrics path.** A `recover()` is
  acceptable at the sink boundary if it logs the recovered
  panic.

Tested with three injected faults: (a) read-only data
directory at boot, (b) sqlite open returning a synthetic error
at boot, (c) a flush error mid-run. In all three the proxy
keeps answering 200 OK on a known route during and after the
fault.

**AC #14 — Frontend tests pass.** `npm run check` clean and
`npm test` green.

**AC #15 — Backend tests pass.** `go test ./...` green across
all packages.

**AC #16 — Lint / vet / format clean.** `gofmt`, `go vet`,
`staticcheck` on Step L surface clean.

**AC #17 — Bundle budget.** `npm run build` stays within the
Step J §1 bundle budget. The dashboard page is allowed to add
up to 10 kB gz (D3 already loaded as a dependency for the
topology page).

**AC #18 — Auth gate viewer-accessible.** A viewer (cf. Step
K.2 role model) can navigate to `/observability` and read the
metrics. No write surface — there's nothing to write.

## 3. Architecture impact

### 3.1 Domain model deltas

```go
// internal/observability/storage.go

// MetricBucket represents one aggregated time window for one
// route. Persisted to SQLite; the same struct shape is used
// for both 1-minute and 1-hour buckets (the table tells them
// apart, not the struct).
type MetricBucket struct {
    RouteID string    // foreign-id to storage.Route, NOT a FK constraint (Routes can be deleted; we keep historical buckets)
    Ts      time.Time // bucket start (UTC, rounded to the bucket size)
    ReqCount     int64
    FourxxCount  int64
    FivexxCount  int64
    LatencyP95Ms int32 // milliseconds, 0 if no samples in this bucket
}

// LatencyHistogram is the in-process accumulator before flush.
// Linear ms buckets mirror the Caddy Prometheus exporter.
type LatencyHistogram struct {
    Buckets [10]int64 // counts in 10/25/50/100/250/500/1000/2500/5000/10000ms
}
```

### 3.2 Step E integration

`internal/metrics.Registry` gains nothing; it stays the source
of truth for `request_count` and `req5xx_count` atomic counters.
A new consumer:

```go
// internal/observability/aggregator.go

// BucketAggregator reads the same atomic counters as Step E's
// Broadcaster (at the same 1-second tick interval) and groups
// 60 consecutive ticks into one row per route. At the minute
// rollover it flushes the row to SQLite. Idempotent on the
// minute boundary: a second tick lands in the next bucket
// even if the rollover is slightly skewed by scheduler jitter.
type BucketAggregator struct {
    registry *metrics.Registry
    store    *Store
    logger   *slog.Logger
    // ... in-memory state per route
}

func (a *BucketAggregator) Start(ctx context.Context) { /* goroutine */ }
```

The existing `Broadcaster.Start` is unchanged.

### 3.3 API surface deltas

One new endpoint, group: hard-auth + viewer-ok (no
`RequireAdminMiddleware`).

```
GET /api/v1/metrics/timeseries?route=<id>&metric=<name>&window=<24h|30d>
```

Query parameters:
- `route` — required, route ID (UUID).
- `metric` — required, one of `req_per_sec` / `four_xx_rate` /
  `five_xx_rate` / `p95_latency_ms`.
- `window` — required, `24h` (returns 1-minute buckets) or
  `30d` (returns 1-hour buckets).

Response (200 OK):
```json
{
  "routeId": "uuid",
  "metric": "req_per_sec",
  "window": "24h",
  "bucketSizeSeconds": 60,
  "points": [
    { "ts": "2026-05-28T10:00:00Z", "value": 12.5 },
    { "ts": "2026-05-28T10:01:00Z", "value": 14.0 },
    // ... 1440 entries for 24h.
    // Gap-fill (cf. AC #5): missing buckets emitted as
    //   value: 0     for req_per_sec / four_xx_rate / five_xx_rate
    //   value: null  for p95_latency_ms (no traffic ⇒ no latency)
  ]
}
```

400 on missing/invalid params. 404 on unknown route ID. 503 on
SQLite read failure (consistent with Step D11).

Plus a small aggregated endpoint for the dashboard:

```
GET /api/v1/metrics/summary
```

Returns:
```json
{
  "windowSeconds": 60,
  "totalReqPerMin": 1234,
  "totalFourXxPerMin": 12,
  "totalFiveXxPerMin": 5,
  "globalP95LatencyMs": 230,
  "topRoutesByTraffic": [
    { "routeId": "...", "host": "...", "reqPerMin": 500 },
    // ... up to 5
  ]
}
```

### 3.4 Frontend surface deltas

New route: `routes/observability/+page.svelte` — the dashboard.

New component: `lib/components/RouteMetricsPanel.svelte` —
the per-route timeline. Mounted inside the existing Routes
page (expanded row or modal — chosen at L.4 implementation
time).

Sidebar: add an "Observability" item between Topology and
Security (which is still disabled). Icon: Lucide `activity`.
Viewer-accessible (no `auth.user?.role === 'admin'` filter).

### 3.5 Migrations

No bbolt schema change. SQLite schema initialised at first
boot via simple `CREATE TABLE IF NOT EXISTS`:

```sql
CREATE TABLE IF NOT EXISTS bucket_1m (
  route_id TEXT NOT NULL,
  ts INTEGER NOT NULL,  -- unix seconds, rounded to the minute
  req_count INTEGER NOT NULL,
  fourxx_count INTEGER NOT NULL,
  fivexx_count INTEGER NOT NULL,
  latency_p95_ms INTEGER NOT NULL,
  PRIMARY KEY (route_id, ts)
);

CREATE INDEX IF NOT EXISTS idx_bucket_1m_ts
  ON bucket_1m (ts);

CREATE TABLE IF NOT EXISTS bucket_1h (
  route_id TEXT NOT NULL,
  ts INTEGER NOT NULL,  -- unix seconds, rounded to the hour
  req_count INTEGER NOT NULL,
  fourxx_count INTEGER NOT NULL,
  fivexx_count INTEGER NOT NULL,
  latency_p95_ms INTEGER NOT NULL,
  PRIMARY KEY (route_id, ts)
);

CREATE INDEX IF NOT EXISTS idx_bucket_1h_ts
  ON bucket_1h (ts);

CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER PRIMARY KEY
);
INSERT OR IGNORE INTO schema_version (version) VALUES (1);
```

Schema version 1 ships with L.1. Any future schema bump goes
through a `migrate(currentVersion, targetVersion)` chain.

## 4. Sub-tasks (ordered)

| # | Title | Surface | Tag/Commit |
|---|-------|---------|------------|
| L.1 | SQLite schema + driver + bucket aggregator | backend | 1 commit |
| L.2 | REST API `/api/v1/metrics/*` + viewer auth wiring | backend | 1 commit |
| L.3 | `/observability` dashboard | frontend | 1 commit |
| L.4 | Per-route drill-down panel | frontend | 1 commit |
| L.5 | Smoke test + tag `v0.8.0-step-l` | smoke + doc | 1 commit + tag |

## 5. Per-sub-task design

### 5.1 L.1 — SQLite + bucket aggregator

**Component decomposition:**

- New package `internal/observability/`:
  - `storage.go` — SQLite open/close, schema init, `Store` type with `Insert1m`, `InsertOrUpdate1h`, `Query1m`, `Query1h`.
  - `aggregator.go` — `BucketAggregator` struct, goroutine driven by `time.Tick(1s)`, accumulates 60 ticks then flushes.
  - `retention.go` — `RetentionLoop` goroutine, prunes + rolls up at the hour boundary.
  - `histogram.go` — `LatencyHistogram` + p95 calculation helper.
- `cmd/arenet/main.go` wires the lifecycle (open + start before Caddy, close after).
- `internal/caddymgr/manager.go` exposes a hook to feed `request_duration_seconds` from the Caddy handler chain into a new `Registry` method (`ObserveLatency(routeID, durMs)`).

**Atomic counter accumulator state machine:**

1. `Broadcaster` keeps its 1-second tick (existing Step E
   behaviour).
2. `BucketAggregator` runs its own 1-second tick. Per route,
   maintains an in-memory counter quadruplet (req, 4xx, 5xx,
   latency histogram).
3. At the minute boundary (when `time.Now().Truncate(time.Minute)`
   crosses): flush the in-memory quadruplet as one row in
   `bucket_1m`, reset the in-memory state.
4. Hour boundary: `RetentionLoop` reads the last 60 minutes of
   `bucket_1m` rows per route, aggregates, inserts in
   `bucket_1h`. Then prunes old data.

**SQLite write batching:** at the minute boundary, all routes
flush in one transaction (`BEGIN; INSERT...; INSERT...; COMMIT`).
Single I/O cost regardless of route count.

**Crash recovery:** the in-memory quadruplet is lost on SIGKILL.
At boot the aggregator initialises with zero counters; the next
flush at the next minute boundary contains only post-boot data.
The `bucket_1m` table has the integrity invariant `(route_id, ts)`
as PRIMARY KEY — no risk of duplicate row.

**Tests (in-process, unit-level):**

- `TestSchema_InitIdempotent` — `Open` twice on the same file
  is a no-op.
- `TestStore_Insert1mAndQuery1m` — round-trip + window query.
- `TestHistogram_P95Correct` — known-distribution sanity.
- `TestAggregator_FlushAtMinuteBoundary` — driver with synthetic
  clock, verify the flush triggers exactly once per minute.
- `TestRetention_Prune1mOlder24h` — inject buckets with stale
  timestamps, verify the prune sweeps them.
- `TestRetention_Rollup1hCorrect` — 60 1-min buckets → 1 1-h
  bucket with correct sums + p95.

### 5.2 L.2 — REST API

Handler: `internal/api/metrics_handlers.go`.

```go
func (h *Handler) metricsTimeseries(w http.ResponseWriter, r *http.Request) {
    routeID := r.URL.Query().Get("route")
    metric  := r.URL.Query().Get("metric")
    window  := r.URL.Query().Get("window")
    // ... validation
    // ... query observability.Store
    // ... gap-fill per AC #5: 0 for count metrics, null for p95_latency_ms
    //     (a "0 ms p95" would render as a fake latency dip).
    // ... writeJSON
}

func (h *Handler) metricsSummary(w http.ResponseWriter, r *http.Request) {
    // ... aggregate the latest minute across all routes
    // ... writeJSON
}
```

Routes wired in the existing hard-auth chain (`SoftAuthMiddleware`
+ `HardAuthMiddleware`), **NOT** in the `RequireAdmin` sub-chain.
Q4 decision: viewer-ok.

**Tests:**
- `TestMetricsTimeseries_Happy` — known buckets in store, expected JSON shape.
- `TestMetricsTimeseries_UnknownRoute_404`.
- `TestMetricsTimeseries_MissingParam_400`.
- `TestMetricsTimeseries_ViewerAllowed` — a viewer session can GET (anti-regression on the auth gate).
- `TestMetricsSummary_TopRoutesByTraffic` — known buckets in store, expected top 5 by req count.

### 5.3 L.3 — `/observability` dashboard

SvelteKit route `routes/observability/+page.svelte`. Six
visual blocks:

1. **Header**: page title "Observability" + last-update
   timestamp.
2. **Stat cards** (5 cards in a row): total req/min, total
   4xx/min, total 5xx/min, global p95 latency, # active
   routes.
3. **Top routes by traffic** (line chart, 24h window). Up to
   5 routes overlaid.
4. **Total req/min over 24h** (single line chart, gap-filled).
5. **Total 4xx/min over 24h** (single line chart, separate from
   5xx to keep the visual signal distinct).
6. **Total 5xx/min over 24h** (single line chart).

Data source: `metricsSummary` for the cards (single fetch on
mount), `metricsTimeseries` per chart (one fetch each).
Refresh: polling every 60 seconds via `setInterval`. No WS
on this page (the 60s cadence is enough for trend view; live
view is the Topology page).

**D3.js usage:** line generator + linear scale + time scale +
axis. Mirror the patterns from the Topology graph (Step E).

**Tests:** Svelte component tests skipped (cf. backlog Phase 2
roadmap re: component testing infrastructure). Page-level test
mocks the metrics API and asserts the cards render with the
right values.

### 5.4 L.4 — Per-route drill-down

New component `lib/components/RouteMetricsPanel.svelte`.
Embedded in the Routes page detail surface (decision deferred
to implementation: expanded row OR modal — picked at L.4 code
time depending on UX flow).

Same four charts as L.3 but scoped to one `routeId`: req/sec,
4xx, 5xx, p95 latency. Window toggle (24h default / 30d).
Same refresh cadence (60s).

**Tests:** component-level unit test on data binding (chart
input shape correctness given mocked timeseries data).

### 5.5 L.5 — Smoke + tag

Same pattern as K.4. Live smoke against a running Arenet
instance with at least one route generating traffic
(`curl -H "Host: probe.test" ...` in a tight loop). Acceptance
matrix verified against the 18 ACs.

Smoke doc: `docs/smoke-test-step-l.md`. Findings triaged
fix-before-tag vs backlog. Tag `v0.8.0-step-l` after PASS.

## 6. Migration strategy

No bbolt migration. SQLite schema migrate via the
`schema_version` table (currently v1). Future bumps document
the up/down migrations in `internal/observability/migrate.go`
(empty in L.1).

Boot-time SQLite open is non-destructive: `CREATE TABLE IF NOT
EXISTS` for first install, no-op for existing files.

If the SQLite file is corrupt (rare), the boot fails loudly
(slog ERROR + Arenet exit non-zero). The operator can either
delete `metrics.db` (history lost, recreated empty) or restore
from backup. **No automatic recovery / repair** — pre-emptive
fallbacks would mask the real cause.

## 7. Smoke test plan (skeleton, filled at L.5)

Range smoke:
- Start Arenet on a fresh data-dir.
- Configure one or two routes pointing at a local HTTP echo
  server (Python `http.server`).
- Run a traffic generator in the background (`hey -z 1m -c 5
  http://localhost:8080/...` or a simple curl loop).
- Verify the metrics database receives rows at the minute
  rollover.
- Verify the dashboard renders with non-zero values.
- Verify per-route drill-down shows the same data.
- Verify a viewer session can read both surfaces.
- Stop Arenet, restart, verify the previously-flushed buckets
  remain queryable.
- Generate a synthetic 5xx (kill the upstream mid-curl, or
  return 500 from the Python handler) — verify the 5xx counter
  increments and the dashboard shows the spike.
- Long-running rotation: NOT covered (the smoke does not run
  for 24h+). Verified instead by the in-process test
  `TestRetention_Prune1mOlder24h` which injects synthetic
  timestamps.

Gaps declared upfront (mirror K.4 §7 style):
- Long-running 24h+ smoke not feasible in the smoke window.
- Per-upstream observability (out of scope §1.4).

## 8. Tag plan

1. Implement L.1, L.2, L.3, L.4 — one commit each on `main`.
2. Run gates per commit (gofmt, vet, go test, npm check, npm
   test, npm build).
3. Open `docs/smoke-test-step-l.md`, run the smoke per §7,
   record findings.
4. Triage findings: fix-before-tag (security or functional) vs
   backlog (cosmetic, UX polish).
5. Land any fix-before-tag commits.
6. Final sanity gate green: `gofmt -s -l . && go vet ./... &&
   go test ./... && cd web/frontend && npm run check && npm
   test -- --run && npm run build`.
7. Commit smoke doc (`docs: Step L smoke test report`).
8. Tag `v0.8.0-step-l` with the annotated message summarising
   ACs PASS, findings, backlog.
9. Push tag.

## 9. Spec freeze tag

The spec doc itself is frozen by tagging `v0.8.0-step-l-spec`
on the commit that lands this file. Subsequent implementation
commits never amend the spec; if reality diverges during
implementation, the spec is amended in a follow-up commit
with an explicit "spec amendment" prefix and re-tagged
`v0.8.0-step-l-spec-2`.

(Step K used the same pattern with `v0.7.0-step-k-spec` →
spec-1 amendments via Spec-1 commit.)
