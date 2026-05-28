# Step M — Security dashboard (WAF events)

**Status:** FROZEN — tag `v0.9.0-step-m-spec` on 2026-05-28.
**Target spec-freeze tag:** `v0.9.0-step-m-spec`.
**Target implementation tag:** `v0.9.0-step-m` after the M.5 smoke
verdict PASS.
**Author:** Claude + Ludovic Ramos.
**Draft date:** 2026-05-28.

> Scope α only — WAF events. CrowdSec integration is deferred to
> a future **Step N** (the spec author's reasoning, validated by
> the user: CrowdSec brings real operational complexity — LAPI
> URL, bouncer auth, decision sync, cache semantics — that
> deserves its own step on top of M's foundation).

---

## 1.1 Goal

Step M ships a **Security dashboard** that closes the "Security &
Threat" roadmap item from CLAUDE.md Phase 2 and the Step L spec's
§1.1 future work note. Today an operator who wants to know
"is the proxy under attack right now?" or "which routes are being
scanned?" has no answer beyond the live 4xx rate on the Step L
dashboard.

Step M ships **per-route WAF block events with rolling history**,
exposed on a new `/security` page with the same shape as Step L's
`/observability`:

1. **`/security` dashboard** — global view: WAF blocks/min (the
   total tells you whether you're being attacked); top-attacked
   routes (which surfaces are taking the heat); the timeline of
   blocks over 24h / 30d so an operator can spot a coordinated
   scan that started two hours ago.
2. **Per-route drill-down** — `/security/<routeId>` mirrors the
   L.4 per-route page, scoped to security events.

The L foundation (SQLite bucket store, TimelineChart, dashboard
chrome, viewer-auth gating) is reused **verbatim**. Step M's
spec is intentionally lean because most of the chrome was
already proved out in L.

---

## 1.2 Scope

Five sub-tasks, mirror Step L's L.1–L.5 cadence:

| Sub-task | Surface       | Subject |
|----------|---------------|---------|
| M.1      | backend       | Custom Coraza-v3 module (`internal/waf/coraza_module.go`) wrapping `coraza/v3` directly to expose per-block events (rule ID, OWASP category, severity, src IP, payload sample). Schema migration v1→v2 adds `waf_block_count` to the bucket tables AND creates the new `waf_event` table. Bucket aggregator absorbs the count; the event store persists per-block rows. |
| M.2      | backend       | REST API extends `/api/v1/metrics/*` (D2=A) with `waf_block_rate` + summary field `totalWafBlockedPerMin` + the per-OWASP-category breakdown the dashboard mocks require. New `GET /api/v1/security/events?limit=20` endpoint for the recent-events widget (single new endpoint despite D2=A, because the event log is a different data shape from the bucket timeseries — see §1.3 D2 amendment). |
| M.3      | frontend      | `/security` dashboard page: 5 stat cards + 3 timeline charts + top-5 + **recent-events widget**. |
| M.4      | frontend      | Per-route `/security/[routeId]` drill-down: WAF block timeline + recent events scoped to the route + per-rule breakdown. |
| M.5      | smoke + doc   | Live end-to-end smoke with a real CRS-tripping payload. Tag `v0.9.0-step-m`. |

---

## 1.3 Locked decisions

(All decisions arbitrated 2026-05-28; rationale preserved.)

### D1 — WAF event capture mechanism → **B (custom Coraza-v3 module)**

**The constraint.** `coraza-caddy v2.5.0` (the version pinned in
go.mod) exposes **no match hook** — see Step J backlog
"Out of scope" entry. The only signals we get for free today
are:
- HTTP response status (Caradoc returns 403 in block mode).
- Caddy's structured log (info-level WAF match line).

**Two viable paths:**

- **D1.A — status-code-derived counting** (light, cheap).
  Extend `Registry.Inc(routeID, status, durMs)` callers in the
  middleware to also capture a `wafBlocked` boolean derived from
  status==403 AND the route's `WafMode` is `block` or
  `detect`. False positives possible (any upstream returning 403
  AND the route having WAF enabled would count as a block) but
  in practice 403 from an upstream is rare in a homelab and the
  signal is good enough for "is the proxy being scanned"
  semantics.
- **D1.B — custom Coraza-v3 module** (heavy, real).
  ~600 lines of new code consuming `coraza/v3` directly, with
  per-block event capture (rule ID, severity, request sample).
  Closes Step I AC #4 PARTIAL + Step J §1.4 deferred item +
  Step J backlog Out-of-scope item all at once. Security-
  critical: a bug in the match-handling silently weakens the
  WAF. Significantly broader than what the dashboard needs —
  the dashboard wants counts and timelines, not per-rule
  forensics.

**Decision: B (custom Coraza-v3 module).** Locked 2026-05-28
based on the mock review: the `/security` dashboard mocks
(stat cards by OWASP category — SQLi/XSS/RCE — , recent-events
widget with `rule 942100` inline annotations, "unique
attacker IPs" counter, per-event payload preview, auto-
classification of IPs by block nature) all require per-event
fidelity that the status-code-derived path (D1.A) cannot
provide. D1.A would let us count blocks but not categorise
them, and would have produced a dashboard that looks like the
mocks while delivering significantly less signal than the
mocks promise.

**Implications of choosing B:**

- New package `internal/waf/`. Custom Caddy module wrapping
  `coraza/v3` directly. **Replaces `coraza-caddy/v2` for every
  Arenet-managed WAF-enabled route** — no opt-in toggle, no
  new `Route.WafEngine` field. A route whose `WafMode` is
  `block` or `detect` gets the new `arenet_waf` handler
  emitted in its Caddy chain; `WafMode=off` routes get no
  WAF handler at all (unchanged). The `coraza-caddy/v2`
  side-effect import in `cmd/arenet/main.go` becomes unused
  for Arenet-managed routes once M.1 lands; cleanup
  (removing the import + the dep) is deferred to a small
  follow-up commit before Step N to keep M.1's diff focused.
  See §3.2 for the Caddy-emit details.
- New SQLite table `waf_event` capturing one row per block:
  `ts`, `route_id`, `rule_id`, `category` (SQLi/XSS/RCE/…),
  `severity`, `src_ip`, `request_method`, `request_path`,
  `payload_sample` (capped + redacted — see §1.6).
- The bucket aggregator counter (`waf_block_count`) becomes
  derivative — incremented on every event-emit, persisted to
  `bucket_1m` / `bucket_1h` as before. The aggregator stays as
  the dashboard's timeseries data source; the new event table
  is read directly by the `/security/events` endpoint and by
  drill-down per-rule breakdowns.
- AC #13 discipline preserved: event emission is non-blocking
  (channel-buffered like the L aggregator's `Ingest`),
  drops-on-full, never blocks the request path.

**Rejected alternative — D1.A (status-code-derived):**
Cheaper (~30 lines, no new package) but only provides a count.
Mocks rule it out. Documented here so a future reader sees the
trade-off was considered and chosen against deliberately.

### D2 — REST API namespace → **A (extend `/api/v1/metrics/*`)** with one carve-out

**The choice:**

- **D2.A — extend `/api/v1/metrics/*`** with new metric names:
  `waf_block_rate`, plus a new `summary` field
  `totalWafBlockedPerMin`. Same handlers, same response shapes,
  same auth gate. One endpoint family for the operator to
  remember. The `MetricName` enum gains one entry.
- **D2.B — new `/api/v1/security/*` namespace.** Parallel
  handler family. Pros: clear separation between operational
  metrics (L) and security signals (M), might invite divergent
  evolution if M and L acquire different access controls or
  retention horizons later. Cons: two endpoint families for the
  frontend to consume, more handler code.

**Decision: A.** Timeseries + summary extend `/api/v1/metrics/*`
with a new `waf_block_rate` metric name + new summary fields
(`totalWafBlockedPerMin`, `wafBlocksByCategory` map). Same
response shape, same handlers, same auth gate.

**Carve-out forced by D1=B**: the event log is a different
data shape (sparse per-event rows vs dense per-minute
buckets), so a single dedicated endpoint is added:

```
GET /api/v1/security/events?limit=<n>&route=<id-or-omitted>&category=<cat-or-omitted>
```

This is the smallest possible surface to carry the event-log
data shape. Pagination via `limit` (capped at 100); optional
filters by route or OWASP category for the drill-down page.
Auth gate identical to the metrics endpoints (viewer-
accessible, read-only). The endpoint name uses `/security/`
rather than `/metrics/` because the data is not a metric;
keeps the URL semantically honest.

**Rejected alternative — D2.B (full `/security/*` parallel
namespace):** would have meant duplicating the timeseries
handler + summary handler for security data. Churn rejected
the same reasoning still applies. The carve-out above is the
minimum-necessary deviation.

### D3 — SQLite schema for the new counter → **A (shared columns)**

**Decision: A** — extend `bucket_1m` / `bucket_1h` with
`waf_block_count INTEGER NOT NULL DEFAULT 0`. Old rows get the
default; AC #3 "tracked separately" discipline is about
*fields*, not *tables*. The schema-migration path declared by L
§6 is exercised here for the first time.

**Forced addition by D1=B**: the v1→v2 migration ALSO creates
the new `waf_event` table for per-block events. This is not
optional once D1=B is locked. Full v1→v2 SQL:

```sql
-- bucket-table counter column (D3.A)
ALTER TABLE bucket_1m ADD COLUMN waf_block_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bucket_1h ADD COLUMN waf_block_count INTEGER NOT NULL DEFAULT 0;

-- per-event table (forced by D1=B)
CREATE TABLE IF NOT EXISTS waf_event (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,            -- unix seconds (event time)
  route_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,          -- e.g. "942100" (CRS ID)
  category TEXT NOT NULL,         -- "SQLi" | "XSS" | "RCE" | "LFI" | "PROTOCOL" | "OTHER"
  severity INTEGER NOT NULL,      -- Coraza severity 0-7
  src_ip TEXT NOT NULL,           -- redacted per §1.6 if needed
  request_method TEXT NOT NULL,   -- "GET" | "POST" | ...
  request_path TEXT NOT NULL,     -- capped at 512 chars per §1.6
  payload_sample TEXT NOT NULL    -- capped at 256 chars per §1.6 + redacted
);
CREATE INDEX IF NOT EXISTS idx_waf_event_ts ON waf_event (ts);
CREATE INDEX IF NOT EXISTS idx_waf_event_route_ts ON waf_event (route_id, ts);
CREATE INDEX IF NOT EXISTS idx_waf_event_category_ts ON waf_event (category, ts);

UPDATE schema_version SET version = 2;
```

**Rejected alternative — D3.B (parallel tables for the counter
alone):** still rejected. The bucket counter sits on the
existing tables; the new `waf_event` table is genuinely new
data (per-event rows, not aggregates).

### D4 — Migration mechanism → **A (`ALTER TABLE` + `CREATE TABLE` at boot)**

**Decision: A.** Wrapped in a single transaction with the
schema-version bump (atomic: either v2 is fully there or the
DB stays at v1). Idempotent re-open: on a v2 DB, the migration
short-circuits. New `internal/observability/migrate.go`
implements the migrate(current, target) chain declared by L §6.

**Down-migration not supported.** A v2 binary cannot
meaningfully run against a v1 DB after upgrade is started; a
v1 binary running against a v2 DB ignores the new columns
(SQLite is column-tolerant on `SELECT *`-style reads but the
existing storage code uses explicit column lists, so reads
stay correct — the v1 binary just won't surface the v2 data).

### D5 — Other security signals on the dashboard → **A (WAF only)**

The audit log already carries `ActionLoginFailure`,
`ActionUnlockFailure`, `ActionOIDCLoginRejected`, etc. The rate
limiter (`internal/auth/ratelimit.go`) emits Tier-2 warn lines
but no audit event.

**Three options:**

- **D5.A — WAF-only for Step M.** The dashboard surfaces ONLY
  WAF block counts and the AC #3 4xx/5xx (already covered by
  L). Clean, narrow, ships.
- **D5.B — WAF + auth-failure counts** by reading the audit
  store. The dashboard adds a stat card "Auth failures / 24h"
  and possibly a timeline. Stretches M's scope but uses data
  that already exists.
- **D5.C — WAF + auth-failures + add an `ActionRateLimitHit`
  audit event** to close the gap and surface rate-limit Tier
  hits too. Stretches further; requires touching the rate
  limiter.

**Decision: A.** WAF-only for M. M absorbs ~600 lines from
D1=B already; piling auth-failure timeline + a new
`ActionRateLimitHit` audit event on top would risk neither
piece getting careful treatment.

**Carry-forward for a future step:** the mocks show a
"THROTTLE" tag in the event feed, which the operator wants
alongside WAF events. The rate limiter (`internal/auth/
ratelimit.go`) currently only emits `slog.Warn` — no audit
event. Closing that gap is its own step (call it Q tentative-
ly) because it touches the rate limiter's hot path and needs
its own design pass (audit emission cost, action enum addition,
backward-compatibility with the existing Tier-2 log line).

### D6 — Per-route filtering on WAF blocks → **B (hide WAF-off routes)**

A route with `WafMode == "off"` cannot produce WAF blocks. Its
timeseries on `/security` would be all zeros forever.

- **D6.A — surface all routes uniformly.** Idle WAF-off routes
  render as gap-filled zero series. Consistent with L's "show
  every persisted route" pattern, but visually noisy on the
  top-5 table (a WAF-off route at the top with 0 blocks is
  confusing).
- **D6.B — filter out WAF-off routes** in the dashboard's
  top-5 and route picker. The drill-down page (`/security/<id>`)
  still works if someone navigates to it directly, but shows
  "WAF not enabled on this route" rather than an all-zero
  chart.

**Decision: B.** Dashboard top-5 and route picker hide
WAF-off routes. Direct navigation to
`/security/<waf-off-route-id>` still resolves but renders a
"WAF not enabled on this route" panel (similar to L.4's
"Route introuvable" empty state) rather than an all-zero chart.

### D7 — Retention horizon → **A (same as L)**

L ships 24h at 1-minute granularity + 30d at 1-hour granularity.

- **D7.A — same as L:** WAF counter rides the same bucket
  tables, inherits the same retention.
- **D7.B — longer for security.** Security signals matter
  weeks after the fact (post-incident forensics) more than
  performance metrics do. Could push to 90d at 1-hour
  granularity for the security counter only.

**Decision: A.** WAF block counter inherits the L retention
(24h at 1-min, 30d at 1-hour). The new `waf_event` table
inherits a NEW retention rule: **30 days at row granularity**,
pruned by the same `RetentionRunner` that handles L's tables.
Documented in §3.4 — the retention loop gains a third prune
step for `waf_event WHERE ts < now - 30d`.

**Rationale for matching the bucket retention rather than
going to 90d**: per-event rows can balloon under sustained
attack (one row per blocked request). 30 days at row
granularity is already significantly more storage than L's
aggregated buckets; operators who need post-incident forensics
beyond 30 days should snapshot `metrics.db` externally
(rsync-friendly, single SQLite file).

### D8 — Dashboard layout → **A (as proposed) + recent-events widget**

Same chrome as L's `/observability`:
- 4–5 stat cards
- 2–3 timeline charts (independent per AC #3 discipline)
- top-5 table

Concrete proposal:

**Stat cards (5):**
1. WAF blocks / min (the headline)
2. Top attacked route's blocks/min (one number worth seeing)
3. % of requests blocked (block count / total req across system)
4. Total 4xx / min (carried over from L for context)
5. Active WAF-enabled routes count

**Charts (3):**
1. WAF blocks / min (24h or 30d)
2. 4xx / min (cross-link to L semantically — same data, shown
   here so the operator sees both the scanner-suggestive 4xx
   and the WAF blocks side-by-side)
3. WAF blocks per top attacked route (top-3 routes overlaid? or
   3 separate small-multiples? → see D9)

**Decision: A.** 5 stat cards + 3 charts + top-5 table as
proposed, **plus** the recent-events widget (new — added at
arbitration). Widget sits below the top-5 table on
`/security`, shows the last 10-20 WAF events with
ts / route / category / rule_id / src_ip / payload preview.
Reads from `GET /api/v1/security/events?limit=20`.

The per-OWASP-category counters the mocks require (SQLi /
XSS / RCE / LFI / PROTOCOL) live in the summary response's
new `wafBlocksByCategory` map — rendered as a small
distribution strip above the recent-events widget on the
dashboard.

### D9 — Top-attacked routes visualisation → **A (top-5 table only)**

The dashboard's signature visual question: "which routes are
being attacked most?"

- **D9.A — Top-5 table only.** Same shape as L's top-5,
  cell shows blocks/min for the just-closed minute.
- **D9.B — Stacked area chart** (top-3 routes by blocks
  overlaid). Risks violating AC #3 discipline ("never stacked
  or overlaid"). Defer.
- **D9.C — Small multiples** (3 mini timelines, one per top
  route). Adds visual complexity. Defer.

**Decision: A.** Drill-down (M.4) covers per-route timelines.
Dashboard is the global view; one number per route in a table
is enough at this layer. Small-multiples (D9.C) was rejected
to keep the dashboard's visual hierarchy clear: cards →
distribution → table → events feed.

---

## 1.4 Out of scope

Explicitly NOT in Step M:

- **CrowdSec integration.** → Step N.
- **Rate-limiter "THROTTLE" events in the feed.** Mocks show
  a `THROTTLE` tag alongside WAF events; closing the gap
  requires adding an `ActionRateLimitHit` audit event +
  changing the rate limiter's hot path. Own step (tentative
  Step Q) — see D5 carry-forward.
- **Audit-log-derived auth failure timelines.** → Tentative
  Step Q alongside the rate-limit work; shares the
  "audit-events-as-security-timeline" pattern.
- **Alerting / notifications on threshold crossings.** → Phase 3.
- **IP-reputation deny dashboard.** → Step N (CrowdSec) covers this.
- **Per-event payload forensics beyond a 256-char sample.**
  Full request capture is a privacy + storage hazard; the
  256-char redacted sample is enough to understand the attack
  shape without retaining sensitive bodies. See §1.6.
- **In-app event search / arbitrary filtering.** The events
  endpoint accepts `route` and `category` filters; full-text
  search is deferred.

---

## 1.5 Range of change

Files expected to be touched / added.

**Backend — Coraza-v3 custom module (new):**

| Path | Touch |
|------|-------|
| `internal/waf/module.go` (NEW) | Custom Caddy module `arenet_waf` consuming `coraza/v3` directly. Provision + Validate + ServeHTTP. ~250 lines. |
| `internal/waf/event.go` (NEW) | `WafEvent` struct, OWASP category classifier (rule ID → category map). ~120 lines. |
| `internal/waf/sink.go` (NEW) | `EventSink` interface + non-blocking channel-buffered implementation (same shape as L's `Aggregator.Ingest`). ~80 lines. |
| `internal/waf/module_test.go` (NEW) | Unit tests for the module wiring + category classifier + sink-non-blocking. |
| `internal/waf/category.go` (NEW) | OWASP CRS rule-id → category lookup table. Static map; data sourced from CRS file headers. |
| `go.mod` / `go.sum` | + direct dep on `github.com/corazawaf/coraza/v3` (already indirect via `coraza-caddy/v2`). |

**Backend — observability (extend):**

| Path | Touch |
|------|-------|
| `internal/observability/storage.go` | + `ALTER TABLE` migration (D4); + `WafBlockCount int64` on `MetricBucket`; + new column in InsertBatch / Query / QueryAggregated; + new `InsertWafEvent`, `QueryWafEvents` methods; + the new `waf_event` table + indexes in the schema. |
| `internal/observability/bucket.go` | + `WafBlockCount` field on `MetricBucket`. |
| `internal/observability/aggregator.go` | + counter on `routeState`; absorb path widened. |
| `internal/observability/retention.go` | + sum on hourly rollup; + new prune step for `waf_event WHERE ts < now - 30d`. |
| `internal/observability/migrate.go` (NEW) | `migrate(db, currentVersion, targetVersion)` chain. v1→v2 step adds the bucket column + creates `waf_event`. Wrapped in a single transaction; idempotent re-open. |
| `internal/observability/waf_event.go` (NEW) | `WafEvent` type (mirror of `internal/waf.WafEvent` but lives in the observability domain too; small struct duplication kept honest by a compile-time assertion. Alternative: shared type lives in `internal/waf` and observability imports it — final placement chosen during M.1 implementation). |

**Backend — API:**

| Path | Touch |
|------|-------|
| `internal/api/metrics_handlers.go` | + `waf_block_rate` to MetricName enum; + `totalWafBlockedPerMin` + `wafBlocksByCategory` to summary response. |
| `internal/api/security_handlers.go` (NEW) | `GET /api/v1/security/events` handler. ~80 lines. |
| `internal/api/handler.go` | + `WafEventReader` interface + `SetWafEventReader` setter (same pattern as `SetMetricsReader`). |
| `internal/api/routes.go` | + mount of `/security/events` in the hard-auth-no-admin group (viewer-accessible per D5 → AC #17 carry). |

**Backend — Caddy emit:**

| Path | Touch |
|------|-------|
| `internal/caddymgr/manager.go` | Swap the emit: WafMode ∈ `{block, detect}` routes now get the new `arenet_waf` handler instead of the legacy `waf` (coraza-caddy/v2) handler. Full replacement, no per-route opt-in toggle. See §3.2. |

**Frontend:**

| Path | Touch |
|------|-------|
| `web/frontend/src/lib/api/types.ts` | + `MetricName` literal `waf_block_rate`; + summary fields; + `WafEvent`, `WafEventsResponse`, `OwaspCategory` types. |
| `web/frontend/src/lib/api/security.ts` (NEW) | Typed wrapper for `/security/events`. |
| `web/frontend/src/lib/api/metrics.ts` | No change (extended enum already routes through `fetchTimeseries`). |
| `web/frontend/src/routes/security/+page.svelte` (NEW) | Dashboard. |
| `web/frontend/src/routes/security/[routeId]/+page.svelte` (NEW) | Drill-down. |
| `web/frontend/src/routes/security/[routeId]/+page.ts` (NEW) | `prerender = false`. |
| `web/frontend/src/lib/components/WafEventList.svelte` (NEW) | Recent-events widget. Reused by both `/security` (limit=20, unfiltered) and `/security/[routeId]` (limit=20, route-scoped). |
| `web/frontend/src/lib/components/CategoryDistribution.svelte` (NEW) | Per-OWASP-category bar strip (SQLi / XSS / RCE / LFI / PROTOCOL / OTHER counts). |
| `web/frontend/src/lib/components/Sidebar.svelte` | Flip `/security` from `disabled: true` to enabled. |

**Other:**

| Path | Touch |
|------|-------|
| `cmd/arenet/main.go` | + `apiHandler.SetWafEventReader(obsStore)` mirroring the existing `SetMetricsReader` wiring. |
| `docs/smoke-test-step-m.md` (NEW) | M.5 evidence + verdict. |
| `docs/backlog-step-m.md` (NEW, if findings accumulate). |

---

## 1.6 Threat model deltas vs Step L

D1=B brings real new surface: we capture per-request data
(method, path, payload sample, src IP, rule ID) into a
persisted SQLite table that a viewer-role user can read. This
section enumerates the deltas and the mitigations.

### 1.6.1 Data capture scope (capped + redacted)

Hard caps on capture, applied at the WAF-module event-emit
boundary (NEVER stored uncapped, NEVER logged):

| Field | Cap / treatment |
|-------|-----------------|
| `request_method` | Verbatim — fixed enum, low risk. |
| `request_path` | Cap at **512 chars**; query string included up to the cap. Excess truncated and an ellipsis `…` appended. |
| `payload_sample` | Cap at **256 chars**. Body excerpt only when Coraza matched on the body; otherwise empty string. Excess truncated with `…`. |
| `src_ip` | Verbatim by default. Mitigation against accidental capture of internal RFC1918 IPs: see 1.6.3. |
| `rule_id` / `category` / `severity` / `route_id` / `ts` | Verbatim — Coraza-internal, low risk. |

### 1.6.2 Redaction of common credential patterns

`payload_sample` and `request_path` are run through a single
redaction pass before storage:

- Bearer tokens: `Authorization: Bearer xxxxx` → `Authorization: Bearer [REDACTED]`.
- Cookie headers: `Cookie: ...` → `Cookie: [REDACTED]`.
- Common query params: `?password=...`, `?api_key=...`,
  `?token=...`, `?secret=...` → value replaced with `[REDACTED]`.
- Pattern set defined in `internal/waf/redact.go` (NEW) with
  unit tests asserting each pattern.

This is best-effort, not a security guarantee — operators
running with WAF=block on routes that handle sensitive bodies
should be aware the 256-char sample MAY contain attack-payload
fragments that include credential-shaped strings the
redaction missed. The 256-char cap bounds the worst case.

### 1.6.3 Source IP exposure

`src_ip` is captured from the request's remote address (or the
operator-configured `ARENET_TRUSTED_PROXIES` chain, same as the
audit log). Viewer-role users see the raw IP. This is
intentional — the dashboard's "unique attacker IPs" mocks
require it, and IPs in a security event log are standard
practice.

**Operator note:** if Arenet runs in front of an internal
network (LAN routes), the captured IP may be a private RFC1918
address. No automatic anonymisation in Step M; documented in
the page copy.

### 1.6.4 Read access

`waf_event` rows are exposed via `/api/v1/security/events`,
gated by the same hard-auth-no-admin middleware as Step L
metrics. Viewer-role can read. **No write path** — events are
only emitted from the in-process WAF module; there is no API
to insert / mutate / delete them.

### 1.6.5 Data plane integrity invariant (L AC #13 carried)

WAF-event emission is non-blocking: the new `EventSink.Emit`
does the same atomic-channel-send-or-drop pattern as L's
`Aggregator.Ingest`. A full channel, a flaky SQLite write, or
a panic inside the sink goroutine MUST NOT block the request
path. The WAF *block decision* itself (Coraza's verdict) stays
synchronous and blocks the request as required — that's the
data-plane behaviour we want. Only the *observability emission*
of the event is async.

### 1.6.6 Storage growth

A sustained attack at 100 req/s on a WAF-block route would
emit 100 events/s, each ~600 bytes (rough estimate: ~512 path
+ ~256 payload + headers + indexing overhead). At 100 events/s
sustained, the 30d retention horizon (D7 amendment) accumulates
~150 GB before pruning kicks in — clearly too much.

**Mitigation: rate-limit event emission per route-IP-rule
triple.** If the same (route, src_ip, rule_id) tuple already
emitted an event in the last 60s, subsequent matches increment
the bucket counter but do NOT emit a new event row. The
operator still sees the attack volume on the timeline (counter
increments); the event log retains the first sample as the
representative event. Implementation: an LRU keyed by the
triple, capped at 10k entries, lives in the event sink. Tested
at M.1.

---

## 2. Acceptance Criteria

Numbered, each PASS/PARTIAL/N/A at L.5-style smoke time.

**AC #1 — WAF event emitted on a real CRS-tripping payload.**
With a route in WAF=block mode receiving a SQL-injection probe
(or any other known-bad payload that trips an OWASP CRS rule),
a row appears in the `waf_event` table within a few seconds.
Fields populated: `route_id`, `rule_id` (e.g. `942100`),
`category=SQLi`, `severity` (Coraza scale), `src_ip`,
`request_method`, `request_path` (capped + redacted),
`payload_sample` (capped + redacted). Verified live with
multiple payloads tripping different rule categories
(SQLi / XSS / RCE).

**AC #2 — WAF block counter on the same event.**
The minute-bucket row for the same route at the same `ts`
shows `waf_block_count` incremented by 1 (the per-event-emit
also drives the aggregator's counter). The aggregator and the
event log are populated by the same `EventSink.Emit` call —
asserted by counting events seen in `waf_event` and reconciling
with the bucket counter for the same minute.

**AC #3 — A 403 from a WAF=off route does NOT touch the WAF
counter or the event table.** Routes with `WafMode=off` get
no WAF handler emitted in their Caddy chain (unchanged from
Step I.4 — the handler emit is gated on `WafMode ∈ {block,
detect}`). A 403 returned by such a route's backend produces
zero WAF activity in either store.

**AC #4 — WAF counters INDEPENDENT of 4xx and 5xx.**
A WAF block increments `waf_block_count` and `req_count` only —
NOT `fourxx_count` despite the response status being 403.
(Otherwise the operator would double-count blocks as both WAF
events and 4xx.) Anti-regression: a WAF-block test asserts
`fourxx_count` stayed at 0 in the row that captured the block.
Symmetric for 5xx.

**AC #5 — Per-event rate-limit (LRU) holds under sustained
attack.** Sustained burst of 1000 identical requests
(same route, same src_ip, same rule_id) produces ONE
`waf_event` row + a `waf_block_count` matching the request
count. The bucket counter is NOT rate-limited; only the event
log is. Verified at smoke with a `ab`-style burst.

**AC #6 — Schema migration v1 → v2 succeeds idempotently.**
Boot against a pre-Step-M `metrics.db` (schema version 1):
adds `waf_block_count` column on both bucket tables, creates
`waf_event` + indexes, bumps `schema_version` to 2 — all in a
single transaction. Re-opening on a v2 DB is a no-op. Verified
by snapshotting an L-era metrics.db, booting M against it, and
asserting both the old data is intact and the new tables /
columns are present.

**AC #7 — REST API extensions.**
- `GET /api/v1/metrics/timeseries?metric=waf_block_rate` works
  with the same shape as L's other metrics (1440 points over
  24h, gap-fill 0 — counts always 0-fillable).
- `GET /api/v1/metrics/summary` includes `totalWafBlockedPerMin`
  AND `wafBlocksByCategory` (map of category → count over the
  just-closed minute).
- `GET /api/v1/security/events?limit=20` returns the 20 most
  recent events, ts-descending. Supports `route` and
  `category` filters. Each event includes all the fields
  from AC #1.

**AC #8 — Dashboard renders the full mock layout.**
`/security` shows: 5 stat cards (WAF blocks/min,
top-attacked-route blocks/min, % requests blocked, total
4xx/min for context, active WAF-enabled routes), category
distribution strip (SQLi/XSS/RCE/LFI/PROTOCOL/OTHER), 3
independent timeline charts (WAF blocks, 4xx for context, top-3
categories overlayed), top-5 table, recent-events widget.
Loads under 1 s on a 100-row metrics.db with 10k events.

**AC #9 — Drill-down renders.**
`/security/<routeId>` shows: route header (host, WAF mode),
the WAF block timeline alongside req for context, the
per-rule breakdown table for the route's blocks over the
window, recent-events widget filtered to the route.

**AC #10 — WAF-off route drill-down empty state.**
`/security/<waf-off-route-id>` resolves to 200 (route exists)
but renders a dedicated "WAF not enabled on this route" panel
instead of an all-zero chart. Per D6.

**AC #11 — Sidebar entry enabled.**
`/security` becomes the new sidebar entry; the existing
`disabled: true` placeholder is flipped. Viewer-accessible.

**AC #12 — Viewer-accessible.**
Same gate as Step L `/observability`. Anon → 401. Viewer →
200 (timeseries + summary + events). Admin → 200. Asserted by
a unit test identical in shape to `TestMetricsEndpoints_Viewer200`.

**AC #13 — Data plane integrity (the L AC #13 invariant carried).**
WAF-event emission is non-blocking (channel-buffered, drops on
full). A faulty sink (synthetic InsertWafEvent error) is
logged + counted + swallowed; the request path never sees it.
Verified by a unit test mirroring L's `TestAggregator_FlushErrorIsLoggedAndSwallowed`.

**AC #14 — Payload redaction enforced.**
Unit tests assert each declared redaction pattern (Bearer
token, Cookie header, password / api_key / token / secret
query params). Verified at smoke with a synthetic payload
containing each pattern; the stored `payload_sample` carries
`[REDACTED]` markers in their place.

**AC #15 — Step L unchanged.**
All Step L tests + endpoints keep working. The `/observability`
dashboard still renders. The L.5 smoke matrix re-runs at M.5
and stays PASS.

**AC #16 — Bundle budget.**
`/security` page chunk + drill-down chunk + the two new
components (WafEventList, CategoryDistribution) together stay
under 10 kB gz.

**AC #17 — Tests pass.**
Go: all packages green. Frontend: 172 passing (baseline +
M's new tests), 2 known-flaky preserved.

**AC #18 — Lint clean.**
`go vet`, `staticcheck`, `svelte-check` all clean on the M
surface.

---

## 3. Architecture impact

### 3.1 Domain model deltas

```go
// internal/observability/bucket.go — add one field
type MetricBucket struct {
    RouteID        string
    Ts             time.Time
    ReqCount       int64
    FourxxCount    int64
    FivexxCount    int64
    WafBlockCount  int64 // ← NEW, Step M
    LatencyP95Ms   int32
}

// internal/waf/event.go (NEW) — per-event row.
type WafEvent struct {
    ID             int64
    Ts             time.Time
    RouteID        string
    RuleID         string        // e.g. "942100" (OWASP CRS)
    Category       OwaspCategory // SQLi / XSS / RCE / LFI / PROTOCOL / OTHER
    Severity       int           // Coraza 0–7
    SrcIP          string
    RequestMethod  string
    RequestPath    string        // capped 512 + redacted
    PayloadSample  string        // capped 256 + redacted
}

type OwaspCategory string

const (
    CategorySQLi     OwaspCategory = "SQLi"
    CategoryXSS      OwaspCategory = "XSS"
    CategoryRCE      OwaspCategory = "RCE"
    CategoryLFI      OwaspCategory = "LFI"
    CategoryProtocol OwaspCategory = "PROTOCOL"
    CategoryOther    OwaspCategory = "OTHER"
)
```

### 3.2 Custom Coraza-v3 module integration

`internal/waf/module.go` defines a new Caddy module
`arenet_waf` that wraps `github.com/corazawaf/coraza/v3`
directly. The module's `ServeHTTP` evaluates Coraza on the
request; on a match in block mode it calls
`EventSink.Emit(WafEvent{...})` BEFORE returning the 403 to
the client. The sink call is non-blocking.

For routes that previously emitted the `coraza-caddy/v2`
`waf` handler (Step I.4), the new module is emitted INSTEAD
when `WafMode` ∈ `{block, detect}` — full replacement, no
opt-in toggle (see §1.3 D1 implications). The
`coraza-caddy/v2` dep stays in go.mod for now because the
caddymgr unit tests still import it via side-effect to keep
the legacy `waf` handler ID registered for back-compat
fixture assertions; removing the dep entirely is a small
follow-up commit that lands after M.5 PASS (touching tests
+ go.mod) before Step N starts.

### 3.3 Event sink

```go
// internal/waf/sink.go (NEW)
type EventSink interface {
    Emit(WafEvent) // non-blocking; drops on full channel
}
```

Production implementation: channel-buffered (1024 events),
drained by a goroutine that batches inserts into
`waf_event` every 250 ms or every 100 events, whichever comes
first. Same shape as L's `Aggregator.Run` / `Aggregator.flush`
pattern. The aggregator's bucket counter is incremented by
the SAME `Emit` call (one event → one increment + one row
queued), so the two stores never drift.

### 3.4 REST API

- `/api/v1/metrics/timeseries?metric=waf_block_rate` — extends
  the existing handler. Same shape as L's other count metrics.
- `/api/v1/metrics/summary` — gains `totalWafBlockedPerMin`
  and `wafBlocksByCategory` (a `map[string]int64` keyed by
  `OwaspCategory`). The category map is computed by joining
  the most-recent-minute `waf_event` rows on category.
- `/api/v1/security/events?limit=<n>&route=<id>&category=<cat>`
  (NEW) — sparse event rows, ts-descending. `limit` capped
  server-side at 100; `route` and `category` optional filters.

### 3.5 Schema migration

```sql
-- internal/observability/migrate.go (NEW)
-- v1 → v2 transaction:

ALTER TABLE bucket_1m ADD COLUMN waf_block_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bucket_1h ADD COLUMN waf_block_count INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS waf_event (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  route_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  category TEXT NOT NULL,
  severity INTEGER NOT NULL,
  src_ip TEXT NOT NULL,
  request_method TEXT NOT NULL,
  request_path TEXT NOT NULL,
  payload_sample TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_waf_event_ts          ON waf_event (ts);
CREATE INDEX IF NOT EXISTS idx_waf_event_route_ts    ON waf_event (route_id, ts);
CREATE INDEX IF NOT EXISTS idx_waf_event_category_ts ON waf_event (category, ts);

UPDATE schema_version SET version = 2;
```

The default 0 on the bucket columns is critical: rows from
before Step M get a sensible value, no NULL handling on the
read path. The migration is wrapped in a single transaction:
either v2 is fully there or the DB stays at v1.

### 3.6 Retention

`RetentionRunner` gains a third prune step:

```go
// Delete waf_event rows older than 30d.
DELETE FROM waf_event WHERE ts < ?
```

Runs at the same hourly cadence as the L prunes. No rollup
(events are not aggregated into a coarser table; they're
discarded at 30d).

---

## 4. Sub-tasks (ordered)

| # | Title | Surface | Commit |
|---|-------|---------|--------|
| M.1 | WAF event capture + schema migration | backend | 1 |
| M.2 | REST API extension | backend | 1 |
| M.3 | `/security` dashboard | frontend | 1 |
| M.4 | `/security/[routeId]` drill-down | frontend | 1 |
| M.5 | Smoke + tag | smoke + doc | 1 + tag |

---

## 5. Per-sub-task design

### 5.1 M.1 — Custom Coraza module + schema v1→v2

**New files:**
- `internal/waf/module.go` — `ArenetWafHandler` (Caddy
  module), Provision (loads CRS + Coraza-recommended
  directives + per-route mode), Validate, ServeHTTP. On a
  Coraza match in `block` mode: call `sink.Emit(WafEvent)`,
  then return the 403 to the client. In `detect` mode: emit
  the event, do not block.
- `internal/waf/event.go` — `WafEvent`, `OwaspCategory` const
  block.
- `internal/waf/category.go` — `categoryForRule(ruleID
  string) OwaspCategory` — lookup table from CRS rule-ID
  ranges to category (e.g. 942000-942999 → SQLi, 941000-
  941999 → XSS, etc., per CRS conventions). Hardcoded map;
  unit-tested per category against the CRS doc.
- `internal/waf/sink.go` — `EventSink` interface + struct
  + Run goroutine. Channel size 1024. Batched flush every
  250 ms or every 100 events.
- `internal/waf/redact.go` — payload redaction (Bearer,
  Cookie, password / api_key / token / secret patterns).
  Pure-function `redact(s string) string`. Unit-tested per
  pattern.
- `internal/waf/lru.go` — `(routeID, srcIP, ruleID) → lastEmit
  time.Time` LRU, capped at 10k entries, 60s TTL. The event
  sink consults this BEFORE emitting; if the triple is
  recently-seen, only the bucket counter increments. The
  event log skips.
- `internal/observability/migrate.go` — `Migrate(db, from,
  to)` chain; v1→v2 transaction (column add + new table +
  indexes + version bump). Idempotent; `Open()` calls
  `Migrate(db, currentVersion, targetVersion=2)` after
  reading `schema_version`.
- `internal/observability/storage.go` — `InsertWafEvent(ctx,
  WafEvent) error`, `InsertWafEventBatch(ctx, []WafEvent)
  error`, `QueryWafEvents(ctx, filter) ([]WafEvent, error)`.
  `filter` carries `RouteID *string`, `Category
  *OwaspCategory`, `From time.Time`, `Limit int` (capped 100
  server-side).
- `internal/caddymgr/manager.go` — emit `arenet_waf`
  handler for routes with WafMode ∈ `{block, detect}` in
  place of the existing `waf` (coraza-caddy/v2) handler.
  TestBuildConfigJSON_HandlersAllResolvable extended to
  cover the new handler ID.

**Tests (in-process unit-level):**
- `TestMigrate_v1_to_v2` — open an L-era schema-version-1 DB,
  run Migrate, assert v2 schema present + old rows intact.
- `TestMigrate_v2_to_v2_NoOp` — re-open on v2.
- `TestCategoryForRule_AllCRSRanges` — assert each known CRS
  range maps to the documented category.
- `TestRedact_AllPatterns` — each declared pattern produces
  `[REDACTED]`; non-matching text passes through unchanged.
- `TestEventSink_NonBlocking` — Emit under contention; full
  channel drops; Dropped() counter increments.
- `TestEventSink_LRU_RateLimitsEmission` — Emit 1000 events
  with the same (route, IP, rule) within 60s → expect ONE
  row persisted, 1000 Dropped-by-LRU counted separately
  from channel drops.
- `TestStorage_InsertWafEvent_RoundTrip` — round-trip + query
  by route, category, limit.
- `TestArenetWafHandler_BlockModeEmitsAndDenies` — driving the
  module with a mock Coraza match → asserts the sink saw the
  event AND the response status is 403.
- `TestArenetWafHandler_DetectModeEmitsAndPasses` — same but
  passes through to the next handler.

### 5.2 M.2 — REST API extension

**Touched files:**
- `internal/api/metrics_handlers.go` — extend `MetricName`
  enum with `waf_block_rate`. `pickMetricValue` learns the
  new metric → `bucket.WafBlockCount` mapping. Summary
  response gains `totalWafBlockedPerMin` and
  `wafBlocksByCategory map[string]int64`. The category
  breakdown is computed by querying the most-recent-minute
  `waf_event` rows GROUP BY category — one extra small query
  per summary call (acceptable, the summary endpoint is
  already a few per-route queries on the dashboard load).
- `internal/api/security_handlers.go` (NEW) —
  `securityEvents` handler. Validates limit (≤100), parses
  optional `route` and `category` filters, calls
  `WafEventReader.QueryWafEvents`, returns JSON
  `WafEventsResponse{events: [...]}`.
- `internal/api/handler.go` — `WafEventReader` interface
  + `SetWafEventReader` setter. `*observability.Store`
  satisfies the interface.
- `internal/api/routes.go` — mount
  `/api/v1/security/events` in the hard-auth-no-admin group
  (viewer-accessible).
- `cmd/arenet/main.go` — `apiHandler.SetWafEventReader(obsStore)`
  next to the existing `SetMetricsReader` call. Same nil-
  guard discipline.

**Tests:**
- `TestSecurityEvents_Anon401`, `TestSecurityEvents_Viewer200`
  — auth gate (mirror L's pattern).
- `TestSecurityEvents_NilReader_DisabledResponse` — boot-
  failed observability → 200 with `disabled: true`.
- `TestSecurityEvents_QueryError_503` — synthetic failing
  reader.
- `TestSecurityEvents_LimitCappedAt100` — limit=500 is
  clamped to 100.
- `TestSecurityEvents_RouteFilter`, `TestSecurityEvents_CategoryFilter`
  — filters work.
- `TestMetricsSummary_WafBlockedByCategoryAggregates` — the
  category map is populated correctly given a mixed event set.

### 5.3 M.3 — `/security` dashboard

**New files:**
- `web/frontend/src/routes/security/+page.svelte` — 5 stat
  cards, category distribution strip, 3 timeline charts
  (waf-blocks, 4xx for context, top-3-category overlay via
  3 stacked TimelineCharts), top-5 table (filtered to
  WAF-enabled routes per D6), recent-events widget.
- `web/frontend/src/lib/api/security.ts` — `fetchEvents`
  typed wrapper.
- `web/frontend/src/lib/components/WafEventList.svelte` —
  Recent-events table. Props: `events: WafEvent[]`,
  `compact?: boolean` (drill-down uses compact). Renders
  ts (relative), route (link to drill-down), category
  badge (status-warn for SQLi/XSS/RCE, status-info for
  PROTOCOL/OTHER), rule_id (mono), src_ip (mono), payload
  preview (truncated).
- `web/frontend/src/lib/components/CategoryDistribution.svelte`
  — Per-category horizontal bar strip. Each category gets a
  fixed colour token (SQLi=status-down, XSS=status-warn,
  RCE=status-down, LFI=status-warn, PROTOCOL=status-info,
  OTHER=text-muted). Width proportional to count over the
  window.

**Type additions in `lib/api/types.ts`:**

```ts
export type OwaspCategory = 'SQLi' | 'XSS' | 'RCE' | 'LFI' | 'PROTOCOL' | 'OTHER';
export interface WafEvent {
    id: number;
    ts: string;
    routeId: string;
    ruleId: string;
    category: OwaspCategory;
    severity: number;
    srcIp: string;
    requestMethod: string;
    requestPath: string;
    payloadSample: string;
}
export interface WafEventsResponse {
    disabled?: boolean;
    events: WafEvent[];
}
// SummaryResponse already declared; extends with:
//   totalWafBlockedPerMin: number;
//   wafBlocksByCategory: Record<OwaspCategory, number>;
```

**Sidebar wiring:** flip `disabled: true` → enabled; icon
remains the existing `shield` Lucide path; entry stays at its
current position (between Observability and Settings).

### 5.4 M.4 — Per-route `/security/[routeId]` drill-down

**New files:**
- `web/frontend/src/routes/security/[routeId]/+page.svelte`
  — Route header (host, WAF mode badge), WAF timeline chart
  (req chart alongside for context), per-rule breakdown
  table (rule_id, category, count, last-seen), recent-events
  widget filtered to the route.
- `web/frontend/src/routes/security/[routeId]/+page.ts`
  — `prerender = false`.

**WAF-off route handling (AC #10):** the page detects
`route.wafMode === 'off'` after `getRoute()` resolves and
renders a dedicated "WAF not enabled on this route" panel
instead of the charts. Drill-down on a WAF-enabled route that
has had zero blocks in the window shows the chart's in-SVG
"no data in this window" empty state (same as L's pattern).

### 5.5 M.5 — Smoke + tag

Mirror Step L.5. Use `ARENET_HTTP_PORT` / `ARENET_HTTPS_PORT`
overrides. Differences:
- Send a known CRS-tripping payload (SQLi-like
  `?id=1+OR+1=1+--`, XSS `?q=<script>`, etc.) via curl
  against a route with WafMode=block.
- Verify `waf_event` rows are persisted with the expected
  rule_id and category.
- Verify the bucket counter increments alongside the events.
- Verify the API surfaces both.
- Verify the dashboard renders the events feed + category
  strip.
- Verify the LRU rate-limit holds under a 1000-burst.
- Verify AC #15: re-run the L.5 smoke matrix in this same
  binary → still PASS.
- Verify the AC #4 split (4xx counter NOT incremented on a
  WAF block).

---

## 6. Migration strategy

`metrics.db` schema v1 → v2 via `ALTER TABLE` at boot, gated by
the `schema_version` row. First time the L §6 future-bump path
is exercised in production. Down-migration: not supported (a v2
binary cannot meaningfully run against a v1-only operator who
rolled back).

---

## 7. Smoke test plan (skeleton, filled at M.5)

Mirror Step L's smoke plan. Use the `ARENET_HTTP_PORT` /
`ARENET_HTTPS_PORT` overrides already in place. Differences:

- Send a known-bad SQL-injection payload to exercise the WAF
  block path (`curl ... '?id=1 OR 1=1'` or similar; the OWASP
  CRS-bundled rules should trip).
- Verify `waf_block_count` increments in SQLite.
- Verify the API surfaces the new metric.
- Verify the dashboard renders.
- Verify the L.5 matrix still PASSes (no regression).

---

## 8. Tag plan

Spec freeze: `v0.9.0-step-m-spec` after arbitration. Implementation
tag `v0.9.0-step-m` after M.5 PASS. Same discipline as L: no
push without operator sign-off, no implementation tag before
smoke verdict.

---

## 9. Spec freeze tag

Same convention as L (spec doc §9): freeze with
`v0.9.0-step-m-spec`. Subsequent amendments land as in-doc
"Spec-1 §10" sections + a refreshed `v0.9.0-step-m-spec-N` tag
near M.5 if anything material shifted. Do not churn spec tags
during M.1–M.4 work.

---

## 10. Decisions resolved (2026-05-28)

Arbitration outcome, captured here for future readers:

| ID | Decision |
|----|----------|
| D1 | **B** — custom Coraza-v3 module (mocks require per-event fidelity that status-code A cannot deliver). |
| D2 | **A** with carve-out — extend `/metrics/*` for counters; one new `/security/events` endpoint for the event log. |
| D3 | **A** — shared columns + new `waf_event` table (the latter forced by D1=B). |
| D4 | **A** — `ALTER TABLE` + `CREATE TABLE` at boot, single transaction. |
| D5 | **A** — WAF only. Rate-limit "THROTTLE" events deferred to a future step (Q tentative). |
| D6 | **B** — hide WAF-off routes from dashboard top-5; drill-down on a WAF-off route shows a dedicated empty state. |
| D7 | **A** for the bucket counter (same as L); 30 d row-granularity retention for `waf_event`. |
| D8 | **A** as proposed + recent-events widget. |
| D9 | **A** — top-5 table only on the dashboard; per-route detail lives on the drill-down. |

Spec freeze tag `v0.9.0-step-m-spec` lands on the commit that
introduces this file in its final form. Subsequent amendments
go through the §9 Spec-1 amendment pattern (in-doc §11 section,
spec-N re-tag only at M.5 if anything material shifted).
