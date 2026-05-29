# Step N — CrowdSec integration

**Status**: DRAFT (decisions OPEN — see §1.3).
**Date**: 2026-05-29.
**Builds on**: Steps M (WAF events) + Q (rate-limit + auth-failure events).
**Tag (post-freeze)**: `v1.1.0-step-n-spec` (local), then `v1.1.0-step-n` after N.5 smoke.

---

## 1. Goal & scope

### 1.1 Goal

Integrate CrowdSec as a third security gate on the Arenet data plane, alongside the WAF (Step M, Coraza/CRS) and the per-IP auth rate limiter (Step Q). CrowdSec's distinctive value is **community-sourced IP reputation**: an attacker who tripped a scenario on any participating node ends up on the local LAPI's deny list, which Arenet then enforces at the proxy edge — BEFORE the request reaches the WAF or the auth gate.

The Step Q.4 dashboard mock surface promises rows like
`185.142.86.0/24 · SQLi · auto` — these correspond to CrowdSec
**range-scoped ban decisions** with the scenario name surfaced as
the kind. Step N is what makes those rows real.

### 1.2 Scope (5 sub-tasks)

| Sub-task | Surface | Description |
|----------|---------|-------------|
| N.1 | backend | Embed `github.com/hslatman/caddy-crowdsec-bouncer v0.12.1` as a Caddy app + handler in the runtime config. Add the `apps.crowdsec` block to `caddymgr.buildConfigJSON`. Confirm boot-time bouncer init in live and degraded modes. |
| N.2 | backend | Parallel decision consumer: spawn an independent `go-cs-bouncer.StreamBouncer` (Arenet's own consumer of LAPI, distinct from the embedded bouncer's enforcement loop). Mirror every `{new, deleted}` delta into a new `decision_event` SQLite table. Schema migration v3→v4. New `internal/crowdsec/` package with sink + LRU + global pattern. |
| N.3 | backend | REST API: `GET /api/v1/security/decisions` (event log, mirror of `/throttle-events`), extend `/metrics/timeseries` with `crowdsec_decision_rate`, extend `/metrics/summary` with `totalCrowdSecDecisionsPerMin` + `activeCrowdSecIpsUnique`, extend `/security/attackers-summary` to add CrowdSec as a 4th union source. |
| N.4 | frontend | `/security` dashboard: +2 stat cards (CrowdSec / min, active bans), +1 timeline chart, +1 source in MixedEventList (`CROWDSEC` badge with scenario as detail). New `/security/decisions` page with the active-ban list (`185.142.86.0/24 · SQLi · auto`-style rows) per spec D5 mock promise. Per-route drill-down unchanged. |
| N.5 | smoke + doc | Live smoke against a local LAPI instance: bootstrap a `cscli bouncers add arenet-test`, push a decision via `cscli decisions add`, verify Caddy 403s the IP, verify `decision_event` row + bucket counter ticks + dashboard surfaces. AC #13 sabotage: kill LAPI mid-run + boot with LAPI unreachable. Tag `v1.1.0-step-n`. |

### 1.3 Locked decisions

(All decisions arbitrated 2026-05-29; rationale of record preserved.)

#### D1 — Bouncer enforcement mode → **A (streaming)**

The Caddy bouncer (`caddy-crowdsec-bouncer`) supports two modes:

- **D1.A — Streaming mode** (`enable_streaming: true`). Bouncer polls LAPI every `ticker_interval` (default 60s in the Caddy app), maintains an in-memory `ipstore.Store` of decisions, matches inbound IP against the local cache. Sub-millisecond hot path. **Known issue #61**: graceful reload hangs the Caddy admin API. Since `caddymgr.applyLocked` calls `caddy.Load()` on every route mutation, this could hang the admin path during heavy edits.

- **D1.B — Live mode** (`enable_streaming: false`). Bouncer makes a synchronous `GET /v1/decisions?ip=<value>` to LAPI on every request. ~10ms LAPI round-trip per request. No reload hang, but every blocked-or-not request hits LAPI. Doesn't scale, and creates a fail-closed dependency on LAPI uptime for the entire data plane.

**Decision: A.** Streaming mode is the documented production shape
for the bouncer; live mode adds 10 ms LAPI round-trip per request,
which is unacceptable for a reverse proxy. The reload-hang trade-off
(#61) is acceptable on a homelab where route mutations happen by
the dozen per day, not per second. Documented as known limitation
in §7 risks; operators who hit a hung reload restart Arenet.

**Rejected — D1.B:** added per-request LAPI latency in exchange for
clean reload semantics is the wrong trade — reloads are rare,
requests are the steady state.

#### D2 — Fail-open vs fail-closed on LAPI unreachable → **A (fail-open)**

The bouncer exposes `enable_hard_fails`:

- **D2.A — Fail open** (`enable_hard_fails: false`, the default). LAPI unreachable → requests pass through unchecked. Smoke test would: stop LAPI, hit a previously-banned IP, expect 200 (degraded reputation gate but data plane vivant).

- **D2.B — Fail closed** (`enable_hard_fails: true`). LAPI unreachable at startup → Caddy load fails → Arenet boot fails. Mid-process LAPI loss is murkier (bouncer keeps the last snapshot in `ipstore.Store` so cached bans still apply, but new decisions stop arriving).

**Decision: A.** Homelab data plane must NEVER fail closed on a
peripheral subsystem outage. WAF (Step M) + rate-limiter (Step Q)
remain meaningful protection floors even without CrowdSec; the
reputation gate is additive, not load-bearing. Coherent with AC #13
across M, Q, and N: "Caddy keeps serving requests" is the
invariant, "degraded protection" is a documented and operator-
visible state.

**Rejected — D2.B:** boot-failure on a peripheral subsystem is the
exact kind of cascading failure homelab operators (single binary,
single host) cannot recover from remotely. The production-paranoid
shape is appropriate for a different deployment topology than
Arenet targets.

#### D3 — Decision consumer architecture → **A (parallel StreamBouncer)**

The bouncer exposes **no callback or event hook** — confirmed via source read of `internal/core/core.go` and `internal/bouncer/stream.go`. To get `{new, deleted}` deltas into Arenet's own `decision_event` table for the dashboard, two options:

- **D3.A — Parallel StreamBouncer consumer.** Arenet runs its OWN `go-cs-bouncer.StreamBouncer` instance pointed at the same LAPI as the Caddy bouncer. Both poll independently; small bandwidth duplication. **Pros**: clean separation; bouncer enforcement and Arenet mirroring stay decoupled; if either fails, the other survives. **Cons**: 2× HTTP polls against LAPI.

- **D3.B — Fork the bouncer to add a hook.** Patch `caddy-crowdsec-bouncer` locally to expose an event callback when decisions are added/removed. Avoids the duplicate poll but creates a fork-maintenance burden. We've avoided forks elsewhere (M used the upstream Coraza unmodified).

**Decision: A.** Arenet's M and Q precedents both consume upstream
libraries verbatim (Coraza, go-cs-bouncer itself). Maintaining a
fork solely to add an event hook would couple Arenet's release
cadence to upstream regression risk on a non-load-bearing surface.
The bandwidth cost — one HTTP stream poll every 60s against
loopback or LAN LAPI — is invisible. Independent consumers also
give us per-process recover-on-panic semantics: if the Arenet
consumer panics, the bouncer enforcement is unaffected, and vice
versa.

**Rejected — D3.B:** fork maintenance burden outweighs the
bandwidth saving by orders of magnitude; we lose alignment with
the upstream ecosystem that this Step N integration explicitly
joins (the `hub.crowdsec.net` endorsed bouncer line).

#### D4 — Decision event LRU dedupe semantics → **A (dedupe BEFORE bump)**

The fundamental shape difference from M/Q:

- M (WAF) and Q (throttle) emit ONE event per decision moment. The sink LRU **dedupes AFTER bump** (bump-then-suppress per AC #3): every absorb bumps the bucket counter, only the first per `(key)` lands in the event table.

- CrowdSec LAPI **re-emits every active decision on every Sync** when `?startup=true` AND every poll cycle the bouncer reads the full active set. A naive bump-then-suppress would inflate `crowdsec_decision_count` by `(active_count × polls_per_minute)` every minute — wrong.

- **D4.A — Dedupe BEFORE bump.** LRU keyed on `decision.UUID` with a long TTL (e.g. 1 hour). First sight → emit + bump. Re-sight → drop without bump. Tombstone on `deleted[]` event. The bucket counter then reflects "decisions ARRIVED this minute" (new bans), not "decisions ACTIVE this minute".

- **D4.B — Dedupe AFTER bump, but only count first-sight.** Conditional bump: `if shouldEmit(uuid) { bump(); persist() }`. Same net result as A; the difference is whether the bump is conditional or the LRU is positioned before the counter.

**Decision: A.** The functional outcomes are equivalent, but the
asymmetry vs M/Q is load-bearing for future-reader comprehension:
M and Q dedupe AFTER bump because they're 1-to-1 with a request
decision moment. N dedupes BEFORE bump because the producer
(LAPI Stream) re-emits the active set on every poll. Placing the
LRU as an explicit gate BEFORE the counter makes that semantic
visible at the call site (`if !shouldEmit { return }` reads as
"this is a re-sight, drop entirely") rather than embedded in a
conditional bump. Code archaeology when someone later asks "why
is N's sink different" is one read of `absorb()` instead of three.

**Rejected — D4.B:** functionally equivalent but obscures the
semantic difference behind a conditional. The asymmetry vs M/Q
is the point — documenting it structurally beats documenting it
in a comment.

#### D5 — Scope of the decision_event row → **B (operator-facing subset)**

The decision JSON shape from LAPI:
```
{id, uuid, scope, value, type, scenario, origin, duration, until}
```

Some fields are operator-facing (scenario, value, until); others are internal (id, origin). What do we persist?

- **D5.A — Full row.** All 9 fields. Storage tax minimal (decisions per day on a homelab is tens to low-hundreds).

- **D5.B — Operator-facing subset.** `{uuid, ts, scope, value, type, scenario, expires_at, duration_seconds}`. Drops `id` (server-local, useless on Arenet side), `origin` (CrowdSec metadata).

**Decision: B.** `id` is LAPI's server-local autoincrement — useless
on the Arenet side because `uuid` is the stable cross-instance
identifier (the LAPI `id` would change if the operator rebuilt
their CrowdSec install, breaking row identity continuity across
Arenet boots). `origin` is operational CrowdSec metadata (whether
the decision came from `cscli`, the agent, or a community list)
that has no admin-UI surface in Step N — adding it adds noise
without operator value. Future-proofing if either field becomes
useful: the migration step adds it as a column without backfill,
same shape as the v1→v2 / v2→v3 pattern.

**Rejected — D5.A:** "store everything just in case" inflates the
table for fields the dashboard will never read. The reverse
migration is trivial when needed.

#### D6 — Trusted-proxy IP discrepancy → **A (bouncer-observed only)**

Backlog finding #Q.5-2 (live smoke): the WAF event's `src_ip` is the connection-level remote address (Caddy's `mr.ClientIPAddress()`), NOT the trusted-proxy-resolved IP. CrowdSec faces the same: the bouncer reads the request's IP from Caddy's middleware chain, which (depending on the bouncer's source order) MAY or MAY NOT see the post-XFF IP.

- **D6.A — Store the bouncer-observed IP only.** Whatever the bouncer matched on (the IP that triggered the block). Simpler.

- **D6.B — Store both bouncer-observed AND XFF-resolved IPs.** The dashboard can show both; operator sees the discrepancy explicitly.

**Decision: A.** The IP-extractor discrepancy is a known
cross-cutting backlog item (#Q.5-2) that affects M, Q, AND N. Step
N must not add a new column shape that pre-empts the eventual
fix — when the fix lands, it's a single observability-layer change
that retroactively makes all three signals consistent, not a
schema migration for N alone. Storing both IPs in N's table would
also expose operators to the discrepancy in an inconsistent UX
(only N shows both, M+Q show one).

**Rejected — D6.B:** premature divergence. The cross-cutting fix
is the right surface for this concern, scheduled out-of-band per
backlog #Q.5-2.

#### D7 — Polling cadence → **A (60s, match Caddy bouncer)**

go-cs-bouncer StreamBouncer default `TickerInterval = "10s"`. Caddy bouncer default `"60s"`. Two consumers, two cadences.

- **D7.A — Match Caddy bouncer cadence** (60s). Lower bandwidth, decisions land in Arenet within ~60s of LAPI insertion. Fine for the dashboard which updates per-minute anyway.

- **D7.B — 10s for the Arenet consumer.** Faster dashboard update, 6× the LAPI poll volume.

**Decision: A.** The dashboard chart aggregates per-minute; a ~60s
freshness ceiling is the inherent UX granularity. Driving the
consumer at 10s would increase LAPI poll volume 6× for zero
operator-visible improvement (the new decisions don't land in
buckets faster than the minute boundary anyway). Both consumers
on the same 60s tick also simplifies operator mental model: "every
~60s, both the bouncer cache and the Arenet mirror catch up to
LAPI".

**Rejected — D7.B:** 6× the poll volume against LAPI for a
benefit the dashboard can't render. Latency-cost trade-off is
inverted vs the gain.

#### D8 — Decision retention horizon → **A (30 days)**

Mirror of M.5 / Q.5 D9: how long do we keep historical `decision_event` rows after they expire?

- **D8.A — 30 days at row granularity.** Same as RetainWafEvents / RetainThrottleEvents.

- **D8.B — Match the longest possible CrowdSec decision duration.** CrowdSec community blocklists carry `4h` (default Crowdsec scenarios) to `8760h` (1y, blocklist-style). Retaining beyond the longest active duration is forensic. 30 d is plenty.

**Decision: A.** Consistent with M.5 D7 (waf_event 30d) and Q.5 D9
(throttle_event 30d). An operator investigating an incident at day
29 should find WAF, throttle, AND CrowdSec signal in the same
horizon — heterogeneous horizons across the three event tables
would create confusing dashboard gaps. The 30d cap also keeps
storage bounded against a noisy LAPI (community blocklists can
churn thousands of decisions per day).

**Rejected — D8.B:** matching the longest CrowdSec duration
(potentially 1y) creates an asymmetry with M / Q that the
dashboard cannot represent cleanly. Forensic operators who need
beyond-30d retention snapshot metrics.db externally — same
guidance as the M / Q backlog notes.

#### D9 — Bootstrap UX → **A (manual `cscli`)**

CrowdSec bouncer auth: `X-Api-Key` header, key bootstrapped via `cscli bouncers add <name>` on the CrowdSec host.

- **D9.A — Manual bootstrap.** Operator runs `cscli bouncers add arenet` on their CrowdSec host, pastes the key into Arenet's Settings page (new admin UI surface). Documented in README.

- **D9.B — Settings-UI-driven.** Arenet's Settings page POSTs a `/v1/watchers/register` or similar to LAPI to mint the key automatically. **Not supported by the LAPI** — bouncer registration goes through the `cscli` CLI only, the watcher-register endpoint is for the CrowdSec agent itself, not bouncers.

**Decision: A.** B is not actually achievable: the LAPI surface
exposes `/v1/watchers/register` for the CrowdSec agent (which IS
self-registering by design), but bouncer registration goes through
`cscli bouncers add` exclusively — the only path that mints a hashed
bouncer credential in the LAPI database. Attempting B would require
either (a) running `cscli` from inside Arenet (operational coupling
we cannot accept) or (b) replicating its hashing logic against an
LAPI internal table (brittle, version-bound to CrowdSec internals).
A is also the documented community pattern for every bouncer in
the hub.

**Rejected — D9.B:** not supported by the LAPI surface; the docs
sample mentioning watchers is for the agent role, not bouncers.

---

## 1.4 Range of change

### New backend package: `internal/crowdsec/`

| Path | Touch |
|------|-------|
| `internal/crowdsec/decision.go` (NEW) | `Decision` type (uuid, ts, scope, value, type, scenario, expires_at, duration_seconds — per D5.B). |
| `internal/crowdsec/sink.go` (NEW) | `DecisionSink` interface + `Inserter` + `BlockCounter` + production `Sink`. Mirror of `waf/sink.go` and `throttle/sink.go`. **Key difference**: LRU dedupe BEFORE the BlockCounter bump (per D4) — the asymmetry vs M/Q is documented in code. |
| `internal/crowdsec/lru.go` (NEW) | Per-`decision.UUID` LRU, larger cap (e.g. 50,000) and longer TTL (1 h) than M/Q because CrowdSec re-emits the full active set on every poll. |
| `internal/crowdsec/stream.go` (NEW) | The Arenet-owned `StreamBouncer` consumer. Wraps `go-cs-bouncer.StreamBouncer`, drains the `Stream` channel, calls `Sink.Emit` for `new[]` and `Sink.Tombstone` for `deleted[]`. AC #13 recover-on-panic. |
| `internal/crowdsec/global.go` (NEW) | `SetGlobalSink` / `GetGlobalSink` singleton (same pattern as M/Q — the Stream consumer is wired at boot, before the sink exists in some test scaffolds). |

### Backend — existing files extended

| Path | Touch |
|------|-------|
| `internal/caddymgr/manager.go` | + `apps.crowdsec` block in `buildConfigJSON`. + `crowdsec_handler` directive injection at the start of every route's handler chain (BEFORE the WAF handler — the IP-reputation gate runs first). Config JSON shape per the bouncer's `crowdsec/crowdsec.go:74-127` field tags. **Critical**: every reload via `caddy.Load()` must include the `apps.crowdsec` block, otherwise the bouncer is silently removed (manager.go:278). |
| `internal/observability/migrate.go` | v3→v4 step: ALTER bucket_1m + bucket_1h to add `crowdsec_decision_count INTEGER NOT NULL DEFAULT 0`, CREATE TABLE `decision_event` + 3 indexes, bump schema_version to 4. Same single-tx shape as v2→v3. |
| `internal/observability/storage.go` | + `DecisionEvent` type + filter + Insert/Query/Prune. Bucket InsertBatch / Query / QueryAggregated extended with the new column. + `DistinctDecisionSrcIPs` for the attackers-summary union. |
| `internal/observability/bucket.go` | + `CrowdSecDecisionCount int64` on `MetricBucket`. |
| `internal/observability/aggregator.go` | + `BumpCrowdSecDecisions(srcIP string)` method satisfying `crowdsec.BlockCounter`. New sentinel routeID `_crowdsec` consistent with M's `_throttle` (per D5 mock pattern). |
| `internal/observability/retention.go` | + `RetainDecisionEvents = 30 * 24 * time.Hour` (per D8), + prune step in `tick`, + sum on hourly rollup. |
| `internal/api/handler.go` | + `DecisionReader` interface (Query + DistinctSrcIPs + AggregateByScenario) + setter. |
| `internal/api/security_handlers.go` | + `securityDecisions` handler (`GET /security/decisions`). + extend `metricsSummary` with `totalCrowdSecDecisionsPerMin`, `activeCrowdSecIpsUnique`. + extend `securityAttackersSummary` to add 4th source. |
| `internal/api/metrics_handlers.go` | + `crowdsec_decision_rate` to `metricName`. |
| `internal/api/routes.go` | Mount `/security/decisions`. |
| `cmd/arenet/main.go` | + `crowdsec.NewSink(crowdsecInserterAdapter{obsStore}, obsAggregator, ...)`. + spawn the StreamBouncer consumer goroutine. + crowdsecConfig (api_url, api_key) loaded from env vars `ARENET_CROWDSEC_API_URL` / `ARENET_CROWDSEC_API_KEY` initially (admin Settings UI is a stretch goal). + AC #13: nil/empty config → no-op sink + log degraded line. |

### Frontend

| Path | Touch |
|------|-------|
| `web/frontend/src/lib/api/types.ts` | + `Decision`, `DecisionsResponse`, `DecisionScope` types. + new `MetricName` literal `crowdsec_decision_rate`. + new `SummaryResponse` fields `totalCrowdSecDecisionsPerMin` + `activeCrowdSecIpsUnique`. + `AttackersByBucketSource` gains `crowdsec` field. |
| `web/frontend/src/lib/api/security.ts` | + `fetchDecisions` typed wrapper. |
| `web/frontend/src/lib/components/MixedEventList.svelte` | + CROWDSEC source (4th kind). Detail badge = scenario name (`SQLi`, `http-probing`, etc.). Color = `status-down`. Same merge-sort by ts desc. |
| `web/frontend/src/routes/security/+page.svelte` | + 2 new stat cards (CrowdSec/min, Active bans). + 1 new chart (`crowdsec_decision_rate`). Stat-grid wraps from 8 → 10 cards on wide; chart-grid 5 → 6. |
| `web/frontend/src/routes/security/decisions/+page.svelte` (NEW) | List page: active decisions as the mock promises (`185.142.86.0/24 · SQLi · auto`). Columns: scope+value, scenario, origin, expires_at countdown, action (revoke — POST to LAPI via Arenet API? — out of scope for v1, view-only). |
| `web/frontend/src/lib/components/Sidebar.svelte` | + entry for `/security/decisions`. |

### Docs / smoke

| Path | Touch |
|------|-------|
| `docs/smoke-test-step-n.md` (NEW) | N.5 evidence + verdict. |
| `docs/backlog-step-n.md` (NEW, if findings accumulate). |

---

## 1.5 Wire types (per D5.B + extensions)

```ts
// decision_event row
interface Decision {
  uuid: string;       // CrowdSec's stable UUID, not the server-local int id
  ts: string;         // when Arenet first saw this decision
  scope: 'ip' | 'range' | string; // 'ip', 'range', 'country', 'as' — free-form
  value: string;      // IP, CIDR, country code, AS — depends on scope
  type: string;       // 'ban', 'captcha', 'throttle' — see §3.3
  scenario: string;   // e.g. 'crowdsecurity/http-probing'
  origin: string;     // 'CAPI', 'cscli', 'lists', 'console' (D5.A retained, D5.B drops)
  expiresAt: string;  // RFC3339; tombstoned at this ts
  durationSeconds: number;
}

interface DecisionsResponse {
  disabled?: boolean;
  partial?: boolean;
  events: Decision[];
}

// Summary additions
interface SummaryResponse {
  // ...existing M + Q fields...
  totalCrowdSecDecisionsPerMin: number;
  activeCrowdSecIpsUnique: number; // distinct src_ip seen in window
}

// AttackersByBucketSource gains a 4th
interface AttackersByBucketSource {
  waf: number;
  throttle: number;
  audit: number;
  crowdsec: number; // NEW
}
```

---

## 1.6 Threat model deltas vs Step Q

### 1.6.1 LAPI is now a trust boundary

CrowdSec LAPI is an external HTTP API the Arenet proxy reads decisions from. A compromised LAPI could insert ban decisions for arbitrary IPs (denial of service), or revoke active bans (denial of protection). Arenet treats LAPI as trusted (the API key is the trust token); operator runs CrowdSec on the same homelab subnet behind the same firewall.

### 1.6.2 Bouncer fail-open vs DoS

With D2.A (fail-open), an attacker who can take down LAPI ALSO disables the IP-reputation gate. WAF and rate-limiter still work — the data plane stays alive, just with degraded reputation. This is acceptable for a homelab (the WAF + rate-limit floor is meaningful protection). It is NOT acceptable for production exposure — D2.B is the production-paranoid choice.

### 1.6.3 Decision storage size

50k decisions × ~200 bytes/row (after the D5.B subset) ≈ 10 MB. 30-day retention with churn (decisions expire and arrive constantly) caps at perhaps 200k row-lifetimes ≈ 40 MB. Well within homelab budget.

---

## 2. Acceptance criteria

(Numbered following M's 19 + Q's 19 + N's new ones.)

**AC #1 — Bouncer enforces blocked IP at the proxy edge.** With LAPI deny on `1.2.3.4`, an HTTP request from `1.2.3.4` to any route → **403** (per D2: writeBanResponse, bouncer source `internal/httputils/http.go:99-106`). Request never reaches WAF or auth.

**AC #2 — Decision event captured.** Adding the LAPI deny on `1.2.3.4` causes a row to appear in `decision_event` within `TickerInterval + flush_interval` (~60s + 250ms). Row fields per D5.B.

**AC #3 — Decision tombstoned on revoke.** `cscli decisions delete --ip 1.2.3.4` causes the bouncer's local cache to drop the entry (within next poll) AND the Arenet `decision_event` row gets an `expires_at` update (or a tombstone marker — see N.1 design).

**AC #4 — Bucket counter increments on new decisions only.** Per D4: bucket `crowdsec_decision_count` ticks ONCE per distinct decision UUID seen in the minute, regardless of how many poll cycles re-include it.

**AC #5 — Sync retention.** Decision rows pruned after 30 d (per D8). Re-running `cscli decisions list` then a fresh Arenet boot + 30d simulation prunes the row.

**AC #6 — Schema v3→v4 migration idempotent.** Mirror of Q.6.

**AC #7 — `/api/v1/security/decisions` endpoint.** Wire shape per §1.5. Filters: `limit`, `scope`, `srcIp`, `scenario`. Viewer-accessible. AC #13 paths.

**AC #8 — `/metrics/timeseries?metric=crowdsec_decision_rate` accepted.** Reads `bucket.CrowdSecDecisionCount`, gap-fill = 0.

**AC #9 — `/metrics/summary` extended.** Adds `totalCrowdSecDecisionsPerMin` + `activeCrowdSecIpsUnique`. AC #15-equivalent independence: CrowdSec bumps do NOT inflate WAF / throttle / 4xx / 5xx counters.

**AC #10 — `/security/attackers-summary` extended.** `byBucketSource` gains `crowdsec`. Union now over 4 sources.

**AC #11 — Dashboard renders 4-source mixed feed.** MixedEventList shows interleaved WAF + THROTTLE + AUTH + CROWDSEC rows.

**AC #12 — `/security/decisions` page renders.** Active decisions list, scope+value column, scenario column, scope-aware row colour.

**AC #13 — Data plane integrity: CrowdSec sink failure does not block requests.** Mirror of M.13 / Q.13. (a) Boot-failure: LAPI unreachable + `ARENET_CROWDSEC_API_KEY` empty → bouncer not loaded (per D2.A fail-open) AND Arenet's own consumer logs degraded INFO line + sink runs as no-op. (b) Runtime-failure: LAPI dies mid-process → Stream channel goes silent, sink panic in consumer goroutine recovered, data plane unaffected.

**AC #14 — Caddy reload preserves the crowdsec app.** Every `caddymgr.applyLocked` includes `apps.crowdsec` in the JSON. Adding/removing a route does NOT silently drop the bouncer. Pinned by a unit test analogous to the existing `TestBuildConfigJSON_HandlersAllResolvable`.

**AC #15 — AC #13 boot-degraded API surface.** With sabotaged LAPI (or empty API key), `/security/decisions` returns 200 disabled=true. `/security/attackers-summary` returns `partial: true` if other sources are present.

**AC #16 — Step Q unchanged.** Re-run Q.5 matrix subset: `/security/throttle-events`, `/security/auth-failures`, `/security/attackers-summary` (with CrowdSec count=0), `/metrics/timeseries?metric=throttle_block_rate`. AC #15 carry-forward.

**AC #17 — Step M unchanged.** Re-run M.5 matrix subset: `/security/events`, `/security/events/by-rule`, WAF block on a CRS payload still produces a row.

**AC #18 — Tests pass.** `go test ./... -count=1` clean. Vitest baseline.

**AC #19 — Lint clean.** `go vet`, `gofmt -l -s`, `svelte-check`.

**AC #20 — Viewer-accessible.** `/security/decisions` mounted in the hard-auth-no-admin group.

**AC #21 — Bundle budget.** Combined N frontend addition < 3 kB gz on top of Q's 1 kB. Total /security surface < 10 kB gz.

**AC #22 — Bouncer pinned to v0.12.1.** `go.mod` entry frozen at the verified-against version. Upgrade is a separate change with a smoke pass.

**AC #23 — License compliance.** Apache 2.0 NOTICE / LICENSE preserved for caddy-crowdsec-bouncer (Apache → AGPL one-way compatible).

**AC #24 — CrowdSec blocks counted in fourxx_count (divergence vs M's AC #4).** A CrowdSec 403 response IS included in the `bucket.fourxx_count` counter, OPPOSITE to the WAF behaviour pinned by M's AC #4 (WAF 403s are excluded from fourxx_count via a Coraza callback that flags the request as wafBlocked, verified live at M.5 with 212 WAF blocks + 3 real backend 404s that "never collide"). The mechanism: `hslatman/caddy-crowdsec-bouncer` v0.12.1 exposes NO callback hook of any shape — confirmed by source read of `internal/core/core.go` and `internal/bouncer/stream.go` at v0.12.1, the Step-N spec research agent #1 found no listener registration API. We therefore cannot raise a "crowdsecBlocked" flag on the request context for the metrics middleware to honour.

The architectural consequence:

- `bucket.fourxx_count`  = real backend 4xx **+ CrowdSec 403s** (M's WAF 403s remain excluded).
- `bucket.waf_block_count` = pure WAF signal (M's AC #4 invariant preserved).
- `bucket.crowdsec_decision_count` (the new N.2 sentinel counter under route_id="_crowdsec") = pure CrowdSec signal, populated independently via the parallel StreamBouncer consumer's `BumpCrowdSecDecisions` hook.

The pure CrowdSec signal IS available to operators — but at the sentinel-route counter, NOT at the per-route 4xx column. The N.4 dashboard surfaces the CrowdSec count as its own stat card so the operator never has to subtract.

Smoke (N.5) verification: trip a CrowdSec 403 on one route, hit the same route with a real backend-404 path, query `bucket_1m`. Expected row: `fourxx_count = 2` (both the CrowdSec block AND the backend 404), `crowdsec_decision_count = 1`, `waf_block_count = 0`. A test under `internal/caddymgr` cannot reach this AC because the metrics observation happens at request-time, NOT in the JSON-build path; AC #24 is therefore declared smoke-only.

---

## 3. Architecture

### 3.1 Three layers, one LAPI

```
                     ┌──────────────────────┐
                     │  CrowdSec LAPI       │
                     │  (separate process /  │
                     │   host)              │
                     └─────┬────────────────┘
                           │ /v1/decisions/stream
                           │ ?startup=true, every 60s
              ┌────────────┴────────────┐
              ▼                         ▼
  ┌───────────────────────┐   ┌────────────────────────┐
  │ caddy-crowdsec-bouncer │   │ Arenet StreamBouncer   │
  │ (Caddy app, embedded) │   │ (internal/crowdsec/     │
  │                       │   │  stream.go)            │
  │ Enforces: 403 on ban  │   │ Mirrors: decision_event │
  │ from local ipstore    │   │ + bucket counter        │
  └─────────┬─────────────┘   └─────────┬──────────────┘
            │ blocks request           │ writes SQLite
            ▼                         ▼
    HTTP data plane              Admin dashboard
```

**Two independent consumers of the same LAPI** is the cleanest separation (per D3.A): the bouncer enforces; Arenet's consumer mirrors. If either fails, the other survives. Bandwidth duplication is one HTTP GET every 60s against `127.0.0.1:8080` — negligible.

### 3.2 Sink pattern: dedupe-before-bump (the inversion)

```go
// internal/crowdsec/sink.go (sketch)
func (s *Sink) absorb(d Event) {
    if !s.lru.shouldEmit(d.UUID) {
        // Already seen this decision in the current 1h TTL.
        // Don't bump bucket counter, don't re-persist.
        atomic.AddUint64(&s.suppressedByLRU, 1)
        return
    }
    // First sight: bump THEN persist. AC #4 invariant:
    // bucket counter = count of distinct decisions seen
    // this minute.
    if s.counter != nil {
        s.counter.BumpCrowdSecDecisions(d.SrcIP)
    }
    // ...batch-persist path same as WAF/throttle...
}
```

**Why inverted vs M/Q**: M and Q emit one event per request decision (synchronous, monotonically progressing). CrowdSec re-emits every active decision every poll cycle (asynchronous, repeating). Naive bump-on-every-absorb would over-count by `(active × polls_per_minute)` per minute.

### 3.3 Decision type handling

The bouncer translates LAPI decision types to HTTP responses (`internal/httputils/http.go`):
- `ban` → 403 (default)
- `captcha` → 403 (upstream issue #46: no captcha challenge; functionally identical to ban for now)
- `throttle` → 429 + Retry-After header
- unknown → 403 (fallback)
- whitelist → silently dropped (upstream issue #116)

Arenet's `decision_event.type` mirrors LAPI verbatim, but the dashboard treats `ban` and `captcha` identically. The list view (N.4) renders `throttle` decisions distinctly because the semantic is "soft-cap" rather than "deny".

### 3.4 Caddy reload trap

`caddymgr.applyLocked` builds the full Caddy config JSON and calls `caddy.Load(cfg, true)`. There is no patch path. **Every reload MUST include the `apps.crowdsec` block in the JSON**, otherwise the bouncer is silently removed on the next route edit. AC #14 pins this.

```go
// internal/caddymgr/manager.go (sketch — add to buildConfigJSON)
cfg.Apps["crowdsec"] = map[string]any{
    "api_url":            m.crowdsecAPIURL,    // from env / settings
    "api_key":            m.crowdsecAPIKey,    // from env / settings
    "ticker_interval":    "60s",                // per D7.A
    "enable_streaming":   true,                  // per D1.A
    "enable_hard_fails":  false,                 // per D2.A
}
// Plus prepend `{"handler": "crowdsec"}` to every route's handler chain
// (BEFORE waf, BEFORE forward_auth, BEFORE basic_auth — reputation gate is
// the first wall).
```

Issue #61 (reload hang) note: route mutations during heavy traffic may stall the admin API. Acceptable for homelab; document as known limitation.

### 3.5 Aggregator sentinel routeID

Mirror of Q's `_throttle` sentinel: CrowdSec decisions are per-IP, not per-route. The aggregator stores them under sentinel routeID `_crowdsec`. The dashboard's "CrowdSec / min" stat card reads
`bucket_1m WHERE route_id = '_crowdsec'`.

```go
// internal/observability/aggregator.go
const CrowdSecSentinelRouteID = "_crowdsec"

func (a *Aggregator) BumpCrowdSecDecisions(srcIP string) {
    _ = srcIP // intentionally unused at bucket layer (per-IP detail in decision_event)
    a.Ingest(TickDelta{RouteID: CrowdSecSentinelRouteID, CrowdSecDecisions: 1})
}
```

### 3.6 Schema migration v3→v4

```sql
ALTER TABLE bucket_1m ADD COLUMN crowdsec_decision_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bucket_1h ADD COLUMN crowdsec_decision_count INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS decision_event (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,
  ts INTEGER NOT NULL,
  scope TEXT NOT NULL,
  value TEXT NOT NULL,
  type TEXT NOT NULL,
  scenario TEXT NOT NULL,
  origin TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  duration_seconds INTEGER NOT NULL
);

CREATE INDEX idx_decision_event_ts ON decision_event (ts);
CREATE INDEX idx_decision_event_value_ts ON decision_event (value, ts);
CREATE INDEX idx_decision_event_scenario_ts ON decision_event (scenario, ts);

UPDATE schema_version SET version = 4;
```

Single transaction, same idempotency pattern as Q.6.

### 3.7 Retention

Three prune steps now (M waf_event + Q throttle_event + N decision_event), each on the same hourly cadence in `RetentionRunner.tick()`. 30 d horizon (D8.A).

### 3.8 Dependency direction

`internal/crowdsec/` defines its own `Inserter` / `BlockCounter` interfaces; does NOT import `internal/observability`. `cmd/arenet/main.go` bridges via `crowdsecInserterAdapter`. Mirror of M / Q convention.

### 3.9 LAPI bootstrap

Per D9.A:
1. Operator runs `cscli bouncers add arenet-prod` on their CrowdSec host.
2. CLI returns a one-time plaintext key.
3. Operator pastes key into Arenet via the Settings UI (or env var `ARENET_CROWDSEC_API_KEY`).
4. Operator sets `ARENET_CROWDSEC_API_URL` (default `http://127.0.0.1:8080/`).
5. Arenet reload picks up the new config; the bouncer probes LAPI on next Caddy load.

If either env var is unset / empty, the bouncer is NOT loaded into the Caddy config (the apps.crowdsec block is omitted). Per AC #13, Arenet still boots fully — the IP-reputation gate is disabled but WAF + rate-limit still work.

---

## 4. Sub-task ordering & cadence

| Step | Description | Surface | Days |
|------|-------------|---------|------|
| N.1 | Embed bouncer + Caddy apps wiring + reload trap pin | backend | 1.5 |
| N.2 | Schema v4 + Sink (dedupe-before-bump) + StreamBouncer consumer | backend | 1.5 |
| N.3 | REST API (decisions + summary extension + timeseries) | backend | 1 |
| N.4 | Dashboard: +2 cards, +1 chart, MixedEventList +1 source, /security/decisions page | frontend | 1 |
| N.5 | Live smoke against local CrowdSec + tag `v1.1.0-step-n` | smoke + doc | 1 |

Total: ~6 days. Larger surface than Q (was ~5 days) because of the external integration.

Cadence per chunk: same as M.1 / Q.1 — present result before commit, full gate green (`gofmt`, `go vet`, `go test -race ./...`, `svelte-check`, `npm run build`).

---

## 5. Per-sub-task design

### 5.1 N.1 — Embed bouncer + Caddy app wiring

**New files:**
- `internal/caddymgr/crowdsec.go` — small helper that builds the `apps.crowdsec` JSON block from config. Keeps `manager.go` lean.

**Touched files:**
- `internal/caddymgr/manager.go`:
  - `import _ "github.com/hslatman/caddy-crowdsec-bouncer/crowdsec"` (Caddy module registration side effect).
  - `import _ "github.com/hslatman/caddy-crowdsec-bouncer/http"` (handler registration).
  - `buildConfigJSON`: if `crowdsecAPIKey != ""`, inject `apps.crowdsec` block AND prepend `{"handler":"crowdsec"}` to every route's handler chain.
  - Manager struct gains `crowdsecAPIURL`, `crowdsecAPIKey` fields, settable via a new setter `SetCrowdSecConfig(url, key string)`.
- `cmd/arenet/main.go`:
  - Read `ARENET_CROWDSEC_API_URL` (default `http://127.0.0.1:8080/`) + `ARENET_CROWDSEC_API_KEY`.
  - If both set, call `mgr.SetCrowdSecConfig` before `mgr.Start`. Log boot line:
    - `"crowdsec bouncer wired"` (both vars set, key validated).
    - `"crowdsec bouncer not configured (set ARENET_CROWDSEC_API_KEY)"` (degraded, AC #13).

**Tests:**
- `TestBuildConfigJSON_WithCrowdSec_EmitsApp`: when API key is set, the JSON contains `apps.crowdsec` with the right field values.
- `TestBuildConfigJSON_WithCrowdSec_PrependedToEveryRoute`: every route's handler chain starts with `{"handler":"crowdsec"}`.
- `TestBuildConfigJSON_WithoutCrowdSec_NoAppsBlock`: when API key is empty, no `apps.crowdsec` key in the config (degraded mode).
- `TestBuildConfigJSON_LoadsCleanly` extension: the emitted JSON validates with `caddy.Validate()` even with the crowdsec block.
- AC #14 pin: `TestBuildConfigJSON_HandlersAllResolvable` extension — the `crowdsec` handler ID resolves.

**Live smoke deferred to N.5** (this chunk validates the JSON shape; live LAPI interaction is N.5).

### 5.2 N.2 — Schema v4 + Sink + StreamBouncer consumer

**New files:** entire `internal/crowdsec/` package per §1.4. Plus:
- `internal/crowdsec/stream_test.go` — fake StreamBouncer (returns canned `{new, deleted}` deltas) wired into the consumer, verifies the consumer drains the channel and calls Sink.Emit appropriately.

**Touched files:**
- `internal/observability/migrate.go` (v3→v4 step).
- `internal/observability/storage.go` (DecisionEvent CRUD).
- `internal/observability/bucket.go`, `aggregator.go`, `retention.go` (new column, BumpCrowdSecDecisions, prune).
- `cmd/arenet/main.go`: when LAPI config is set, spawn the StreamBouncer consumer goroutine + Run + LIFO defer-close.

**Tests:**
- Mirror of Q.1 sink tests: nil inserter, failing inserter, panic recovery, LRU dedupe (verify dedupe-before-bump — distinct from M/Q).
- Migration: `TestMigrate_V3ToV4_PreservesExistingData` (mirror of Q's v2→v3 test).
- Aggregator: `TestAggregator_BumpCrowdSecDecisions_FlushesUnderSentinel`.

### 5.3 N.3 — REST API

**Touched files:**
- `internal/api/handler.go`: `DecisionReader` interface + setter.
- `internal/api/security_handlers.go`: `securityDecisions` handler. Extend `metricsSummary` with the two new fields. Extend `securityAttackersSummary` to add `crowdsec` to `byBucketSource` + union into uniqueIps.
- `internal/api/metrics_handlers.go`: `crowdsec_decision_rate` enum + pickMetricValue routing.
- `internal/api/routes.go`: mount `/security/decisions`.
- `cmd/arenet/main.go`: `apiHandler.SetDecisionReader(obsStore)`.

**Tests:**
- `TestSecurityDecisions_*`: anon 401, viewer 200, nil reader 200-disabled, query error 503, filter by scope/srcIp/scenario.
- `TestMetricsTimeseries_CrowdSecDecisionRate`.
- `TestMetricsSummary_CrowdSecFields_IndependentFromQ` (AC #15-style independence).
- `TestSecurityAttackersSummary_UnionAcrossFourSources`.

### 5.4 N.4 — Dashboard

**New file:**
- `web/frontend/src/routes/security/decisions/+page.svelte`: list view with the mocked rows. Columns per §1.5; expiresAt rendered as countdown.

**Touched files:**
- types.ts, security.ts wrappers, MixedEventList (add CROWDSEC source), security/+page.svelte (cards + chart), Sidebar.svelte.

**Bundle target:** N adds ~2 kB gz on top of Q's 1 kB. Total /security surface ~3 kB gz, well under the 10 kB per-page budget.

### 5.5 N.5 — Smoke + tag

Live smoke against a real CrowdSec instance (containerized: `docker run -d crowdsecurity/crowdsec:latest`):
1. Build arenet ✓
2. Boot CrowdSec container, `cscli bouncers add arenet-test`, capture key.
3. Boot arenet with the key.
4. Verify boot log: `crowdsec bouncer wired`.
5. `cscli decisions add --ip 1.2.3.4 --duration 1h --type ban --reason 'smoke test'`.
6. Wait `TickerInterval` + flush window. Verify `decision_event` row.
7. HTTP request from `1.2.3.4` (spoofed via XFF, trusted proxy) → expect 403.
8. Verify `bucket_1m.crowdsec_decision_count` ticked.
9. Query every N.3 endpoint.
10. AC #13 sabotage: `docker stop crowdsec`, hit a previously-banned IP, verify (a) request goes through (fail-open) AND (b) Arenet log line `crowdsec stream: poll failed, retrying` AND (c) `/security/decisions` returns 200 with the cached rows (the bouncer cache survives in `ipstore.Store` until process restart).
11. AC #13 boot-degraded: drop the `ARENET_CROWDSEC_API_KEY` env, reboot, verify `crowdsec bouncer not configured` log line + `/security/decisions` returns disabled=true + WAF / throttle paths still work (AC #16/17 carry-forward).
12. Frontend gate: svelte-check + build, measure bundle delta vs Q.4 baseline.
13. Write `docs/smoke-test-step-n.md` with AC matrix.
14. **Verdict honnête**. PARTIAL acceptables avec citations unit-test.
15. If VERDICT = PASS → tag `v1.1.0-step-n` local. If FAIL → no tag, fix-before-tag findings documented.

---

## 6. Migration strategy

`metrics.db` schema v3 → v4 via the existing migrate-chain pattern. Two ALTERs (`bucket_1m`, `bucket_1h` get `crowdsec_decision_count`) + one CREATE (`decision_event` + 3 indexes). Single transaction. Idempotent re-open. No bbolt schema change — Arenet's bbolt stores (routes, audit, users, sessions) are untouched.

---

## 7. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Bouncer issue #61 (reload hang in streaming mode) | Document as known limitation; route edits during a hung reload time out gracefully; operator can restart Arenet. |
| LAPI burst at startup (100k+ active decisions) | `ChannelBuffer = 16384` on the crowdsec.Sink (16× WAF/throttle default). `?startup=true` returns the full active set; consumer drains in one goroutine, sink batches into SQLite at 250ms / 100 rows. |
| Two consumers polling LAPI doubles load | Negligible: one 60s-cadence stream poll is < 1 KB / hour. |
| Pre-existing #Q.5-2 IP discrepancy carries forward | Per D6.A, document explicitly; cross-cutting fix is out of scope. |
| Caddy reload silently drops the bouncer | AC #14 unit test pin. |
| Operator forgets to bootstrap LAPI bouncer key | `crowdsec bouncer not configured` log line at INFO; dashboard shows `disabled=true` on /security/decisions; degraded mode is honest. |

---

## 8. Out of scope (for v1.1)

- Revoke-from-dashboard (operator clicks "unban" in /security/decisions → POSTs DELETE /v1/decisions/<id> to LAPI). Add in v1.2; v1.1 is view-only.
- Captcha challenge response (upstream issue #46 — bouncer doesn't implement it).
- AppSec integration (bouncer supports it but it's a separate scenario surface beyond the IP-reputation gate; v1.1 stays narrow).
- LAPI deployment tooling (we don't ship a CrowdSec container or auto-bootstrap; operator provisions it).
- Custom CrowdSec scenarios (operators write their own `acquis.yaml` on the CrowdSec host).

---

## Appendix A — Research sources

Three parallel background-agent reports consolidated into this draft:

- `caddy-crowdsec-bouncer v0.12.1` source (Apache 2.0): module shape, JSON config keys, decision type → HTTP mapping, reload semantics, known issues #46/#61/#65/#86/#116.
- `crowdsec` LAPI + `go-cs-bouncer` (MIT): `/v1/decisions/stream` semantics, decision JSON shape, LiveBouncer vs StreamBouncer, lifecycle, API-key bootstrap.
- Arenet internal: sink pattern fit, schema migration shape, dependency direction, frontend bundle estimate, gotchas (Caddy reload, LAPI burst, IP discrepancy, dedupe inversion).

Citations available in the agent transcripts under `/private/tmp/claude-501/-Users-l-ramos-Documents-Projets-AreNET/.../tasks/`.
