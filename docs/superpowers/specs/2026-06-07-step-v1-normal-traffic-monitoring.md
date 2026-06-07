<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step V.1 — Spec: Normal traffic monitoring on the geographic threat map

**Date frozen**: 2026-06-07
**Status**: Locked. Implementation follows the §6 sub-task plan.
**Builds on**: v1.4.0-step-v + HF1/HF2/HF3 + legend polish (commit `2319699`).
**Discovery**: `docs/superpowers/discovery/2026-06-07-step-v1-normal-traffic-monitoring.md` (commit `d3933b0`).

## §1 Intent + scope

Step V shipped a 5-category color taxonomy on `/map` but only emits 4 (waf / throttle / crowdsec / auth). The `normal` category — green, `--status-up` — is locked in the wire shape and reserved in the legend with an "(à venir)" marker (commit `2319699`). Step V.1 closes that gap: emit `GeoEvent{category: "normal"}` for legitimate user traffic that successfully passes through Arenet to an upstream, so the operator sees real traffic patterns on the same map as the threat signal. **The intent is observability, not security**: V.1 doesn't change request-path behavior, doesn't block, doesn't add headers.

Out of scope (deferred): per-route opt-in (`#R-NORMAL-TRAFFIC-per-route`), static-asset URL coalescing (sampling is the primary cap), multi-instance coordination, traffic-heatmap aggregate view (`#R-NORMAL-TRAFFIC-heatmap`).

## §2 Locked decisions

### §D1 — Status codes accepted

Emit when the final response status is in `[200, 299] ∪ [300, 399]`, EXCLUDING `304 Not Modified`. Reject 1xx (e.g. `101 Switching Protocols` for WS upgrades — once-per-connection, signals nothing), 4xx (already covered by waf / throttle / auth where relevant), 5xx (failures — not "normal"), and methods `HEAD` / `OPTIONS` (probes / preflights, not user traffic).

Rationale: 3xx redirects are "the server did what the client asked"; counts as normal from the operator's "is my service working" perspective. 304 dominates asset-heavy page loads and adds no operational signal.

### §D2 — LAN / RFC1918 sources

RFC1918, loopback, and link-local source IPs are **counted in the V.6 LAN pill** (no extra UI change — the pill already increments on every LAN event from any source) and **the arc is NOT rendered**. Mirrors spec §3.8 for waf/auth/throttle/crowdsec — the operator's "you are here" Arenet marker pulse already carries the in-network signal; rendering green arcs from RFC1918 sources to the Arenet position would clutter the homelab view.

### §D3 — Health-check / observability exclusion

Hardcoded path-prefix exclusion list applied at the middleware gate, BEFORE sampling:

```
/healthz
/metrics
/api/v1/ws/topology
```

Operator can extend (NOT replace) the list via `ARENET_NORMAL_TRAFFIC_EXCLUDE_PATHS` — comma-separated path prefixes. Example: `/api/v1/ws/geo-events,/internal/probes`. Whitespace around commas trimmed; empty entries skipped. Prefix-match semantics: `/api` excludes everything under it.

### §D4 — Static asset coalescing

**None.** Each eligible request emits (subject to D9 sampling). URL classification (HTML vs JS/CSS/image, page-load vs single-asset) is heuristic land and would require per-route MIME / pattern config the operator doesn't have today. The D9 sampling + cooldown bound the noise.

If operators report visible clutter post-V.1, a per-`(IP, route)` coalescing knob lands in a future increment (`#R-NORMAL-TRAFFIC-asset-coalesce`).

### §D5 — Opt-in mechanism

`ARENET_NORMAL_TRAFFIC_SAMPLE_PCT` env var. Integer `0..100`. **Default `0` = disabled** (entire V.1 emission path no-ops; no behavior change for upgraders). Values:

- `0` — disabled; no events emitted, no MMDB lookups, no LRU updates. Effectively V.1 = inert.
- `1..100` — enable at that random sample percentage; the bus + frontend render green arcs.

Invalid values (negative, > 100, non-integer) log a `WARN` at boot and fall back to `0`. Operator sees `normal traffic sink wired present=false sample_pct=0` in journalctl.

### §D6 — Per-route vs global

**Global toggle for V.1.** The single env var from D5 applies process-wide across all routes. Per-route opt-in deferred to `#R-NORMAL-TRAFFIC-per-route` because it requires:

- A route-schema column addition (DB migration).
- An admin UI checkbox per route.
- A `caddymgr` config-emit branch that threads the flag into the middleware's JSON config.

The D9 sampling already bounds total volume; per-route filtering is a precision knob that doesn't gate v1 ship.

### §D7 — Persistence

**Bus-only, NO `normal_event` table.** Coherent with Step V spec §3.5 (geo bus is volatile by design). Normal-traffic events are a live-view observability signal, not a security audit trail. The existing `metrics.Registry.Inc` already persists per-route counters in the per-minute bucket table; a per-event row at 50+ events/s sustained would dominate `metrics.db` without operator value.

The ring buffer N=500 + WS live stream cover the live-view UX. Page replay restores the last 500 events on mount (mixed across all 5 categories).

### §D8 — Frontend changes

**Single line.** Remove the `comingSoon: true` flag on the `normal` row in `web/frontend/src/lib/components/Map/MapLegend.svelte`. The legend's `(à venir)` italic suffix disappears.

Arc rendering, color application, WS reception, replay all work uniformly across the 5 categories already (proven by the V.6 `it.each(['normal', 'throttle', 'waf', 'crowdsec', 'auth'])` per-category-color test in `WorldMap.test.ts`). **Zero new frontend component code.**

If operators want a "hide normal arcs" toggle post-ship (to focus on threats during an incident), defer to a future polish increment.

### §D9 — Sampling strategy (Option D combined)

Two gates applied **in sequence**:

1. **Random sample gate**: `rand.Float64() * 100 < ARENET_NORMAL_TRAFFIC_SAMPLE_PCT`. Single fast PRNG call (math/rand/v2's PCG, synchronized). Reject 95% by default (PCT=5).
2. **Per-IP cooldown gate**: hash(srcIP) → last-emit-timestamp LRU. If `now - last < ARENET_NORMAL_TRAFFIC_PER_IP_COOLDOWN`, drop the event. Otherwise update `last := now` and pass.

```
ARENET_NORMAL_TRAFFIC_SAMPLE_PCT   default 0   (disabled; 0..100)
ARENET_NORMAL_TRAFFIC_PER_IP_COOLDOWN  default 30s  (Go duration; 0 = disabled)
```

Both gates run **AFTER** the D1-D4 eligibility checks (status / LAN / exclude paths / method) and **BEFORE** the MMDB lookup. The MMDB lookup is the dominant CPU cost (~1-5 µs warm); rejecting at the cheaper gates first saves the cost on the dropped 95% (per discovery §3.3).

LRU cache: capacity 4096 entries, eviction policy LRU (mirror `internal/waf/lru.go` pattern). Periodic pruning of entries older than 2× cooldown to bound memory. Single sync.Mutex (homelab scale — sharding deferred).

Why combined rather than either alone (per discovery §4):
- Random sample alone (Option B): one chatty client dominates the 5%.
- Per-IP cooldown alone (Option C): 10 000 unique IPs in 60 s = 10 000 events.
- Combined: both rate AND diversity bounded. Random sample fires the cheap rejection first; cooldown lookup runs on fewer events.

## §3 Architectural components

### §3.1 New: `internal/geo/normal_sink.go`

```go
package geo

type NormalSink interface {
    Submit(srcIP, routeID string, statusCode int, method string)
}

type DefaultNormalSink struct {
    enricher  *Enricher
    bus       *Bus
    samplePct int             // 0..100
    cooldown  time.Duration
    lru       *normalIPCache  // sync.Mutex-guarded LRU
    prng      *rand.PCG       // math/rand/v2
}

func NewNormalSink(...) *DefaultNormalSink
```

Public surface kept minimal — the wrapper at §3.3 only needs `Submit(srcIP, routeID, status, method)`. The sink owns:

- D9 random sample gate (cheap reject).
- D9 LRU cooldown gate (per-IP rate cap).
- RFC1918 short-circuit (D2 — call `isLAN(net.ParseIP(srcIP))` from `internal/geo/lookup.go`; on true, no emission and no LRU update — the V.6 LAN pill counts the event via a different path).
- Enricher lookup + `Bus.Publish` on pass.

Disabled sink (sample_pct=0): `Submit` returns immediately on the first PCT compare. Zero allocation, zero LRU touch, zero MMDB lookup.

Nil-safe: `(*DefaultNormalSink)(nil).Submit(...)` is a no-op (AC #12 degraded mode).

Estimated size: ~150-200 LOC including the LRU helper.

### §3.2 Extended: `internal/metrics/middleware.go`

Add gate logic inside the existing `defer` block at lines 120-130:

```go
defer func() {
    durMs := float64(time.Since(start).Microseconds()) / 1000.0
    h.registry.Inc(h.RouteID, rec.status, durMs)

    // Step V.1 — normal traffic emission (gated).
    if h.normalSink != nil && eligibleForNormal(r.Method, rec.status, r.URL.Path, h.excludePaths) {
        srcIP := h.ipExtractor.ClientIP(r)
        h.normalSink.Submit(srcIP, h.RouteID, rec.status, r.Method)
    }
}()
```

`eligibleForNormal` is the D1 + D3 gate (D2 RFC1918 + D4 sampling live inside `NormalSink.Submit` per §3.1). Pure function, testable in isolation.

New `RouteMetricsHandler` fields:

- `normalSink geo.NormalSink` — installed at Provision time via a new `geo.GlobalNormalSink()` accessor mirror of the existing `metrics.GlobalRegistry()` pattern.
- `excludePaths []string` — D3 default `{/healthz, /metrics, /api/v1/ws/topology}` plus the env-var extension. Resolved once at Provision (not per-request).
- `ipExtractor *auth.IPExtractor` — V.1.2 wires from a package-level singleton (mirror of `auth.GlobalIPExtractor()` if it exists; otherwise add it). Same TRUSTED_PROXIES semantics as the auth + audit paths.

If `geo.GlobalNormalSink()` returns nil at Provision time (operator didn't set the env var, or set it to 0), `h.normalSink` stays nil and the defer's branch is dead code — no measurable per-request cost.

### §3.3 Extended: `cmd/arenet/geo_forwarders.go`

Add 5th wrapper type, same publish-then-delegate shape as the existing 4:

```go
type geoForwardingNormalSink struct {
    bus      *geo.Bus
    enricher *geo.Enricher
    inner    geo.NormalSink   // nil-tolerant
}

func (g geoForwardingNormalSink) Submit(srcIP, routeID string, statusCode int, method string) {
    // No bus.Publish here — DefaultNormalSink does it
    // internally after passing all gates. The wrapper is
    // a passthrough for now; kept for API symmetry with
    // the other 4 sinks + future-proofing for cross-cutting
    // hooks (audit, log, metric).
    if g.inner != nil {
        g.inner.Submit(srcIP, routeID, statusCode, method)
    }
}
```

Install in `main.go` after the existing 4 sink wires:

```go
sampleP := readEnvInt("ARENET_NORMAL_TRAFFIC_SAMPLE_PCT", 0)
cooldown := readEnvDuration("ARENET_NORMAL_TRAFFIC_PER_IP_COOLDOWN", 30*time.Second)
excludeExtra := readEnvCSV("ARENET_NORMAL_TRAFFIC_EXCLUDE_PATHS")

var normalSink geo.NormalSink
if sampleP > 0 {
    normalSink = geo.NewNormalSink(geoEnricher, geoBus, sampleP, cooldown)
}
geo.SetGlobalNormalSink(geoForwardingNormalSink{
    bus:      geoBus,
    enricher: geoEnricher,
    inner:    normalSink,
})
```

The `excludeExtra` env value threads into `caddymgr`'s middleware emit-config so each `RouteMetricsHandler` receives the union of the hardcoded list + the operator's extras.

### §3.4 Boot signal

One new HF4-pattern log line, emitted after the sink wire:

```
INFO  normal traffic sink wired
      present=<bool>
      sample_pct=<int>
      cooldown=<duration>
      exclude_paths_count=<int>
```

`present=true` only when `sample_pct > 0` (D5). When disabled, the line still fires with `present=false` so the operator can grep `normal traffic sink` in journalctl and see "disabled" rather than "missing".

### §3.5 Frontend: `MapLegend.svelte`

Single-line edit on the `LEGEND_ROWS` array:

```ts
{ category: 'normal', label: 'Trafic légitime — requête réussie' }
//                                                  ^^^^^^^^^^^^
//                                       remove `, comingSoon: true`
```

The `legend-coming-soon` CSS class + the `{#if entry.comingSoon}` branch in the template stay (other future categories may reuse them). `categoryColors.test.ts`'s `normal → --status-up` pin already covers the visual; no test update needed beyond the legend test's "à venir" assertion (it expected the marker on `normal`; V.1 removes it).

## §4 Acceptance criteria

**AC #1** — When `ARENET_NORMAL_TRAFFIC_SAMPLE_PCT=0`, no normal events are emitted. Verified by an integration test: 1000 successful requests through a fixture route → `Bus.SnapshotLimited(1000)` contains zero `category=normal` events.

**AC #2** — When `SAMPLE_PCT=50` with cooldown disabled (`PER_IP_COOLDOWN=0`), the emission ratio over a 10 000-request sample is within `[45%, 55%]` (3-sigma confidence). Tested with a fixed PRNG seed for determinism.

**AC #3** — Per-IP cooldown drops repeat emissions: 100 successful requests from the same source IP within the cooldown window produce AT MOST 1 emission. Beyond the window, the next request passes. Tested with a fake clock injected into the LRU.

**AC #4** — D1 status gate: requests resolving to `1xx`, `304`, `4xx`, `5xx` produce 0 emissions regardless of `SAMPLE_PCT`. Per-status-class parametrized test.

**AC #5** — D1 method gate: requests with `HEAD` or `OPTIONS` method produce 0 emissions. Parametrized test.

**AC #6** — D2 LAN gate: requests with RFC1918 / loopback / link-local source IP produce 0 emissions AND the LRU is not updated for that IP. Tests cover `10.0.0.1`, `172.16.0.1`, `192.168.1.1`, `127.0.0.1`, `::1`, `fe80::1`.

**AC #7** — D3 exclude-path gate: requests to hardcoded paths `/healthz`, `/metrics`, `/api/v1/ws/topology` produce 0 emissions. Operator-supplied `ARENET_NORMAL_TRAFFIC_EXCLUDE_PATHS=/foo,/bar` extends (not replaces) the list. Prefix-match semantics: `/foo/baz` also excluded.

**AC #8** — Bus emit preserves the V.6 GeoEvent shape verbatim: `{timestamp, category:"normal", sourceIp, sourceLat, sourceLon, sourceCountry, sourceCity, isLan:false, statusCode, routeId, details:""}`. Tests assert the JSON wire shape against a known-good fixture.

**AC #9** — WS broadcast pipeline reaches `/map` page without any new V.1 code: a normal event published to the bus arrives at a subscribed WS client within ~10 ms (same as the existing 4 categories). Integration test reuses the V.6 WS fixture.

**AC #10** — Frontend renders green arcs from normal events. The existing per-category-color parametrized test in `WorldMap.test.ts` already covers `normal → var(--status-up)`. No new test needed; V.1's role is to make this code path REACHED at runtime by emitting the events.

**AC #11** — Boot signal `normal traffic sink wired` fires when `SAMPLE_PCT > 0`, with `present=true sample_pct=<N> cooldown=<D> exclude_paths_count=<I>`. When `SAMPLE_PCT=0`, the same line fires with `present=false sample_pct=0`.

**AC #12** — Nil-safe degraded mode: when `geo.GlobalNormalSink()` returns nil (operator never enabled V.1, or `geo.SetGlobalNormalSink(nil)` was called), `RouteMetricsHandler.ServeHTTP` runs without panic and the defer's V.1 branch is a single nil-check. Pinned by a unit test on `RouteMetricsHandler` with `normalSink=nil`.

**AC #13** — Invalid env values fall back gracefully: `SAMPLE_PCT=-1` / `SAMPLE_PCT=101` / `SAMPLE_PCT=abc` all log WARN at boot and resolve to `0` (disabled). `PER_IP_COOLDOWN=garbage` logs WARN and resolves to the 30 s default.

**AC #14** — LRU eviction: at capacity (4096 entries), inserting the 4097th key evicts the least-recently-used entry. Tests verify the eviction order via the existing `internal/waf/lru.go` test pattern.

**AC #15** — Legend "(à venir)" marker disappears from the `normal` row on `/map` once V.1.4 lands. Test in `MapLegend.test.ts` flips from `expect("à venir")` to `expect.not("à venir")` on the `normal` entry.

## §5 Operator config surface

| Env var | Type | Default | Notes |
|---|---|---|---|
| `ARENET_NORMAL_TRAFFIC_SAMPLE_PCT` | int `0..100` | `0` | **Master switch**. 0 = V.1 disabled (no events, no LRU touch, no MMDB lookups). 1-100 = sample percentage. Invalid values WARN at boot, fall back to 0. |
| `ARENET_NORMAL_TRAFFIC_PER_IP_COOLDOWN` | Go duration | `30s` | Per-IP rate cap. `0s` disables the cooldown (random sample alone). Values < 1s WARN at boot (likely a typo; e.g. `30` parsed as 30 ns). Values > 1h WARN (likely operator confusion; legitimate but suspicious). |
| `ARENET_NORMAL_TRAFFIC_EXCLUDE_PATHS` | CSV string | `""` | Extends the hardcoded `{/healthz, /metrics, /api/v1/ws/topology}`. Whitespace around commas trimmed. Empty entries skipped. Prefix-match semantics. |

Interaction semantics:

- `SAMPLE_PCT=0` short-circuits everything — the other two vars are read but have no effect.
- `SAMPLE_PCT=100 PER_IP_COOLDOWN=0` emits EVERY eligible request (load-test scenario; documented but not recommended at >100 req/s sustained).
- `SAMPLE_PCT=100 PER_IP_COOLDOWN=30s` emits at most one event per unique IP per 30 s. Useful for "show me which countries are reaching me" without volume.

Documentation lands in `docs/operations/normal-traffic-monitoring.md` (new) at V.1.5 ship time.

## §6 Sub-task plan

Single commit per sub-task. AC mapping per sub-task. Effort estimates carry over from the discovery doc.

| Sub-task | Scope | Files touched | ACs covered | Effort |
|---|---|---|---|---|
| **V.1.1** | `internal/geo/normal_sink.go` (NEW): NormalSink interface + DefaultNormalSink impl with Option D sampling (PCT + LRU per-IP cooldown). `internal/geo/normal_sink_test.go` (NEW): sampling distribution, LRU eviction, cooldown TTL, RFC1918 short-circuit, nil-receiver no-op. Env var parsers (`SAMPLE_PCT`, `PER_IP_COOLDOWN`) with WARN-and-fallback on invalid values. | `internal/geo/normal_sink.go`, `internal/geo/normal_sink_test.go`, `internal/geo/lookup.go` (export `isLAN` if not already) | AC #1, #2, #3, #6, #12, #13, #14 | ~2 h |
| **V.1.2** | Extend `RouteMetricsHandler.ServeHTTP` with the gate logic (`eligibleForNormal`). Add `normalSink`, `excludePaths`, `ipExtractor` fields. Resolve excludePaths union at Provision (hardcoded + env extension). Tests cover all 4 gate branches per AC #4-#7. | `internal/metrics/middleware.go`, `internal/metrics/middleware_test.go`, `internal/caddymgr/builder.go` (emit `excludePaths` JSON in route handler config) | AC #4, #5, #7, #8 | ~1.5 h |
| **V.1.3** | `cmd/arenet/geo_forwarders.go`: add `geoForwardingNormalSink` (5th wrapper, passthrough). Wire-up in `main.go` after the existing 4 sinks. Boot signal at HF4 pattern. End-to-end test: real successful HTTP request through a fixture route → bus contains 1 normal event with the correct shape. | `cmd/arenet/geo_forwarders.go`, `cmd/arenet/main.go`, `internal/geo/global.go` (NEW `SetGlobalNormalSink` / `GlobalNormalSink` accessors) | AC #8, #9, #11 | ~1 h |
| **V.1.4** | Frontend: remove `comingSoon: true` from the `normal` row in `MapLegend.svelte`. Update `MapLegend.test.ts` — flip the "à venir on normal" expectation from `toContain` to `not.toContain`. Verify `WorldMap.test.ts`'s per-category-color parametrized test still covers green. | `web/frontend/src/lib/components/Map/MapLegend.svelte`, `web/frontend/src/lib/components/Map/MapLegend.test.ts` | AC #10, #15 | ~30 min |
| **V.1.5** | Live smoke (manual): start backend with `SAMPLE_PCT=20 PER_IP_COOLDOWN=10s`, curl 50 requests from a remote IP against a real route, confirm green arcs appear on `/map` at roughly 1 in 5 requests, then stop and confirm no more arcs after cooldown. Operator-facing doc at `docs/operations/normal-traffic-monitoring.md`. Release notes at `docs/release-notes/v1.5.0-step-v1.md`. Operator validation gate before tag. | `docs/operations/normal-traffic-monitoring.md` (NEW), `docs/release-notes/v1.5.0-step-v1.md` (NEW) | Validation only | ~1 h |

**Total Step V.1 effort estimate**: ~6 h, deliverable in 1-2 sessions. Single tag after V.1.5: `v1.5.0-step-v1`.

## §7 Known limitations (cite, don't fix)

- **Per-route opt-in deferred** (`#R-NORMAL-TRAFFIC-per-route`): D6 keeps V.1 at a global toggle. If operators report wanting to limit to specific routes (e.g. enable for the auth-portal route, disable for the heavy-static landing page), V.1.X ships a route-schema column + admin UI checkbox + `caddymgr` config-emit branch.
- **Static asset URL coalescing NOT implemented** (`#R-NORMAL-TRAFFIC-asset-coalesce`): D4 relies on the D9 sampling + per-IP cooldown to bound noise. If a page load produces 10-20 events that the cooldown doesn't suppress (different routes per asset), the operator may see a visible burst. Future work: per-(IP, route) cooldown OR a MIME-type filter on the response Content-Type header.
- **Sampling is per-process** (`#R-NORMAL-TRAFFIC-multi-instance`): in a multi-instance Arenet deployment (Step X scope), each instance samples independently. Two instances at `SAMPLE_PCT=5` behind a load balancer produce ~10% combined emission rate (assuming round-robin), and per-IP cooldowns are per-instance — the same IP hitting both instances within 30 s emits twice. Acceptable for v1 (single-instance is the homelab target); coordination via a shared Redis cache deferred.
- **No "hide normal arcs" frontend toggle** (`#R-NORMAL-TRAFFIC-hide-toggle`): D8 ships green arcs alongside the existing 4 categories. During a security incident the operator may want to focus on threats only. Future polish: a per-category visibility toggle in the legend (checkbox per row).
- **`/api/v1/ws/geo-events` excluded by default but `/api/v1/ws/topology` is NOT**: D3 hardcodes `/api/v1/ws/topology` but not `/api/v1/ws/geo-events` (the latter exists post-V.3). Reason: the geo-events WS would generate a meta-event for itself (operator opens `/map` → 1 normal event for the WS upgrade → arc → operator sees their own connection). Add `/api/v1/ws/geo-events` to the hardcoded list during V.1.2 implementation if smoke surfaces the meta-recursion.

## §8 Builds-on references

- **Step V** spec: `docs/superpowers/specs/2026-06-06-step-v-geographic-threat-map.md` (commit `c9ff5e9`) — locks §5.6 5-category enum + §3.5 bus volatility + §3.8 LAN handling.
- **Step V** tag: `v1.4.0-step-v` + HF1/HF2/HF3 (`6b9a299`, `092e118`, `bc4b145`).
- **Map legend**: commit `dde76f6` (refactor to topology visual language); commit `2319699` (initial legend with `(à venir)` marker on `normal`).
- **`arenet_routemetrics` middleware**: `internal/metrics/middleware.go:120-130` — V.1.2 hook point.
- **`geo.Bus`**: `internal/geo/bus.go` — ring buffer N=500, V.3.
- **`geo.Enricher`**: `internal/geo/enricher.go` — MMDB lookup + GeoEvent translation, V.2.
- **`CATEGORY_COLORS`**: `web/frontend/src/lib/components/Map/categoryColors.ts` — locked palette including `normal → var(--status-up)`.
- **`MapLegend`**: `web/frontend/src/lib/components/Map/MapLegend.svelte` — V.1.4 single-line edit.
- **`auth.IPExtractor`**: `internal/auth/ipextract.go` — trusted-proxy-aware client IP extraction, reused by V.1.2.
- **`waf.lru`**: `internal/waf/lru.go` — LRU cache pattern reused by V.1.1's `normalIPCache`.
- **Step V.1 discovery**: `docs/superpowers/discovery/2026-06-07-step-v1-normal-traffic-monitoring.md` (commit `d3933b0`) — recon + sampling-strategy options + scope-boundary Q&A.

## §9 Frozen tag

Tag after merge: `v1.5.0-step-v1-spec`.
