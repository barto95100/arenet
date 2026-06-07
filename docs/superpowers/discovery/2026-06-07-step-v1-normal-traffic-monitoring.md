<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step V.1 — Discovery: Normal traffic monitoring on the geographic threat map

**Date**: 2026-06-07
**Status**: Discovery — no decisions locked yet. Operator answers to §5 → spec freeze in a follow-up.
**Builds on**: Step V (v1.4.0-step-v + HF1/HF2/HF3), legend polish (commit `dde76f6`), legend `(à venir)` marker for `normal` category (commit `2319699`).

## §0 Intent

Step V shipped a 5-category color taxonomy on the `/map` page (waf / throttle / crowdsec / auth — 4 emitting today; `normal` reserved for "trafic légitime" but not produced by any backend sink). Step V.1 closes that gap: emit `GeoEvent{category: "normal"}` for legitimate user traffic that successfully passes through Arenet to an upstream, so the operator can see real traffic patterns on the same map (green arcs alongside the threat colors).

The intent is **observability**, not security: V.1 doesn't change request-path behavior, doesn't block anything, doesn't add headers. The goal is "this is what your traffic looks like when nothing is wrong" — a baseline the operator can compare against during incidents.

The big architectural question for V.1 is **sampling**: arenet handles N × waf/throttle/crowdsec/auth events per minute (single-to-double-digit hour at homelab scale), but a busy homelab landing page can produce thousands of successful requests per minute. Streaming all of them through the geo bus + WebSocket + frontend arc animation is not viable. §3-§4 below cover the performance footprint and sampling-strategy options.

## §1 Architecture recon — touchpoints

### 1.1 Existing observation point on the success path

**Arenet already runs a Caddy middleware on EVERY request through every route**: `arenet_routemetrics` at `internal/metrics/middleware.go:120-130`:

```go
func (h *RouteMetricsHandler) ServeHTTP(
    w http.ResponseWriter, r *http.Request, next caddyhttp.Handler,
) error {
    rec := newStatusRecorder(w)
    start := time.Now()
    defer func() {
        durMs := float64(time.Since(start).Microseconds()) / 1000.0
        h.registry.Inc(h.RouteID, rec.status, durMs)
    }()
    return next.ServeHTTP(rec, r)
}
```

This handler:

- Wraps the response writer in a `statusRecorder` that captures the final status code.
- Runs `next.ServeHTTP` (typically `reverse_proxy`, sometimes the WAF chain first then `reverse_proxy`).
- In a `defer`, after the full chain has resolved, calls `Registry.Inc(routeID, status, durMs)`.

The defer observes the FINAL status code (success: 2xx from the upstream; failure: 502/504 from a circuit-breaker / dial timeout; block: 403 from coraza or arenet's own auth middleware).

**This is the V.1 hook point.** Adding the geo bus emission alongside the existing `Registry.Inc` is a 3-5 line change.

### 1.2 Caddy reverse_proxy internals (for context)

`/Users/l.ramos/go/pkg/mod/github.com/caddyserver/caddy/v2@v2.11.3/modules/caddyhttp/reverseproxy/reverseproxy.go`:

- Line **1039** — structured access-log emission: `zap.Int("status", res.StatusCode)`. This is what Caddy's `http.log` shows for every upstream response, success or failure.
- Line **1049** — circuit-breaker metric recording: `di.Upstream.cb.RecordMetric(res.StatusCode, duration)`.
- Line **1081** — placeholder set: `repl.Set("http.reverse_proxy.status_code", res.StatusCode)`. Available downstream in the same request scope.
- Line **1229** — final write: `rw.WriteHeader(res.StatusCode)`. By the time control returns to arenet's middleware defer, this has already executed (or NOT, if the chain errored before reaching reverse_proxy).

We do NOT need to fork or patch Caddy. The arenet middleware sits BEFORE reverse_proxy in the chain (per `caddymgr`'s emitted JSON), so the defer fires after Caddy has written the response. Same observation point as `Registry.Inc` — V.1 doesn't change the timing surface.

### 1.3 Frontend touchpoints

The 5-category color taxonomy is locked at `web/frontend/src/lib/components/Map/categoryColors.ts`:

```ts
export const CATEGORY_COLORS: Record<GeoEventCategory, string> = {
    normal:   'var(--status-up)',     // green — V.1
    throttle: 'var(--status-warn)',
    waf:      'var(--status-down)',
    crowdsec: 'var(--accent-cyan)',
    auth:     'var(--status-info)'
};
```

The legend marks `normal` as "(à venir)" in `web/frontend/src/lib/components/Map/MapLegend.svelte`. V.1's frontend deliverable is removing the `comingSoon: true` flag on that row — single-line change. **Zero new frontend code** otherwise; the arc rendering, WS reception, replay, color application all work uniformly across the 5 categories already.

## §2 Existing sink pattern analysis

### 2.1 The 4 sinks today

| Sink | Type | Install point | Event fired at |
|---|---|---|---|
| **waf** | `waf.EventSink` interface, set via `waf.SetGlobalSink` | `cmd/arenet/main.go` wraps the real sink with `geoForwardingWafSink` at boot. The Caddy `arenet_waf` module reads `waf.getGlobalSink()` and calls `Emit` on every block. | Inside Caddy's WAF module's denial path — only when coraza decides to block. |
| **throttle** | `throttle.EventSink` interface, set via `throttle.SetGlobalSink` | `cmd/arenet/main.go` wraps with `geoForwardingThrottleSink`. The `auth/ratelimit.go` rate-limiter reads `throttle.GetGlobalSink()` and calls `Emit` on every Tier-1/Tier-2 trigger. | Inside the rate-limiter when a bucket exceeds its threshold — only when 429 is returned. |
| **crowdsec** | `crowdsec.EventSink` interface (`Emit` + `Tombstone`), set via `crowdsec.SetGlobalSink` | `cmd/arenet/main.go` wraps with `geoForwardingCrowdsecSink`. The `crowdsec.StreamBouncer` consumer calls `Emit` on every new decision (and `Tombstone` on revocations). | Inside the CrowdSec consumer goroutine when LAPI streams a new decision — independent of request path. |
| **auth** | `observability.AuthEventSink` ingress, wrapped at `apiHandler.SetAuthEventSink` time with `geoForwardingAuthSink` | `internal/api/audit_helpers.go appendAudit` reads the wrapped sink and submits an `AuthEvent` for every audit action in the `authFailureKind` map. | Inside the auth handlers' audit fan-out — only when a 401/403 audit row fires. |

**All four are FAILURE-PATH sinks**: each runs only when something went wrong from the client's perspective. None of them observe successful traffic.

### 2.2 Cross-cutting pattern (geoForwarders)

`cmd/arenet/geo_forwarders.go` defines 4 thin wrapper types (one per sink interface) that publish to the geo bus via the enricher AND delegate to the underlying real sink. The wrappers install at sink-construction time in `main.go`. **Zero changes to the four sink packages** — the cross-cutting concern lives entirely in `cmd/arenet`.

V.1 doesn't fit this pattern cleanly because there's no existing "normal sink" package to wrap — the success path doesn't currently emit anything. V.1's choice is:

- **Option A**: extend `RouteMetricsHandler.ServeHTTP` (in `internal/metrics/middleware.go`) to also call a new `geo.NormalSink.Submit` when status is success. Minimal diff; couples `metrics` to `geo`.
- **Option B**: create a parallel `arenet_normaltraffic` middleware module, installed in the route chain by `caddymgr`. Zero coupling between packages; one new module.
- **Option C**: install a hook on the `metrics.Registry.Inc` method (registry pattern, observer interface). Maximal decoupling; most plumbing.

CC's recommendation: **Option A** for V.1 (smallest diff, lowest test surface). The `metrics` package already imports `caddyhttp`; adding a `geo.NormalSink` interface dependency is symmetric. Option B is the right call if V.1's surface grows (e.g. per-route enable/disable that doesn't fit the metrics module's per-route lifecycle), but that's not in scope today.

### 2.3 Is there any "success" emission point to piggyback on?

**No.** Verified:

- `arenet_routemetrics.ServeHTTP` only calls `Registry.Inc` (counters, not events).
- `Registry.Inc` only mutates atomic counters; no fan-out observer interface.
- No middleware in `internal/` calls `bus.Publish` or any equivalent on the success path.
- Caddy's structured logger (`http.log`) emits a Zap record per response but is not consumable from arenet code (it's a Caddy core surface; arenet would need a custom Zap sink, which is heavier than just adding a middleware hook).

V.1 builds a new emission point. There is no shortcut.

## §3 Performance footprint

### 3.1 Per-event cost

A `GeoEvent` is ~200-300 bytes serialized JSON (camelCase fields + ~10 string columns). The pipeline cost per event:

| Stage | Cost (est) |
|---|---|
| Construct `geo.GeoEvent` in Go (struct literal + lat/lon/country fill) | ~50 ns |
| GeoIP MMDB lookup via `oschwald/geoip2-golang` (mmap-backed) | ~1-5 µs on warm cache, ~50-200 µs on cold |
| `geo.Bus.Publish` (lock + ring buffer write + fan-out) | ~200 ns + ~100 ns per subscriber |
| JSON marshal + WS write per subscriber | ~5-10 µs |
| Frontend D3 arc spawn + render | ~100 µs (5-10 GC cycles avoided by V.6's per-frame redraw) |

**Per-event end-to-end: ~10-20 µs at the backend, ~100 µs at the frontend.**

### 3.2 Sustained load scenarios

| req/s | Per-event cost | Unsampled CPU | Bus capacity (N=500) saturates in |
|---|---|---|---|
| 10 | 100 µs | negligible | 50 s |
| 100 | 1 ms | 0.1 % of 1 core | 5 s |
| 1 000 | 10 ms | 1 % of 1 core | **0.5 s** — ring buffer cycles, oldest events drop |
| 10 000 | 100 ms | 10 % of 1 core | **0.05 s** — page replay shows last 50 ms only |

At 1 000+ req/s the ring buffer cycles faster than a human can read; the WS fan-out saturates the browser; the frontend arc count exceeds the visual budget (V.6's `ARC_TOTAL_MS = 3500` → ~3500 in-flight arcs at 1k req/s).

**Conclusion**: any homelab with >100 req/s sustained needs sampling. Sampling is a SHIP-BLOCKING decision, not an optimization knob.

### 3.3 GeoIP lookup placement

The MMDB lookup is the dominant CPU cost. Two strategies:

- **Sample-before-lookup**: skip the lookup for events we won't emit. Saves 1-200 µs per dropped event. Implementation: sample decision happens in the middleware defer BEFORE constructing the `GeoEvent`.
- **Lookup-then-sample**: always look up, decide afterward. Simpler code path but burns the dominant cost on every request.

CC's recommendation: **sample-before-lookup**. The middleware already extracts the source IP for `Registry.Inc`; the sampling decision is a single integer compare. The enricher's lookup runs only for the sampled subset.

## §4 Sampling strategy options

### Option A — 1/N rate (`ARENET_NORMAL_TRAFFIC_SAMPLE_N=100`)

**Mechanism**: increment a per-process counter; emit when `counter % N == 0`.

| Pros | Cons |
|---|---|
| Deterministic — operator can compute the exact emission rate from req/s. | Synchronization: a 1k req/s burst from 50 sources emits 10 events but they may all come from the same 1-2 sources. |
| Simple to implement — single atomic counter, single modulo. | No per-IP cooldown — one chatty client dominates the sample. |
| Sample size scales predictably with load. | Bursty patterns under-sample at quiet moments. |

### Option B — Random percentage (`ARENET_NORMAL_TRAFFIC_SAMPLE_PCT=5`)

**Mechanism**: `rand.Float64() < pct/100.0` per request.

| Pros | Cons |
|---|---|
| Statistically uniform across sources. | Non-deterministic — operator can't predict event count exactly. |
| Single math.Rand call per request — fast. | Need a synchronized fast PRNG (math/rand/v2's PCG is fine; sync/atomic for the seed). |
| Easy to reason about: "5% of all traffic". | Same problem as A: chatty clients still dominate proportionally. |

### Option C — Per-IP cooldown (`ARENET_NORMAL_TRAFFIC_PER_IP_COOLDOWN=60s`)

**Mechanism**: hash(srcIP) → last-emit-timestamp map; emit if `now - last >= cooldown`.

| Pros | Cons |
|---|---|
| Each source IP appears AT MOST 1× per cooldown window — perfect operator signal "diverse sources are talking to me right now". | Memory + lookup cost: O(unique IPs) map; needs periodic pruning. |
| One chatty client doesn't dominate. | Implementation complexity: LRU cache (mirror of `waf.lru`) or sync.Map with TTL. |
| Operator-friendly: cooldown=60s means "at most one green arc per IP per minute". | Doesn't bound the total event rate — 10 000 unique IPs in 60s = 10 000 events. |

### Option D — Combination (sampling AND per-IP cooldown)

**Mechanism**: apply Option B first (cheap random gate), then Option C (per-IP rate cap).

| Pros | Cons |
|---|---|
| Both rate AND diversity bounded. | Two knobs to tune. |
| Sample first → cooldown lookup runs on fewer events → cheaper. | Implementation: ~3× lines vs Option A alone. |
| Defensible against both burst floods AND chatty clients. | Operator has to understand the interaction. |

### Option E — No sampling, count-only metric

**Mechanism**: don't emit individual GeoEvents at all. Instead, aggregate per-IP-per-minute counts in a new metric, expose via `/api/v1/observability/normal-traffic` (poll-based, no WS).

| Pros | Cons |
|---|---|
| Zero load on the geo bus / WS / frontend arc layer. | Different scope — not what V.1's intent describes. |
| Honest count metric (no sampling distortion). | Frontend needs a different rendering surface (heatmap? choropleth?). |
| Cheap implementation. | Doesn't deliver the "see traffic patterns live" UX V.1 promises. |

### CC's recommendation

**Option D with sane defaults**: 5% random sampling + 30 s per-IP cooldown. At 1k req/s sustained, this caps emissions at ~50/s (after the random gate) and further bounds by unique IPs (the cooldown drops the dominant-source repeats). Both knobs configurable via env; both default-on; both can be set to `0` / `disabled` to opt out.

Reject Option E for V.1 (different scope). Keep it on the backlog for "Step V+N — traffic heatmap" if operators ask for aggregate visualization later.

## §5 Scope-boundary questions for the operator

CC pre-answers with recommendations; operator confirms or overrides.

### Q1 — Which status codes count as "normal"?

**Options**: 2xx only? +3xx? exclude 304? exclude 1xx? include HEAD/OPTIONS?

**CC recommendation**: **2xx and 3xx (except 304)**. Rationale:
- 2xx is unambiguously success.
- 3xx (redirects, 301/302/307) is "the server did what the client asked"; counts as normal from the operator's "is my service working" perspective.
- 304 Not Modified is cache-hit noise — exclude (dominates an asset-heavy page load and signals nothing operationally interesting).
- 1xx (101 WebSocket upgrade) — exclude; the WS connection itself is what matters, and the upgrade is once-per-connection.
- HEAD/OPTIONS — exclude (probes, preflights — not user traffic).

### Q2 — LAN/RFC1918 source IPs

**Options**: count in the LAN pill (V.6 pattern) and skip arc rendering? Render LAN arcs at the Arenet position with `(LAN)` label per spec §3.8? Skip entirely?

**CC recommendation**: **count in the existing LAN pill, skip arc rendering** (mirror the spec §3.8 / V.6 behavior). Adding green arcs from RFC1918 sources at the Arenet position would clutter the homelab view where most successful traffic IS internal. The pill carries the signal.

### Q3 — Health-check noise

**Options**: exclude `/healthz`, `/metrics`, Caddy's internal `health_checker_active` probes?

**CC recommendation**: **exclude `/healthz` and `/metrics` by default; per-route opt-in for other paths**. Caddy's internal health probes hit `/` of upstream servers (not arenet's admin paths), so they pass through arenet's `arenet_routemetrics` middleware AS user traffic from the upstream-probe IP — they SHOULD count as normal traffic for the route they target. But arenet's own health endpoint and Prometheus scrape are not interesting.

Implementation: a configurable `excludePaths []string` on `RouteMetricsHandler`, defaulting to `["/healthz", "/metrics"]`. Per-route overridable via the route's admin-config form (V.1 frontend addition or deferred to V.1.X).

### Q4 — Static asset noise

**Options**: emit one event per request (a page load = 10-20 events) or coalesce by URL pattern?

**CC recommendation**: **emit one event per request, but rely on the sampling (§4 Option D) to bound the noise**. Trying to coalesce asset requests on the backend means parsing URLs, maintaining a path classifier, distinguishing HTML pages from JS/CSS/images — heuristic land. The 5% sample × 30s per-IP cooldown already bounds the visual cost.

If operators report visible clutter, V.1.X can ship an optional "min interval between same-IP/same-route" knob to coalesce per-(IP, route) bursts.

### Q5 — Opt-in or opt-out?

**Options**: env var to enable (off by default) vs always-on?

**CC recommendation**: **opt-in via `ARENET_NORMAL_TRAFFIC_SAMPLE_PCT > 0`**. Default 0 = disabled. The operator chooses the sample rate to enable the feature; setting to 0 (or omitting) leaves the existing 4-color map unchanged. This is more conservative than opt-out (no operator should be surprised by green arcs after an upgrade).

### Q6 — Per-route opt-in or global?

**Options**: each route in the admin UI declares interest, or one global toggle?

**CC recommendation**: **global toggle for V.1 (single env var)**. Per-route opt-in adds a route-schema change (DB migration + admin UI checkbox + caddymgr emit-config branch). Defer per-route control to V.1.X if operators report wanting to limit to specific routes. The §4 sampling already bounds the volume.

### Q7 — Persistence

**Options**: new `normal_event` table (mirror cert/auth pattern) or bus-only volatile?

**CC recommendation**: **bus-only, NO persistence**. Normal-traffic events are an observability/visual signal, not a security audit trail. Persisting them at 50+ events/s sustained would dominate the metrics DB without operator value (the existing `Registry.Inc` already records per-route counters; a per-event row adds nothing). The ring buffer N=500 + the WS live stream cover the live-view UX. Replay restores the last 500 events on page mount.

### Q8 — Frontend changes

**Options**: just remove the "à venir" marker, or richer UI?

**CC recommendation**: **just remove the "à venir" marker on the legend's `normal` row**. The arc rendering, color application, WS reception, replay all work uniformly across the 5 categories already. V.1 ships green arcs alongside the existing 4 colors with zero new component code.

If operators want a "hide normal arcs" toggle (to focus on threats during an incident), defer to V.1.X — it's a per-session preference and adds toggle state, not arc plumbing.

## §6 Sub-tasks proposal

CC's reading of the right breakdown (operator confirms / re-scopes):

| Sub-task | Scope | Effort |
|---|---|---|
| **V.1.1** | Backend: `geo.NormalSink` interface + sampling logic (Option D from §4). Env vars `ARENET_NORMAL_TRAFFIC_SAMPLE_PCT` (default 0 = disabled) and `ARENET_NORMAL_TRAFFIC_PER_IP_COOLDOWN` (default 30s). Per-IP cooldown LRU. Unit tests on the sampling distribution + cooldown TTL. | ~2 h |
| **V.1.2** | Wire `RouteMetricsHandler.ServeHTTP` to emit when status ∈ `Q1` set AND not RFC1918 AND not in `excludePaths`. Path-exclusion list as middleware config field (default `["/healthz", "/metrics"]`). Tests cover all 4 gate branches. | ~1.5 h |
| **V.1.3** | `cmd/arenet/geo_forwarders.go`: add a 5th `geoForwardingNormalSink` wrapping the `geo.NormalSink` ingress — same publish-then-delegate pattern as the existing 4. Boot-log signal. Backend integration test: end-to-end successful request → GeoEvent on bus. | ~1 h |
| **V.1.4** | Frontend: remove `comingSoon: true` from the `normal` row in `MapLegend.svelte`. Update the legend test. Update the page snapshot test if any. Pin the `normal` color via the existing `categoryColors.test.ts` (already covered). | ~30 min |
| **V.1.5** | Smoke + release-notes: live smoke (curl/reqbin against a real route, confirm green arc appears within sample window). Update `docs/release-notes/v1.4.X-step-v1.md` per the project pattern. Operator validation gate before tag. | ~1 h |

**Total Step V.1 effort estimate**: ~6 h, deliverable in 1-2 sessions. Single commit per sub-task. Single tag at the end (`v1.4.X-step-v1`).

## §7 References

- **Step V spec**: `docs/superpowers/specs/2026-06-06-step-v-geographic-threat-map.md` (commit `c9ff5e9`) — locks the 5-category enum at §5.6.
- **Step V discovery**: `docs/superpowers/discovery/2026-06-06-step-v-geographic-threat-map.md` (commit `508ac9f`) — original 7-layer architecture recon.
- **`arenet_routemetrics` middleware**: `internal/metrics/middleware.go:120-130` — V.1's hook point.
- **`geo.Bus`**: `internal/geo/bus.go` — ring buffer N=500.
- **`geo.Enricher`**: `internal/geo/enricher.go` — MMDB lookup + GeoEvent translation.
- **`CATEGORY_COLORS`**: `web/frontend/src/lib/components/Map/categoryColors.ts` — locked palette.
- **`MapLegend`**: `web/frontend/src/lib/components/Map/MapLegend.svelte` — `(à venir)` marker on `normal` (commit `dde76f6`).
- **GeoIP library**: `github.com/oschwald/geoip2-golang v1.9.0`, mmap-backed reader.
