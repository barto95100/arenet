<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step V — Discovery: Geographic threat map

**Status**: discovery only — read-only audit of the existing
tree, no implementation. Operator review gates the spec freeze.

**Driver**: the `/map` page is a Step R.2 stub
(`web/frontend/src/routes/map/+page.svelte:14-18` — "Vue
géographique · Bientôt disponible"). The Step V brief locks
the shape: a 2D Mercator world map rendered live via
WebSocket, with each incoming HTTP request geo-located by
source IP and drawn as an animated arc from origin → Arenet's
own position, color-coded by category (normal / throttle /
WAF block / CrowdSec block / auth failure).

**Operator-locked decisions** (the four cardinals):

1. **Tempo**: LIVE via WebSocket. NOT polling.
2. **Arenet position**: auto-detected from server's public IP
   via GeoIP, with manual override in `/settings`.
3. **Style**: 2D Mercator (NOT 3D globe).
4. **Effort**: medium scope, ~3 days target.

---

## §A — Architecture mapping (today's state)

### A.1 — Current `/map` page (frontend stub)

**File**: `web/frontend/src/routes/map/+page.svelte` (26 lines
total).

The page is a pure placeholder shipped in Step R.2. It
renders a French copy block ("Vue géographique · Bientôt
disponible") with the explicit note that the feature requires
"l'intégration d'une base GeoLite2 (MaxMind) et un nouvel
ensemble de handlers backend." No imports, no state, no
fetcher. Reachable today via browser, no feature flag.

**Sidebar entry** (verified at
`web/frontend/src/lib/components/Sidebar.svelte:63`):

```ts
{ href: '/map', label: 'Map', icon: 'map' }
```

Visible to all authenticated users (no admin role gate).

### A.2 — Existing WebSocket infrastructure (the
template to reuse)

The topology subsystem already ships a production-quality WS
broadcaster pattern. Step V reuses the SHAPE; whether it
reuses the SAME broadcaster or spins a parallel one is §C's
proposal.

**Handler**: `internal/api/ws_topology.go` (192 lines total).
Hard-auth applied by middleware BEFORE the handler runs
(`ws_topology.go:37-39`).

Key contract anchors:

- **Route registration**: `internal/api/routes.go:228`
  registers `/api/v1/ws/topology` inside the hard-auth chi
  group. Step V would mirror this for `/api/v1/ws/geo` (or
  whatever name §C locks).
- **Upgrade logic**: `gorilla/websocket.Upgrader` with 4 KB
  read/write buffers (`ws_topology.go:66-71`). Dev-mode
  `CheckOrigin` callback allows `http://localhost:5173` for
  Vite (`ws_topology.go:72-81`).
- **Subscription model**: single global broadcaster, all
  subscribers receive identical frames. No per-client
  filtering (`ws_topology.go:104`).
- **Authentication**: cookie session checked by the chi
  middleware chain before upgrade (`ws_topology.go:37-39, 92-93`).
  No in-WS re-auth. 401 fires before upgrade, never inside
  the WS lifecycle.
- **Frame format**: JSON text frames written via
  `writeJSONFrame` (`ws_topology.go:161, 178-188`). Payload
  shape is `metrics.Snapshot` for topology; Step V uses its
  own envelope per §C.
- **Read pump**: control-frame only, payload ignored
  (`ws_topology.go:119-126`). The pump exists purely so
  gorilla can process pings/pongs and detect dropped
  clients.
- **Write pump**: drains subscriber channel, encodes to
  JSON, writes with `metrics.WSWriteDeadline`. Slow clients
  observed via write-deadline failure → close
  (`ws_topology.go:154-171`).
- **Disconnect handling**: three sources — ctx cancel, read
  error, write error — converge on a `sync.Once`-protected
  `done` channel (`ws_topology.go:108-113`).

**Broadcaster**: `internal/metrics/broadcaster.go` —
mutex-protected map of subscribers, non-blocking
`Publish(snap Snapshot)` drains each subscriber channel once
per tick. Slow subscribers drop frames; the broadcaster
returns `(sent, dropped)` for telemetry, rate-limiting the
drop log to 1 line per minute per subscriber. Buffered
channel capacity is **1 frame per subscriber** — backpressure
absorbed via drops.

**Frontend client template**: `web/frontend/src/routes/topology/_api.ts`
(`connectLiveStream` function, ~lines 153-240 per Explore
recon). Reconnect schedule `[1s, 2s, 5s, 10s, 10s, ...]` with
10s cap. Step V's frontend client reuses this lifecycle
verbatim.

### A.3 — Request observability points (the critical layer)

**No single choke point.** The request lifecycle in Arenet is
a layered short-circuit chain:

```
client → Caddy
  → WAF (Coraza)        — can 403 [emits to waf.Sink]
  → Throttle            — can 429 [emits to throttle.Sink]
  → Auth                — can 401/403 [NO event sink today]
  → Route metrics       — records status [counts only, no geo]
  → reverse_proxy upstream
```

CrowdSec lives as a Caddy-level bouncer (different layer):
the `caddy-crowdsec-bouncer` module enforces decisions at the
edge BEFORE the WAF runs, and Arenet's parallel
`crowdsec.Sink` mirrors LAPI decisions to `decision_event`
for the dashboard.

Each block layer is independent. **A geo event must be
emitted from N points** (one per category) OR captured via a
single Caddy access-log hook (§B option B).

**Per-category emission anchors**:

| Source | File | Existing sink shape |
|---|---|---|
| WAF block | `internal/waf/module.go` + `internal/waf/sink.go` | `Emit(Event)` non-blocking channel + batcher → `InsertWafEventBatch`. LRU dedupe per `(RouteID, SrcIP, RuleID)` × 60s TTL. |
| Throttle (429) | `internal/throttle/sink.go` | Same `Emit(Event)` shape. LRU per `(SrcIP, Tier)` × 60s. Dedupes AFTER bump (different invariant from WAF). |
| CrowdSec ban | `internal/crowdsec/sink.go` | Same shape, larger ingress buffer (16k) for LAPI stream bursts. Dedupes BEFORE bump (spec N D4.A). |
| Auth failure | `internal/auth/middleware.go` | **No event sink wired today.** 401/403 are logged via `slogLogger` middleware at `internal/api/middleware.go:28-61` only. The auth-failure timeline on `/logs` is derived from the audit bucket via `AuthFailureReader.QueryByActionRange`. |
| Normal 2xx/3xx | `internal/metrics/middleware.go` | Per-route per-status counters via `statusRecorder`. No per-request emission. |

**Step T.1 forward-compat seam pattern (commit `1350777`,
AC #18)** is the model for the geo event bus: a `Subscribe()`
hook that fans out to N consumers (WS broadcaster, future
audit log, future replay buffer) without modifying the
producers.

### A.4 — GeoIP integration status

**Grep confirms**: nothing imported today.
`grep -rn "geoip\|maxmind\|oschwald\|GeoLite\|mmdb"` returns
0 hits in `/internal` and `/cmd`. `go.mod` carries no
geo-related deps.

**Caddy MaxMind module**: Caddy ships
`github.com/caddyserver/caddy/v2/modules/caddyhttp/maxmind`
upstream but Arenet does NOT side-effect-import it (verified
against the `_ "github.com/...` import list in
`cmd/arenet/main.go`). Adding it gives request-level GeoIP
filtering inside Caddy but does NOT solve our lat/lon-for-
animation need — the Caddy module is a matcher (allow/deny
based on country), not a metadata enricher.

**Recommended library**: `github.com/oschwald/geoip2-golang`
(MIT, pure Go, no cgo). Standard for MaxMind .mmdb reads.
Lightweight (~single reader instance per process), supports
City + ASN databases. License-compatible with AGPL v3.

**MMDB file**: GeoLite2-City — free, requires MaxMind
account for download, CC BY-SA 4.0 attribution required.
Lifecycle is operationally non-trivial — see §E question 2.

### A.5 — Server's public IP detection

**Search result**: nothing today.
`grep -rn "ipify\|icanhazip\|publicIP\|external.*IP"` returns
0 hits. Caddy's certmagic does ACME challenges but does not
expose its outbound IP to the host process via any API.

**Recommended approach**: HTTP GET at boot to a STUN-like
endpoint with aggressive timeout (1s) + env-var override.
Cached for process lifetime; homelab IPs rarely change. List
of candidate endpoints (decide in §E):

| Endpoint | Response | License/cost | Notes |
|---|---|---|---|
| `https://api.ipify.org` | plain text IP | free, no auth | most common |
| `https://icanhazip.com` | plain text IP | free, no auth | Cloudflare-backed |
| `https://api64.ipify.org` | plain text IPv4 or IPv6 | free, no auth | dual-stack variant |

Settings UX (§A.6) provides a manual override (an IP OR a
lat/lon pair) for: operators behind NAT cascades, multi-
homed setups, "I don't want to leak my IP via outbound
query at boot."

### A.6 — Settings infrastructure

**Settings page**: `web/frontend/src/routes/settings/+page.svelte`.
Existing sections include Account, Appearance, Sessions, About,
DNS provider (Step O), Automation rules (Step P), and managed
domains (Step T).

**Persistence pattern** (Step T precedent — verified path):
`internal/storage/managed_domain.go` exposes CRUD on a
BoltDB-backed bucket with typed read/write. The API layer
in `internal/api/managed_domain.go` exposes
`GET/POST/DELETE /api/v1/settings/managed-domains/[/{apex}]`
with admin-auth gating. Step T HF3 added the tracker-purge
hook on DELETE (commit `e4177e4`) — the same hook pattern is
applicable if a future "reset Arenet position to auto-detect"
control needs to trigger a cache rebuild.

**Step V precedent to mirror**:
- BoltDB key/value entry for `ArenetPosition { mode:
  "auto"|"manual", lat?: number, lon?: number, city?:
  string, country?: string, sourceIP?: string,
  detectedAt?: time }`
- API: `GET/PUT /api/v1/settings/arenet-position` (admin
  scope — operator decides, not viewer).
- Frontend: new card on `/settings` with mode toggle +
  optional manual lat/lon inputs + "redetect now" action
  button.

### A.7 — Frontend stack & libraries

**Verified `web/frontend/package.json`**:

| Dep | Version | Geo / map relevance |
|---|---|---|
| `@xyflow/svelte` | ^1.6.0 | Topology graph (not a map lib). |
| `svelte` | ^5.55.2 | Framework. |
| `tailwindcss` | ^3.4.19 | Styling. |
| `vite` | ^8.0.7 | Bundler. |
| `vitest` | ^4.1.6 | Tests. |

**Conspicuously absent**: `d3` / `d3-geo` / `topojson` /
`leaflet` / `deck.gl` / `mapbox-gl` / `three.js`. The Map
page will add the FIRST geo/map dependency to the stack.

**`web/frontend/static/`** verified — contains `fonts/`,
`robots.txt`, `sso-providers/`. **No world topology JSON
file shipped today.** Step V needs to add one — see §E
question 7 for the candidate shortlist.

**Bundle budget**: Step T spec §AC #17 set a bundle budget
that the U work didn't breach. Adding a map library expands
the bundle non-trivially. Sizes for reference:

| Stack option | Gzip cost (rough) | Comments |
|---|---|---|
| `leaflet@1.9` | ~40 kB JS + ~5 kB CSS | mature, declarative, MIT |
| `d3-geo` + `topojson-client` + Natural Earth land-50m.json | ~55 kB JS + ~50 kB TopoJSON | finer-grained control, idiomatic SVG |
| `maplibre-gl-js` | ~230 kB JS + tiles network cost | overkill for our scope |

Recommend `d3-geo` (§C) — best fit for animated arcs over a
static base map without inheriting a tile-loader stack.

### A.8 — Design system color tokens

**File**: `web/frontend/src/lib/styles/tokens.css` (~268
lines, recently audited in the U.7 hotfix `e9228eb`).

Status palette (lines 79-83, dark theme; mirrored
[data-theme='light'] lines 123-127):

```css
--status-up:   oklch(72% 0.16 150);   /* green - allowed/healthy */
--status-warn: oklch(80% 0.14 85);    /* amber - warn/throttle */
--status-down: oklch(66% 0.20 25);    /* red - blocked/dangerous */
--status-info: oklch(72% 0.12 230);   /* blue - info */
--status-meta: oklch(62% 0.012 250);  /* muted - metadata */
```

Glow shadows (lines 90-91):
```css
--shadow-glow-cyan: 0 0 16px oklch(68% 0.21 255 / 0.4);
--shadow-glow-red:  0 0 16px oklch(66% 0.20 25 / 0.4);
```

The five status tokens map 1-to-1 to the five geo event
categories proposed in §C. No new palette tokens needed.

---

## §B — Event verification (empirical)

### B.1 — Verified per-category emission sites

| Category | File:line | Trigger | Notes |
|---|---|---|---|
| WAF block | `internal/waf/sink.go` `Emit(Event)` | Coraza per-rule callback in `internal/waf/module.go` | Per-rule, with LRU dedupe. |
| Throttle (429) | `internal/throttle/sink.go` `Emit(Event)` | rate-limit middleware | Tier 1 (5 fails / 5 min) or Tier 2 (10 fails / 1h). |
| CrowdSec ban | `internal/crowdsec/sink.go` `Emit(Decision)` | LAPI stream consumer | Scope=ip/range/country/as. |
| Auth failure | not wired today | `internal/auth/middleware.go` lines ~50-157 | Only logged + audit bucket. **§E question 3 must answer this.** |
| Normal 2xx/3xx | not wired today | `internal/metrics/middleware.go` `statusRecorder` | Per-route per-status counters only. |

### B.2 — Single-hook alternative via Caddy access logs

**Verified upstream**: Caddy v2.11.3
`modules/caddyhttp/server.go:220` declares
`Logs *ServerLogConfig \`json:"logs,omitempty"\``. The
field accepts a `logger_names` map keyed by host pattern.
Each access log entry carries the final HTTP status, latency,
remote addr, request URI, and the named loggers can route to
any `caddy.WriterModule` — including a custom Arenet writer
module.

**Implication**: Arenet COULD register a new module
`arenet_geo_log` under `caddy.logging.writers.*`, configure
`apps.http.servers.proxy.logs.default_logger_name` to route
to it, and receive every request after the chain finalises
with the actual status code. This gives the single choke
point §A.3 said didn't exist.

**Tradeoffs**:

| Approach | Pros | Cons |
|---|---|---|
| **B-1 — N emission points** | Reuses existing waf / throttle / crowdsec / (new) auth sinks. Each event carries category-specific metadata (rule ID, tier, scenario, action) the WAF/throttle/decision tables already store. | Auth failures need a new sink. Normal 2xx/3xx is a NEW emission point (per-request hook on the metrics middleware). |
| **B-2 — Caddy access log hook** | Single emission site. Final status known. Future-proof for any new layer. Latency + path naturally available. | Need a Caddy WriterModule + JSON-log-format parser. The disposition CATEGORY isn't always recoverable from status alone (a 403 could be WAF or auth or CrowdSec — disambiguation needs request headers Coraza sets). |

**Recommendation in §C**: pursue B-1 (N emission points) for
v1 because the existing sinks already carry the right
category-discriminated metadata. Keep B-2 in mind as the
upgrade path for V+1 if the per-emission-point wiring proves
hard to maintain across N steps.

### B.3 — Auth failure emission gap

Today, auth failures land in the audit bucket
(`internal/audit/`), read via `AuthFailureReader.QueryByActionRange`
for the Activity log page. There is NO event sink emitting
auth failures in real-time.

The cleanest V.2 sub-task is to wire a thin
`auth.Sink` mirroring the WAF/throttle shape, emitting on
each 401/403 from the soft/hard auth middleware. The audit
append stays the canonical record (per spec D2.B); the sink
is the real-time fan-out.

---

## §C — Integration proposal

### C.1 — Architectural choice

Following Step T.1's forward-compat seam pattern
(`internal/certinfo/tracker.go` `Subscribe()`), introduce:

```
internal/geo/
├── geoip.go         (oschwald reader + MMDB lifecycle)
├── event.go         (GeoEvent type + Category enum)
├── bus.go           (Subscribe seam — N producers, N consumers)
├── ring.go          (in-memory replay buffer, last N events)
├── public_ip.go     (server position auto-detect)
└── settings.go      (BoltDB-backed ArenetPosition)
```

**Bus pattern**: identical fan-out shape as
`certinfo.Tracker.Subscribe(handler)`. WAF/throttle/CrowdSec/
auth sinks each get a translator adapter (analogous to U.2's
`observability.CertEventAdapter`) that converts their native
event → `geo.Event{ts, srcIP, category, lat, lon, country,
city, statusCode, routeID?, ruleID?, scenario?, ...}`. The
geo bus fans out to:

1. The **ring buffer** (in-memory, last N=1000 events for
   replay on WS connect).
2. The **WS broadcaster** (`internal/api/ws_geo.go`,
   parallel to `ws_topology.go`).
3. Future Step V+1 consumers (persisted disk log,
   `cert_event`-style table if operators want historical
   replay across restarts).

### C.2 — Backend pipeline

```
HTTP request hits Arenet
  ├─ WAF block      → waf.Sink.Emit → geo bus
  ├─ Throttle 429   → throttle.Sink.Emit → geo bus
  ├─ CrowdSec ban   → crowdsec.Sink.Emit → geo bus
  ├─ Auth 401/403   → auth.Sink.Emit (new) → geo bus
  └─ Normal 2xx/3xx → metrics hook → geo bus (optional/§E)

geo bus → translator → geo.Event{lat, lon, category, srcIP, ts, ...}
        → ring buffer (last 1000)
        → WS broadcaster
            └─ /api/v1/ws/geo subscribers
```

Per-event enrichment in the translator:
- GeoIP lookup on `srcIP` (private/RFC1918 → §E question 8)
- Category classification (5-valued enum)
- Strip any per-table-specific metadata that isn't useful for
  the map (the WS payload is small: ~150 bytes per event JSON)

### C.3 — API surface

| Endpoint | Method | Purpose |
|---|---|---|
| `GET /api/v1/geo/snapshot` | GET | Initial state on page mount: `{serverPosition, recentEvents: [...last N from ring]}`. |
| `GET /api/v1/ws/geo` | WS | Live stream of new events. |
| `GET /api/v1/settings/arenet-position` | GET | Current Arenet position config. |
| `PUT /api/v1/settings/arenet-position` | PUT | Override mode/lat/lon. Admin-only. |
| `POST /api/v1/settings/arenet-position/redetect` | POST | Force re-run of public-IP detection. Admin-only. |

Degraded-mode contract (AC #13 from Step T, carried forward):
- `geo.Bus` not wired → `/snapshot` returns `{serverPosition:
  null, recentEvents: [], degraded: true}`.
- MMDB file missing or expired → events still flow but
  `country`/`city`/`lat`/`lon` are null; frontend renders
  arcs from a generic "unknown location" or omits the arc.

### C.4 — Frontend pipeline

```
/map page mount
  ├─ fetch /api/v1/geo/snapshot     → bootstrap state
  ├─ render Mercator world (d3-geo + countries-50m.json)
  ├─ place Arenet pin at serverPosition
  ├─ render initial arcs from recentEvents (faded)
  └─ open WS /api/v1/ws/geo
       └─ onMessage(event) → enqueue → animate arc → fade out → remove

reconnect schedule: mirror topology client _api.ts ([1s, 2s, 5s, 10s, 10s, ...])
```

State shape:

```ts
type GeoEvent = {
  ts: string;
  category: 'normal' | 'throttle' | 'waf_block'
          | 'crowdsec_block' | 'auth_failure';
  srcIp: string;
  country: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
  statusCode: number;
  routeId?: string;
};

type ArenetPosition = {
  mode: 'auto' | 'manual';
  lat: number;
  lon: number;
  city: string;
  country: string;
  sourceIp?: string;
  detectedAt?: string;
};

type GeoSnapshot = {
  serverPosition: ArenetPosition | null;
  recentEvents: GeoEvent[];
  degraded?: boolean;
};
```

### C.5 — Color taxonomy proposal

Maps the 5 categories onto the existing `--status-*` tokens
(no new palette):

| Category | Token | Glow | Operator-readable |
|---|---|---|---|
| `normal` | `--status-up` (green) | — | "allowed traffic" |
| `throttle` | `--status-warn` (amber) | — | "rate-limited (429)" |
| `waf_block` | `--status-down` (red) | `--shadow-glow-red` | "WAF block (403)" |
| `crowdsec_block` | `--status-down` w/ darker oklch shift | `--shadow-glow-red` | "CrowdSec ban (403)" |
| `auth_failure` | `--status-info` (blue) — operator may prefer violet — see §E q6 | — | "auth failure (401)" |

Operator can decide in §E q6 whether `waf_block` and
`crowdsec_block` should merge into one color (red) and
disambiguate via the tooltip only.

### C.6 — Server position lifecycle

```
boot
  ├─ load ArenetPosition from BoltDB
  ├─ if mode=manual → use stored lat/lon, done
  └─ if mode=auto:
       ├─ HTTP GET api.ipify.org (1s timeout)
       │   ├─ success → use returned IP
       │   └─ failure → fallback: keep prior detected IP if any
       ├─ GeoIP lookup on IP → lat/lon/city/country
       └─ persist {sourceIp, lat, lon, city, country, detectedAt}

settings UI
  ├─ mode toggle (auto | manual)
  ├─ if manual: lat/lon number inputs + optional city/country display
  └─ "Redetect" button (only enabled in auto mode)
```

---

## §D — Effort estimation

| Phase | Scope | Hours | Sub-tasks (preview) |
|---|---|---|---|
| Backend GeoIP | oschwald lib import + MMDB lifecycle + license attribution surfacing | 3 | V.1 |
| Backend events | New auth.Sink wired + WAF/throttle/CrowdSec adapters into geo bus + optional normal-traffic hook | 4-5 | V.2 |
| Backend WS | `internal/geo/bus.go` + ring + WS handler + `/snapshot` endpoint | 4 | V.3 |
| Backend settings | Public IP detect + BoltDB ArenetPosition CRUD + settings API | 3 | V.4 |
| Frontend map | `/map` page scaffold + d3-geo Mercator + Natural Earth land-50m TopoJSON | 4 | V.5 |
| Frontend arcs + WS | Arc animation + WS client + snapshot replay + reconnect lifecycle | 5 | V.6 |
| Frontend settings | New `/settings` section: mode toggle + manual inputs + Redetect button | 2-3 | V.7 |
| Smoke + tag | AreNET-test deploy + procedure (per T.7) + tag v1.4.0-step-v | 1-2 | V.8 |
| **Total** | | **~26-30h** | matches operator's "~3 days = 24h × 1.2 buffer" budget |

---

## §E — Open questions for operator decision

Before spec freeze, resolve these:

1. **GeoIP library choice.** Recommendation:
   `github.com/oschwald/geoip2-golang` (MIT, pure Go, standard
   for MaxMind reads). Alternative:
   `github.com/IncSW/geoip2` (also pure Go, smaller surface
   but less common). Recommendation stands; operator may
   prefer the leaner one for binary size.

2. **MMDB file lifecycle.** Three options:
   - **(a) Embed at build time** via `go:embed`. Pros:
     zero-config for operator, deterministic ship. Cons:
     binary grows by ~70 MB (GeoLite2-City is ~70-80 MB
     uncompressed), license requires MaxMind account
     during build pipeline.
   - **(b) Download on first boot** via MaxMind account token
     env var. Pros: small binary, always current. Cons:
     operator must configure account, adds network
     dependency at first boot.
   - **(c) Operator places file manually** at a documented
     path (e.g. `/var/lib/arenet/geoip/GeoLite2-City.mmdb`).
     Pros: zero opinionated lifecycle. Cons: more friction.
   
   Recommendation: **(c)** for v1 (simplest, no license
   pipeline). Document a clear "how to install GeoLite2" in
   the operator manual. Reconsider (b) for V+1 if operators
   ask.

3. **CC BY-SA 4.0 attribution.** GeoLite2 license requires
   visible attribution. Where to surface? Options: `/settings`
   about section, `/map` footer caption ("Geographic data ©
   MaxMind / GeoLite2"), or both. Recommendation: caption
   under the map.

4. **Server public IP detection endpoint.** Recommendation:
   `https://api.ipify.org`. Operator may prefer a privacy-
   leaning alternative (`https://ifconfig.co` is GDPR-
   compliant per their TOS) or disable auto-detect entirely
   (always manual). The risk is one outbound query at boot;
   homelab operators may consider this a metadata leak.

5. **Storage**: in-memory ring only (volatile, ~150 bytes ×
   1000 events ≈ 150 kB RAM), OR also persist a longer
   window in `metrics.db` (similar to `cert_event` from
   Step U)? Recommendation: **ring only for v1**, no DB
   persistence. Step T+1 pattern showed that persistence
   adds a schema migration and retention sweep — out of
   the 3-day budget. V+1 can promote to disk if operators
   ask for "show me yesterday's attack map."

6. **Auth failure event sink.** Wire a new `auth.Sink`
   mirroring WAF/throttle shape, OR pass auth failures
   through the existing `throttle.Sink` with a `Tier=0`
   special case, OR skip auth failures from the map
   entirely (the Activity log already covers them)?
   Recommendation: **new dedicated `auth.Sink`** to keep
   semantics clean. Three-event-type tier on throttle is
   confusing.

7. **Map base layer.** Recommendation: Natural Earth
   `land-50m.json` via `d3-geo` + `topojson-client` (~50 kB
   gz). Alternative: `leaflet@1.9` with a basemap tile
   provider — but tiles add network calls per session and a
   tile-hosting concern. Recommendation stands.

8. **Private IPs / RFC1918 sources.** When the
   `srcIp` is 10.x / 172.16-31 / 192.168.x or loopback, the
   GeoIP lookup returns nothing. Three options:
   - **(a) Skip entirely** — drop the event from the map
     bus.
   - **(b) Show at Arenet's own position** — visualize as
     "internal traffic" hitting Arenet.
   - **(c) Show at a configurable LAN-pin location** —
     operator sets where LAN traffic visually originates.
   
   Recommendation: **(b)** — operationally honest, no extra
   config. Operator may want to filter via a frontend toggle
   "show LAN traffic" (defaults on).

---

## §F — Sub-task preview (informational)

Spec freeze will re-lock these; surfaced here for budgeting.

- **V.1** — `internal/geo/`: GeoIP integration (oschwald lib
  + MMDB lifecycle + license attribution surfacing). Plus
  `geo.Event` type + `Category` enum. **Effort: 3h**.

- **V.2** — Event bus wiring: new `auth.Sink` + WAF /
  throttle / CrowdSec / auth adapters translating native
  events → `geo.Event` and submitting to the bus. **Effort:
  4-5h**.

- **V.3** — `geo.Bus` (Subscribe seam, fan-out pattern from
  T.1) + ring buffer (last 1000 events) + `ws_geo.go` WS
  handler + `GET /api/v1/geo/snapshot`. **Effort: 4h**.

- **V.4** — Public IP auto-detect (HTTP GET to ipify with
  1s timeout) + BoltDB `ArenetPosition` CRUD +
  `GET/PUT /api/v1/settings/arenet-position` +
  `POST /redetect`. **Effort: 3h**.

- **V.5** — `/map` page scaffold: d3-geo + Natural Earth
  TopoJSON + Mercator projection + Arenet pin placement +
  legend with 5-category color taxonomy. **Effort: 4h**.

- **V.6** — Arc animation system (incoming event → arc
  drawn from event location → Arenet → fade) + WS client
  (lifecycle mirroring `topology/_api.ts`) + snapshot
  replay on connect. **Effort: 5h**.

- **V.7** — `/settings` new section: mode toggle (auto /
  manual) + lat/lon manual inputs + Redetect button.
  **Effort: 2-3h**.

- **V.8** — Live smoke on AreNET-test + tag `v1.4.0-step-v`.
  Procedure mirror of T.7 + U.7. **Effort: 1-2h**.

Total: ~26-30h, fits the operator's medium budget.

---

## §G — References

Path / commit cross-references (all verified to exist in the
tree at HEAD):

- **Step U discovery** (template for this doc):
  `docs/superpowers/discovery/2026-06-06-step-t-plus-1-cert-events-logs.md`
  — commit `27b110a` ("docs(step-t-plus-1): discovery —
  cert events in Logs page").
- **Step U spec freeze**:
  `docs/superpowers/specs/2026-06-06-step-u-cert-events-activity-log.md`
  — commit `bb88300` ("docs(step-u): spec freeze — cert
  events in Activity log").
- **Step T spec freeze** (forward-compat seam pattern
  origin): commit `9a34eb1` ("docs(spec): Step T —
  Certificates runtime metadata + UX refactor").
- **T.1 forward-compat Subscribe seam**: commit `1350777`
  ("feat(certinfo): T.1 — backend cert-info bridge via
  Caddy events + on-disk reconcile"). The
  `internal/certinfo/tracker.go` `Subscribe(handler)` shape
  is the model for `internal/geo/bus.go`.
- **U.5 Logs aggregator pattern** (frontend WS-source
  integration template): commit `d769cad` ("feat(logs):
  U.5 — wire cert events into unified Activity log
  aggregator").
- **U.7 CSS hotfix** (token vocabulary, ensuring
  `--status-*` is the canonical palette): commit `e9228eb`
  ("fix(styles): migrate legacy --ok/--warn/--bad/--down/
  --info to --status-* vocabulary").
- **Existing topology WS** (handler shape template):
  `internal/api/ws_topology.go` (192 lines, verified).
- **Existing WAF sink pattern** (translator-to-bus shape
  template): `internal/waf/sink.go`.
- **Step T HF4 boot-log visibility pattern** (will reapply
  to `geo.Bus` wiring): commit `30418ea`
  ("fix(certs): boot-time visibility for cert tracker
  wire-up").

This document is a **discovery output**, not a spec. The
spec freeze (`v1.4.0-step-v-spec` or similar) follows
operator answers to §E.
