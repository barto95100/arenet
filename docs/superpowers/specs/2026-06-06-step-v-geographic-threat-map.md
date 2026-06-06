<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step V — Geographic threat map

**Tag**: `v1.4.0-step-v-spec` (to be created post-merge by the operator)
**Status**: FROZEN
**Discovery**: `docs/superpowers/discovery/2026-06-06-step-v-geographic-threat-map.md` (commit `508ac9f`)

## §0 Executive summary

Real-time threat-map page on `/map` rendering geographic
origin of every HTTP request hitting Arenet, with animated
arcs from source → Arenet's GPS position. Color-coded by
category (normal / throttle / WAF block / CrowdSec block /
auth failure). Built on a new `internal/geo/` package that
enriches events with `oschwald/geoip2-golang` lookups, fans
them out over WebSocket, and lets a D3 + TopoJSON frontend
visualize the live feed.

A new `auth.Sink` is the only fresh emission seam — the four
other categories already emit via existing sinks (WAF,
throttle, CrowdSec, certs from Step U). The GeoIP
enrichment infrastructure is forward-compat: Step W
country-block matcher will reuse the same MMDB file and
license attribution.

## §1 Goals

- Surface the real-time geographic origin of every HTTP
  request in an operator-facing 2D Mercator visualization.
- Reuse existing event sink seams (WAF, throttle, CrowdSec,
  Step U cert sink). Only the auth-failure path requires a
  new sink; everything else hooks via thin adapters.
- Establish the shared GeoIP enrichment layer
  (`internal/geo/`) so Step W country-block matcher can
  reuse the same MMDB file, same license attribution, same
  operator-managed lifecycle.
- Continue the HF4 boot-log visibility pattern (commit
  `30418ea`): every new seam emits a `present=<bool>` log
  line at startup so wire-up regressions surface in
  journalctl rather than as silent endpoint degradation.

## §2 Non-goals (explicit)

- **3D globe view** — operator selected 2D Mercator per
  cardinal decision §3. Deferred to a future spec if
  operators ask for it.
- **WebSocket auth gating beyond the existing session
  cookie** — out of scope for V; future hardening.
- **MMDB auto-download / auto-update** — manual placement
  v1 per §3.2. Step V+1 may add an updater.
- **Persistence of enriched events to `metrics.db`** —
  in-memory ring buffer only (size N=500 per §3.5). Cert
  events already cover the audit need via the `cert_event`
  table (Step U). Auth events DO persist to a new
  `auth_event` table per §3.6 because they're a security
  signal in their own right, but the GEO-enriched view is
  ephemeral.
- **Caddy access-log `WriterModule` integration (path B-2
  in discovery §B)** — deferred. The N-emission-point
  approach (B-1) was chosen because existing sinks already
  carry category-specific metadata.
- **Country-block matcher** — Step W scope; spec'd
  separately. Step V only establishes the shared MMDB
  convention.
- **Real-time SSE / Server-Sent Events fallback** —
  WebSocket only.

## §3 Locked decisions

All nine decisions below are the spec's response to the
discovery doc §E open questions (operator approved all 8)
plus one architecture-forward addition (§3.9 — shared
geoip layer with Step W).

### §3.1 GeoIP library: `oschwald/geoip2-golang`

Rationale: mature MIT-licensed (AGPL-v3 compatible), pure
Go (no cgo, clean cross-compile for Linux amd64/arm64),
~1M lookups/s in upstream benchmarks, industry-standard
for Go MMDB reads. Single `*geoip2.Reader` instance per
process, read-only, no daemon, no init cost beyond first
`geoip2.Open(path)` call.

### §3.2 MMDB lifecycle: manual operator placement (v1)

Operator scp's the GeoLite2-City `.mmdb` file to
`/var/lib/arenet/GeoLite2-City.mmdb` (or wherever
`ARENET_GEOIP_MMDB` points). Rationale:

- Avoids embedding a ~70 MB asset into the Arenet binary
  (build-time license-key handling, slower CI, bigger
  Docker image).
- Avoids MaxMind account-token handling at boot (privacy
  + dependency on a third-party HTTP service at startup).
- Operator is in control: they decide if they want
  GeoLite2 at all.

Path constant in code: defaults to
`/var/lib/arenet/GeoLite2-City.mmdb`, configurable via
`ARENET_GEOIP_MMDB` env var. Step W will reuse the same
path constant.

Degraded mode: missing / corrupted MMDB → geoip lookups
return `country="UNK"`, `lat=0`, `lon=0`, `city=""`.
Endpoint returns `200 + degraded:true` marker per the
AC #13 pattern established in Step T. The Map page renders
a warning banner ("Geographic lookups unavailable — see
operator docs").

Auto-updater deferred to Step V+1; tracked in
`docs/backlog-step-v.md` after V.8 ships.

### §3.3 License attribution

GeoLite2 is CC BY-SA 4.0 — visible attribution required.

- **Map page footer**: small text "This product includes
  GeoLite2 data created by MaxMind, available from
  https://www.maxmind.com" with a small `(i)` icon
  linking to `/settings#geoip-license`.
- **`/settings#geoip-license` panel**: full CC BY-SA 4.0
  notice + link to MaxMind GeoLite2 EULA
  (https://www.maxmind.com/en/geolite2/eula).

### §3.4 Public IP detection at boot

HTTP GET to `https://api.ipify.org` at startup (5 s
timeout). Result cached for process lifetime.

Fallback chain:

1. `ARENET_PUBLIC_IP` env var (if set, skip ipify entirely
   — privacy-preserving option for operators who don't
   want an outbound query at boot).
2. ipify response (success path) → GeoIP lookup → Arenet's
   `lat/lon/city/country` → cached as `serverPosition`.
3. ipify failure (timeout, network error, malformed
   response) → `serverPosition.mode = "manual"`, the
   `/settings` UI surfaces a banner "Auto-detection
   failed — set your position manually" and the Map page
   shows the same banner.

Cached in BoltDB under the existing `arenet.db` settings
bucket (same persistence layer Step T managed-domains
uses).

### §3.5 Storage model: in-memory ring buffer N=500

Rationale: the Map is a visualization tool, not an audit
log. Cert events already cover the audit case via the
`cert_event` table (Step U). Auth events get their own
`auth_event` table per §3.6 because they're a security
signal worth persisting, but the GEO-ENRICHED view fed
to the WebSocket is ephemeral.

Ring buffer characteristics:

- Size: 500 most-recent enriched events.
- Concurrency: `sync.RWMutex` guarding a fixed-size
  circular array. Writers (event-bus producers) take the
  write lock briefly; readers (WS replay + `/geo-events`
  GET) take the read lock.
- Replay: last 500 served on WebSocket connect for
  frontend bootstrap (so the page is non-empty
  immediately after refresh).
- Restart behavior: cleared on process restart
  (acceptable — visualization, not audit). Auth events
  outlive restart via the `auth_event` table.

### §3.6 New `auth.Sink` (V.2 deliverable)

Shape: identical to `internal/observability/{waf,throttle,
decision}_event_sink.go` pattern from Steps M / N / Q,
plus the cert sink shape Step U.1 added. Channel +
batcher + `InsertAuthEventBatch`.

Storage: new `auth_event` table in `metrics.db` (schema
v6 migration, mirror of `cert_event` schema v5 from Step
U.1). Columns:

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | autoincrement |
| `ts` | INTEGER | epoch seconds (uniform with other tables) |
| `kind` | TEXT | `login_failure` / `session_expired` / `oidc_callback_rejected` / `forbidden` |
| `src_ip` | TEXT | source IP |
| `username` | TEXT | attempted username (audit bucket already redacts where needed) |
| `path` | TEXT | request path (e.g. `/auth/login`, `/api/v1/...`) |
| `details` | TEXT | optional reason string |

Indexes: `ts`, `(src_ip, ts)`, `(kind, ts)` — same shape
as `cert_event`.

Retention: 30 days (matches the `RetainWafEvents` /
`RetainThrottleEvents` constants in
`internal/observability/retention.go`). NOT 90 days like
cert events — auth failures are operationally
short-window security signals, not lifecycle records.

Boot log: `msg="auth event sink wired" present=true
degraded=false`.

Subscriber wiring: the existing auth middleware emits to
this sink on every 401/403. The audit-bucket append (Step
Q D2.B canonical record) stays — the new sink is a
real-time fan-out parallel to it, not a replacement.

### §3.7 Map base layer: TopoJSON natural-earth 50m

Path: `web/frontend/static/world-50m.topo.json`
(~80 kB gzipped).

Source: https://github.com/topojson/world-atlas
(CC0 / public domain — no attribution required, but a
courtesy credit in the Map page about panel is fine).

Rendering stack:

- `d3@^7` for projections + selections
- `d3-geo@^3` for `geoMercator()` + `geoPath()` (already
  part of `d3` distribution — verify subpath import path
  in V.5)
- `topojson-client@^3` for converting TopoJSON →
  GeoJSON at runtime

These three packages MUST be added to
`web/frontend/package.json` in V.5 (discovery §A.7
confirmed they're absent today — the page would otherwise
have NO map library bundled).

Projection: `d3.geoMercator()` centered on the Arenet
position. Operator's view of the world is "Arenet at
center, threats arrive from around it".

### §3.8 RFC1918 sources: render at Arenet position with `(LAN)` label

Rationale: operator wants visibility into LAN /
internal traffic. Hiding it silently would obscure a
real traffic class (an internal scan, a misbehaving
container, etc.).

Behavior:

- Source IP in any of:
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
  - `127.0.0.0/8`
  - `fe80::/10` (IPv6 link-local)
- → render the arc as a small loop centered on Arenet
  position with label `(LAN)`. The loop is visually
  distinct from a continental arc so the operator can
  tell at a glance.
- Color taxonomy still applies (normal / throttle / WAF /
  CrowdSec / auth).
- The frontend's `isLan: true` flag on the wire payload
  carries the classification (computed server-side at
  enrichment time).
- Operator can hide LAN entirely via a toggle in the Map
  page header (UI affordance for noise reduction in busy
  LANs / CI environments). Toggle state persists per
  user via local storage; no backend setting needed.

### §3.9 Layered GeoIP architecture (forward-compat Step W)

Step V owns the GeoIP enrichment layer:

- Library: `oschwald/geoip2-golang` (read-only lookups
  inside Arenet observability path).
- MMDB file: `/var/lib/arenet/GeoLite2-City.mmdb`
  (operator-placed per §3.2).
- Used by: event enrichment middleware → Map WebSocket
  fan-out.
- Scope: read-only metadata enrichment for
  visualization.

Step W (FUTURE — not this spec) will add a country-block
matcher layer:

- Library candidate: `porech/caddy-maxmind-geolocation`
  vendored into the Caddy module set OR a hand-rolled
  matcher that reuses Step V's `*geoip2.Reader`
  instance.
- Same MMDB file: `/var/lib/arenet/GeoLite2-City.mmdb`.
- Used by: Caddy match pipeline → allow/deny by
  country code.
- Scope: HTTP request gating — write-side action, NOT
  just enrichment.

Both layers share:

1. The SAME MMDB file — single source of truth, single
   update path.
2. The SAME MaxMind license attribution.
3. The SAME operator-managed lifecycle (no auto-update
   in v1).

Step V is responsible for ensuring the path
`/var/lib/arenet/GeoLite2-City.mmdb` is conventional and
stable; Step W will reuse without modification. If Step W
ends up needing a SEPARATE country-only MMDB (smaller,
faster matcher path), that's a Step W decision and
doesn't break Step V's contract.

## §4 Architecture

Reference the discovery doc for full mapping with
file:line citations (commit `508ac9f`). Summary of the
V-introduced components:

### Backend pipeline

```
Caddy HTTP request
  ├── WAF block       (existing waf.Sink)     ─┐
  ├── Throttle 429    (existing throttle.Sink) ─┤
  ├── CrowdSec ban    (existing crowdsec.Sink) ─┤── geo enrichment
  ├── Auth 401/403    (NEW auth.Sink)         ─┤   adapter
  └── cert lifecycle  (existing certinfo bus)  ─┘
                          ↓
                    internal/geo/lookup.go
                    (MMDB lookup)
                          ↓
                  internal/geo/bus.go
                  (ring buffer N=500 + fan-out)
                          ↓
              ┌───────────┴───────────┐
              ↓                       ↓
        WS /api/v1/ws/geo-events   GET /api/v1/observability/geo-events
        (live push)                (initial replay)
```

### Frontend pipeline

```
/map page mount
  ↓
  ├── GET /api/v1/observability/server-position
  │     (where to center the Mercator + place Arenet pin)
  │
  ├── GET /api/v1/observability/geo-events
  │     (initial replay — last 500 to populate the map
  │     immediately rather than blank-until-first-event)
  │
  └── WS /api/v1/ws/geo-events
        (live stream — each frame is one enriched event)
        ↓
        render arc (D3 + topojson-client + d3-geo)
        ↓
        animate ease-out, fade 3-5 s, remove
```

### Nine new components

1. `internal/geo/lookup.go` — `*geoip2.Reader` wrapper,
   degraded-mode handling, `LookupIP(net.IP) Result`
   returning `{country, lat, lon, city, isLAN, degraded}`.
2. `internal/geo/bus.go` — Subscribe seam (T.1 AC #18
   pattern) + ring buffer N=500.
3. `internal/geo/server_position.go` — public-IP
   auto-detect (`api.ipify.org` with 5 s timeout) + GeoIP
   lookup + BoltDB persistence for manual override.
4. `internal/observability/auth_event_sink.go` — NEW sink
   (schema v6 migration, `auth_event` table, retention
   30 d).
5. `internal/api/ws_geo_events.go` — WebSocket handler
   (mirror of `ws_topology.go` shape — 192 lines).
6. `internal/api/server_position_handler.go` — `GET`/`PUT`
   the auto/manual position.
7. `internal/api/geo_events_handler.go` — `GET` replay
   endpoint with `limit` query param.
8. `web/frontend/src/routes/map/+page.svelte` — real
   implementation replacing the Step R.2 stub.
9. `web/frontend/src/lib/components/Map/` — D3 + WS +
   arc animation Svelte components (split into
   `WorldMap.svelte`, `ArcLayer.svelte`,
   `geo-events-client.ts` — exact split decided in V.5).

Two HF4 boot-log signals confirm the wire-up:

- `msg="geoip database loaded" path=<…> present=<bool>`
- `msg="geo event bus wired" present=true`
- `msg="auth event sink wired" present=<bool> degraded=<bool>`
- `msg="api handler wired with server position" position_present=<bool>`

## §5 API contract

### 5.1 `GET /api/v1/observability/server-position`

Returns Arenet's current geographic position (where to
center the Mercator + place the central pin).

Response shape:

```json
{
  "lat": 48.8566,
  "lon": 2.3522,
  "city": "Paris",
  "country": "FR",
  "mode": "auto",
  "sourceIp": "203.0.113.42",
  "detectedAt": "2026-06-06T12:00:00.000Z",
  "degraded": false
}
```

| Field | Notes |
|---|---|
| `mode` | `"auto"` (ipify + GeoIP) or `"manual"` (operator override) |
| `sourceIp` | populated when `mode="auto"` — the public IP ipify returned; null when manual |
| `detectedAt` | RFC 3339; when the auto-detect last succeeded |
| `degraded` | true when MMDB missing or ipify failed AND no manual override |

Degraded path: missing MMDB or ipify failure with no
manual override → returns the empty-shape
`{lat:0, lon:0, city:"", country:"", mode:"auto",
sourceIp:null, detectedAt:null, degraded:true}` with
HTTP 200. Frontend renders a banner + falls back to a
world-centered Mercator (lat=0, lon=0).

### 5.2 `PUT /api/v1/observability/server-position`

Admin-auth gated. Sets `mode="manual"` and persists the
operator's chosen position.

Request body:

```json
{
  "lat": 45.7640,
  "lon": 4.8357,
  "city": "Lyon",
  "country": "FR"
}
```

Validation:

- `lat` ∈ [-90, 90] — 400 if out of range.
- `lon` ∈ [-180, 180] — 400 if out of range.
- `city` and `country` are operator-supplied display
  strings; empty allowed.

Response: same shape as 5.1, with `mode="manual"` and
`sourceIp:null`, `detectedAt:null`.

### 5.3 `POST /api/v1/observability/server-position:redetect`

Admin-auth gated. Forces a re-run of the
ipify-then-GeoIP detection path. Resets `mode="auto"`.
Useful when the operator's network has moved (new public
IP) or the MMDB was just placed.

Response: same shape as 5.1. Synchronous (5 s timeout on
the ipify call); returns degraded if redetect fails.

### 5.4 `GET /api/v1/observability/geo-events`

Returns the in-memory ring buffer for initial bootstrap.

Query params:

| Param | Type | Default | Notes |
|---|---|---|---|
| `limit` | int | 100 | Max 500 (clamped silently above). |

Response:

```json
{
  "events": [<GeoEvent>...],
  "total": 487,
  "degraded": false
}
```

`total` is the ring buffer's current size, NOT a database
count (since events don't persist past restart). `degraded`
is true when the geoip lookup path is degraded — events
still flow but with empty country/lat/lon.

### 5.5 `WS /api/v1/ws/geo-events`

Server pushes one `GeoEvent` frame per enriched event in
real-time. Mirror of `ws_topology.go` shape: hard-auth at
the router upstream, no in-WS re-auth, gorilla upgrader
with 4 KB buffers, cookie session enforced before upgrade.

### 5.6 `GeoEvent` wire shape

```json
{
  "timestamp": "2026-06-06T14:34:56.123Z",
  "category": "waf",
  "sourceIp": "1.2.3.4",
  "sourceLat": 51.5074,
  "sourceLon": -0.1278,
  "sourceCountry": "GB",
  "sourceCity": "London",
  "isLan": false,
  "statusCode": 403,
  "routeId": "r-abc",
  "details": ""
}
```

| Field | Notes |
|---|---|
| `category` | `"normal"` / `"throttle"` / `"waf"` / `"crowdsec"` / `"auth"` |
| `sourceLat` / `sourceLon` | 0 when geoip degraded or LAN source |
| `sourceCountry` | ISO-3166-1 alpha-2; `"UNK"` when degraded |
| `isLan` | true for RFC1918 / loopback / link-local; arc renders as Arenet-centered loop per §3.8 |
| `statusCode` | final HTTP status (403, 429, 401, etc.) |
| `routeId` | populated when known (WAF / metrics events carry it); empty otherwise |
| `details` | optional short string (rule ID, scenario name, etc.) — display in tooltip |

## §6 Acceptance criteria

### Functional

**AC #1** `internal/geo/lookup.go` enriches an IP → country,
lat/lon, city via the MMDB. Tested against
`TestLookup_KnownIP` with a fixture MMDB containing
known entries.

**AC #2** `cert_obtained` / `cert_failed` /
`cert_ocsp_revoked` events flow through geo enrichment.
The cert sink from Step U.2 gains an adapter that
submits to the geo bus alongside its existing
persistence path.

**AC #3** WAF block events flow through geo enrichment.
The existing `waf.Sink` (commit `1350777`-era pattern)
emits to the geo bus via a thin adapter.

**AC #4** Throttle events flow through geo enrichment.
Same adapter pattern.

**AC #5** CrowdSec decisions flow through geo enrichment.
Same adapter pattern.

**AC #6** NEW `auth.Sink` created; auth failures (401/403)
emit events with the same shape and flow through geo
enrichment. Schema v6 migration adds the `auth_event`
table.

**AC #7** In-memory ring buffer caps at 500, FIFO
eviction on overflow. Tested concurrently under `-race`.

**AC #8** WS `/api/v1/ws/geo-events` broadcasts every
enriched event in real-time. Slow clients dropped via
the broadcaster pattern from `ws_topology.go`.

**AC #9** Server public IP detected via `api.ipify.org`
at boot (5 s timeout), cached. Failure → `mode="manual"`
forced, settings UI surfaces a banner.

**AC #10** `GET`/`PUT` `/api/v1/observability/server-position`
works; manual override persists across restart via
`/var/lib/arenet/arenet.db`.

**AC #11** Frontend renders TopoJSON world map +
Arenet position marker. Verified via component test
with a synthetic position.

**AC #12** New events render as animated arcs with 3-5 s
lifetime, ease-out fade. Verified via animation test
(stub time + assert SVG attrs at key frames).

**AC #13** Color coding by category honors §3.8 mapping
to `--status-*` tokens (no new palette tokens).

**AC #14** Initial state load replays last 500 events
from `/api/v1/observability/geo-events` on page mount,
BEFORE the WS connects, so the map is non-empty
immediately after page load.

**AC #15** RFC1918 source IPs render at the Arenet
position with `(LAN)` label per §3.8. LAN toggle in
header hides them.

**AC #16** License attribution visible in Map page
footer (small inline text) + `/settings#geoip-license`
panel (full CC BY-SA 4.0 notice).

**AC #17** Degraded mode (missing MMDB) → endpoint
returns `200` with `events: []` and `degraded: true`
marker; Map page shows a non-blocking banner ("Geographic
data unavailable — see operator docs"). Other observability
endpoints remain unaffected.

**AC #18** Boot logs emit four HF4-pattern signals:

- `msg="geoip database loaded" path=<…> present=<bool>`
- `msg="geo event bus wired" present=true`
- `msg="auth event sink wired" present=<bool> degraded=<bool>`
- `msg="api handler wired with server position" position_present=<bool>`

A future regression where any setter is dropped surfaces
as `..._present=false` / `position_present=false` in
journalctl instead of silent endpoint degradation.

### CI gates

**AC #19** `go test -race -count=1 ./internal/geo/...` —
all green.

**AC #20** `go test -race -count=1 ./...` — no regression
elsewhere (no change to existing event sink / API tests).

**AC #21** `npm run check` (0 errors, 0 warnings) +
`npm test` (no regression) + `npm run build` (clean) —
all green.

## §7 Sub-tasks

| Sub-task | Scope | Effort |
|---|---|---|
| **V.1** | Backend: `internal/geo/` package — `lookup.go` MMDB wrapper + degraded mode + `server_position.go` public-IP auto-detect at boot. Tests: `TestLookup_KnownIP`, `TestLookup_DegradedMode`, `TestPublicIP_Timeout`. | 3h |
| **V.2** | Backend: NEW `auth.Sink` (schema v6 migration, `auth_event` table, retention 30d) + adapter wiring for the 4 existing categories (WAF/throttle/CrowdSec/cert) into the geo bus. Tests: `TestAuthSink_RoundTrip`, `TestAdapter_<Category>_FlowsToBus` × 4. | 4h |
| **V.3** | Backend: WS `/api/v1/ws/geo-events` handler + ring buffer N=500 + `GET /api/v1/observability/geo-events` replay endpoint. Tests: `TestRingBuffer_FIFOEviction`, `TestWSGeoEvents_Broadcast`, `TestGeoEventsReplay_Limit`. | 4h |
| **V.4** | Backend: server-position GET/PUT/redetect + persistence in `arenet.db` (auto/manual mode). Tests: handler-level happy path + degraded + reversal of mode. Boot-log signal: `position_present=true`. | 3h |
| **V.5** | Frontend: Map page scaffold + TopoJSON world rendering + Arenet position marker + license footer. Adds `d3`, `topojson-client` to `package.json`. Tests: component renders TopoJSON without crash, position marker placed at right coords. | 4h |
| **V.6** | Frontend: arc animation system + WebSocket client (mirror `topology/_api.ts` lifecycle) + replay logic + color taxonomy via `--status-*` tokens. Tests: arc lifecycle (mount → fade → unmount), reconnect schedule. | 5h |
| **V.7** | Frontend: `/settings` UI for manual position override + LAN toggle for Map page (local storage persistence). Tests: PUT happy path, banner shown on degraded auto. | 2h |
| **V.8** | Live smoke on AreNET-test + tag `v1.4.0-step-v`. Procedure mirror of T.7 / U.7. | 1-2h |

Each sub-task lands as one scope-distinct commit, following
the Step T / Step U shipping discipline.

## §8 Effort estimate

Per discovery doc §D and the sub-task table above:

- **Backend**: V.1 + V.2 + V.3 + V.4 ≈ **14h**
- **Frontend**: V.5 + V.6 + V.7 ≈ **11h**
- **Smoke + tag**: V.8 ≈ **1-2h**
- **Total: ~26-30h** (≈ 3 days). Matches operator's
  "medium" budget verbatim.

## §9 References

- **Discovery**: `docs/superpowers/discovery/2026-06-06-step-v-geographic-threat-map.md`
  (commit `508ac9f`). All §A architecture mapping +
  §B-C alternatives + §E open questions answered
  here.
- **Step U spec (cert events)**:
  `docs/superpowers/specs/2026-06-06-step-u-cert-events-activity-log.md`
  (commit `bb88300`). Established the AC #13
  degraded-mode pattern + schema-migration shape that
  V.6 (`auth_event` schema v6) mirrors.
- **Step U release notes**: `docs/release-notes/v1.3.0-step-u.md`
  — **NOT YET WRITTEN**. Step U shipped v1.3.0-step-u
  without committing release notes (only Step T's
  `docs/release-notes/v1.2.0-step-t.md` exists). This is
  not a Step V blocker, but flagged here so a future
  Step U.8.1 closeout (or T.6-style annotation pass for
  Step U) writes them.
- **Step T spec (forward-compat seam pattern)**:
  `docs/superpowers/specs/2026-06-04-step-t-certificates-runtime-refactor.md`
  (commit `9a34eb1`). The T.1 AC #18 `Subscribe()` seam
  is the model for `internal/geo/bus.go`.
- **HF4 boot-log pattern**: commit `30418ea`
  ("fix(certs): boot-time visibility for cert tracker
  wire-up"). The `present=<bool>` log convention is
  carried over to V.1 / V.2 / V.4 (four new signals per
  AC #18 above).
- **U.1 cert sink + retention pattern**: commit `05fea9f`
  ("feat(observability): U.1 — cert_event schema + sink +
  retention"). Direct template for the V.2
  `auth_event` table + sink shape.
- **U.5 frontend WS aggregator**: commit `d769cad`
  ("feat(logs): U.5 — wire cert events into unified
  Activity log aggregator"). Pattern template for V.6's
  WS client.
- **U.7 CSS token migration**: commit `e9228eb`
  ("fix(styles): migrate legacy
  --ok/--warn/--bad/--down/--info to --status-*
  vocabulary"). Establishes that `--status-up` /
  `--status-warn` / `--status-down` / `--status-info`
  are the canonical palette — V.5's color taxonomy must
  use these tokens.
- **`oschwald/geoip2-golang`**:
  https://github.com/oschwald/geoip2-golang (MIT
  license, AGPL-v3 compatible).
- **GeoLite2 license**:
  https://www.maxmind.com/en/geolite2/eula
  (CC BY-SA 4.0).
- **`world-atlas` TopoJSON**:
  https://github.com/topojson/world-atlas (CC0 /
  public domain).
- **Step W (future) candidate library**:
  `porech/caddy-maxmind-geolocation` — placeholder
  reference for the country-block matcher Step W will
  spec separately. Same MMDB path convention from
  §3.9 applies.

## §10 Frozen tag

To be tagged by the operator after this commit merges:

```bash
git tag -a v1.4.0-step-v-spec -m "Step V spec freeze — geographic threat map"
git push origin v1.4.0-step-v-spec
```

The `release.yml` pipeline excludes `v*-spec` tags from
the release-build trigger (Step T CI hotfix). The tag
serves as the design-shape marker only; implementation
follows in V.1 → V.8 commits.
