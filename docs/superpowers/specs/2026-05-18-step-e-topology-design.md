<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step E — Topology & Live Metrics

## 1.1 Goal

Add a live topology visualization to Arenet, fulfilling items 4 and 5 of
the Phase 1 scope declared in `CLAUDE.md` (per-route metrics over WebSocket
+ animated topology dashboard).

Step E transforms Arenet from a credentialed admin panel (Step D, v0.2.0)
into a system that **shows what it is doing right now**: every routed
request increments a counter, every second a snapshot is broadcast, and
the admin watches particles flow across an SVG topology that reflects
real traffic.

Predecessors: Step D closed at v0.2.0-step-d (auth, audit, HIBP, idle
lock). Successors planned:

- Step F — Security & threat dashboard (Phase 2)
- Step G — WAF (Coraza) integration (Phase 2)
- Step H — IP reputation (CrowdSec) (Phase 2)

## 1.2 Scope

Step E delivers, end-to-end:

- **Per-route request counter** — a Caddy middleware module
  (`arenet.routemetrics`) registered into the Caddy module system,
  injected into each route's handler chain by `caddymgr`. Counts total
  requests and 5xx responses, keyed by `routeID`. Atomic, zero
  contention on the hot path.

- **Live snapshot loop** — a background goroutine ticks every 1 s,
  computes per-route deltas (requests, errors) since the previous tick,
  publishes a `Snapshot` to subscribed WebSocket clients.

- **WebSocket endpoint `/api/v1/ws/topology`** — hard-auth gated
  (same `arenet_session` cookie as the rest of the API). Full-state
  JSON tick every second; the tick itself doubles as heartbeat. Single
  connection per tab; reconnect with exponential backoff on the client.

- **New page `/topology`** — SVG topology with three vertical columns
  (Clients · Routes · Upstreams) and animated particles flowing
  Client → Route → Upstream. Particle density per edge ∝ req/s; particle
  color ∝ 5xx error rate. Honors `prefers-reduced-motion` (animation
  disabled, static lines + counter only).

- **Per-route state visual** — `active`, `idle`, `error_spike`. Three
  discrete colors, no in-between blending. Thresholds (active window,
  spike window, spike ratio) are named constants in §8; rationale
  there too.

- **Interactions** — click on a route node opens a side panel showing
  the route's full detail (host, upstream, TLS/WAF flags, current req/s,
  current 5xx %); hover shows a small tooltip with the live req/s.

- **Sidebar entry** — the existing dashboard sidebar gains a
  "Topology" item between "Audit" and "Settings".

- **Backward compatibility** — a Step D binary started on a Step E
  database opens cleanly; the metrics module is not used. A Step E
  binary on a Step D database registers its module, applies the config,
  reloads. No migration required (metrics live in memory only).

## 1.3 Out of scope

Explicitly deferred from Step E. Each is in `docs/roadmap.md`:

- **Bandwidth (bytes in/out)**, **latency histograms (p50/p95/p99)**,
  **active connections**, **TLS handshake counters** — not required for
  topology visualization. Some land in Step F or Phase 2 if real usage
  motivates them.

- **Health checks** — Step E does not probe upstreams. "Upstream up/down"
  is not displayed because we do not measure it. Step F may add it.

- **4xx tracking** — 4xx responses are typical on an authenticated admin
  surface (401 / 403 / 404 on session probes, scanner bots). Counting
  them as errors would render every route permanently "in error spike".
  5xx-only is the MVP signal.

- **Metric history (rolling window, persistence, replay)** — the server
  pushes live ticks and forgets. Clients keep a small ring buffer in
  memory (60 ticks ≈ 1 min); nothing is written to BoltDB. Phase 2
  Step F may add a 1 h ring or Prometheus export.

- **Sparklines in the main topology view** — deferred. The vertical
  density of a sparkline per route would clutter the SVG and dilute
  the topology metaphor. Sparklines ARE rendered inside the
  **per-route detail panel** (§6.9) where they have room to breathe;
  the main view stays focused on particles + node state.

- **Multi-tab / shared connection** — each open tab opens its own WS.
  SharedWorker complexity not worth it on a single-admin app.

- **Force-directed graph, search bar, route grouping/tags** — the layout
  is the explicit three-column flow described in §6. No physics, no
  search, no tags.

- **Per-route enable/disable** — the route schema has no `enabled` flag.
  Phase 2 (Step F+) will introduce it; Step E displays every persisted
  route.

- **D3.js** — explicitly not used. SVG is rendered directly from Svelte
  templates; CSS keyframes animate particles. Decision §4.

- **Prometheus / OpenMetrics export** — the counter map is internal.
  Phase 3 may expose it.

- **Anomaly detection** — Step F.

---

## 2. Architecture overview

```
┌──────────────────────────────────────────────────────────────────────┐
│  Arenet binary                                                       │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Caddy v2 (embedded)                                            │  │
│  │                                                                │  │
│  │   Server :80 / :443                                            │  │
│  │     Route 1 [matchers: host=app.example] →                     │  │
│  │       handlers: [ ⚡ arenet.routemetrics{routeID:UUID1} ,       │  │
│  │                  reverse_proxy{...} ]                          │  │
│  │     Route 2 [matchers: host=api.example] →                     │  │
│  │       handlers: [ ⚡ arenet.routemetrics{routeID:UUID2} ,       │  │
│  │                  reverse_proxy{...} ]                          │  │
│  │     ...                                                        │  │
│  └────────────────────┬───────────────────────────────────────────┘  │
│                       │ counters incremented                         │
│                       ▼                                              │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ internal/metrics.Registry  (singleton)                         │  │
│  │   map[routeID]*counterCell { reqs uint64, errs uint64 }        │  │
│  │   atomic.AddUint64 in the hot path                             │  │
│  │   Snapshot() returns deltas + resets via swap                  │  │
│  └────────────────────┬───────────────────────────────────────────┘  │
│                       │ tick 1 s                                     │
│                       ▼                                              │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ internal/metrics.Broadcaster                                   │  │
│  │   subscribers map[*subscriber]chan Snapshot                    │  │
│  │   fan-out non-blocking; slow client → dropped tick             │  │
│  └────────────────────┬───────────────────────────────────────────┘  │
│                       │ JSON frame                                   │
│                       ▼                                              │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ internal/api WebSocket handler  ws://…/api/v1/ws/topology      │  │
│  │   gorilla/websocket, hard-auth via cookie                      │  │
│  └────────────────────┬───────────────────────────────────────────┘  │
│                       │                                              │
└───────────────────────┼──────────────────────────────────────────────┘
                        │ ws frame, every 1 s, all routes
                        ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Browser tab                                                         │
│  /topology page                                                      │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                │
│   │  Clients    │═══│   Routes    │═══│  Upstreams  │                │
│   │  (●●●)      │   │  (R1 R2 R3) │   │  (U1 U2 U3) │                │
│   └─────────────┘   └─────────────┘   └─────────────┘                │
│   particles flow ● ─→ ● ─→ ● animated by CSS keyframes               │
└──────────────────────────────────────────────────────────────────────┘
```

### 2.1 Components

| Layer | New package / file | Responsibility |
|---|---|---|
| Caddy module | `internal/metrics/middleware.go` | Caddy middleware `arenet.routemetrics` |
| Counters | `internal/metrics/registry.go` | Atomic counter map keyed by routeID |
| Broadcast | `internal/metrics/broadcaster.go` | Fan-out snapshots to subscribers |
| Tick loop | `internal/metrics/ticker.go` | 1 s goroutine snapshotting the registry |
| WS handler | `internal/api/ws_topology.go` | gorilla/websocket upgrade + write pump |
| Routing | `internal/caddymgr/manager.go` | Inject the module into each route's chain |
| Frontend route | `web/frontend/src/routes/topology/+page.svelte` | Page shell |
| Frontend viz | `web/frontend/src/lib/components/Topology*.svelte` | SVG + particles |
| Frontend WS | `web/frontend/src/lib/api/topology.ts` | WebSocket client, reconnect, store |
| Sidebar | `web/frontend/src/lib/components/Sidebar.svelte` | Add `/topology` item |

### 2.2 Data flow per request

1. Browser at `http://app.example` hits Caddy `:80`.
2. Caddy matches Route 1, enters its handler chain.
3. `arenet.routemetrics` handler is invoked first: it wraps the
   `ResponseWriter` in a `statusRecorder`, defers
   `registry.Inc(routeID, recorder.Status())`, then calls
   `next.ServeHTTP(recorder, r)`.
4. `reverse_proxy` runs and produces the response status code via the
   wrapped writer.
5. The deferred `registry.Inc` reads the recorded status and increments
   counters (§4.1).
6. The response returns to the client.

The middleware adds: one atomic add (`reqs`), one conditional atomic add
(`errs` only if 5xx), one `ResponseWriter` wrap. No allocation per
request beyond the wrapper struct. Benchmark target: < 200 ns overhead
per request (§9.3).

### 2.3 Data flow per tick (1 Hz)

1. Ticker goroutine fires at t = N × 1 s.
2. `registry.Snapshot()` iterates the counter map, swaps each cell's
   counters to 0 with `atomic.SwapUint64`, returns
   `map[routeID]Delta{reqs, errs}`.
3. `broadcaster.Publish(snapshot)` sends to each subscriber's channel
   (capacity 1, non-blocking write; if channel full, tick dropped for
   that subscriber, debug-logged).
4. Each WS subscriber drains its channel, marshals JSON, writes to the
   socket with a 1 s write deadline. Failure to write → close the
   connection.

The snapshot includes **every persisted route**, including those at
0 req/s. Routes are listed from `storage.ListRoutes`, joined with
counter deltas (missing key in registry → zeros).

---

## 3. The Caddy middleware module

### 3.1 Module identity

```go
const moduleID = "http.handlers.arenet_routemetrics"
```

The dotted-form ID follows Caddy's namespacing convention. Module
struct:

```go
type RouteMetricsHandler struct {
    RouteID string `json:"route_id,omitempty"`
}
```

Registered in `init()`:

```go
caddy.RegisterModule(RouteMetricsHandler{})
```

`CaddyModule()` returns the module info; `Provision(ctx caddy.Context)`
resolves a reference to the singleton `*metrics.Registry` (set at binary
startup via a `caddy.Context` `App` or via a package-level variable
guarded by `sync.Once`). `Validate()` rejects empty `RouteID`.

### 3.2 Why a real Caddy module

A Caddy-registered module gives us four properties a plain wrapper
cannot:

1. **Post-routing context** — the handler runs after Caddy's matcher
   selected the route, so the `RouteID` we read is authoritative.
2. **Lifecycle hooks** — `Provision` runs after the config is loaded,
   `Cleanup` on reload. We piggyback on Caddy's reload to ensure no
   handler ever runs without a Registry pointer.
3. **JSON-config-native** — `caddymgr` already produces Caddy JSON; we
   only insert one extra map per route's handler list.
4. **No re-matching** — a wrapper before Caddy would have to re-match
   the host to recover the routeID, duplicating logic.

### 3.3 ServeHTTP

```go
func (h RouteMetricsHandler) ServeHTTP(
    w http.ResponseWriter, r *http.Request, next caddyhttp.Handler,
) error {
    rw := &statusRecorder{ResponseWriter: w, status: 200}
    defer registry.Inc(h.RouteID, rw.status)
    return next.ServeHTTP(rw, r)
}
```

`statusRecorder` is a tiny wrapper exposing `Status() int` after the
inner handler returned. It implements `http.Hijacker`, `http.Flusher`,
and `http.Pusher` only by **forwarding** to the wrapped writer, falling
back to a runtime check (`if h, ok := w.(http.Hijacker); ok { return
h.Hijack() }`).

**Graceful degradation** — if the wrapped writer does *not* implement
the requested interface, the recorder returns the standard
`http.ErrNotSupported` (Hijack) / no-op (Flush) / `http.ErrNotSupported`
(Push). The metric handler itself never panics regardless of the
inner writer's capabilities; a WS upgrade through a proxied route
fails the upgrade with a normal error (just as it would without the
metrics handler in the chain), and the next request proceeds.

### 3.4 Provision and registry lookup

The middleware needs the `*metrics.Registry`. Approaches considered:

- **(rejected) Inject via constructor field** — Caddy instantiates
  modules from JSON config; we cannot pass arbitrary Go pointers
  through `RouteID string` fields.
- **(chosen) Package-level singleton, set once at startup** —
  `metrics.SetRegistry(*Registry)` is called from `cmd/arenet/main.go`
  before `caddymgr.Start`. `Provision` reads the singleton and
  returns an error if nil. Single-binary, single-process; no
  multiplicity.

The singleton API:

```go
// metrics/global.go
var (
    globalOnce     sync.Once
    globalRegistry *Registry
)

// SetRegistry installs the process-wide registry. Safe to call
// multiple times; only the first call wins (sync.Once). Subsequent
// calls are silent no-ops to keep startup robust if main() is
// refactored or a test mistakenly re-initializes.
func SetRegistry(r *Registry) {
    globalOnce.Do(func() { globalRegistry = r })
}

// GlobalRegistry returns the installed registry, or nil if SetRegistry
// was never called. Provision uses this and errors out on nil.
func GlobalRegistry() *Registry { return globalRegistry }

// ResetForTest clears the singleton and the once. Tests that need a
// fresh registry per case (Chunk 2 module tests, Chunk 3 WS tests)
// call this in t.Cleanup. Build-tagged or guarded by a test-only
// file is not necessary: a t.Helper() call documents intent.
func ResetForTest() {
    globalOnce = sync.Once{}
    globalRegistry = nil
}
```

`sync.Once` guarantees set-once with zero race at boot. A double-set
in main() (programming error) is silently dropped rather than
panicking. Tests reset via `ResetForTest()` between cases.

### 3.5 Caddy JSON injection

`caddymgr.buildConfigJSON` currently produces one `httpRoute` per
storage route with a single `reverse_proxy` handler. After Step E:

```json
{
  "match": [{"host": ["app.example"]}],
  "handle": [
    { "handler": "arenet_routemetrics", "route_id": "UUID1" },
    { "handler": "reverse_proxy", "upstreams": [...] }
  ]
}
```

The handler name in the JSON `"handler"` field is exactly
**`arenet_routemetrics`** — underscore, no dot, no `http.handlers.`
prefix. That string is the **last segment** of the dotted module ID
`http.handlers.arenet_routemetrics` (§3.1), per Caddy's JSON config
convention. Mixing forms (e.g., writing `http.handlers.arenet_routemetrics`
in the `handler` field) silently fails: Caddy refuses to load the
config with an unhelpful "unknown handler" error.

**Mandatory test (Chunk 2): JSON-roundtrip.** A unit test in
`caddymgr_test.go` constructs a `[]storage.Route` of length ≥ 1,
calls `buildConfigJSON`, and asserts that:

1. The produced JSON parses cleanly.
2. For each route, the `handle` array has the metrics handler at
   index 0 with `"handler": "arenet_routemetrics"` (exact string).
3. The `route_id` field equals the route's storage UUID.

This catches any silent breakage from a typo in the constant, a
refactor of `buildConfigJSON`, or an accidental rename. Failure on
this test gates the merge.

---

## 4. The metrics package

### 4.1 Registry

```go
type Registry struct {
    mu     sync.RWMutex
    cells  map[string]*counterCell // routeID → cell
}

type counterCell struct {
    reqs uint64 // atomic
    errs uint64 // atomic, incremented only when status >= 500
}
```

Operations:

- `Inc(routeID string, status int)` — hot path. `RLock`, look up cell;
  if absent, drop the increment **silently** (this happens during the
  brief window between a route being deleted and the Caddy reload
  finishing). `atomic.AddUint64(&cell.reqs, 1)`; conditionally
  `atomic.AddUint64(&cell.errs, 1)` if `status >= 500`. `RUnlock`.

- `Sync(routeIDs []string)` — called by `caddymgr` after each successful
  Caddy reload with the canonical list of current route IDs. Takes the
  write lock **once** and:
  - Inserts cells for IDs present in the slice but absent from the map.
  - Deletes cells for IDs present in the map but absent from the slice.

  Single critical section per reload, regardless of how many routes
  were added or removed. Cells preserved across the call retain their
  current counter values (a route updated in place — same ID, new
  upstream — keeps accumulating, per §11.2).

- `Snapshot() map[string]Delta` — called once per tick by the ticker.
  Iterates cells with `RLock`, performs `atomic.SwapUint64(&cell.reqs, 0)`
  on each (and `&cell.errs`), returns a fresh map of deltas. RWMutex is
  read-locked so concurrent `Inc` calls proceed; the swap is the
  serialization point.

```go
type Delta struct {
    Reqs uint64 `json:"reqs"`
    Errs uint64 `json:"errs"`
}
```

### 4.2 Broadcaster

```go
type Broadcaster struct {
    mu    sync.Mutex
    subs  map[*subscriber]struct{}
}

type subscriber struct {
    ch              chan Snapshot
    logger          *slog.Logger
    lastDropLogAt   time.Time // rate-limit per §5.6
}
```

- `Subscribe() *subscriber` — locks, allocates `ch` with capacity 1,
  registers, returns. The capacity-1 channel implements the "latest
  wins, slow clients drop" semantics.
- `Unsubscribe(s *subscriber)` — locks, deletes, closes `s.ch`.
- `Publish(snap Snapshot)` — locks, iterates subscribers. For each:
  `select { case s.ch <- snap: default: ... }`. Drop with a debug log.

### 4.3 Ticker

```go
func (t *Ticker) Run(ctx context.Context) {
    tick := time.NewTicker(1 * time.Second)
    defer tick.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-tick.C:
            snap := t.makeSnapshot()
            t.broadcaster.Publish(snap)
        }
    }
}
```

`makeSnapshot` reads `registry.Snapshot()` (deltas), joins with the
current `storage.ListRoutes` result for canonical IDs and metadata
(host, upstream), produces the wire shape (§5).

Cost of `ListRoutes` per tick: one BoltDB read transaction. Bench
target: < 1 ms on a 100-route DB (§9.3). Acceptable at 1 Hz.

**Phase 2 note**: if `ListRoutes` ever becomes a bottleneck (very
large route count, slower storage, or higher tick frequency), cache
the slice locally in `Ticker` and invalidate on Caddy reload by
having `caddymgr` push the new slice through a channel. Not warranted
for Step E.

### 4.4 Concurrency model

| Operation | Frequency | Lock | Notes |
|---|---|---|---|
| `Inc` | per request | `RLock` + atomic add | hot path |
| `Snapshot` | 1 Hz | `RLock` + atomic swap | does not block `Inc` |
| `Sync` | on Caddy reload (rare) | `Lock` | single critical section per reload |
| `Subscribe` / `Unsubscribe` | per WS connect/close | broadcaster `Lock` | short |
| `Publish` | 1 Hz | broadcaster `Lock` | iterates subscribers |

The two mutexes (`Registry.mu`, `Broadcaster.mu`) never nest.

---

## 5. WebSocket protocol

### 5.1 Endpoint

```
GET /api/v1/ws/topology
Cookie: arenet_session=...
Upgrade: websocket
```

Hard-auth middleware runs before the upgrade. If the session is missing,
expired, or idle-locked, the handshake returns `401` (no upgrade).
After successful upgrade, the handler subscribes to the broadcaster and
enters a write loop.

### 5.2 Frame shape — server to client

A single message type, sent every 1 s:

```json
{
  "t": "2026-05-18T18:32:11Z",
  "routes": [
    {
      "id": "01J...",
      "host": "app.example",
      "upstream": "http://192.168.1.10:3000",
      "reqs": 47,
      "errs": 2,
      "reqPerSec": 47,
      "errRate5xx": 0.0426
    },
    ...
  ]
}
```

Field semantics:

- `t` — RFC 3339 UTC timestamp of the tick (server-side).
- `routes[].id` — route UUID, stable across ticks.
- `routes[].host`, `upstream` — denormalized into every tick. Cheap
  (~50 bytes/route) and saves the client a `GET /routes`.
- `routes[].reqs`, `errs` — raw deltas (count over the last second).
- `routes[].reqPerSec` — equals `reqs` since the tick is exactly 1 s,
  but kept as an explicit field so future tick variation does not break
  the contract.
- `routes[].errRate5xx` — `errs / reqs` when `reqs > 0`, else `0`.
  The client MUST clamp to `min(value, 1.0)` because a rare swap race
  in the server's snapshot (§11.8) can produce `errs > reqs` for a
  single tick.

Routes with zero traffic for the last tick are still listed with
`reqs:0, errs:0, errRate5xx:0`. The frontend uses this for the "idle"
state.

### 5.3 Frame shape — client to server

The MVP is **unidirectional server → client**. The client sends no
application frames. The browser is expected to send WS pings on its own
schedule; the server replies with pongs via `gorilla/websocket`
defaults.

A future Step F may send filter commands (e.g., subscribe to a subset
of routes). Not in Step E.

### 5.4 Connection lifecycle (server)

1. Upgrade. If hard-auth fails before this point, no upgrade.
2. `Subscribe`. Set write deadline 1 s on every write.
3. Read loop (separate goroutine): continuously call
   `conn.ReadMessage()`. The call returns on every incoming frame
   (handled by gorilla internally for ping → pong, control frames),
   on read deadline, or on connection error. We **never act on the
   payload** (the protocol is unidirectional, §5.3); any text or
   binary message is discarded. On **any** error returned by
   `ReadMessage` (network error, timeout, client close), the read
   loop signals shutdown to the write loop via a shared `done`
   channel and exits. Required by gorilla so that pings can be
   received and pongs auto-sent — without an active reader, the
   library cannot detect a dropped client.
4. Write loop: select between subscriber channel (send JSON frame
   with the 1 s write deadline) and the `done` channel from (3).
   On write error or `done`: close the connection cleanly with code
   1000 (normal), unsubscribe, return.
5. On `ctx.Done()` (server shutdown): both loops observe the cancel,
   the write loop closes the connection with code 1001 (going away).

### 5.5 Reconnection (client)

- **Initial connect** on page mount.
- **On clean close** (code 1000 / 1001 / 4xxx other than 4401): reconnect
  with exponential backoff starting at `reconnectMinMs` (1 s), doubling,
  capped at `reconnectMaxMs` (30 s).
- **On unauthorized** during handshake (HTTP 401): redirect to
  `/login`, consistent with the rest of the API. No retry loop.
- **On `visibilitychange` → hidden**: the client **actively closes**
  the WS with code 1000 (normal) and pauses the reconnect loop. Saves
  server resources for a tab that nobody is watching and avoids the
  cross-browser ambiguity around whether/when the browser throttles
  or kills hidden WS connections.
- **On `visibilitychange` → visible**: the client re-opens immediately
  (no backoff — this is a fresh user-driven event). If the initial
  open fails, the normal backoff kicks in.
- **On page unmount** (`onDestroy`): close the WS with code 1000 and
  cancel any pending reconnect timer.

### 5.6 Backpressure

The server's per-subscriber channel has capacity 1. A subscriber that
falls behind misses ticks; on resume it receives only the latest. This
matches the UX (a smooth animation with occasional jumps is better than
buffered-and-stale ticks).

**Drop logging** — when `Publish` cannot enqueue (channel full), the
event is logged at **debug level only** and **rate-limited per
subscriber**: at most one drop log per minute. The subscriber struct
holds a `lastDropLogAt time.Time`; the broadcaster checks
`now.Sub(s.lastDropLogAt) >= 60s` before emitting, updates the
timestamp on emit. A persistently slow client produces at most 60
log lines/hour, not 3600.

If a subscriber's write fails or times out (1 s deadline), the
connection is closed. Step E does not retry sends.

---

## 6. Frontend — page, viz, animation

### 6.1 Page shell — `routes/topology/+page.svelte`

Hard-auth gated by `auth.state === 'authenticated'` in `+layout.svelte`
(unchanged from Step D).

Layout:

```
┌──────────────────────────────────────────────────────────┐
│  Topology                                  [● connected] │  header
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌────────┐         ┌────────┐         ┌────────┐        │
│  │Clients │         │ Routes │         │Upstrm. │        │
│  │        │ ●─→─●─→ │   R1   │ ─→─●─→─ │   U1   │        │
│  │        │         │        │         │        │        │
│  │        │ ─●─→─●─ │   R2   │ ─●─→─●─ │   U2   │        │
│  │        │         │        │         │        │        │
│  │ idle   │         │   R3   │         │   U3   │        │
│  └────────┘         └────────┘         └────────┘        │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

The page subscribes to the topology store on mount and renders an SVG
of fixed dimensions. Mobile is out of scope (homelab admin desktop
context).

### 6.2 Node layout

Three columns, fixed X positions. Within the **Routes** column,
route nodes are distributed vertically by their `order` (= insertion
order from `GET /routes`). A small layout helper packs Y positions to
fit the viewport height with a minimum vertical gap of 64 px.

**Clients column** — a single aggregate node ("All clients") that
spans the **full height of the Routes column** (top to bottom of the
SVG content area). Visually it reads as a vertical pillar / bracket,
not a small box that would look orphaned facing 10 route nodes. We
do not track per-client traffic in Step E, so there is no
ambiguity to express via multiple sub-nodes. The pillar has a single
left-edge anchor; every Client→Route edge originates from a different
Y on that anchor, aligned with its target route's Y. Total req/s
across all routes is shown as a label inside the pillar.

**Upstreams column** — one node per **unique `upstream` URL**.
Several routes pointing at the same upstream collapse into one
upstream node. Visual rules:

- Each route still draws its own Route→Upstream edge, with its own
  particle stream (density and color reflect that route's traffic).
- The upstream node displays an aggregate label: `192.168.1.10:3000`
  with a secondary line `← 3 routes` when more than one route fans
  into it. Hover shows the list.
- If two routes route to the same upstream with very different
  health (one healthy, one error-spike), the upstream node itself
  carries no state color — only its incoming edges do. The
  upstream column is informational, not stateful.

The pillar+aggregate-node design avoids the 1-vs-N ratio that would
make a small "Clients" box look misplaced beside N route nodes.

### 6.3 Edges

For each route, two edges:

- Client → Route (left side)
- Route → Upstream (right side)

Each edge is rendered as a single `<path>` (bezier curve). Particles
travel along the path using SVG's `<animateMotion>` or, preferentially,
a small Svelte component that moves a `<circle>` via `requestAnimationFrame`
along the path's parametric form (`path.getPointAtLength`). The latter
gives precise control over density and color without spawning N
`<animateMotion>` elements.

### 6.4 Particle density and color

Constants (`particleDensityCap`, `colorWarnThreshold`,
`colorErrorThreshold`, `particleTravelMs`) live in §8.

- **Density** (particles/sec emitted per edge) = `clamp(reqPerSec, 0,
  particleDensityCap)`. At 0 req/s no particles. At the cap, no extra
  particles to avoid CPU melt.
- **Color** — three discrete states evaluated on the **current tick's**
  `errRate5xx`:
  - `errRate5xx == 0` → `--accent-cyan` (#00d9ff)
  - `0 < errRate5xx < colorErrorThreshold` → `--status-warn` (#ffaa00)
  - `errRate5xx >= colorErrorThreshold` → `--status-down` (#ff4757)

  Note: the **particle color** threshold (current tick) is distinct
  from the **node error-spike** threshold (sliding window, §6.5).
  §8 sets both at the same numeric value (5 %) for visual consistency
  but the two semantics may diverge in a future spec.

- **Particle TTL** — fixed travel time `particleTravelMs` per edge,
  regardless of density. Particles travel at constant speed; only
  the spawn rate varies.

### 6.5 Route node visual state

Three discrete states, with thresholds defined in §8:

- **Active** (≥ 1 req inside the active window) — full opacity, normal
  border.
- **Idle** (zero req for longer than the active window) — opacity 0.4,
  dashed border.
- **Error spike** (5xx rate over the spike window exceeds the spike
  threshold) — red border + subtle pulse animation (1 s ease-in-out
  loop).

All three are computed **client-side** from the ring buffer (§6.7),
not server-side. The server emits raw 1 s deltas only. The named
constants (`activeWindow`, `spikeWindow`, `spikeThreshold`) live in
`lib/stores/topology.svelte.ts`; §8 is the single source of truth for
their values.

### 6.6 Reduced motion

If `window.matchMedia('(prefers-reduced-motion: reduce)').matches`, the
page renders:

- Static SVG topology (lines without particles).
- Each edge shows its current `reqPerSec` as a text label near the
  midpoint.
- Route node color still reflects the active/idle/spike state.
- No pulse animation.

This is checked once at mount and re-evaluated on `change` event of
the matchMedia query.

### 6.7 Client-side state — topology store

```ts
// lib/stores/topology.svelte.ts
type RouteTick = { reqs: number; errs: number; ts: number };
type RouteState = {
  id: string;
  host: string;
  upstream: string;
  history: RouteTick[]; // capacity 60 ticks (~1 min)
  reqPerSec: number;     // last tick's reqPerSec
  errRate5xx: number;    // last tick's errRate5xx
};
```

Operations:

- `applyTick(snap: Snapshot)` — for each route in the snapshot, push a
  tick onto `history`, trim to capacity 60.
- `isActive(state)` — `history.some(t => t.reqs > 0 && now - t.ts < 60_000)`.
- `isErrorSpike(state)` — over the last 10 ticks: total errs / total reqs > 0.05.

### 6.8 Connection indicator

Top-right of the page header:

- Green dot + "connected" when WS is open.
- Amber dot + "reconnecting…" when the reconnect loop is active.
- Red dot + "disconnected" when more than 5 reconnect attempts have
  failed in a row (≥ ~30 s of downtime).

### 6.9 Detail panel (click on route node)

Clicking a route node opens a right-side panel showing:

- Host, upstream URL.
- TLS / WAF flags from the stored route.
- Live req/s + 5xx % (large numbers, updated every tick).
- Sparkline of the last 60 s (single thin SVG path), one for req/s,
  one for 5xx %.
- Button "Edit route" → links to `/routes` with the row pre-expanded
  (later Phase 2 deep link; for Step E, just routes to `/routes`).

Panel closes on Escape, on overlay click, or on a second click of the
same node.

### 6.10 Tooltip on hover

Hovering a route node shows a small inline tooltip:

```
app.example
47 req/s · 4.3 % 5xx
```

200 ms delay before show, instant hide. CSS `:hover` + a Svelte block
toggling a tooltip element.

### 6.11 Sidebar entry

```
- Dashboard
- Routes
- Audit
- Topology      ← new
- Settings
```

Lucide icon: `network`. Active state on `/topology`. If the icon is
absent from the locally bundled Lucide subset, add it during Chunk 5
— do not substitute another glyph silently.

---

## 7. Auth & security

### 7.1 WebSocket auth

Identical to `/api/v1/audit` (hard-auth). The handshake passes through
`HardAuthMiddleware`, which:

1. Reads `arenet_session` cookie.
2. Resolves the session, checks `LastActivity + 15 min > now` (idle
   lock), `ExpiresAt > now` (absolute lock).
3. On success, calls `Touch` then invokes `next`. **`Touch` happens
   before the upgrade**, mirroring Step D §5.6.

After upgrade, the WS connection is **not** re-authenticated on
subsequent ticks. The 15-minute idle window is **not enforced** on the
WS itself (a long-running WS would naturally fail when the cookie's
session expires; but the server does not actively kick a connection
when the idle window elapses). Rationale: the WS is observability,
not mutation. A locked admin can still see the live state until the
session's absolute `ExpiresAt` is reached.

### 7.2 Reload-after-lock

When the admin re-logs in after an idle lock, the WS connection that
was established before the lock is **still open** (assuming
`ExpiresAt` not reached). The client's reconnect logic does not need
to do anything special.

### 7.3 Audit emissions

No new audit actions in Step E. The WS connection itself is not
audited (would generate noise on every reconnect). Route mutations
continue to emit `route_created` / `route_updated` / `route_deleted`
per Step D.

### 7.4 Information disclosure

The wire frame contains `host` and `upstream` for every route. This is
the same data a `GET /routes` returns. No PII beyond what Step D
already exposes to authenticated admins.

### 7.5 DoS exposure on WS endpoint

The handshake goes through `HardAuthMiddleware` which the Step D
rate-limiter does not gate (auth rate-limit is only on
`/api/v1/auth/*`). An authenticated admin spamming reconnects is the
only theoretical client. Acceptable; if abused, a Phase 2 per-IP
connection cap can be added.

---

## 8. Configuration & env vars

No new env vars. Step E uses defaults baked into code:

| Name (code identifier) | Value | Where used | Rationale |
|---|---|---|---|
| `tickInterval` | 1 s | server ticker | UI smoothness + bandwidth balance |
| `particleTravelMs` | 2000 ms | client edge | visual continuity at 1 Hz |
| `particleDensityCap` | 50 / s / edge | client edge | CPU safety on background tabs |
| `colorWarnThreshold` | > 0 | client particle | visual: any 5xx > 0 already a warning |
| `colorErrorThreshold` | 0.05 (5 %) | client particle | red particles above this rate |
| `subscriberChanCap` | 1 | server broadcaster | latest-wins backpressure |
| `activeWindow` | 60 s | client state | "recent activity" rule of thumb |
| `spikeWindow` | 10 s | client state | fast enough to catch incidents |
| `spikeThreshold` | 0.05 (5 %) | client state | high enough to ignore noise |
| `historyCapacity` | 60 ticks | client state | ~1 min of memory for sparklines |
| `reconnectMinMs` / `reconnectMaxMs` | 1000 / 30000 | client WS | typical browser-friendly pattern |
| `wsWriteDeadlineMs` | 1000 | server WS | slow clients drop, not block |

The values above are **the** source of truth. Go constants live in
`internal/metrics/constants.go`; TypeScript constants in
`web/frontend/src/lib/stores/topology-constants.ts`. Any divergence is
a bug; CI does not yet check this but a future test may.

A future spec may parameterize these via env vars or admin UI. Not
Step E.

---

## 9. Performance & resource budget

### 9.1 Server steady state

For 10 routes, 100 req/s aggregate (typical homelab):

- `Inc`: ~100 atomic adds/s. Negligible.
- `Snapshot`: 10 atomic swaps + 1 BoltDB read tx/s. Bench < 1 ms.
- `Publish`: 1-3 channel sends/s.
- `Marshal + write`: per WS client, ~600 byte payload (10 routes ×
  ~60 bytes each + overhead), 1 write/s.

Total CPU footprint: well under 1 % on any modern hardware. RAM
overhead: O(routes) for the counter map (~64 bytes/route + cell), so
~1 kB for 10 routes.

### 9.2 Client steady state

- 1 WS frame/s, parsed, applied to the store.
- ~30 particles in flight at peak per edge (60 edges × peak 30 = 1800
  DOM circles at extreme; realistic is 10 routes × ~5 particles/edge
  ≈ 100).
- `requestAnimationFrame` ticking at 60 Hz, updating particle positions
  along their parent edge via `path.getPointAtLength`. The browser
  caches the path's parametric tabulation after the first call so
  per-frame cost is amortized to O(particles), not O(particles × path
  length).
- Sparkline re-renders: only when detail panel is open.

Tested target: **60 fps stable on Chrome 120 on a 2020 MacBook Air
with 100 particles in flight simultaneously across 20 edges**. The
Chunk 5 smoke procedure (§12.5b) MUST measure this — DevTools
Performance tab, record 10 s, assert mean FPS ≥ 55 and no long task
> 50 ms.

### 9.3 Benchmarks to write

Spec mandates the following benchmarks alongside the implementation:

- `BenchmarkRouteMetrics_Inc` — < 200 ns per op, allocs/op ≤ 0.
- `BenchmarkRegistry_Snapshot_10Routes` — < 50 µs.
- `BenchmarkRegistry_Snapshot_100Routes` — < 500 µs.
- `BenchmarkBroadcaster_Publish_10Subs` — < 10 µs.
- `BenchmarkBroadcaster_PublishWithStuckSub` — < 15 µs. Setup: 9 fast
  subscribers (draining their channel in a goroutine) and 1 stuck
  subscriber (never reads its channel). Asserts that the stuck
  subscriber does not increase per-publish cost beyond the 50 % budget
  versus the 10-sub bench. Critical: validates the non-blocking
  `select { case s.ch <- snap: default: ... }` of §5.6 in a runnable
  contract.

Failures on these benches block the merge.

---

## 10. Acceptance criteria

A Step E implementation is accepted when **all** of the following hold:

1. **Module registration** — starting the binary registers
   `http.handlers.arenet_routemetrics` with Caddy (visible via
   Caddy's admin API at `/config/`). The applied Caddy JSON config
   contains one `arenet_routemetrics` handler per route.

2. **Counter accuracy** — over a 10 s test where 1000 requests are
   issued **serially** against a single route, the registry reports
   exactly **999 or 1000 reqs** aggregated across the ticks. The
   single-request tolerance covers exactly one case: a request whose
   response wrote between the snapshot's `atomic.SwapUint64` and the
   handler's deferred `Inc`. No other source of loss is acceptable.
   Test must use a synchronous HTTP client (no overlapping requests)
   to keep the analysis exact.

3. **5xx classification** — when the upstream returns 503 for 50/100
   requests, the registry reports `errs / reqs ≈ 0.5` over the
   relevant ticks.

4. **WS handshake auth** — handshake without cookie returns 401, no
   upgrade. Handshake with a locked session returns 403, no upgrade.
   Handshake with a valid session upgrades successfully.

5. **WS payload** — the WS sends a JSON frame matching §5.2 every
   ~1 s (±200 ms, widened for CI under variable load — local runs
   typically stay within ±50 ms). Every persisted route is listed,
   including idle ones.

6. **Reload preservation** — creating a new route via `POST /routes`
   triggers a Caddy reload; within ≤ 2 s the next WS tick lists the
   new route. Deleting a route removes it from subsequent ticks within
   ≤ 2 s.

7. **Frontend smoke** — `/topology` page loads, shows particles
   flowing when a route is exercised, transitions a route to "idle"
   after 60 s of zero traffic, and to "error_spike" when the upstream
   returns 503s sustained.

8. **Reduced motion** — with `prefers-reduced-motion: reduce`, no
   particles animate; numeric req/s and 5xx % are visible as labels.

9. **Reconnect** — killing the binary while the page is open shows
   "reconnecting…" within 2 s. Restarting the binary restores
   "connected" within ≤ 30 s.

10. **Benchmarks** — all four benchmarks in §9.3 pass their bounds.

11. **No regression** — full `go test ./...` and `npm test` green;
    the 8 sections of `docs/smoke-test-step-d.md` (setup → login →
    route + Caddy reload → audit content → idle lock → unlock →
    change password → logout) all still pass end-to-end on the Step
    E binary.

12. **AGPL headers** — every new file (Go and Svelte/TS) carries the
    AGPL v3 header.

---

## 11. Edge cases & invariants

### 11.1 Route deleted while in flight

A request matched a route, entered the handler chain, the admin then
deleted the route via `/routes`. Caddy reload completes; old config is
discarded; the in-flight request finishes against the old upstream.
Our `Inc` runs with the old `routeID`. `Registry.Inc` looks up the
cell; if `Sync` removed it between the matcher's decision and the
`Inc`, the cell is gone and `Inc` is a no-op. **Acceptable**: at
most one tick of counts can be lost for a deleted route. Documented.

### 11.2 Route updated (same ID)

`PUT /routes/{id}` keeps the ID, changes host/upstream/etc. The
counter cell persists. Counters keep accumulating against the new
identity. **By design**: the route is conceptually "the same"
(same UUID); upstream change is an admin operation, not a new route.

### 11.3 Many simultaneous WS clients

The fan-out is O(N) per tick. For N = 10 subscribers, < 100 µs at
the lock. The mutex is held during fan-out, so other Subscribe
operations queue. Worst case: a new tab waits ≤ 100 µs to connect.
Acceptable.

### 11.4 Backpressure on slow clients

A client whose channel is full (capacity 1) misses ticks. The
`select … default` is non-blocking. Logged at debug. The client sees
a visual stutter, never blocks the server.

### 11.5 Handler chain order

The metrics handler MUST be the first in the route's handler list,
before `reverse_proxy`. Otherwise the proxy may write the response
without the metrics handler observing the status. `caddymgr` constructs
the chain explicitly to enforce this; a test asserts the JSON order.

### 11.6 Status code 0

If the wrapped `ResponseWriter`'s `WriteHeader` is never called (e.g.,
`reverse_proxy` returns an error to Caddy's error handler before
writing), `statusRecorder.status` stays at its default 200. This
matches Caddy's default behavior (a request with no body and no header
is implicitly 200 from the client's perspective). Documented; a future
spec may capture this case more precisely.

### 11.7 Server clock jumps

`time.NewTicker` is monotonic-based on modern Go runtimes; clock jumps
do not affect tick cadence. The `t` field in the WS frame uses
wall-clock UTC, so if the operator manually adjusts the clock, `t`
will reflect that. Acceptable.

### 11.8 Swap of reqs and errs is not atomic across the pair

`Snapshot` calls `atomic.SwapUint64` on `cell.reqs` then on `cell.errs`
in sequence — each swap is atomic individually, but the **pair** is
not. If an `Inc` for a 5xx response runs between the two swaps, the
following can happen:

- `reqs.Swap(0)` returns 47.
- `Inc` arrives, `cell.reqs` becomes 1, `cell.errs` becomes 1 (still
  the previous tick's value 2 plus this new one — but reqs was just
  reset, so reqs=1 and errs=3).
- `errs.Swap(0)` returns 3.

Result for that tick's delta: `{Reqs: 47, Errs: 3}`. The 1 req that
arrived between the swaps is double-charged on errs (counted in this
tick's errs, then reset → next tick's reqs sees 1 with errs=0).

Worst-case symptom in the JSON frame: a single tick with
`errs > reqs`, hence `errRate5xx > 1.0` if naively computed.
Probability per tick: roughly `(window_ns / 1s) × inc_rate`. For 100
req/s with a 100-ns window between the two swaps, ~1 occurrence per
hour, statistically.

**Mitigations**:
- Client computes `errRate5xx = min(errs / reqs, 1.0)` to mask the
  cosmetic spike. Confirmed in §5.2 wire shape spec.
- The next tick auto-corrects (the over-counted err vanishes from the
  next delta because errs was reset alongside the swap).
- Step E does not introduce a `errs <= reqs` invariant. A future spec
  may use a single `uint64` packing reqs (high 32) + errs (low 32) with
  a single atomic swap, or per-cell mutex. Deferred to Phase 2.

### 11.9 Counters are deltas, not cumulatives

`Registry.Snapshot()` performs `atomic.SwapUint64(&cell.reqs, 0)`, so
each tick produces the count **since the previous tick**. There is no
running total preserved across ticks server-side, and nothing
written to disk. Long-term tracking (a cumulative `reqs_total`, a
percentile histogram, a rolling 24 h window) is **deferred to Phase 2**
(Step F or beyond) where the trade-off between memory footprint,
persistence, and Prometheus integration can be designed together.

Clients that want a longer history maintain their own ring buffer
(§6.7, 60 ticks ≈ 1 min). Reload-resistant aggregation is not a
Step E concern.

---

## 12. Implementation plan (chunks)

Step E is implemented in **5 chunks**, ~14-18 h total. Each chunk ends
on a green test suite; chunks are committed separately.

### Chunk 1 — `internal/metrics` package (≈ 3 h)

Files:
- `internal/metrics/registry.go` + `_test.go`
- `internal/metrics/broadcaster.go` + `_test.go`
- `internal/metrics/ticker.go` + `_test.go`
- `internal/metrics/snapshot.go` (type definitions)

Deliverables:
- `Registry` with `Inc / Sync / Snapshot`, full test coverage of the
  swap semantics under concurrent writes and of `Sync` add/remove
  diffing.
- `Broadcaster` with `Subscribe / Unsubscribe / Publish`, test of the
  "slow subscriber drops" semantics.
- `Ticker` that fires every 1 s and calls a configurable
  snapshot-producing function; injected `clock` (or use `synctest`)
  to make tests fast and deterministic.
- Benchmarks per §9.3 pass.

AC: `go test ./internal/metrics/... -race -bench=.` green within the
bench bounds.

### Chunk 2 — Caddy module + `caddymgr` wiring (≈ 3 h)

Files:
- `internal/metrics/middleware.go` + `_test.go` (the Caddy module)
- `internal/caddymgr/manager.go` modified (handler chain)
- `cmd/arenet/main.go` modified (wire `metrics.SetRegistry`)

Deliverables:
- `RouteMetricsHandler` registered in `init()`. `Provision`,
  `Validate`, `ServeHTTP` implemented.
- `statusRecorder` wrapper with Hijacker/Flusher/Pusher forwarding.
- `caddymgr.buildConfigJSON` inserts the handler **first** in every
  route's chain.
- `cmd/arenet/main.go` constructs `*Registry`, calls
  `metrics.SetRegistry`, starts the broadcaster + ticker before
  `caddymgr.Start`.
- Tests:
  - `TestRouteMetrics_IncrementsOnSuccess` — 200 OK increments only
    `reqs`.
  - `TestRouteMetrics_IncrementsOnError` — 503 increments both.
  - `TestRouteMetrics_StatusRecorder_ForwardsHijacker` — interface
    detection.
  - `TestCaddymgr_HandlerChainOrder` — JSON has metrics handler
    first.

AC: above tests pass; existing `caddymgr` tests still green; smoke
test §3 of Step D still passes (route reload via `POST /routes`).

### Chunk 3 — WebSocket endpoint (≈ 3 h)

Files:
- `internal/api/ws_topology.go` + `_test.go`
- `internal/api/routes.go` modified (mount handler)
- `go.mod` add `github.com/gorilla/websocket`

Deliverables:
- Handler at `GET /api/v1/ws/topology`, hard-auth gated.
- Upgrade with `gorilla/websocket`, subscribe to broadcaster, write
  loop with 1 s write deadline.
- Tests:
  - `TestWS_Topology_RequiresAuth` — 401 without cookie.
  - `TestWS_Topology_LockedSession_403` — 403 with locked session.
  - `TestWS_Topology_Upgrades_AndStreams` — with a real broadcaster,
    `Publish` once, client receives the JSON frame within 100 ms.
  - `TestWS_Topology_SlowClient_DropsTicks` — client that does not
    read drops subsequent ticks without crashing the server.

AC: all WS tests green with `-race`. Manual `curl` of the path
without WS upgrade returns 400 (gorilla default).

### Chunk 4 — Frontend store + WS client (≈ 2 h)

Files:
- `web/frontend/src/lib/api/topology.ts` + `topology.test.ts`
- `web/frontend/src/lib/stores/topology.svelte.ts` + test (helpers
  pure → Vitest; runes deferred to Phase 2 per Step D debt)

Deliverables:
- `TopologyClient` class wrapping `WebSocket` with reconnect
  exponential backoff, exposing `subscribe(handler)` /
  `disconnect()`.
- `TopologyStore` with `$state`: `routes: Map<id, RouteState>`,
  `connectionStatus: 'connected' | 'reconnecting' | 'disconnected'`,
  `lastTickAt: Date | null`.
- Tests for the pure logic of `applyTick` (push to history, trim to
  60), `isActive`, `isErrorSpike`. WebSocket itself mocked.

AC: `npm test` green; ≥ 80 % coverage on `topology.ts` and the pure
helpers of `topology.svelte.ts`.

### Chunk 5 — `/topology` page + Svelte SVG viz (≈ 4 h)

Files:
- `web/frontend/src/routes/topology/+page.svelte`
- `web/frontend/src/lib/components/TopologySvg.svelte`
- `web/frontend/src/lib/components/TopologyNode.svelte`
- `web/frontend/src/lib/components/TopologyEdge.svelte`
- `web/frontend/src/lib/components/TopologyParticle.svelte`
- `web/frontend/src/lib/components/TopologyDetailPanel.svelte`
- `web/frontend/src/lib/components/Sidebar.svelte` modified

Deliverables:
- Page subscribes to the topology store, renders the three-column
  SVG.
- `TopologyNode` renders a route box with active/idle/spike state.
- `TopologyEdge` renders the bezier path + spawns
  `TopologyParticle` instances at a rate proportional to `reqPerSec`,
  capped at 50/s.
- `TopologyParticle` animates a `<circle>` along its parent path
  using `path.getPointAtLength` + `requestAnimationFrame`, with
  `prefers-reduced-motion` short-circuit.
- `TopologyDetailPanel` opens on click, shows live metrics +
  sparkline.
- Sidebar gains the Topology entry.

AC: `npm run build` succeeds; manual browser session shows particles
on a route exercised via `curl`; reduced-motion media query disables
particles; click on node opens panel; Escape closes it.

### Post-merge smoke validation (gates the tag)

After Chunk 5 lands on `main`, run a manual end-to-end smoke session
and document it in `docs/smoke-test-step-e.md` (new file, mirrors the
Step D pattern). Coverage required:

- WS handshake authz (401 / 403 / 200 paths).
- Particle flow under `curl` load against one route.
- Idle transition after 60 s of zero traffic on a route.
- Error spike under sustained upstream 503s.
- `prefers-reduced-motion` check (CSS override or DevTools emulation).
- **DevTools FPS measurement per §9.2** — Performance tab, record
  10 s, assert mean FPS ≥ 55 and no long task > 50 ms.

Smoke session validation gates the `v0.3.0-step-e` tag. The smoke
doc itself is committed in a separate `docs:` commit after the
session passes, exactly like the Step D pattern.

### 12.1 Sequencing

Strict serial order: **1 → 2 → 3 → 4 → 5**. No parallelization. Each
chunk merges to `main` before the next begins. Rationale:

- Chunk 2 depends on Chunk 1 (it imports `metrics.Registry`).
- Chunk 3 depends on Chunk 1 (broadcaster) and on Chunk 2 (server
  start sequence with the registry singleton wired by `main.go`).
- Chunk 4 validates the wire shape; it depends on Chunk 3 being
  merged so the WebSocket spec is anchored in real server behavior
  rather than the spec alone.
- Chunk 5 depends on Chunk 4 (store + client) for the page to mount.

Allowing parallel work (e.g., Chunk 4 mocked against the spec while
Chunk 3 is in progress) introduces drift risk: two reviewers touching
overlapping interfaces, contract guesses, and inevitable rework. The
total budget is tight (14-18 h); the speedup from parallelism would
not pay for the merge-conflict cost. Single-developer pace is
strictly serial.

### 12.2 Tag plan

- Spec tagged `v0.3.0-step-e-spec` immediately after spec freeze.
- Each chunk pushed as a single commit on `main`.
- After Chunk 5 + smoke validation: tag `v0.3.0-step-e` on HEAD.

### 12.3 E2E test integration — deferred to Phase 2

Step E intentionally does NOT ship an automated end-to-end test that
spans Caddy + the metrics module + the WS endpoint + a browser
checking that particles animate. Reasons:

- A real-Caddy E2E demands either an embedded Caddy spin-up per test
  (slow, leaky goroutines) or a Docker-Compose harness (CI complexity
  Step E does not justify).
- A real-browser E2E demands Playwright or similar — a tooling
  commitment we have explicitly avoided in Phase 1 (Step D Vitest
  debt is already a stated Phase 2 item).
- The MVP verification surface is **the manual smoke session** of
  §12 "Post-merge smoke validation" plus the Go unit tests / benches.
  Together they cover:
  - Counter accuracy + 5xx classification (Go unit tests).
  - Module registration + JSON-config-roundtrip (Chunk 2 tests).
  - WS handshake + payload + slow-client + shutdown (Chunk 3 tests).
  - Frontend pure logic (Chunk 4 Vitest tests).
  - Browser-visible behavior (manual smoke at FPS budget §9.2).

Phase 2 will revisit E2E with the same trade-off framing it gets in
Step D's roadmap entry (Vitest component tests). A future framework
choice may consolidate both debts.

---

## 13. Risks & mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Caddy module API divergence vs current Caddy v2 release | Low | High | Pin Caddy version in go.mod; cite the exact method names with their godoc URLs in Chunk 2 commit message |
| `statusRecorder` breaks WS upgrade through proxied route | Medium | Medium | Forward Hijacker; integration test against a backend that upgrades |
| Particle animation kills CPU on background tabs | Low | Medium | Cap density; pause `requestAnimationFrame` when `document.hidden` (Phase 2) — Step E logs frame drops |
| WS connection leak on server shutdown | Medium | Low | Context-cancelled write loop; tested |
| Counter map grows unbounded if routes leak | Low | Low | `Sync` is called on every Caddy reload with the canonical route list; tested |
| Browser stalls on reconnect storm | Low | Low | Cap backoff at 30 s; documented in §5.5 |

---

## 14. Open questions

None at spec-freeze time. All design decisions resolved per the
brainstorm transcript on 2026-05-18:

- Hook strategy: real Caddy module (§3)
- Error rate: 5xx-only (§1.3)
- WS path: `/api/v1/ws/topology` (§5.1)
- Full-state ticks: yes, every route every tick (§5.2)
- Lib: SVG vanilla + CSS, no D3 (§1.3 + §6)
- Source: hook custom in caddymgr (§2 + §3)
- Registry API: single `Sync` method, not `EnsureRoute`/`DropRoute`
  pair (§4.1)
- Reqs/errs swap atomicity: documented edge case, client clamp
  (§5.2 + §11.8)
- visibilitychange: client actively closes WS (§5.5)
- Drop log: debug-only, rate-limited per subscriber (§5.6)
- Sparklines: detail panel only, not main view (§1.3 + §6.9)
- Sidebar icon: `network` (§6.11)
- Clients column: full-height pillar (§6.2)
- Upstreams collapse: aggregate node, per-route edges (§6.2)
- Chunk sequencing: strict serial 1 → 2 → 3 → 4 → 5 (§12.1)
- Smoke validation: separate `docs/smoke-test-step-e.md`, gates tag

### 14.1 Amend-before-diverge rule

If an implementation chunk uncovers an ambiguity, a missing
requirement, or a real-world constraint that contradicts the spec,
the **mandatory procedure** is:

1. **Stop the chunk** — do not write code that contradicts the spec
   silently.
2. **Open a PR that amends this file** with the proposed change,
   pointing to the section affected and the chunk that surfaced it.
   The PR title prefix is `spec(step-e):` for grep-ability.
3. **Merge the spec amendment first**, then continue the chunk
   against the amended spec.
4. The Step E tag (`v0.3.0-step-e`) is placed on a HEAD where the
   spec file in tree describes the implementation accurately. A spec
   that has diverged from code at tag time blocks the tag.

This is the Step D "amend before diverge" rule applied verbatim to
Step E. Step D's smoke session surfaced and fixed 2 bugs (Bug 1
audit emission, Bug 2 CORS Allow-Credentials) before its tag. The
same pattern is expected here.

---

## 15. References

### External docs

- Caddy v2 module developer docs: https://caddyserver.com/docs/extending-caddy
- gorilla/websocket godoc: https://pkg.go.dev/github.com/gorilla/websocket
- `prefers-reduced-motion`: https://developer.mozilla.org/en-US/docs/Web/CSS/@media/prefers-reduced-motion
- `path.getPointAtLength`: https://developer.mozilla.org/en-US/docs/Web/API/SVGGeometryElement/getPointAtLength

### Repo-internal

- CLAUDE.md Phase 1 scope items 4-5 (the original Step E promise)
- Step D spec: `docs/superpowers/specs/2026-05-17-step-d-auth-design.md`
- Step D smoke: `docs/smoke-test-step-d.md`
- `docs/roadmap.md` — Step E entry + Phase 2 backlog

### Design provenance — brainstorm session 2026-05-18

The 12 design decisions of this spec were resolved during a live
brainstorm session between user and assistant on 2026-05-18. The
transcript is preserved as part of the Claude Code session log at
`/Users/l.ramos/.claude/projects/-Users-l-ramos-Documents-Projets-AreNET/`
(local-only; not committed for privacy).

Key items debated:
- **Decision axes A1-A12** — source of metrics, granularity, retention,
  metrics exposed, WS protocol, connection lifecycle, topology model,
  viz lib, particle animation, route states, interactions, scope vs
  Phase 2.
- **Scope proposals 1-7** — from spartan live-counter table to a
  fully force-directed dynamic graph.
- **Final decision** — Scope 3 (three-column topology + particles,
  req/s + 5xx), SVG vanilla (no D3), real Caddy module hook
  (no wrapper).

For future audit / "why did we decide X?" questions, refer to that
transcript. If a Step E follow-up amends a decision, cite both this
spec section and the new rationale in the amendment PR.
