# Topology API — Live Data Feed (Phase 2)

Spec for the backend endpoints that drive the Arenet topology
canvas at `/topology`. Authored after #R-TOPO-v2 phases 1–3 shipped
the read-only frontend (currently consuming `_mock-data.ts`).

This document is the contract Claude Code should implement to
replace the mock import with a live data feed.

---

## Status

| Phase | Scope | Status |
|-------|-------|--------|
| 1     | Frontend canvas (Svelte Flow + custom nodes/edges + sidebar) | shipped |
| 2     | Live data feed (this spec) — Stage A | **shipped** |
| 2 / B | Per-upstream measured instrumentation (replaces weight-split estimates) | backlog (#R-TOPO-upstream-metrics) |
| 2.1   | Operator actions (drain upstream, reload Caddy, snapshot export) | future |

Phase 2.1 is intentionally deferred so Phase 2 can ship read-only.
Stage B is deferred so Phase 2 can ship without backend-instrumentation
churn — see "Stage A limitations" below for the exact contract drift.

---

## Frontend domain model (recap)

The frontend already defines its own domain types in
`web/frontend/src/routes/topology/_types.ts`. The backend payload
should be assignable to these as-is so the frontend code becomes:

```typescript
// Phase 1 (current):
import { mockRoutes } from './_mock-data';
let routes = mockRoutes;

// Phase 2 (target):
const res = await fetch('/api/v1/topology/snapshot');
const { routes } = await res.json();
```

Frontend types (reference):

```typescript
interface TopologyRoute {
  id: string;
  host: string;
  aliases?: string[];
  upstreams: TopologyUpstream[];
  lbPolicy: 'round_robin' | 'weighted_round_robin' | 'least_conn'
          | 'ip_hash' | 'random' | 'first';
  reqPerSec: number;
  p99LatencyMs: number;
  errorRate5xx: number;    // 0-100
  tlsEnabled: boolean;
  wafLevel?: 'off' | 'detect' | 'block';
  rateLimited?: boolean;
  mtlsRequired?: boolean;
  clusterLabel?: string;   // optional override; defaults to host basename
}

interface TopologyUpstream {
  id: string;
  url: string;             // "10.0.4.12:8080"
  runtime?: string;        // "Go", "Next.js 15" — operator-visible metadata
  status: 'healthy' | 'unhealthy' | 'draining' | 'unknown';
  reqPerSec: number;
  p99LatencyMs: number;
  fairnessRatio: number;   // 0-1; share of cluster traffic this instance got
}
```

---

## Endpoints

### 1. `GET /api/v1/topology/snapshot`

Returns the current full snapshot. Used on initial page mount, and
as a fallback after a WebSocket reconnect.

**Auth**: session cookie (`arenet_session`). Role: viewer or admin.

**Response** (200):

```json
{
  "generatedAt": "2026-06-03T12:00:00.123Z",
  "routes": [
    {
      "id": "api",
      "host": "api.arenet.fr",
      "aliases": ["admin.arenet.fr"],
      "lbPolicy": "round_robin",
      "reqPerSec": 624,
      "p99LatencyMs": 38,
      "errorRate5xx": 0,
      "tlsEnabled": true,
      "wafLevel": "block",
      "rateLimited": true,
      "upstreams": [
        {
          "id": "api-v2-01",
          "url": "10.0.4.12:8080",
          "runtime": "Go",
          "status": "healthy",
          "reqPerSec": 220,
          "p99LatencyMs": 38,
          "fairnessRatio": 0.35
        }
      ]
    }
  ]
}
```

**Empty case** (no routes configured): `routes: []`, valid response.

---

### 2. `GET /api/v1/topology/stream` (WebSocket upgrade)

Pushes the latest snapshot to the client every **2 seconds**.

**Auth**: session cookie. Role: viewer or admin. Authentication is
enforced by the chi router's HardAuthMiddleware BEFORE the WebSocket
upgrade — an unauthenticated dial receives HTTP `401 Unauthorized`
and a session that's been locked (idle past `SessionIdleTimeout`)
receives HTTP `403 Forbidden`, both as regular HTTP responses. The
WebSocket upgrade NEVER happens on auth failure. (Earlier drafts of
this doc mentioned in-WS close codes `4401`/`4403`; that was
aspirational. The shipped pattern matches the existing
`/api/v1/ws/topology` endpoint.)

**Message format**: identical to the `GET /snapshot` payload — full
snapshot per tick (Design A). No diff/delta protocol in Phase 2.

```json
{
  "generatedAt": "2026-06-03T12:00:02.456Z",
  "routes": [ ... ]
}
```

**Why full snapshot every tick (not diffs)?**
- Simpler server (no per-client state)
- Trivial client reconnect (no resync logic needed)
- Bandwidth at 2s tick + ~10 routes ≈ 2–5 KB/s gzipped — negligible
  for an admin UI on a local network
- Diff protocol can be retro-fitted later if needed (transparent to
  the UI as long as the resulting state is the same)

**Why 2s tick?**
- 1s: too jumpy for human reading of rates
- 5s: feels stale when actively watching during incident
- 2s: standard for ops dashboards, smooth without being noisy

If 2s turns out problematic, this should be configurable via env:
`ARENET_TOPOLOGY_TICK_MS` (default 2000).

**Reconnect**: client closes/reopens; server sends current snapshot
immediately on connection, then continues normal ticks.

---

## Stage A limitations (shipped 2026-06-03)

Phase 2 ships in two stages so the read-only contract can land
without blocking on backend instrumentation changes:

- **Stage A** (this iteration) — wire types + endpoints land with
  best-effort synthesised values where the metrics pipeline
  doesn't expose them yet. Frontend can consume the payload
  directly and renders correctly; values reflect operator INTENT
  (configured weights) more than measured reality where noted.
- **Stage B** (backlog `#R-TOPO-upstream-metrics`) — replaces the
  synthesised fields with real per-upstream measurements.

### Synthesised / approximate fields

| Wire field | Stage A behaviour | Stage B target |
|---|---|---|
| `routes[].p99LatencyMs` | **p95 substitute** — the existing metrics histogram already drains p95 per tick (Step L). True window p95 is not aggregated across the 60 slots (aggregating per-tick percentiles is statistically dubious); the LATEST slot's p95 is reported. | p99 from the histogram + true window aggregation |
| `routes[].errorRate5xx` | Count-weighted mean across the 60-slot window. `sum(errs) / max(sum(reqs), 1) × 100`. Correct shape; this is not synthesised. | unchanged |
| `routes[].reqPerSec` | Arithmetic mean across populated slots (sum / count, not sum / 60). Real measurement. | unchanged |
| `routes[].rateLimited` | Always `false` — storage doesn't model a per-route rate-limit flag. The route-level rate-limit handler is currently global. | per-route bit when storage models it |
| `routes[].mtlsRequired` | Always `false` — storage doesn't model mTLS yet. | per-route bit when storage models it |
| `upstreams[].reqPerSec` | **Synthesised** — route reqPerSec × (upstream weight / sum of weights). Reflects configured weight share, NOT measured per-upstream traffic. Caddy's LB selector doesn't currently surface per-pick counts back to the metrics middleware. | real per-upstream counter (custom selector hook or `/reverse_proxy/upstreams` `num_requests` polling) |
| `upstreams[].p99LatencyMs` | Echoes the route-level p95 to every upstream of that route. No per-upstream latency histogram exists today. | per-upstream histogram |
| `upstreams[].fairnessRatio` | Configured weight share (sums to ≈ 1.0 by construction). | derived from real per-upstream counts |
| `upstreams[].status` | **Real** — `/reverse_proxy/upstreams` Caddy admin endpoint, polled every 1 s by a background refresher. `Fails > 0` → `unhealthy`; address absent → `unknown`. `draining` reserved for Phase 2.1. | unchanged |
| `upstreams[].runtime` | Always omitted (no source — operator metadata not modelled). | new storage field when there's a tagging UI |

### Window aggregation note

The 60-slot ring lives entirely server-side in
`internal/api/topology.SlidingWindow`. The source metrics ticker
stays at 1 Hz (`metrics.TickInterval`); the stream handler pushes
every source tick into the ring, then emits a frame every Nth tick
where `N = ceil(ARENET_TOPOLOGY_TICK_MS / 1000)`. Non-multiple
`tickMs` values are snapped UP at handler-init time so the
operator's "slower emit" intent is respected.

The window's per-tick `p95LatencyMs` push currently receives `0`
from the broadcaster fan-out path (the wire shape
`metrics.RouteSnapshot` drops `LatencyP95Ms` for backward compat
with the Step E contract). Stage B will wire a
`metrics.TickConsumer` fanout to feed real p95 into the ring.

### What this means for the frontend

The frontend doesn't need to know any of this — the wire shape
matches the `TopologyRoute` / `TopologyUpstream` interfaces and
the canvas renders correctly. The values just **reflect intent**
where they reflect intent (configured weights) and **reflect
measurement** where they reflect measurement (route-level
reqPerSec, errorRate5xx, upstream health). The visual story is
faithful enough for the operator to spot real problems (a SPOF
shows as 1.0 fairness, a 5xx incident shows as a bad-tier edge);
Stage B sharpens the numerical fidelity without changing the
wire contract.

---

## Source of metrics — investigation needed

The previous (now-removed) `/topology` page was driven by some kind
of live data collection — curl loops to the admin port triggered
visible particle animations, and stopping the curl loop stopped the
animations. The frontend client lived at
`web/frontend/src/lib/api/topology.ts` (also removed). The backend
endpoint serving that client likely still exists in the Go code.

**Action for CC**: locate the existing collector before designing
anything new. Reusing the collector with a different response shape
is preferred over a fresh instrumentation pass.

**Per-field source mapping** (to validate):

| Field | Likely source |
|-------|---------------|
| `host`, `aliases`, `lbPolicy`, `tlsEnabled`, `wafLevel`, `rateLimited`, `mtlsRequired`, `clusterLabel`, `upstreams[].url`, `runtime` | `storage.Route` / `storage.Upstream` (BoltDB config) |
| `upstreams[].status` | Active health-check state (existing) |
| `*.reqPerSec` (route-level and per-upstream) | Caddy/Arenet request counter over a 60s sliding window |
| `*.p99LatencyMs` | Latency histogram (60s window). If exact p99 is expensive, p95 is acceptable as a substitute — but be consistent. |
| `errorRate5xx` | Count of 5xx responses / total responses (60s window), as a 0–100 percentage |
| `fairnessRatio` | Per-upstream request count / cluster total (60s window). The 5 ratios within a cluster should sum to ≈ 1.0 |

**Window**: 60s sliding average matches the legend note in the UI
("L'épaisseur est calculée sur la moyenne glissante des 60 dernières
secondes"). If the existing collector uses a different window, the
UI legend can be adapted in the same PR.

**Cardinality**: routes count is typically 5–50 in practice. Going
much higher is uncommon for a homelab reverse proxy, but the design
should not collapse at 200 routes.

---

## Auth & permissions

- Both endpoints require an authenticated session (same as the
  rest of the admin API).
- Viewer role: full read access (`GET /snapshot`, WS `stream`).
- Admin role: same + Phase 2.1 mutating endpoints later.
- No mutation in Phase 2; no rate limiting needed.

---

## Frontend integration plan

After this spec lands as backend, the frontend changes will be
small and self-contained in `web/frontend/src/routes/topology/`:

1. New module `_api.ts` exporting:
   - `fetchSnapshot(): Promise<{ routes: TopologyRoute[] }>`
   - `connectLiveStream(onTick: (routes: TopologyRoute[]) => void): () => void`
     (returns a close function)
2. `+page.svelte`:
   - Replace `import { mockRoutes } from './_mock-data'`
     with `import { fetchSnapshot, connectLiveStream } from './_api'`
   - Loading state while initial fetch resolves
   - Error state if fetch fails (with retry)
   - On mount: fetch snapshot → build graph; then open WS → update
     graph on each tick
   - On unmount: close WS
3. Keep `_mock-data.ts` around for dev / Storybook (could be
   gated behind `import.meta.env.DEV` later).

---

## Phase 2.1 (future, not in scope)

These will share the same auth and the same spec process:

- `POST /api/v1/topology/upstreams/{upstreamId}/drain` — mark
  upstream draining (no new requests, existing complete). Wires
  the "Drainer un upstream…" sidebar button.
- `POST /api/v1/topology/reload` — trigger Caddy config reload.
  Wires the "Recharger la config Caddy" sidebar button.
- `GET /api/v1/topology/snapshot?format=download` — same payload
  but with `Content-Disposition: attachment` for the "Snapshot
  topology (JSON)" sidebar button. Could also be a client-side
  blob download, no backend change needed.

---

## Open questions — resolved during Stage A implementation

1. **60 s sliding window already maintained server-side?** No.
   The existing metrics collector is per-1 s-tick deltas, per
   route only. Stage A added the
   `internal/api/topology.SlidingWindow` (60-slot ring buffer,
   server-side, fed by the broadcaster fan-out).
2. **`fairnessRatio` tracked?** No. Caddy's LB selector
   doesn't surface per-pick counts back to our metrics
   middleware. Stage A synthesises it from configured weight
   shares; Stage B (`#R-TOPO-upstream-metrics`) will replace
   this with real per-upstream counts (either a custom selector
   hook or `/reverse_proxy/upstreams` `num_requests` polling).
3. **`runtime` stored?** No. Pure operator metadata, no source
   in storage. Stage A omits the field; Stage B can add a
   per-upstream tagging surface if/when operators ask for it.
4. **Aliases modelling?** `aliases[]` on a single route is
   correct. `storage.Route.Aliases []string` carries them; the
   wire shape exposes them as `routes[].aliases`.
5. **Existing WS pattern?** `/api/v1/ws/topology` — gorilla
   upgrade + Broadcaster fan-out + buffered subscriber channels
   + slow-client drop + hard-auth-before-upgrade. Stage A's
   `StreamHandler` mirrors this exactly.

---

## File layout
docs/api/topology.md           this spec
web/frontend/src/routes/topology/
_api.ts                      shipped (Phase 2)
_mock-data.ts                kept for dev / fallback
_types.ts                    unchanged — backend payload matches
...

---

*Spec authored 2026-06-03 alongside #R-TOPO-v2 phase 3. See git log
on `web/frontend/src/routes/topology/` for the frontend reference
implementation that consumes this contract.*
