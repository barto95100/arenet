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
| 2     | **Live data feed (this spec)** | spec |
| 2.1   | Operator actions (drain upstream, reload Caddy, snapshot export) | future |

Phase 2.1 is intentionally deferred so Phase 2 can ship read-only.

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

**Auth**: session cookie. Role: viewer or admin. Connection closed
with code 4401 if unauthenticated, 4403 if role insufficient.

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

## Open questions for CC

Items to clarify when reading the backend before implementing:

1. Does the existing collector already maintain a 60s sliding
   window per route / per upstream? Or only point-in-time
   instantaneous values?
2. Is `fairnessRatio` already tracked, or does the LB layer only
   know "next pick" without keeping per-upstream historical counts?
3. Is `runtime` (Go / Next.js / Python …) stored anywhere, or is it
   purely operator-supplied metadata? If yes, where?
4. Are aliases (multiple hosts -> same route) modelled as
   separate routes or as `aliases[]` on a single route in storage?
   The frontend assumes the latter.
5. What's the existing pattern for WebSocket endpoints in Arenet
   (if any)? Mirror it.

---

## File layout
docs/api/topology.md           this spec
web/frontend/src/routes/topology/
_api.ts                      to-be-added (Phase 2)
_mock-data.ts                kept for dev / fallback
_types.ts                    unchanged — backend payload matches
...

---

*Spec authored 2026-06-03 alongside #R-TOPO-v2 phase 3. See git log
on `web/frontend/src/routes/topology/` for the frontend reference
implementation that consumes this contract.*
