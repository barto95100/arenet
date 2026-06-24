# Topology

The `/topology` page renders your routes as a **live force-directed graph** with real-time traffic particles flowing from clients to upstreams. SvelteKit + [Svelte Flow](https://svelteflow.dev) for the graph, D3.js for the particle physics, WebSocket for the live data feed.

Useful for : at-a-glance verification that every route is healthy, visual debugging of traffic patterns, demos to non-technical stakeholders.

---

## What you see

```
              ┌──────────┐
              │ Internet │
              └────┬─────┘
                   │ (particles flow here = inbound requests)
              ┌────▼─────┐
              │  Caddy   │  ← center hub node
              └────┬─────┘
                   │
       ┌───────────┼───────────┐
       │           │           │
   ┌───▼──┐   ┌───▼──┐   ┌───▼──┐
   │ FQDN │   │ FQDN │   │ FQDN │  ← one node per route's primary host
   │route1│   │route2│   │route3│
   └───┬──┘   └───┬──┘   └───┬──┘
       │          │          │
       │  (aliases cluster inside a "container" if N>0)
       │          │          │
   ┌───▼──┐   ┌───▼──┐   ┌───▼──┐
   │ Pool │   │ Pool │   │ Pool │  ← upstream backends, one cluster per route
   └──────┘   └──────┘   └──────┘
```

Each connection (edge) carries **animated particles** whose density is proportional to req/s. A route serving 100 req/s shows ~10x more particles than a route serving 10 req/s.

---

## Node types

| Node | Meaning |
| ---- | ------- |
| **Caddy Hub** | The central node, sized by total req/s aggregated across all routes |
| **FQDN** | A route's primary host. Color-coded by status (green=healthy, dim=idle, red=upstream down) |
| **Alias** | An alias hostname of a route. Visually clustered inside a "RouteGroup" container with its primary FQDN |
| **Backend Cluster / Upstream** | The route's upstream pool. One node per upstream URL in the pool ; clustered visually as a "pool" |

Idle nodes (no traffic in the last N seconds) appear in a **dimmed state** — surface still rendered, just visually receded. Make sure your light + dark theme tokens are populated (see [Troubleshooting](Troubleshooting) if idle nodes appear dark on light theme — that was a v2.8.4 hotfix).

---

## Live data feed

The page subscribes to a WebSocket at `/api/v1/topology/stream` that pushes per-second updates :

```json
{
  "ts": "2026-06-24T07:30:00Z",
  "routes": [
    { "id": "uuid-1", "host": "vault.example.com", "reqPerSec": 12.3, "upstreamHealthy": [true] },
    { "id": "uuid-2", "host": "ha.example.com", "reqPerSec": 0.5, "upstreamHealthy": [true] },
    ...
  ],
  "hub": { "reqPerSec": 12.8 }
}
```

The D3.js render loop reads the updates and adjusts particle density in real time. ~60fps target.

---

## Interactions

- **Drag a node** : reposition manually ; the force layout re-stabilizes
- **Click a node** : selects + highlights its edges
- **Double-click a RouteGroup container** : collapses/expands the alias cluster (handy when a route has 20+ aliases)
- **Scroll** : zoom in/out
- **Right-click** (planned) : context menu with "Edit route" / "View security events" / "Test connection"

---

## Performance considerations

- Particle physics runs in the browser ; ~50 routes with average 10 req/s each is comfortable on a modern laptop (Chrome / Firefox / Safari)
- WebSocket feed throttled server-side to 1Hz (one update per second) ; sub-second graph interpolation is client-side smoothing
- Mobile : the page renders but interactions (drag, zoom) are clunky on touch. Mobile is officially read-only as of v2.9.x.

---

## When the graph looks wrong

| Symptom | Likely cause | Fix |
| ------- | ------------ | --- |
| All nodes idle even with live traffic | WebSocket connection dropped | Refresh the page ; check browser console for WS errors |
| One FQDN's edges all red | Upstream marked unhealthy by active health checks | Check `/observability/<routeId>` ; verify the upstream is reachable + the HC URI returns expected status |
| Aliases not clustering inside the parent FQDN | Route refresh after recent edit | Refresh the page ; the layout recomputes on next data tick |
| Nodes appear dark on light theme | Theme token missing | Was a v2.8.4 hotfix ; if you see this on a newer version, [open an issue](https://github.com/barto95100/arenet/issues) |
| Particles don't flow on a route I just created | Cold-start : no req/s data yet | Send a few requests to the route ; particles should appear within 5s |

---

## API reference (read-only)

```bash
# Snapshot of the current topology state (no WebSocket)
curl -b /tmp/jar http://localhost:8001/api/v1/topology/snapshot

# Per-host metrics aggregated over the last N seconds
curl -b /tmp/jar "http://localhost:8001/api/v1/metrics/per-host?windowSecs=60"
```

The WebSocket stream is auth-gated via the same session cookie ; not a separate token.

---

## See also

- [Routes](Routes) — where you create the routes that appear on the graph
- [`docs/api/topology.md`](https://github.com/barto95100/arenet/blob/main/docs/api/topology.md) — full WebSocket protocol + JSON shape
- `internal/api/topology/` — backend per-host aggregator
- `web/frontend/src/routes/topology/` — the SvelteKit page + Svelte Flow components
