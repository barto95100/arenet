# Path-pools in the Topology graph Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make v2.23.0's per-path routing visible on the topology graph — a route whose path-rules declare their own upstream pool branches into one BackendCluster per pool (root pool + one per path-pool), each cluster labelled by its prefix.

**Architecture:** Backend: the topology snapshot's `Route` gains a `PathPools []PathPool` field, populated in `buildRoute` from `storage.Route.PathRules` (only rules with a non-empty pool — decision B2), no metric touched. Frontend: `TopologyRoute` mirrors `pathPools?`; `_layout.ts` emits, per route, the existing root cluster PLUS one BackendClusterNode (+ UpstreamNode children + a caddy→cluster edge) per path-pool, reusing the existing node components; the path-pool clusters are stacked like alias nodes. A `pathPrefix?` on the cluster header labels the branch (root cluster unlabelled — no visual regression).

**Tech Stack:** Go 1.25 (topology snapshot builder), SvelteKit/Svelte 5 + TypeScript + @xyflow/svelte (D3-ish layout), Vitest.

## Global Constraints

- **AGPL header** on every new Go/TS file.
- **Structure only (decision C):** v1 draws the branches statically. NO metric change — path-pool clusters do NOT carry live per-branch traffic (that's the backlog in the spec §5). Path-pool UpstreamNodes may show zero/placeholder traffic.
- **Non-regression (omitempty):** `PathPools` is `omitempty`; a route with no path-pool serialises byte-identically to before, and its graph is unchanged. The ROOT cluster gets NO `pathPrefix` → its rendering is strictly unchanged.
- **B2:** only path-rules with `len(pr.Upstreams) > 0` become a PathPool/cluster. Protection-only rules (e.g. `/docs` that inherits) produce nothing in v1.
- **A2:** the prefix is shown in the cluster HEADER, not on the edge.
- **No `-race` needed** — no caddymgr/emission change.
- **Version:** v2.24.0 (minor). No tag until operator go-ahead.

**Key existing anchors (verbatim):**
- Backend: `internal/api/topology/types.go` — `Route` struct (line 55, has `Upstreams []Upstream` @81, `LBPolicy` @82, `ClusterLabel` @119), `Upstream` struct (line 152: ID/URL/Runtime/Status/HealthCheckConfigured/ReqPerSec/P99LatencyMs/FairnessRatio). `internal/api/topology/builder.go` — `buildRoute(r *storage.Route, metrics MetricsView, status StatusLookup) Route` (line 132); the upstream-building loop is 162-203 (weight-split, status gate on `r.HealthCheck.Enabled`, per-upstream ID `fmt.Sprintf("%s-%d", r.ID, i)`).
- `storage.PathRule` (post-v2.23.1): `PathPrefix`, `Upstreams []Upstream`, `LBPolicy string`, `HealthCheck *HealthCheck`, `InsecureSkipVerify bool`.
- Frontend: `web/frontend/src/routes/topology/_types.ts` — `TopologyRoute` (line 43: `upstreams: TopologyUpstream[]` @63, `lbPolicy` @64, `clusterLabel?` @96), `TopologyUpstream` (line 114), `BackendClusterNodeData` (line 214: kind/clusterLabel/runtime/lbPolicy/healthyCount/unhealthyCount/totalCount/hasHealthCheck/warning), `UpstreamNodeData` (line 240).
- `web/frontend/src/routes/topology/_layout.ts` — cluster+child emission loop (432-491), `clusterId = ` + "`cluster-${route.id}`" (436), caddy→cluster edge `e-caddy-cluster-${route.id}` (593); helpers `clusterTotalHeight(n, hasWarning)` (137), `computeStackYsForHeights(heights[])` (670), `deriveClusterLabel(host)` (685), `dominantRuntime(upstreams)` (690), `deriveClusterWarning(route)` (703). Node components `BackendClusterNode.svelte`, `UpstreamNode.svelte` (reused as-is).

---

### Task 1: Backend — `PathPool` type + `buildRoute` populates `PathPools`

**Files:**
- Modify: `internal/api/topology/types.go` (add `PathPool` type + `Route.PathPools` field)
- Modify: `internal/api/topology/builder.go` (populate in `buildRoute`; extract the upstream-conversion helper)
- Test: `internal/api/topology/builder_pathpools_test.go` (new)

**Interfaces:**
- Consumes: `storage.Route.PathRules` (each has `PathPrefix`, `Upstreams`, `LBPolicy`, `InsecureSkipVerify`).
- Produces: `topology.PathPool{ PathPrefix string; Upstreams []Upstream; LBPolicy string; InsecureSkipVerify bool }`; `topology.Route.PathPools []PathPool` json `pathPools,omitempty`.

- [ ] **Step 1: Write the failing tests**

Create `internal/api/topology/builder_pathpools_test.go`:

```go
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package topology

import (
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

func TestBuildRoute_PathPools_OnlyRulesWithOwnPool(t *testing.T) {
	// A route with two path rules: /v1 has its own pool, /docs is
	// protection-only (no pool). Only /v1 becomes a PathPool (B2).
	r := storage.Route{
		ID:        "r1",
		Host:      "api.example.com",
		Upstreams: []storage.Upstream{{URL: "http://route:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		PathRules: []storage.PathRule{
			{
				PathPrefix: "/v1",
				Upstreams:  []storage.Upstream{{URL: "http://v1a:8080", Weight: 1}, {URL: "http://v1b:8080", Weight: 1}},
				LBPolicy:   storage.LBPolicyRoundRobin,
			},
			{
				PathPrefix: "/docs",
				BasicAuth:  &storage.BasicAuthRouteConfig{Username: "u", PasswordHash: "$h"},
			},
		},
	}
	out := buildRoute(&r, nil, nil)
	if len(out.PathPools) != 1 {
		t.Fatalf("expected 1 path pool (only /v1), got %d: %+v", len(out.PathPools), out.PathPools)
	}
	pp := out.PathPools[0]
	if pp.PathPrefix != "/v1" {
		t.Fatalf("path pool prefix = %q, want /v1", pp.PathPrefix)
	}
	if len(pp.Upstreams) != 2 {
		t.Fatalf("path pool upstream count = %d, want 2", len(pp.Upstreams))
	}
	if pp.LBPolicy != storage.LBPolicyRoundRobin {
		t.Fatalf("path pool lb = %q", pp.LBPolicy)
	}
}

func TestBuildRoute_PathPools_CarriesSkipVerify(t *testing.T) {
	r := storage.Route{
		ID:        "r2",
		Host:      "api.example.com",
		Upstreams: []storage.Upstream{{URL: "http://route:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		PathRules: []storage.PathRule{{
			PathPrefix:         "/legacy",
			Upstreams:          []storage.Upstream{{URL: "https://old:8443", Weight: 1}},
			LBPolicy:           storage.LBPolicyRoundRobin,
			InsecureSkipVerify: true,
		}},
	}
	out := buildRoute(&r, nil, nil)
	if len(out.PathPools) != 1 || !out.PathPools[0].InsecureSkipVerify {
		t.Fatalf("path pool should carry InsecureSkipVerify=true: %+v", out.PathPools)
	}
}

func TestBuildRoute_NoPathRules_PathPoolsNil(t *testing.T) {
	// Non-regression: a route with no path rules emits no PathPools
	// (nil → omitempty → absent from JSON, byte-identical to before).
	r := storage.Route{
		ID:        "r3",
		Host:      "plain.example.com",
		Upstreams: []storage.Upstream{{URL: "http://a:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}
	out := buildRoute(&r, nil, nil)
	if out.PathPools != nil {
		t.Fatalf("route without path rules must have nil PathPools, got: %+v", out.PathPools)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/topology/ -run TestBuildRoute_PathPools -v`
Expected: compile error (`PathPools`/`PathPool` don't exist).

- [ ] **Step 3: Add the `PathPool` type + `Route.PathPools` field**

In `internal/api/topology/types.go`, add after the `Upstream` struct:

```go
// PathPool is one per-path routing branch (v2.24.0): a path-rule that
// declares its own upstream pool. The frontend renders it as a separate
// BackendCluster labelled by PathPrefix. Path-rules WITHOUT a pool
// (protection-only, inherit the route pool) are NOT emitted — v1 shows
// only branches that change the backend. Structure only: no live traffic
// fields (per-path metrics are a backlog item).
type PathPool struct {
	PathPrefix         string     `json:"pathPrefix"`
	Upstreams          []Upstream `json:"upstreams"`
	LBPolicy           string     `json:"lbPolicy"`
	InsecureSkipVerify bool       `json:"insecureSkipVerify,omitempty"`
}
```

And add to the `Route` struct (after `Upstreams`/`LBPolicy`):

```go
	// PathPools (v2.24.0) are the per-path routing branches — one per
	// path-rule that declares its own pool. omitempty → a route without
	// per-path pools serialises exactly as before.
	PathPools []PathPool `json:"pathPools,omitempty"`
```

- [ ] **Step 4: Extract the upstream-conversion helper + populate PathPools**

In `internal/api/topology/builder.go`, the upstream-building loop (162-203) converts `storage.Upstream` → `topology.Upstream`. Extract a helper so the path-pool loop reuses it verbatim (DRY). Add:

```go
// buildUpstreams converts a storage upstream pool into topology.Upstream
// rows, applying the weight-split reqPerSec share and the HC-gated status.
// idPrefix namespaces the per-upstream ID (route ID for the root pool,
// "routeID-path-N" for a path pool). agg is the route-level aggregate the
// share is computed against; healthCheckEnabled gates status lookup.
func buildUpstreams(pool []storage.Upstream, idPrefix string, agg Aggregate, hcEnabled bool, status StatusLookup) []Upstream {
	totalWeight := 0
	for _, u := range pool {
		w := u.Weight
		if w <= 0 {
			w = 1
		}
		totalWeight += w
	}
	if totalWeight == 0 {
		return []Upstream{}
	}
	out := make([]Upstream, 0, len(pool))
	for i, u := range pool {
		w := u.Weight
		if w <= 0 {
			w = 1
		}
		share := float64(w) / float64(totalWeight)
		upstreamStatus := StatusUnknown
		if hcEnabled {
			if s := status.Status(u.URL); s != "" {
				upstreamStatus = s
			}
		}
		out = append(out, Upstream{
			ID:                    fmt.Sprintf("%s-%d", idPrefix, i),
			URL:                   u.URL,
			Status:                upstreamStatus,
			HealthCheckConfigured: hcEnabled,
			ReqPerSec:             agg.ReqPerSec * share,
			P99LatencyMs:          agg.P95LatencyMs,
			FairnessRatio:         share,
		})
	}
	return out
}
```

Replace the inline root-pool loop (162-203) with `out.Upstreams = buildUpstreams(r.Upstreams, r.ID, agg, r.HealthCheck.Enabled, status)` (keeping the empty-pool defensive `return out` behaviour — `buildUpstreams` already returns `[]Upstream{}` for a zero-weight pool; ensure the root case still returns the route early if you want to preserve the exact prior shape, OR just assign and continue since an empty slice is equivalent for downstream). Then after the root pool, add the path-pool loop:

```go
	// Path pools (v2.24.0): one branch per path-rule that declares its own
	// pool (B2 — protection-only rules are skipped). Structure only; the
	// path pool's upstreams reuse the same conversion but there is no
	// per-path metric today, so agg is the route aggregate (the frontend
	// treats path-pool clusters as structural, not traffic-animated).
	for pi, pr := range r.PathRules {
		if len(pr.Upstreams) == 0 {
			continue
		}
		out.PathPools = append(out.PathPools, PathPool{
			PathPrefix:         pr.PathPrefix,
			Upstreams:          buildUpstreams(pr.Upstreams, fmt.Sprintf("%s-path-%d", r.ID, pi), agg, false, status),
			LBPolicy:           pr.LBPolicy,
			InsecureSkipVerify: pr.InsecureSkipVerify,
		})
	}
```

(Note `hcEnabled=false` for path pools — per-path health checks exist in storage but the topology status probe is route-scoped today; surfacing StatusUnknown is honest. A path-pool HC-status wire is a future refinement, out of scope.)

- [ ] **Step 5: Run to verify they pass**

Run: `go test ./internal/api/topology/ -run TestBuildRoute_PathPools -v`
Expected: PASS (all 3).

- [ ] **Step 6: Full topology package suite + vet (regression on existing snapshot tests)**

Run: `go test ./internal/api/topology/ && go test ./internal/api/ && go vet ./internal/api/...`
Expected: PASS — the existing snapshot golden/shape tests must still pass (the refactor into `buildUpstreams` must be behaviour-preserving for the root pool; if an existing test asserts the exact root-pool shape, it guards this).

- [ ] **Step 7: Commit**

```bash
git add internal/api/topology/types.go internal/api/topology/builder.go internal/api/topology/builder_pathpools_test.go
git commit -m "feat(topology): emit per-path pools in the snapshot Route (structure)"
```

---

### Task 2: Frontend types — `TopologyPathPool` + `TopologyRoute.pathPools` + cluster header prefix

**Files:**
- Modify: `web/frontend/src/routes/topology/_types.ts`
- Test: (covered by Task 3's layout tests — no standalone type test)

**Interfaces:**
- Consumes: the wire field `pathPools` (Task 1).
- Produces: `TopologyPathPool` interface; `TopologyRoute.pathPools?`; `BackendClusterNodeData.pathPrefix?`.

- [ ] **Step 1: Add the TS types**

In `web/frontend/src/routes/topology/_types.ts`:

Add near `TopologyUpstream`:
```ts
/** One per-path routing branch (v2.24.0): a path-rule with its own pool,
 *  rendered as a separate backend cluster labelled by pathPrefix. */
export interface TopologyPathPool {
	pathPrefix: string;
	upstreams: TopologyUpstream[];
	lbPolicy: LBPolicy;
	insecureSkipVerify?: boolean;
}
```

Add to `TopologyRoute` (after `upstreams`/`lbPolicy`):
```ts
	/** Per-path routing branches (v2.24.0). Absent/empty = no per-path pool. */
	pathPools?: TopologyPathPool[];
```

Add to `BackendClusterNodeData` (as an optional field):
```ts
	/** When set, this cluster is a per-path branch and the header shows the
	 *  prefix. Absent on the route's root cluster (unchanged rendering). */
	pathPrefix?: string;
```

- [ ] **Step 2: svelte-check**

Run: `cd web/frontend && npx svelte-check --threshold error`
Expected: 0 errors (the field is optional and additive; nothing consumes it yet).

- [ ] **Step 3: Commit**

```bash
git add web/frontend/src/routes/topology/_types.ts
git commit -m "feat(topology): TopologyPathPool type + pathPools on route + cluster pathPrefix"
```

---

### Task 3: Frontend layout — emit one cluster per path-pool + header prefix (LOAD-BEARING)

**Files:**
- Modify: `web/frontend/src/routes/topology/_layout.ts`
- Modify: `web/frontend/src/routes/topology/_components/nodes/BackendClusterNode.svelte` (render the prefix in the header when present)
- Test: `web/frontend/src/routes/topology/_layout.test.ts` (extend)

**Interfaces:**
- Consumes: `TopologyRoute.pathPools` + `BackendClusterNodeData.pathPrefix` (Task 2).
- Produces: for each route, the existing root cluster PLUS one `backend-cluster` node (+ `upstream` children + a caddy→cluster edge) per path-pool, stacked without overlap; the path-cluster header shows the prefix.

**This is the load-bearing task (the spec flagged the D3/xyflow layout). It gets a DEDICATED review.** The core challenge: today `clusterYs` is indexed 1:1 by route (`routes.map(...)` → `clusterYs[i]`). Path-pools break that 1:1 — a route now contributes 1 + N clusters. The stacking must flatten to a per-CLUSTER list (root + path clusters across all routes) whose heights feed `computeStackYsForHeights`, while keeping each cluster's caddy→cluster edge and each cluster's upstream children correctly parented.

- [ ] **Step 1: Write the failing tests**

Extend `web/frontend/src/routes/topology/_layout.test.ts` (match its existing harness — it builds a `TopologyRoute[]` and asserts on the returned nodes/edges):

```ts
it('emits one backend cluster per path-pool plus the root cluster', () => {
	const routes = [{
		id: 'r1', host: 'api.example.com', lbPolicy: 'round_robin',
		upstreams: [{ id: 'r1-0', url: 'http://route:8080', status: 'unknown', reqPerSec: 0, /* ...min fields */ }],
		pathPools: [
			{ pathPrefix: '/v1', lbPolicy: 'round_robin', upstreams: [{ id: 'r1-path-0-0', url: 'http://v1:8080', status: 'unknown', reqPerSec: 0 }] },
			{ pathPrefix: '/legacy', lbPolicy: 'round_robin', upstreams: [{ id: 'r1-path-1-0', url: 'https://old:8443', status: 'unknown', reqPerSec: 0 }] },
		],
	}];
	const { nodes } = buildLayout(routes as any); // match the real entry-point name
	const clusters = nodes.filter((n) => n.type === 'backend-cluster');
	expect(clusters.length).toBe(3); // root + /v1 + /legacy
	const labels = clusters.map((c) => (c.data as any).pathPrefix);
	expect(labels).toContain('/v1');
	expect(labels).toContain('/legacy');
	// root cluster has no pathPrefix
	expect(labels.filter((l) => l === undefined).length).toBe(1);
});

it('a route with no path-pools emits exactly one cluster (non-regression)', () => {
	const routes = [{
		id: 'r2', host: 'plain.example.com', lbPolicy: 'round_robin',
		upstreams: [{ id: 'r2-0', url: 'http://a:8080', status: 'unknown', reqPerSec: 0 }],
	}];
	const { nodes } = buildLayout(routes as any);
	expect(nodes.filter((n) => n.type === 'backend-cluster').length).toBe(1);
});

it('each path-pool cluster has a caddy->cluster edge and parented upstream children', () => {
	const routes = [{
		id: 'r1', host: 'api.example.com', lbPolicy: 'round_robin',
		upstreams: [{ id: 'r1-0', url: 'http://route:8080', status: 'unknown', reqPerSec: 0 }],
		pathPools: [{ pathPrefix: '/v1', lbPolicy: 'round_robin', upstreams: [{ id: 'r1-path-0-0', url: 'http://v1:8080', status: 'unknown', reqPerSec: 0 }] }],
	}];
	const { nodes, edges } = buildLayout(routes as any);
	// the /v1 cluster's child upstream is parented to it
	const v1Cluster = nodes.find((n) => n.type === 'backend-cluster' && (n.data as any).pathPrefix === '/v1');
	expect(v1Cluster).toBeDefined();
	const child = nodes.find((n) => n.type === 'upstream' && n.parentId === v1Cluster!.id);
	expect(child).toBeDefined();
	// a caddy->cluster edge targets the /v1 cluster
	expect(edges.some((e) => e.target === v1Cluster!.id && e.source === 'caddy-hub')).toBe(true);
});
```

READ the existing `_layout.test.ts` first: match the real entry-point function name (`buildLayout` / `computeLayout` / default export), the minimal `TopologyUpstream` fields the harness requires, and the returned shape (`{ nodes, edges }`).

- [ ] **Step 2: Run to verify they fail**

Run: `cd web/frontend && npx vitest run src/routes/topology/_layout.test.ts`
Expected: FAIL (only 1 cluster per route today; no pathPrefix).

- [ ] **Step 3: Refactor the cluster-emission to a per-cluster list**

In `_layout.ts`, replace the route-indexed cluster loop (432-491) with a flattened per-cluster model. Build an array of "cluster specs" across all routes:

```ts
type ClusterSpec = {
	routeId: string;
	clusterId: string;          // `cluster-${route.id}` for root, `cluster-${route.id}-path-${k}` for path pools
	pathPrefix?: string;        // undefined for root cluster
	upstreams: TopologyUpstream[];
	lbPolicy: LBPolicy;
	hasHealthCheck: boolean;
	warning?: string;
};

const clusterSpecs: ClusterSpec[] = [];
routes.forEach((route) => {
	clusterSpecs.push({
		routeId: route.id,
		clusterId: `cluster-${route.id}`,
		upstreams: route.upstreams,
		lbPolicy: route.lbPolicy,
		hasHealthCheck: route.hasHealthCheck,
		warning: deriveClusterWarning(route),
	});
	(route.pathPools ?? []).forEach((pp, k) => {
		clusterSpecs.push({
			routeId: route.id,
			clusterId: `cluster-${route.id}-path-${k}`,
			pathPrefix: pp.pathPrefix,
			upstreams: pp.upstreams,
			lbPolicy: pp.lbPolicy,
			hasHealthCheck: false, // structural; no per-path HC status in v1
			// path-pool clusters get no warning derivation in v1 (no metrics)
		});
	});
});
```

Then drive the existing height/stack machinery off `clusterSpecs` instead of `routes`:

```ts
const clusterHeights = clusterSpecs.map((c) =>
	clusterTotalHeight(c.upstreams.length, c.warning !== undefined),
);
const clusterYs = computeStackYsForHeights(clusterHeights);
clusterSpecs.forEach((spec, i) => {
	const healthyCount = spec.upstreams.filter((u) => u.status === 'healthy').length;
	const unhealthyCount = spec.upstreams.filter((u) => u.status === 'unhealthy').length;
	const clusterData: BackendClusterNodeData = {
		kind: 'backend-cluster',
		clusterLabel: spec.pathPrefix
			? spec.pathPrefix
			: (routeById(spec.routeId).clusterLabel ?? deriveClusterLabel(routeById(spec.routeId).host)),
		pathPrefix: spec.pathPrefix,
		runtime: dominantRuntime(spec.upstreams),
		lbPolicy: spec.lbPolicy,
		healthyCount,
		unhealthyCount,
		totalCount: spec.upstreams.length,
		hasHealthCheck: spec.hasHealthCheck,
		warning: spec.warning,
	};
	nodes.push({ id: spec.clusterId, type: 'backend-cluster', position: { x: COL_X.BACKEND, y: clusterYs[i] }, width: CLUSTER_WIDTH, height: clusterHeights[i], data: clusterData });
	spec.upstreams.forEach((upstream, ui) => {
		const childY = CLUSTER_PADDING_TOP + ui * (UPSTREAM_HEIGHT + UPSTREAM_GAP_Y);
		// ...same childData construction as today (formatUpstreamUrl, loadRatio)...
		nodes.push({ id: `upstream-${spec.routeId}-${upstream.id}`, type: 'upstream', position: { x: UPSTREAM_X_INSET, y: childY }, width: UPSTREAM_INNER_WIDTH, height: UPSTREAM_HEIGHT, parentId: spec.clusterId, extent: 'parent', draggable: false, selectable: false, data: childData });
	});
});
```

(Provide a small `routeById(id)` lookup, or capture the route in the spec. Keep `deriveClusterLabel`/`dominantRuntime` usage identical for the root cluster so its rendering is unchanged.) Preserve the `globalMaxReqPerSec` loadRatio math for children.

- [ ] **Step 4: Emit a caddy→cluster edge per cluster spec**

Find the `e-caddy-cluster-${route.id}` edge emission (~line 593) and drive it off `clusterSpecs` too: one `caddy-hub → spec.clusterId` edge per spec. Root cluster keeps its current edge id (`e-caddy-cluster-${routeId}`); path clusters use `e-caddy-cluster-${routeId}-path-${k}` (unique ids). For v1 (structure only) a path-cluster edge can carry zero/nominal flow (no per-path traffic) — match the existing edge helper's required fields; do NOT fabricate traffic.

- [ ] **Step 5: Render the prefix in the cluster header**

In `BackendClusterNode.svelte`, when `data.pathPrefix` is set, show it in the header (e.g. a small monospace chip before/after the existing `clusterLabel`). When absent, render exactly as today (no visual change to root clusters). Add a `data-testid` like `cluster-path-prefix` for the test.

- [ ] **Step 6: Run tests to verify they pass**

Run: `npx vitest run src/routes/topology/_layout.test.ts`
Expected: PASS (existing + 3 new).

- [ ] **Step 7: svelte-check + full frontend suite**

Run: `npx svelte-check --threshold error && npx vitest run`
Expected: 0 svelte-check errors, full suite green.

- [ ] **Step 8: Commit**

```bash
git add web/frontend/src/routes/topology/_layout.ts web/frontend/src/routes/topology/_components/nodes/BackendClusterNode.svelte web/frontend/src/routes/topology/_layout.test.ts
git commit -m "feat(topology): render one cluster per path-pool, stacked, with a prefix header"
```

---

### Task 4: Build + visual check + smoke note

**Files:**
- Test: full build + suites
- Modify: `docs/smoke-test-path-upstream.md` (add a topology-visibility note) — optional

- [ ] **Step 1: Full frontend build**

Run: `cd web/frontend && npm run build`
Expected: succeeds (adapter-static writes build/).

- [ ] **Step 2: Backend + frontend full suites**

Run from repo root: `go test ./...`
Then from web/frontend: `npx vitest run && npx svelte-check --threshold error`
Expected: all green.

- [ ] **Step 3: Note the topology visibility in the smoke doc**

Append to `docs/smoke-test-path-upstream.md`: a note that (v2.24.0) a route's per-path pools now appear as separate labelled clusters in the Topology graph; a path-rule without its own pool (protection-only) does not add a cluster.

- [ ] **Step 4: Commit**

```bash
git add docs/smoke-test-path-upstream.md
git commit -m "docs(topology): note per-path pools appear as clusters in the graph (v2.24.0)"
```

---

## Post-plan (controller, not a task)
- Task 3 (layout) gets a DEDICATED review (D3/xyflow stacking correctness + non-regression of routes without path-pools + root-cluster rendering unchanged).
- Inline review on Tasks 1, 2, 4.
- **Visual check (mandatory — visual feature):** dogfood on `testpath.worldgeekwide.fr` (has `/v1`, `/legacy` with pools + `/docs` protection-only) → open Topology, confirm 3 clusters (root + /v1 + /legacy), `/docs` adds none, layout readable / no overlap.
- ONE final whole-branch review before PR.
- **Backlog (spec §5):** live per-branch traffic — needs a per-(route,path) metric counter in the hot-path. Its own cycle.
- Version v2.24.0 — tag only after operator go-ahead.

## Self-Review notes
- Spec coverage: C structure-only (Task 1 no metric fields on PathPool; path clusters structural) ✓; A one cluster per branch (Task 3 clusterSpecs root + path) ✓; A2 prefix in header (Task 2 `pathPrefix?` + Task 3 step 5) ✓; B2 only pooled rules (Task 1 `len(pr.Upstreams)==0` skip + test) ✓; Q4 enrich TopologyRoute (Task 1 field from storage.Route.PathRules) ✓; non-regression omitempty + root cluster unchanged (Task 1 nil test, Task 3 non-regression test + step 5 "absent → unchanged") ✓.
- Type consistency: `PathPool{PathPrefix,Upstreams,LBPolicy,InsecureSkipVerify}` (Go) mirrors `TopologyPathPool{pathPrefix,upstreams,lbPolicy,insecureSkipVerify}` (TS); `buildUpstreams(pool, idPrefix, agg, hcEnabled, status)` used for both root and path pools; cluster ids `cluster-${route.id}` (root) / `cluster-${route.id}-path-${k}` (path) consistent between Task 3 steps 3 and 4.
- Open verifications flagged for the implementer: the exact `_layout.test.ts` entry-point name + minimal upstream fields (Task 3 step 1), whether an existing snapshot test asserts the exact root-pool shape to guard the `buildUpstreams` refactor (Task 1 step 6), and the BackendClusterNode header markup (Task 3 step 5).
