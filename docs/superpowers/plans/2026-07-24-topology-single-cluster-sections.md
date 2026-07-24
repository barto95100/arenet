# Topology: paths in ONE cluster with sections Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render a route's path-pools INSIDE a single backend cluster (like a multi-upstream pool), grouped into per-prefix sections (root upstreams, then `── /v1 ──` + its upstreams, etc.), with one hub→section line per pool. Replaces the v2.24.0 separate-clusters-per-path and v2.24.1 dashed-stacked-clusters rendering.

**Architecture:** Frontend-only (backend `topology.Route.PathPools` from v2.24.0 is kept as-is). Collapse the current `clusterSpecs` (root + N path clusters per route) back to ONE cluster per route. Its children become: the root pool's UpstreamNodes, then for each path-pool a new `PathSectionHeaderNode` (a light child node showing the prefix) followed by that pool's UpstreamNodes. Cluster height and child Y become a running cursor over `[root upstreams] + Σ(header + path upstreams)`. Edges: the root pool keeps its existing per-upstream fan-out unchanged; each path-pool gets ONE structural (dashed) `caddy-hub → first-upstream-of-section` edge (reusing v2.24.1's `structural` flag). Remove the v2.24.1 variable-gap stacker + gap constants + cluster `pathPrefix`; restore the uniform `computeStackYsForHeights` for the (now one-per-route) clusters.

**Tech Stack:** SvelteKit/Svelte 5 + TypeScript + @xyflow/svelte, Vitest.

## Global Constraints

- **AGPL header** on the new node component + any new file.
- **Non-regression (THE gate):** a route with NO path pools must render EXACTLY as before v2.24.0 — one cluster, its upstream children, its per-upstream fan-out edges, uniform `computeStackYsForHeights` stacking. No section headers, no structural edges, no `pathPrefix` on the cluster. A test asserts one cluster + zero section-headers + unchanged edge count for a paths-less route.
- **Structure only:** no metric change; path-pool upstreams carry 0 traffic; the hub→section path edges are `structural` (dashed, no particles).
- **Q2=B:** the ROOT pool has NO section header; sections (with headers) are only the path-pools, listed BELOW the root upstreams.
- **Clean removal:** after the rework, `grep` for `computeStackYsWithGaps`, `INTRA_ROUTE_GAP`, `INTER_ROUTE_GAP`, and `pathPrefix` on `BackendClusterNodeData` returns ZERO references (all dead).
- **v2.25.0** (minor). No tag until re-dogfood + operator go-ahead.

**Key existing anchors (verbatim, current post-v2.24.1 state):**
- `web/frontend/src/routes/topology/_layout.ts`:
  - Gap constants `INTER_ROUTE_GAP = 150` (64) + `INTRA_ROUTE_GAP = 24` (65) — REMOVE.
  - `type ClusterSpec` (187, has `route`, `clusterId`, `edgeIdSuffix`, `pathPrefix?`, `upstreams`, `lbPolicy`, `hasHealthCheck`, `warning?`, `isRoot`) — REWORK to a per-ROUTE model (no more path-cluster specs).
  - `clusterSpecs` build (477-503): root push (479) + path push (490) — REPLACE with one-cluster-per-route + a sections list.
  - Emission loop (516-577): cluster node + upstream children — REWORK to emit root upstreams + per-section (header + upstreams).
  - Edge loop (691-704): path-cluster gets one structural edge / root fans out — REWORK to fan-out for root (unchanged) + one structural hub→first-upstream-of-section per path.
  - `computeStackYsWithGaps` (813) — REMOVE. `computeStackYsForHeights` (789) — KEEP (still used by col-0 @281 AND now again by the one-per-route cluster stack).
  - Layout constants: `CLUSTER_WIDTH=300` (127), `CLUSTER_PADDING_TOP` (129), `CLUSTER_PADDING_BOTTOM` (130), `UPSTREAM_HEIGHT=56` (132), `UPSTREAM_GAP_Y=6` (133), `UPSTREAM_X_INSET=8` (134), `UPSTREAM_INNER_WIDTH` (135); `upstreamsBlockHeight(n)` (138), `clusterTotalHeight(n, hasWarning)` (147).
- `web/frontend/src/routes/topology/_types.ts`: `BackendClusterNodeData` has `pathPrefix?` (from v2.24.0) — REMOVE. Add `PathSectionHeaderNodeData`. `FlowEdgeData.structural?` (v2.24.1) — KEEP.
- `web/frontend/src/routes/topology/_components/nodes/UpstreamNode.svelte` — MODEL for the new header component (imports `Handle, Position, NodeProps`; `let { data } = $props()`; a `<div>` + scoped `<style>`).
- `web/frontend/src/routes/topology/+page.svelte`: `nodeTypes` map (62-68) — register `'path-section-header'`.
- Backend `topology.Route.PathPools` (v2.24.0) — UNCHANGED, the data source.

---

### Task 1: Types + PathSectionHeaderNode component

**Files:**
- Modify: `web/frontend/src/routes/topology/_types.ts`
- Create: `web/frontend/src/routes/topology/_components/nodes/PathSectionHeaderNode.svelte`
- Modify: `web/frontend/src/routes/topology/+page.svelte` (register node type)

**Interfaces:**
- Produces: `PathSectionHeaderNodeData { kind: 'path-section-header'; pathPrefix: string }`; a `path-section-header` node component; `BackendClusterNodeData.pathPrefix` removed.

- [ ] **Step 1: Add the section-header data type; remove cluster pathPrefix**

In `_types.ts`, add near `BackendClusterNodeData`:

```ts
/** A per-path section header rendered INSIDE a route's single backend
 *  cluster (v2.25.0). A light child node showing the path prefix, placed
 *  above that path-pool's upstream rows. */
export type PathSectionHeaderNodeData = {
	kind: 'path-section-header';
	pathPrefix: string;
};
```

Remove the `pathPrefix?: string;` field from `BackendClusterNodeData` (added in v2.24.0 — now dead; sections carry the prefix instead).

- [ ] **Step 2: Create the component**

Create `web/frontend/src/routes/topology/_components/nodes/PathSectionHeaderNode.svelte` (AGPL header; model on UpstreamNode.svelte):

```svelte
<!-- AGPL header (copy the // block from UpstreamNode.svelte / any node) -->
<script lang="ts">
	import { Handle, Position, type NodeProps } from '@xyflow/svelte';
	import type { PathSectionHeaderNodeData } from '../../_types';

	let { data }: NodeProps & { data: PathSectionHeaderNodeData } = $props();
</script>

<div class="path-section-header" data-testid="path-section-header">
	<!-- Target handle: the hub->section structural edge lands here (the
	     section header is the anchor for a path-pool's inbound line). -->
	<Handle type="target" position={Position.Left} />
	<span class="psh-rule">── </span>
	<span class="psh-prefix">{data.pathPrefix}</span>
	<span class="psh-rule"> ──</span>
</div>

<style>
	.path-section-header {
		display: flex;
		align-items: center;
		gap: 4px;
		height: 100%;
		font-family: var(--font-mono, monospace);
		font-size: 11px;
		color: var(--text-dim, #8a8f98);
		padding: 0 8px;
	}
	.psh-prefix { font-weight: 600; color: var(--text, #c9d1d9); }
	.psh-rule { opacity: 0.5; }
</style>
```

(Match the codebase's CSS var names — grep an existing node for the real `--` vars; the fallbacks above keep it safe.)

- [ ] **Step 3: Register the node type**

In `+page.svelte`, add to `nodeTypes` (after `upstream: UpstreamNode`):

```ts
	import PathSectionHeaderNode from './_components/nodes/PathSectionHeaderNode.svelte';
	// ... in nodeTypes:
	'path-section-header': PathSectionHeaderNode,
```

- [ ] **Step 4: svelte-check**

Run: `cd web/frontend && npx svelte-check --threshold error`
Expected: 0 errors (removing cluster `pathPrefix` may surface a reference in `_layout.ts`/BackendClusterNode — if so, that's expected and fixed in Task 2/3; if svelte-check errors ONLY on those, note it and proceed, they're rewritten next. If it errors elsewhere, fix here.)

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/routes/topology/_types.ts web/frontend/src/routes/topology/_components/nodes/PathSectionHeaderNode.svelte web/frontend/src/routes/topology/+page.svelte
git commit -m "feat(topology): PathSectionHeaderNode + type; drop cluster pathPrefix"
```

---

### Task 2: Layout — one cluster per route with sections (LOAD-BEARING)

**Files:**
- Modify: `web/frontend/src/routes/topology/_layout.ts`
- Modify: `web/frontend/src/routes/topology/_components/nodes/BackendClusterNode.svelte` (drop the v2.24.0 prefix-chip in the header, if present)
- Test: `web/frontend/src/routes/topology/_layout.test.ts`

**Interfaces:**
- Consumes: `TopologyRoute.pathPools` (v2.24.0), `PathSectionHeaderNodeData` (Task 1).
- Produces: ONE `backend-cluster` per route; children = root upstreams, then per path-pool a `path-section-header` + its upstreams; one structural hub→first-path-upstream edge per path-pool; root fan-out unchanged.

**This is the load-bearing task (3rd rework of `_layout.ts`). DEDICATED review.** The core work: (a) collapse `clusterSpecs` to one cluster per route; (b) compute the cluster height as `CLUSTER_PADDING_TOP + rootUpstreamsHeight + Σ_path(SECTION_HEADER_HEIGHT + gap + pathUpstreamsHeight) + CLUSTER_PADDING_BOTTOM`; (c) lay out children with a running Y cursor: root upstreams first, then for each path-pool a header at the cursor + its upstreams; (d) edges: root keeps its per-upstream fan-out, each path-pool gets ONE structural edge `caddy-hub → first-upstream-node-of-that-section` (or → the section-header node — decide and be consistent); (e) restore `computeStackYsForHeights` for the one-per-route cluster stack; remove `computeStackYsWithGaps` + gap constants.

- [ ] **Step 1: Write the failing tests**

In `_layout.test.ts` (match its `makeRoute` helper + minimal-field conventions — read it first). Add:

```ts
it('renders ONE cluster per route with a section header per path-pool', () => {
	const routes = [{
		id: 'r1', host: 'api.example.com', lbPolicy: 'round_robin',
		upstreams: [{ id: 'r1-0', url: 'http://route:8080', status: 'unknown', reqPerSec: 0 }],
		pathPools: [
			{ pathPrefix: '/v1', lbPolicy: 'round_robin', upstreams: [{ id: 'r1-path-0-0', url: 'http://v1:8080', status: 'unknown', reqPerSec: 0 }] },
			{ pathPrefix: '/legacy', lbPolicy: 'round_robin', upstreams: [{ id: 'r1-path-1-0', url: 'https://old:8443', status: 'unknown', reqPerSec: 0 }] },
		],
		reqPerSec: 0, tlsEnabled: false, httpRedirect: false, hasHealthCheck: false, disabled: false,
	}];
	const { nodes } = buildTopologyGraph(routes as any);
	// exactly ONE cluster
	expect(nodes.filter((n) => n.type === 'backend-cluster').length).toBe(1);
	// one section header per path-pool, carrying the prefix
	const headers = nodes.filter((n) => n.type === 'path-section-header');
	expect(headers.length).toBe(2);
	expect(headers.map((h) => (h.data as any).pathPrefix).sort()).toEqual(['/legacy', '/v1']);
	// all upstreams (root + paths) parented to the single cluster
	const cluster = nodes.find((n) => n.type === 'backend-cluster')!;
	const ups = nodes.filter((n) => n.type === 'upstream');
	expect(ups.length).toBe(3);
	for (const u of ups) expect(u.parentId).toBe(cluster.id);
	for (const h of headers) expect(h.parentId).toBe(cluster.id);
});

it('a paths-less route renders one cluster, zero section headers (non-regression)', () => {
	const routes = [{
		id: 'r2', host: 'plain.example.com', lbPolicy: 'round_robin',
		upstreams: [{ id: 'r2-0', url: 'http://a:8080', status: 'unknown', reqPerSec: 0 }],
		reqPerSec: 0, tlsEnabled: false, httpRedirect: false, hasHealthCheck: false, disabled: false,
	}];
	const { nodes } = buildTopologyGraph(routes as any);
	expect(nodes.filter((n) => n.type === 'backend-cluster').length).toBe(1);
	expect(nodes.filter((n) => n.type === 'path-section-header').length).toBe(0);
});

it('each path-pool gets one structural hub->section edge; root keeps its fan-out', () => {
	const routes = [{
		id: 'r1', host: 'api.example.com', lbPolicy: 'round_robin',
		upstreams: [{ id: 'r1-0', url: 'http://route:8080', status: 'unknown', reqPerSec: 0 }],
		pathPools: [{ pathPrefix: '/v1', lbPolicy: 'round_robin', upstreams: [{ id: 'r1-path-0-0', url: 'http://v1:8080', status: 'unknown', reqPerSec: 0 }] }],
		reqPerSec: 0, tlsEnabled: false, httpRedirect: false, hasHealthCheck: false, disabled: false,
	}];
	const { edges } = buildTopologyGraph(routes as any);
	const structural = edges.filter((e) => (e.data as any)?.structural === true);
	expect(structural.length).toBe(1); // one per path-pool
	// root edge(s) exist and are NOT structural
	const rootEdges = edges.filter((e) => e.source === 'caddy-hub' && (e.data as any)?.structural !== true);
	expect(rootEdges.length).toBeGreaterThanOrEqual(1);
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd web/frontend && npx vitest run src/routes/topology/_layout.test.ts`
Expected: FAIL (still emits multiple clusters, no section headers).

- [ ] **Step 3: Add the section-header constant + rework the cluster model**

In `_layout.ts`:
- Add `const SECTION_HEADER_HEIGHT = 22;` and `const SECTION_GAP_Y = 8;` near the other cluster constants (~127-135).
- Remove `INTER_ROUTE_GAP`, `INTRA_ROUTE_GAP`, `computeStackYsWithGaps`, and the `isRoot`/`pathPrefix`/`edgeIdSuffix` path-cluster machinery from `ClusterSpec`.
- Replace the `clusterSpecs` (root+path) build with a per-ROUTE build: one entry per route holding `{ route, rootUpstreams, pathSections: {prefix, upstreams}[] }`.
- New height function:
  ```ts
  function singleClusterHeight(rootN: number, pathSections: {upstreams: unknown[]}[], hasWarning: boolean): number {
  	let h = CLUSTER_PADDING_TOP + upstreamsBlockHeight(rootN);
  	for (const s of pathSections) {
  		h += SECTION_GAP_Y + SECTION_HEADER_HEIGHT + SECTION_GAP_Y + upstreamsBlockHeight(s.upstreams.length);
  	}
  	h += CLUSTER_PADDING_BOTTOM;
  	return hasWarning ? h + CLUSTER_WARNING_FOOTER_HEIGHT : h;
  }
  ```
- Stack the (now one-per-route) clusters with `computeStackYsForHeights(clusterHeights)` (uniform gap — restored).

- [ ] **Step 4: Emit the cluster + interleaved children (running Y cursor)**

For each route's cluster, push the `backend-cluster` node (data WITHOUT `pathPrefix`), then walk children with a cursor:
```ts
let cy = CLUSTER_PADDING_TOP;
// root upstreams (no header — Q2=B)
for (const [ui, u] of rootUpstreams.entries()) {
	pushUpstreamChild(u, clusterId, route.id, cy);   // extract the existing child-push into a helper
	cy += UPSTREAM_HEIGHT + (ui < rootUpstreams.length - 1 ? UPSTREAM_GAP_Y : 0);
}
for (const section of pathSections) {
	cy += SECTION_GAP_Y;
	pushSectionHeader(section.prefix, clusterId, route.id, cy); // new path-section-header child
	cy += SECTION_HEADER_HEIGHT + SECTION_GAP_Y;
	for (const [ui, u] of section.upstreams.entries()) {
		pushUpstreamChild(u, clusterId, route.id, cy);
		cy += UPSTREAM_HEIGHT + (ui < section.upstreams.length - 1 ? UPSTREAM_GAP_Y : 0);
	}
}
```
Extract `pushUpstreamChild` from the existing child block (lines 544-575) preserving all `UpstreamNodeData` fields + `loadRatio`/`globalMaxReqPerSec` math + `parentId`/`extent`/`draggable:false`. The section-header child mirrors it: `type:'path-section-header'`, `height: SECTION_HEADER_HEIGHT`, `width: UPSTREAM_INNER_WIDTH`, `parentId: clusterId`, `extent:'parent'`, `draggable:false`, `selectable:false`, `data: { kind:'path-section-header', pathPrefix: section.prefix }`, position `{ x: UPSTREAM_X_INSET, y: cy }`. Upstream node ids stay `upstream-${route.id}-${upstream.id}` (backend already namespaces path upstream ids as `${route.id}-path-${pi}-${j}` → unique).

- [ ] **Step 5: Rework the edges**

Root pool: keep the EXISTING per-upstream fan-out for the root upstreams (the current 686-703 logic, but only for the root pool now — no `pathPrefix` branch). For each path section: push ONE structural edge `caddy-hub → <anchor>` where `<anchor>` is the section's FIRST upstream node id (`upstream-${route.id}-${firstUpstream.id}`) OR the section-header node id — pick the section-header node id for a stable per-section anchor, and give the header a target Handle (Task 1 already did). Edge id `e-caddy-section-${route.id}-${sectionIndex}`, data `pathPoolFlowData()` (structural, from v2.24.1 — keep that helper).

- [ ] **Step 6: Run tests to verify they pass**

Run: `npx vitest run src/routes/topology/_layout.test.ts`
Expected: PASS (existing + 3 new). Existing tests that asserted the v2.24.0/1 multi-cluster shape will need updating — update them to the new single-cluster model (they were testing the now-removed behaviour; the non-regression test covers paths-less routes).

- [ ] **Step 7: Clean-removal grep + svelte-check + full suite**

Run:
```bash
grep -n "computeStackYsWithGaps\|INTRA_ROUTE_GAP\|INTER_ROUTE_GAP" src/routes/topology/_layout.ts   # expect ZERO
grep -rn "pathPrefix" src/routes/topology/_components/nodes/BackendClusterNode.svelte src/routes/topology/_types.ts   # expect ZERO on the cluster
npx svelte-check --threshold error && npx vitest run
```
Expected: no dead refs, 0 svelte-check errors, full suite green.

- [ ] **Step 8: Commit**

```bash
git add web/frontend/src/routes/topology/_layout.ts web/frontend/src/routes/topology/_components/nodes/BackendClusterNode.svelte web/frontend/src/routes/topology/_layout.test.ts
git commit -m "feat(topology): one cluster per route with per-prefix sections + hub->section lines"
```

---

### Task 3: Build + re-dogfood note

**Files:** build + suites; `docs/smoke-test-path-upstream.md`

- [ ] **Step 1: Full frontend build**

Run: `cd web/frontend && npm run build`
Expected: succeeds.

- [ ] **Step 2: Full suites**

Run from repo root: `go test ./...` (untouched — confirm) ; from web/frontend: `npx vitest run && npx svelte-check --threshold error`
Expected: all green.

- [ ] **Step 3: Update the smoke doc**

Replace the v2.24.0/v2.24.1 topology notes in `docs/smoke-test-path-upstream.md` with: (v2.25.0) a route's path-pools now appear INSIDE its single backend cluster as per-prefix sections (root upstreams, then `── /v1 ──` etc.), with one dashed hub→section line per path; a protection-only path (no pool) adds nothing; a route without path pools is unchanged.

- [ ] **Step 4: Commit**

```bash
git add docs/smoke-test-path-upstream.md
git commit -m "docs(topology): note single-cluster per-prefix sections (v2.25.0)"
```

---

## Post-plan (controller, not a task)
- **DEDICATED review on Task 2** (3rd `_layout.ts` rework — verify the height math / child cursor has no overlap or overflow, paths-less non-regression is byte-identical to pre-v2.24.0, and the clean-removal of v2.24.1 code is complete).
- Inline review on Tasks 1, 3.
- **RE-DOGFOOD (mandatory — 2 prior visual dogfoods reshaped this):** dev-local or VM → open Topology on `testpath`: ONE block with `:9099` (root), then `── /v1 ──`+`:9199`, `── /legacy ──`+`:9299`, `── /pub ──`+`:9199`; dashed lines from the hub to each section; `/docs` (no pool) absent; a paths-less route = simple block unchanged.
- ONE final whole-branch review before PR.
- Version v2.25.0 — tag only after re-dogfood + operator go-ahead.

## Self-Review notes
- Spec coverage: Opt.2 one cluster (Task 2 — collapse clusterSpecs) ✓; Q1=C sections (Task 1 header node + Task 2 interleave) ✓; Q2=B root no header (Task 2 cursor: root upstreams first, no header) ✓; Q3 one hub→section line per pool + root fan-out unchanged (Task 2 step 5) ✓; keep PathPools + structural flag (unchanged/reused) ✓; remove v2.24.1 code (Task 2 step 3+7 grep) ✓; non-regression paths-less (Task 2 test #2) ✓.
- Type consistency: `PathSectionHeaderNodeData{kind:'path-section-header', pathPrefix}` created (Task 1), consumed in Task 2 child push + registered in nodeTypes (Task 1). `BackendClusterNodeData.pathPrefix` removed (Task 1) — Task 2 cluster data must not set it. Section anchor = section-header node id (Task 2 step 5) which has a target Handle (Task 1 step 2).
- Open verifications for the implementer: the `_layout.test.ts` makeRoute helper + which existing tests assert the v2.24.0/1 multi-cluster shape (must be updated — Task 2 step 6); the real CSS var names for the header component (Task 1 step 2); whether BackendClusterNode.svelte actually renders a `pathPrefix` chip to remove (Task 2, grep first); `CLUSTER_WARNING_FOOTER_HEIGHT` exact name/usage in the height fn (Task 2 step 3).
