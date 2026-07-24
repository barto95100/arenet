# Topology path branches: visible + grouped Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix two visual defects the v2.24.0 dogfood surfaced — (1) make the hub→path-cluster edges visible as dashed "structural" branches (they're currently drawn at the dead tier, opacity 0.2, so invisible); (2) stack a route's clusters (root + its path pools) contiguously, like aliases under their FQDN, instead of scattered in the global stack.

**Architecture:** Frontend-only. Add a `structural?: boolean` flag on the edge data (set by `pathPoolFlowData()`); `AnimatedFlowEdge` renders a `structural` edge with a dashed, opacity-0.5 stroke and no particles — the flag gates the new style so every real-traffic edge is untouched. For grouping, replace the uniform-gap stacker with a variable-gap one: small `INTRA_ROUTE_GAP` between a route's clusters, `INTER_ROUTE_GAP` (= the current `ROW_SPACING_Y`) before a new route's root cluster, preserving multi-route layouts that have no path pools.

**Tech Stack:** SvelteKit/Svelte 5 + TypeScript + @xyflow/svelte, Vitest.

## Global Constraints

- **AGPL header** on any new file (all edits here are to existing files).
- **Non-regression — edges (the key risk):** the dashed structural style applies ONLY when `data.structural === true`. Every real-traffic edge, and a real idle (0 rps) edge, must render byte-identically to before. A dedicated review + a test guard this.
- **Non-regression — layout:** a route with no path pools produces one cluster at the same Y as before; a multi-route set with no path pools stacks identically (so `INTER_ROUTE_GAP` MUST equal the current `ROW_SPACING_Y = 150`).
- **Structure only:** no metric change; structural edges carry 0 traffic (no particles).
- **v2.24.1** (patch). No tag until re-dogfood + operator go-ahead.

**Key existing anchors (verbatim):**
- `web/frontend/src/routes/topology/_types.ts`: `FlowEdgeData` (line 368) = `{ kind:'flow'; reqPerSec; p99LatencyMs; errorRate5xx } & Record<string, unknown>`; `resolveFlowTier(data)` (line 422) → FlowTier; `FlowTier` (line 28) = `'dead'|'idle'|'low'|'mid'|'high'|'warn'|'bad'`.
- `web/frontend/src/routes/topology/_components/edges/AnimatedFlowEdge.svelte`: `type Props = EdgeProps & { data?: FlowEdgeData }` (28); `tier = $derived(data ? resolveFlowTier(data) : 'idle')` (82); `tierStrokeStyle(t)` (133, returns `stroke: ...; stroke-opacity: ...; stroke-width: 1.5;` + optional dasharray for 'bad'); `strokeStyle = $derived(tierStrokeStyle(tier))` (152); `<BaseEdge {id} path={edgePath} {markerEnd} style={strokeStyle} />` (156); particle circles use `cfg.count` (dead → count 0).
- `web/frontend/src/routes/topology/_layout.ts`: `ROW_SPACING_Y = 150` (56); `ClusterSpec` type (178, has `route`, `clusterId`, `edgeIdSuffix`, `pathPrefix?`, `upstreams`, `lbPolicy`, `hasHealthCheck`, `warning?`); `clusterSpecs.push` root at 464 / path at 474; `clusterHeights = clusterSpecs.map(...)` (488) + `computeStackYsForHeights(clusterHeights)` (right after); `computeStackYsForHeights(heights)` body uses uniform `ROW_SPACING_Y`; the path-edge emission `pathPoolFlowData()` at ~673 / `pathPoolFlowData` def ~745 (returns `{ kind:'flow', reqPerSec:0, p99LatencyMs:0, errorRate5xx:0 }`).

---

### Task 1: Structural edge flag + dashed rendering

**Files:**
- Modify: `web/frontend/src/routes/topology/_types.ts` (`FlowEdgeData` gains `structural?`)
- Modify: `web/frontend/src/routes/topology/_layout.ts` (`pathPoolFlowData` sets `structural: true`)
- Modify: `web/frontend/src/routes/topology/_components/edges/AnimatedFlowEdge.svelte` (dashed style when structural)
- Test: `web/frontend/src/routes/topology/_layout.test.ts` (structural flag on path edges) + a small AnimatedFlowEdge assertion if the harness supports it

**Interfaces:**
- Produces: `FlowEdgeData.structural?: boolean`; a path-pool caddy→cluster edge carries `structural: true`; `AnimatedFlowEdge` renders such edges dashed + no particles.

- [ ] **Step 1: Write the failing test (layout emits structural flag)**

In `web/frontend/src/routes/topology/_layout.test.ts`, add:

```ts
it('marks the hub->path-cluster edge as structural', () => {
	const routes = [{
		id: 'r1', host: 'api.example.com', lbPolicy: 'round_robin',
		upstreams: [{ id: 'r1-0', url: 'http://route:8080', status: 'unknown', reqPerSec: 0 }],
		pathPools: [{ pathPrefix: '/v1', lbPolicy: 'round_robin', upstreams: [{ id: 'r1-path-0-0', url: 'http://v1:8080', status: 'unknown', reqPerSec: 0 }] }],
		reqPerSec: 0, tlsEnabled: false, httpRedirect: false, hasHealthCheck: false, disabled: false,
	}];
	const { edges } = buildTopologyGraph(routes as any);
	const pathEdge = edges.find((e) => e.target === 'cluster-r1-path-0');
	expect(pathEdge).toBeDefined();
	expect((pathEdge!.data as any).structural).toBe(true);
	// a route/root edge must NOT be structural
	const rootEdges = edges.filter((e) => e.source === 'caddy-hub' && e.target !== 'cluster-r1-path-0');
	for (const e of rootEdges) {
		expect((e.data as any).structural).not.toBe(true);
	}
});
```

(Match the harness's `makeRoute` helper + minimal-fields conventions — read `_layout.test.ts` first.)

- [ ] **Step 2: Run to verify it fails**

Run: `cd web/frontend && npx vitest run src/routes/topology/_layout.test.ts`
Expected: FAIL (`structural` not set).

- [ ] **Step 3: Add `structural?` to `FlowEdgeData`**

In `_types.ts`, in the `FlowEdgeData` type (line 368):

```ts
export type FlowEdgeData = {
	kind: 'flow';
	reqPerSec: number;
	p99LatencyMs: number;
	errorRate5xx: number;
	/** v2.24.1 — a structural routing branch (a path-pool cluster edge):
	 *  no measured traffic in v1, rendered as a dashed visible line rather
	 *  than the near-invisible dead-tier stroke. When per-branch metrics
	 *  land, this flag is dropped and the edge animates like any flow. */
	structural?: boolean;
} & Record<string, unknown>;
```

- [ ] **Step 4: Set `structural: true` in `pathPoolFlowData`**

In `_layout.ts`, the `pathPoolFlowData()` helper:

```ts
function pathPoolFlowData(): FlowEdgeData {
	return { kind: 'flow', reqPerSec: 0, p99LatencyMs: 0, errorRate5xx: 0, structural: true };
}
```

- [ ] **Step 5: Run to verify the layout test passes**

Run: `npx vitest run src/routes/topology/_layout.test.ts`
Expected: PASS (structural flag set; existing tests still green).

- [ ] **Step 6: Render the dashed structural stroke in AnimatedFlowEdge**

In `AnimatedFlowEdge.svelte`, gate the stroke style on `data.structural` BEFORE the tier logic. Add a derived and branch in the stroke:

```svelte
	let isStructural = $derived(data?.structural === true);
	let strokeStyle = $derived(
		isStructural
			? 'stroke: oklch(62% 0.01 250); stroke-opacity: 0.5; stroke-width: 1.5; stroke-dasharray: 5 4;'
			: tierStrokeStyle(tier)
	);
```

Particles: a structural edge has `reqPerSec: 0` → `tier` resolves to `dead` → `cfg.count === 0`, so particles are already absent. No change needed to the particle block (verify the dead tier gives count 0). If you want to be explicit/defensive, force `count: 0` when `isStructural`, but do NOT alter the non-structural path.

- [ ] **Step 7: Non-regression check — real edges unchanged**

Confirm by reading: for `data.structural` falsy (undefined/false), `strokeStyle` === `tierStrokeStyle(tier)` exactly as before, and the particle config is untouched. A real idle edge (reqPerSec 0, no structural flag) still renders the dead-tier stroke (opacity 0.2) exactly as v2.24.0.

If the component test harness supports rendering an edge, add a test: a `{structural:true}` edge's `<path>` style contains `stroke-dasharray`; a `{reqPerSec:0}` (no structural) edge's style does NOT (stays dead-tier opacity 0.2). If edge-component rendering isn't easily testable in the harness, rely on the layout test (flag presence) + the dedicated review reading the branch.

- [ ] **Step 8: svelte-check + full frontend suite**

Run: `npx svelte-check --threshold error && npx vitest run`
Expected: 0 errors, full suite green.

- [ ] **Step 9: Commit**

```bash
git add web/frontend/src/routes/topology/_types.ts web/frontend/src/routes/topology/_layout.ts web/frontend/src/routes/topology/_components/edges/AnimatedFlowEdge.svelte web/frontend/src/routes/topology/_layout.test.ts
git commit -m "fix(topology): render path-pool branch edges as visible dashed structural strokes"
```

---

### Task 2: Contiguous per-route cluster stacking (variable gap)

**Files:**
- Modify: `web/frontend/src/routes/topology/_layout.ts` (ClusterSpec flag + variable-gap stacker)
- Test: `web/frontend/src/routes/topology/_layout.test.ts` (contiguity + non-regression)

**Interfaces:**
- Consumes: the existing `clusterSpecs` array (root-then-paths per route).
- Produces: clusters of one route stacked with `INTRA_ROUTE_GAP`; a new route's root cluster separated by `INTER_ROUTE_GAP` (= 150, the old `ROW_SPACING_Y`), so paths-less multi-route layouts are unchanged.

- [ ] **Step 1: Write the failing tests**

In `_layout.test.ts`:

```ts
it('stacks a route\'s clusters contiguously (intra-gap < inter-gap)', () => {
	const routes = [{
		id: 'r1', host: 'api.example.com', lbPolicy: 'round_robin',
		upstreams: [{ id: 'r1-0', url: 'http://route:8080', status: 'unknown', reqPerSec: 0 }],
		pathPools: [{ pathPrefix: '/v1', lbPolicy: 'round_robin', upstreams: [{ id: 'r1-path-0-0', url: 'http://v1:8080', status: 'unknown', reqPerSec: 0 }] }],
		reqPerSec: 0, tlsEnabled: false, httpRedirect: false, hasHealthCheck: false, disabled: false,
	}, {
		id: 'r2', host: 'other.example.com', lbPolicy: 'round_robin',
		upstreams: [{ id: 'r2-0', url: 'http://o:8080', status: 'unknown', reqPerSec: 0 }],
		reqPerSec: 0, tlsEnabled: false, httpRedirect: false, hasHealthCheck: false, disabled: false,
	}];
	const { nodes } = buildTopologyGraph(routes as any);
	const clusters = nodes.filter((n) => n.type === 'backend-cluster');
	const root1 = clusters.find((c) => c.id === 'cluster-r1')!;
	const path1 = clusters.find((c) => c.id === 'cluster-r1-path-0')!;
	const root2 = clusters.find((c) => c.id === 'cluster-r2')!;
	// gap between r1 root and its /v1 path (intra) < gap between /v1 and r2 root (inter)
	const intra = path1.position.y - (root1.position.y + (root1.height ?? 0));
	const inter = root2.position.y - (path1.position.y + (path1.height ?? 0));
	expect(intra).toBeLessThan(inter);
});

it('a paths-less multi-route set stacks identically to before (inter-gap === 150)', () => {
	const routes = [
		{ id: 'r1', host: 'a.example.com', lbPolicy: 'round_robin', upstreams: [{ id: 'r1-0', url: 'http://a:8080', status: 'unknown', reqPerSec: 0 }], reqPerSec: 0, tlsEnabled: false, httpRedirect: false, hasHealthCheck: false, disabled: false },
		{ id: 'r2', host: 'b.example.com', lbPolicy: 'round_robin', upstreams: [{ id: 'r2-0', url: 'http://b:8080', status: 'unknown', reqPerSec: 0 }], reqPerSec: 0, tlsEnabled: false, httpRedirect: false, hasHealthCheck: false, disabled: false },
	];
	const { nodes } = buildTopologyGraph(routes as any);
	const c1 = nodes.find((n) => n.id === 'cluster-r1')!;
	const c2 = nodes.find((n) => n.id === 'cluster-r2')!;
	const gap = c2.position.y - (c1.position.y + (c1.height ?? 0));
	expect(gap).toBe(150); // INTER_ROUTE_GAP === old ROW_SPACING_Y
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `npx vitest run src/routes/topology/_layout.test.ts`
Expected: the contiguity test FAILS (uniform gap → intra === inter).

- [ ] **Step 3: Add gap constants + an `isRoot` flag on ClusterSpec**

In `_layout.ts`, near `ROW_SPACING_Y = 150` (line 56):

```ts
const INTER_ROUTE_GAP = 150; // == old ROW_SPACING_Y — a new route's root cluster keeps the original spacing (non-regression for paths-less sets)
const INTRA_ROUTE_GAP = 24;  // tight gap between a route's own clusters (root + its path pools), grouping them like aliases under their FQDN
```

Add `isRoot: boolean` to the `ClusterSpec` type (line 178). Set `isRoot: true` on the root push (464) and `isRoot: false` on the path push (474).

- [ ] **Step 4: Add a variable-gap stacker + use it**

Add a new helper alongside `computeStackYsForHeights`:

```ts
// Like computeStackYsForHeights but with a per-block leading gap. gaps[i] is
// the gap BEFORE block i (gaps[0] is ignored — the first block has no leading
// gap). Lets a route's clusters stack tight (INTRA) while a new route's root
// cluster gets the full INTER gap.
function computeStackYsWithGaps(heights: number[], gaps: number[]): number[] {
	if (heights.length === 0) return [];
	let total = heights.reduce((sum, h) => sum + h, 0);
	for (let i = 1; i < heights.length; i++) total += gaps[i];
	const startTop = -total / 2;
	const ys: number[] = [];
	let cursor = startTop;
	for (let i = 0; i < heights.length; i++) {
		if (i > 0) cursor += gaps[i];
		ys.push(cursor);
		cursor += heights[i];
	}
	return ys;
}
```

Replace the `clusterYs = computeStackYsForHeights(clusterHeights)` call with:

```ts
const clusterGaps = clusterSpecs.map((spec, i) =>
	i === 0 ? 0 : spec.isRoot ? INTER_ROUTE_GAP : INTRA_ROUTE_GAP,
);
const clusterYs = computeStackYsWithGaps(clusterHeights, clusterGaps);
```

(Keep `computeStackYsForHeights` if other callers use it — grep; if the cluster loop was its only caller, you may leave it for the alias/col-0 stack which uses a different mechanism. Do NOT remove a helper another stack depends on.)

- [ ] **Step 5: Run to verify tests pass**

Run: `npx vitest run src/routes/topology/_layout.test.ts`
Expected: PASS (contiguity: intra 24 < inter 150; non-regression: paths-less gap === 150).

- [ ] **Step 6: svelte-check + full frontend suite**

Run: `npx svelte-check --threshold error && npx vitest run`
Expected: 0 errors, full suite green (the existing layout tests that assert cluster positions for paths-less routes must still pass — INTER_ROUTE_GAP === 150 preserves them).

- [ ] **Step 7: Commit**

```bash
git add web/frontend/src/routes/topology/_layout.ts web/frontend/src/routes/topology/_layout.test.ts
git commit -m "fix(topology): stack a route's clusters contiguously (tight intra-gap, full inter-gap)"
```

---

### Task 3: Build + re-dogfood note

**Files:**
- Test: build + suites

- [ ] **Step 1: Full frontend build**

Run: `cd web/frontend && npm run build`
Expected: succeeds.

- [ ] **Step 2: Full suites**

Run from repo root: `go test ./...` (should be untouched — frontend-only change, but confirm nothing broke) ; from web/frontend: `npx vitest run && npx svelte-check --threshold error`
Expected: all green.

- [ ] **Step 3: Commit (if any doc note)**

Optional: append to `docs/smoke-test-path-upstream.md` a line that (v2.24.1) the path-pool branches render as dashed lines from the hub and a route's clusters are grouped contiguously.

```bash
git add docs/smoke-test-path-upstream.md
git commit -m "docs(topology): note dashed structural branches + grouped clusters (v2.24.1)"
```

---

## Post-plan (controller, not a task)
- **DEDICATED review on Task 1** (`AnimatedFlowEdge` is the SHARED edge component — confirm the dashed style is gated strictly on `data.structural` and every real-traffic / idle edge is byte-identical).
- Inline review on Task 2.
- **RE-DOGFOOD (mandatory — the visual check is what caught the original bug):** dev-local (binary on :8001 + `npm run dev`) OR on the VM after tag → open Topology on `testpath`: dashed branches from the hub to `/v1`/`/legacy`/`/pub`, and the route's clusters grouped contiguously. A paths-less route unchanged.
- ONE final whole-branch review before PR.
- Version v2.24.1 — tag only after re-dogfood + operator go-ahead.

## Self-Review notes
- Spec coverage: Q1 hub→path edges (Task 1 — already emitted, now visible) ✓; Q2 reuse animated-flow (Task 1 — flag on FlowEdgeData, no new type) ✓; Q3 dashed reinforced stroke (Task 1 step 6, dasharray 5 4 + opacity 0.5) ✓; Q4 contiguous stacking (Task 2 — INTRA/INTER gaps + variable stacker) ✓; non-regression edges (Task 1 step 7 — gated on structural) ✓; non-regression layout (Task 2 — INTER===150, test) ✓.
- Type consistency: `structural?: boolean` on `FlowEdgeData` set in `pathPoolFlowData` (Task 1) and read as `data?.structural` in AnimatedFlowEdge (Task 1) — consistent. `isRoot` added to ClusterSpec (Task 2) set at both push sites, read in `clusterGaps`.
- Open verifications for the implementer: the `_layout.test.ts` makeRoute helper + minimal fields (Task 1/2 step 1), whether the dead tier truly gives particle count 0 (Task 1 step 6 — verify in tierConfig), whether `computeStackYsForHeights` has other callers before assuming it's replaceable (Task 2 step 4).
