// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Sujet 1 Phase 3.b + 3.c — _layout.ts alias integration tests.
//
// Pins the operator-visible contract for the col-0 stack:
//   - routes without aliases keep their single-FQDN footprint
//     (backward-compat: legacy traefik / arenet / ha layouts
//     don't shift when aliases ship — no container, no extra
//     edges, no visual change at all).
//   - routes with aliases emit a RouteGroupNode container
//     (Phase 3.c) wrapping the FQDN + alias cards visually.
//   - aliases stack vertically below the primary FQDN, in
//     backend order (sorted desc by reqPerSec).
//   - active aliases (reqPerSec > 0) get their own
//     AnimatedFlowEdge straight to the Caddy hub. Idle
//     aliases (reqPerSec === 0) get no edge — they stay
//     visible inside the container but don't carry particles.
//   - the primary FQDN edge intensity is rebalanced: it
//     carries route.reqPerSec MINUS the sum of active alias
//     rates (the visual sum of particles entering Caddy from
//     a route still equals route.reqPerSec).
//   - 21-alias realistic-load case (operator traefik route)
//     layouts cleanly: 21 alias nodes + 1 container, only the
//     active aliases emit edges, sort preserved end-to-end.

import { describe, it, expect } from 'vitest';
import { buildTopologyGraph } from './_layout';
import type {
	AliasNodeData,
	FlowEdgeData,
	FQDNNodeData,
	RouteGroupNodeData,
	TopologyAlias,
	TopologyRoute
} from './_types';

function makeRoute(overrides: Partial<TopologyRoute> = {}): TopologyRoute {
	return {
		id: 'r-1',
		host: 'primary.local',
		upstreams: [
			{
				id: 'u-1',
				url: 'http://127.0.0.1:9000',
				status: 'unknown',
				healthCheckConfigured: false,
				reqPerSec: 0,
				p99LatencyMs: 0,
				fairnessRatio: 1
			}
		],
		lbPolicy: 'round_robin',
		reqPerSec: 0,
		p99LatencyMs: 0,
		errorRate5xx: 0,
		tlsEnabled: false,
		httpRedirect: false,
		hasHealthCheck: false,
		...overrides
	};
}

function alias(host: string, reqPerSec: number): TopologyAlias {
	return { host, reqPerSec, p99LatencyMs: 0, errorRate5xx: 0 };
}

describe('buildTopologyGraph — alias integration', () => {
	// -------------------------------------------------------
	// Phase 3.b shape — preserved through 3.c with the
	// AliasOfEdge expectations dropped (the dashed semantic
	// edge was removed in 3.c — RouteGroupNode replaces it).
	// -------------------------------------------------------

	it('route without aliases emits a single FQDN node — no container, no alias nodes', () => {
		const graph = buildTopologyGraph([makeRoute()]);
		expect(graph.nodes.filter((n) => n.type === 'route-group')).toHaveLength(0);
		expect(graph.nodes.filter((n) => n.type === 'fqdn')).toHaveLength(1);
		expect(graph.nodes.filter((n) => n.type === 'alias')).toHaveLength(0);
	});

	it('route with empty aliasMetrics array also stays single-FQDN with no container', () => {
		// aliasMetrics: [] (Phase 2.2's non-omitempty wire shape
		// for a route without aliases) must be treated identically
		// to "field absent" — no container, no alias nodes.
		const graph = buildTopologyGraph([makeRoute({ aliasMetrics: [] })]);
		expect(graph.nodes.filter((n) => n.type === 'route-group')).toHaveLength(0);
		expect(graph.nodes.filter((n) => n.type === 'alias')).toHaveLength(0);
	});

	it('route with aliases emits FQDN + AliasNodes in backend order', () => {
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				aliasMetrics: [
					alias('sonarr.example.com', 0.94),
					alias('radarr.example.com', 0.47),
					alias('idle.example.com', 0)
				]
			})
		]);
		const aliasNodes = graph.nodes.filter((n) => n.type === 'alias');
		expect(aliasNodes).toHaveLength(3);
		const hosts = aliasNodes.map((n) => (n.data as AliasNodeData).host);
		expect(hosts).toEqual([
			'sonarr.example.com',
			'radarr.example.com',
			'idle.example.com'
		]);
		expect((aliasNodes[0].data as AliasNodeData).reqPerSec).toBe(0.94);
		expect((aliasNodes[0].data as AliasNodeData).isIdle).toBe(false);
		expect((aliasNodes[2].data as AliasNodeData).isIdle).toBe(true);
	});

	it('AliasNodes positioned below the primary FQDN, top consumer closest', () => {
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				aliasMetrics: [alias('top.example.com', 5), alias('mid.example.com', 1), alias('bot.example.com', 0)]
			})
		]);
		const fqdn = graph.nodes.find((n) => n.id === 'fqdn-r-1');
		const aliases = graph.nodes
			.filter((n) => n.type === 'alias')
			.sort((a, b) => a.position.y - b.position.y);
		expect(fqdn).toBeDefined();
		expect(aliases).toHaveLength(3);
		for (const a of aliases) {
			expect(a.position.y).toBeGreaterThan(fqdn!.position.y);
		}
		expect((aliases[0].data as AliasNodeData).host).toBe('top.example.com');
		expect((aliases[1].data as AliasNodeData).host).toBe('mid.example.com');
		expect((aliases[2].data as AliasNodeData).host).toBe('bot.example.com');
	});

	it('multi-route layout: alias-heavy route does not push neighbours into overlap', () => {
		const graph = buildTopologyGraph([
			makeRoute({ id: 'r-1', host: 'small.local' }),
			makeRoute({
				id: 'r-2',
				host: 'big.local',
				aliasMetrics: [alias('a.big.local', 1), alias('b.big.local', 0), alias('c.big.local', 0)]
			})
		]);
		const fqdn1 = graph.nodes.find((n) => n.id === 'fqdn-r-1')!;
		const fqdn2 = graph.nodes.find((n) => n.id === 'fqdn-r-2')!;
		expect(fqdn1.position.y).not.toBe(fqdn2.position.y);
		const top = fqdn1.position.y < fqdn2.position.y ? fqdn1 : fqdn2;
		const bot = fqdn1.position.y < fqdn2.position.y ? fqdn2 : fqdn1;
		const topRouteAliases = graph.nodes.filter(
			(n) => n.type === 'alias' && (n.data as AliasNodeData).parentRouteId === top.id
		);
		const topBlockBottom =
			topRouteAliases.length > 0
				? Math.max(...topRouteAliases.map((a) => a.position.y)) + 44 // ALIAS_HEIGHT
				: top.position.y + 70; // FQDN_HEIGHT
		expect(bot.position.y).toBeGreaterThan(topBlockBottom);
	});

	it('FQDNNodeData still carries the legacy aliases string array for backward-compat', () => {
		const graph = buildTopologyGraph([
			makeRoute({
				aliases: ['foo.example.com', 'bar.example.com'],
				aliasMetrics: [alias('foo.example.com', 1), alias('bar.example.com', 0)]
			})
		]);
		const fqdn = graph.nodes.find((n) => n.type === 'fqdn')!;
		expect((fqdn.data as FQDNNodeData).aliases).toEqual(['foo.example.com', 'bar.example.com']);
	});

	// -------------------------------------------------------
	// Phase 3.c — RouteGroupNode container + per-alias edges
	// + primary FQDN edge rebalance.
	// -------------------------------------------------------

	it('route with aliases emits a RouteGroupNode container with FQDN + aliases inside its bounds', () => {
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				aliasMetrics: [
					alias('sonarr.example.com', 1),
					alias('radarr.example.com', 0.5),
					alias('idle.example.com', 0)
				]
			})
		]);
		const containers = graph.nodes.filter((n) => n.type === 'route-group');
		expect(containers).toHaveLength(1);
		const container = containers[0];
		expect(container.id).toBe('route-group-r-1');
		expect((container.data as RouteGroupNodeData).routeId).toBe('r-1');
		expect((container.data as RouteGroupNodeData).primaryHost).toBe('primary.local');

		// Container bounds must enclose the FQDN + every alias.
		// SvelteFlow's Node.width/height land directly on the
		// node — read them as the canonical bounds.
		const cx = container.position.x;
		const cy = container.position.y;
		const cw = (container.width as number) ?? 0;
		const ch = (container.height as number) ?? 0;
		expect(cw).toBeGreaterThan(0);
		expect(ch).toBeGreaterThan(0);

		const fqdn = graph.nodes.find((n) => n.id === 'fqdn-r-1')!;
		expect(fqdn.position.x).toBeGreaterThanOrEqual(cx);
		expect(fqdn.position.y).toBeGreaterThanOrEqual(cy);
		expect(fqdn.position.x).toBeLessThanOrEqual(cx + cw);
		expect(fqdn.position.y).toBeLessThanOrEqual(cy + ch);

		const aliases = graph.nodes.filter((n) => n.type === 'alias');
		for (const a of aliases) {
			expect(a.position.x).toBeGreaterThanOrEqual(cx);
			expect(a.position.y).toBeGreaterThanOrEqual(cy);
			// Right edge of alias card ≈ position.x + 140 (alias
			// width). Bottom edge ≈ position.y + 44 (alias height).
			expect(a.position.x + 140).toBeLessThanOrEqual(cx + cw);
			expect(a.position.y + 44).toBeLessThanOrEqual(cy + ch);
		}
	});

	it('container is emitted FIRST in the nodes array so it paints behind FQDN + alias cards', () => {
		// SvelteFlow paints nodes in array order. For the
		// container to act as a background it MUST precede every
		// node it visually wraps.
		const graph = buildTopologyGraph([
			makeRoute({ id: 'r-1', aliasMetrics: [alias('a.example.com', 1)] })
		]);
		const containerIdx = graph.nodes.findIndex((n) => n.type === 'route-group');
		const fqdnIdx = graph.nodes.findIndex((n) => n.id === 'fqdn-r-1');
		const aliasIdx = graph.nodes.findIndex((n) => n.type === 'alias');
		expect(containerIdx).toBeGreaterThanOrEqual(0);
		expect(containerIdx).toBeLessThan(fqdnIdx);
		expect(containerIdx).toBeLessThan(aliasIdx);
	});

	it('active alias (reqPerSec > 0) emits an AnimatedFlowEdge to Caddy with its own rate', () => {
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				reqPerSec: 10,
				aliasMetrics: [alias('sonarr.example.com', 4), alias('radarr.example.com', 2.5)]
			})
		]);
		const aliasEdges = graph.edges.filter((e) => e.source.startsWith('alias-r-1-'));
		expect(aliasEdges).toHaveLength(2);
		for (const edge of aliasEdges) {
			expect(edge.type).toBe('animated-flow');
			expect(edge.target).toBe('caddy-hub');
		}
		const sonarrEdge = aliasEdges.find((e) => e.source === 'alias-r-1-0')!;
		expect((sonarrEdge.data as FlowEdgeData).reqPerSec).toBe(4);
		const radarrEdge = aliasEdges.find((e) => e.source === 'alias-r-1-1')!;
		expect((radarrEdge.data as FlowEdgeData).reqPerSec).toBe(2.5);
	});

	it('idle alias (reqPerSec === 0) emits NO edge — alias node still rendered in container', () => {
		// The idle alias must be visible inside the container
		// (Phase 3.c keeps the visual presence) but NOT carry a
		// particle edge (which would imply traffic where there
		// is none).
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				reqPerSec: 5,
				aliasMetrics: [alias('hot.example.com', 5), alias('idle.example.com', 0)]
			})
		]);
		const aliasNodes = graph.nodes.filter((n) => n.type === 'alias');
		expect(aliasNodes).toHaveLength(2);
		const aliasEdges = graph.edges.filter((e) => e.source.startsWith('alias-r-1-'));
		expect(aliasEdges).toHaveLength(1);
		expect(aliasEdges[0].source).toBe('alias-r-1-0');
	});

	it('primary FQDN edge reqPerSec = route.reqPerSec - sum(active alias rates)', () => {
		// Route total: 10 r/s, split 6/2.5 between two active
		// aliases. Primary's own share: 10 - (6 + 2.5) = 1.5 r/s.
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				reqPerSec: 10,
				aliasMetrics: [alias('a.example.com', 6), alias('b.example.com', 2.5)]
			})
		]);
		const primaryEdge = graph.edges.find((e) => e.id === 'e-fqdn-r-1-caddy')!;
		expect((primaryEdge.data as FlowEdgeData).reqPerSec).toBeCloseTo(1.5, 5);
	});

	it('primary FQDN edge clamps at 0 when alias sum exceeds route rate (rounding drift)', () => {
		// Windowed aggregation can leave the alias sum a hair
		// above the route's own rate. The primary edge must clamp
		// at 0 — never negative — so tier resolution stays sane.
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				reqPerSec: 5,
				aliasMetrics: [alias('a.example.com', 3), alias('b.example.com', 2.5)]
			})
		]);
		const primaryEdge = graph.edges.find((e) => e.id === 'e-fqdn-r-1-caddy')!;
		expect((primaryEdge.data as FlowEdgeData).reqPerSec).toBe(0);
	});

	it('primary FQDN edge keeps full route rate when route has no aliases', () => {
		// Backward-compat: without aliases there is no subtraction
		// to apply. The primary edge must carry route.reqPerSec
		// unchanged.
		const graph = buildTopologyGraph([makeRoute({ id: 'r-1', reqPerSec: 42 })]);
		const primaryEdge = graph.edges.find((e) => e.id === 'e-fqdn-r-1-caddy')!;
		expect((primaryEdge.data as FlowEdgeData).reqPerSec).toBe(42);
	});

	it('21-alias realistic-load case (operator traefik scenario) layouts cleanly', () => {
		// Mirrors the operator's empirically-validated case from
		// the Phase 2.2 smoke: 21 aliases on a single route, top
		// 3 consumers carrying real traffic, rest idle. With
		// Phase 3.c: 1 container + 21 alias nodes; only 3 alias
		// edges to Caddy (the actives); sort preserved end-to-end.
		const heavyAliases: TopologyAlias[] = [
			alias('sonarr.traefik.local', 0.94),
			alias('radarr.traefik.local', 0.47),
			alias('logs.traefik.local', 0.07),
			...Array.from({ length: 18 }, (_, i) => alias(`idle${i}.traefik.local`, 0))
		];
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'traefik',
				host: 'traefik.local',
				reqPerSec: 1.48,
				aliasMetrics: heavyAliases
			})
		]);
		expect(graph.nodes.filter((n) => n.type === 'route-group')).toHaveLength(1);
		const aliasNodes = graph.nodes.filter((n) => n.type === 'alias');
		expect(aliasNodes).toHaveLength(21);

		// Only the 3 actives emit edges to Caddy.
		const aliasEdges = graph.edges.filter((e) => e.source.startsWith('alias-traefik-'));
		expect(aliasEdges).toHaveLength(3);

		// Sort preserved: backend-supplied order matches node
		// order when sorted by y position.
		const aliasNodesSorted = [...aliasNodes].sort((a, b) => a.position.y - b.position.y);
		const renderedHosts = aliasNodesSorted.map((n) => (n.data as AliasNodeData).host);
		const expectedHosts = heavyAliases.map((a) => a.host);
		expect(renderedHosts).toEqual(expectedHosts);

		// Top consumer (sonarr) is closest to the primary FQDN.
		const fqdn = graph.nodes.find((n) => n.id === 'fqdn-traefik')!;
		const closestAliasToFqdn = aliasNodesSorted.find((n) => n.position.y > fqdn.position.y)!;
		expect((closestAliasToFqdn.data as AliasNodeData).host).toBe('sonarr.traefik.local');

		// Primary edge clamped at zero: alias sum (1.48) ==
		// route rate (1.48), so primary's share is exactly 0.
		const primaryEdge = graph.edges.find((e) => e.id === 'e-fqdn-traefik-caddy')!;
		expect((primaryEdge.data as FlowEdgeData).reqPerSec).toBeCloseTo(0, 5);
	});
});
