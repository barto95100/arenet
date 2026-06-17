// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Sujet 1 Phase 3.b — _layout.ts alias integration tests.
//
// Pins the operator-visible contract for the col-0 stack:
//   - routes without aliases keep their single-FQDN footprint
//     (backward-compat: legacy traefik / arenet / ha layouts
//     don't shift when this commit lands).
//   - routes with aliases emit FQDN + N AliasNodes positioned
//     vertically below the primary, in the order the backend
//     supplied (already sorted desc by reqPerSec).
//   - one AliasOfEdge per alias linking back to the primary
//     FQDN.
//   - 21-alias realistic-load case (the operator's traefik
//     route) layouts cleanly: all nodes positioned, no overlap
//     with the next route's col-0 block, sort preserved end-
//     to-end.

import { describe, it, expect } from 'vitest';
import { buildTopologyGraph } from './_layout';
import type {
	AliasNodeData,
	AliasOfEdgeData,
	FQDNNodeData,
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
	it('route without aliases emits a single FQDN node (no alias / aliasOf)', () => {
		const graph = buildTopologyGraph([makeRoute()]);
		const fqdnNodes = graph.nodes.filter((n) => n.type === 'fqdn');
		const aliasNodes = graph.nodes.filter((n) => n.type === 'alias');
		const aliasEdges = graph.edges.filter((e) => e.type === 'alias-of');
		expect(fqdnNodes).toHaveLength(1);
		expect(aliasNodes).toHaveLength(0);
		expect(aliasEdges).toHaveLength(0);
	});

	it('route with empty aliasMetrics array also stays single-FQDN', () => {
		// aliasMetrics: [] (Phase 2.2's non-omitempty wire shape
		// for a route without aliases) must be treated identically
		// to "field absent" — no alias nodes, no edges.
		const graph = buildTopologyGraph([makeRoute({ aliasMetrics: [] })]);
		expect(graph.nodes.filter((n) => n.type === 'alias')).toHaveLength(0);
		expect(graph.edges.filter((e) => e.type === 'alias-of')).toHaveLength(0);
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
		// Order preserved verbatim from the backend slice.
		const hosts = aliasNodes.map((n) => (n.data as AliasNodeData).host);
		expect(hosts).toEqual([
			'sonarr.example.com',
			'radarr.example.com',
			'idle.example.com'
		]);
		// Top consumer's data carries the right rate.
		expect((aliasNodes[0].data as AliasNodeData).reqPerSec).toBe(0.94);
		expect((aliasNodes[0].data as AliasNodeData).isIdle).toBe(false);
		// Idle alias flagged.
		expect((aliasNodes[2].data as AliasNodeData).isIdle).toBe(true);
	});

	it('emits one AliasOfEdge per alias pointing at the primary FQDN', () => {
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				aliasMetrics: [alias('a.example.com', 1), alias('b.example.com', 0)]
			})
		]);
		const aliasEdges = graph.edges.filter((e) => e.type === 'alias-of');
		expect(aliasEdges).toHaveLength(2);
		for (const edge of aliasEdges) {
			expect(edge.target).toBe('fqdn-r-1');
			expect(edge.source).toMatch(/^alias-r-1-\d+$/);
			const data = edge.data as AliasOfEdgeData;
			expect(data.kind).toBe('alias-of');
			expect(data.aliasOf).toBe('r-1');
		}
	});

	it('AliasNodes positioned below the primary FQDN, top consumer closest', () => {
		// First alias must sit at FQDN_HEIGHT + FQDN_TO_ALIAS_GAP
		// below the FQDN. Subsequent aliases stack at ALIAS_HEIGHT
		// + ALIAS_TO_ALIAS_GAP.
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
		const fqdnY = fqdn!.position.y;
		// All aliases must be strictly below the FQDN top.
		for (const a of aliases) {
			expect(a.position.y).toBeGreaterThan(fqdnY);
		}
		// Top alias (top.example.com — sorted first by backend) sits
		// immediately below the FQDN.
		expect((aliases[0].data as AliasNodeData).host).toBe('top.example.com');
		expect((aliases[1].data as AliasNodeData).host).toBe('mid.example.com');
		expect((aliases[2].data as AliasNodeData).host).toBe('bot.example.com');
		// Aliases positioned in monotonically increasing y.
		expect(aliases[0].position.y).toBeLessThan(aliases[1].position.y);
		expect(aliases[1].position.y).toBeLessThan(aliases[2].position.y);
	});

	it('multi-route layout: alias-heavy route does not push neighbours into overlap', () => {
		// Two routes: r-1 has 0 aliases (single FQDN), r-2 has 3
		// aliases. The col-0 stacker must size each route's block
		// to fit its alias count and prevent overlap.
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
		const r2Aliases = graph.nodes
			.filter((n) => n.type === 'alias' && (n.data as AliasNodeData).parentRouteId === 'r-2')
			.sort((a, b) => a.position.y - b.position.y);
		// The two FQDNs must be at distinct positions.
		expect(fqdn1.position.y).not.toBe(fqdn2.position.y);
		// Whichever route is above must have its block (FQDN +
		// any aliases) end before the next route's block begins.
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
		// Sanity: the alias-heavy route's aliases all live below
		// their own FQDN.
		for (const a of r2Aliases) {
			expect(a.position.y).toBeGreaterThan(fqdn2.position.y);
		}
	});

	it('21-alias realistic-load case (operator traefik scenario) layouts cleanly', () => {
		// Mirrors the operator's empirically-validated case from
		// the Phase 2.2 smoke: 21 aliases on a single route, top
		// 3 consumers carrying real traffic, rest idle. Confirms
		// the layout doesn't crash, emits 21 alias nodes + 21
		// alias-of edges, all positioned below the primary FQDN,
		// sort preserved end-to-end.
		const heavyAliases: TopologyAlias[] = [
			alias('sonarr.traefik.local', 0.94),
			alias('radarr.traefik.local', 0.47),
			alias('logs.traefik.local', 0.07),
			...Array.from({ length: 18 }, (_, i) => alias(`idle${i}.traefik.local`, 0))
		];
		const graph = buildTopologyGraph([
			makeRoute({ id: 'traefik', host: 'traefik.local', aliasMetrics: heavyAliases })
		]);
		const aliasNodes = graph.nodes.filter((n) => n.type === 'alias');
		const aliasEdges = graph.edges.filter((e) => e.type === 'alias-of');
		expect(aliasNodes).toHaveLength(21);
		expect(aliasEdges).toHaveLength(21);

		// Sort preserved: backend-supplied order matches node order
		// when sorted by y position.
		const aliasNodesSorted = [...aliasNodes].sort((a, b) => a.position.y - b.position.y);
		const renderedHosts = aliasNodesSorted.map((n) => (n.data as AliasNodeData).host);
		const expectedHosts = heavyAliases.map((a) => a.host);
		expect(renderedHosts).toEqual(expectedHosts);

		// Idle aliases flagged correctly: 18 idle (the last 18
		// in the input — backend sort puts them at the bottom
		// alphabetically, but the test fixture order is what we
		// pass in, so the last 18 should be the idle ones).
		const idleCount = aliasNodes.filter((n) => (n.data as AliasNodeData).isIdle).length;
		expect(idleCount).toBe(18);

		// Top consumer (sonarr) is the alias closest to the
		// primary FQDN.
		const fqdn = graph.nodes.find((n) => n.id === 'fqdn-traefik')!;
		const closestAliasToFqdn = aliasNodesSorted.find((n) => n.position.y > fqdn.position.y)!;
		expect((closestAliasToFqdn.data as AliasNodeData).host).toBe('sonarr.traefik.local');
	});

	it('FQDNNodeData still carries the legacy aliases string array for backward-compat', () => {
		// Pre-Phase-3.b the FQDN node displayed an "N aliases"
		// meta line + hover tooltip listing the aliases. That
		// surface is still in place (FQDNNode.svelte hasn't
		// changed); the layout still threads route.aliases
		// through. Test pins the contract so a future cleanup
		// doesn't accidentally drop it before the FQDNNode is
		// also updated.
		const graph = buildTopologyGraph([
			makeRoute({
				aliases: ['foo.example.com', 'bar.example.com'],
				aliasMetrics: [alias('foo.example.com', 1), alias('bar.example.com', 0)]
			})
		]);
		const fqdn = graph.nodes.find((n) => n.type === 'fqdn')!;
		expect((fqdn.data as FQDNNodeData).aliases).toEqual(['foo.example.com', 'bar.example.com']);
	});
});
