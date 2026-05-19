// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Tests for the topology layout pure function (Chunk 4b.1).
// The function is the basis of the topology refonte — getting it
// wrong is silently catastrophic (nodes overlap or scatter), so
// edge cases and stability are explicitly verified.

import { describe, it, expect } from 'vitest';
import { computeLayout, SPACING_X, SPACING_Y } from './layout';
import type { RouteState } from '$lib/stores/topology.svelte';

/** Build a minimal RouteState for layout tests. Only `id` is read
 *  by `computeLayout`; the rest is fluff. */
function r(id: string): RouteState {
	return {
		id,
		host: `${id}.example`,
		upstream: 'http://10.0.0.1:80',
		history: [],
		reqPerSec: 0,
		errRate5xx: 0
	};
}

describe('computeLayout', () => {
	it('returns an empty Map for an empty input', () => {
		const out = computeLayout([]);
		expect(out.size).toBe(0);
	});

	it('places a single route at the origin (0, 0)', () => {
		const out = computeLayout([r('a')]);
		expect(out.size).toBe(1);
		expect(out.get('a')).toEqual({ x: 0, y: 0 });
	});

	it('places 4 routes in a centered 2×2 grid', () => {
		// 4 routes, cols = ceil(sqrt(4)) = 2, rows = 2.
		// offsetX = -((2-1) * 280) / 2 = -140
		// offsetY = -((2-1) * 220) / 2 = -110
		// Sorted ids: a, b, c, d → positions:
		//   a: col 0 row 0 → (-140, -110)
		//   b: col 1 row 0 → ( 140, -110)
		//   c: col 0 row 1 → (-140,  110)
		//   d: col 1 row 1 → ( 140,  110)
		const out = computeLayout([r('a'), r('b'), r('c'), r('d')]);
		expect(out.size).toBe(4);
		expect(out.get('a')).toEqual({ x: -SPACING_X / 2, y: -SPACING_Y / 2 });
		expect(out.get('b')).toEqual({ x: SPACING_X / 2, y: -SPACING_Y / 2 });
		expect(out.get('c')).toEqual({ x: -SPACING_X / 2, y: SPACING_Y / 2 });
		expect(out.get('d')).toEqual({ x: SPACING_X / 2, y: SPACING_Y / 2 });
	});

	it('places 100 routes in a 10×10 grid', () => {
		const ids = Array.from({ length: 100 }, (_, i) =>
			// pad index to keep lexicographic order = numeric order.
			`r${i.toString().padStart(3, '0')}`
		);
		const routes = ids.map(r);
		const out = computeLayout(routes);

		expect(out.size).toBe(100);

		// cols = ceil(sqrt(100)) = 10
		// First sorted id is r000 at col 0 row 0
		// offsetX = -((10-1) * 280) / 2 = -1260
		// offsetY = -((10-1) * 220) / 2 = -990
		expect(out.get('r000')).toEqual({ x: -1260, y: -990 });
		// Last sorted id r099 at col 9 row 9: x = 9*280 - 1260 = 1260
		expect(out.get('r099')).toEqual({ x: 1260, y: 990 });
		// Middle-ish: r044 at col 4 row 4: x = 4*280 - 1260 = -140
		expect(out.get('r044')).toEqual({ x: -140, y: -110 });
	});

	it('is idempotent — same input order yields same positions on a second call', () => {
		const routes = [r('alpha'), r('beta'), r('gamma')];
		const first = computeLayout(routes);
		const second = computeLayout(routes);
		expect(first.size).toBe(second.size);
		for (const [id, pos] of first) {
			expect(second.get(id)).toEqual(pos);
		}
	});

	it('is order-independent — input order does not affect output', () => {
		// Same set of routes, two different array orderings.
		const a = computeLayout([r('a'), r('b'), r('c'), r('d')]);
		const b = computeLayout([r('d'), r('a'), r('c'), r('b')]);
		expect(a.size).toBe(b.size);
		for (const [id, pos] of a) {
			expect(b.get(id)).toEqual(pos);
		}
	});

	it('appending an id that sorts after existing ids does not shift earlier routes', () => {
		// Three routes whose ids sort alphabetically.
		const baseline = computeLayout([r('a'), r('b'), r('c')]);
		const baselineA = baseline.get('a');
		const baselineB = baseline.get('b');
		const baselineC = baseline.get('c');

		// Add 'z' which sorts AFTER all three; verify a/b/c keep
		// the exact same positions (stability guarantee).
		const expanded = computeLayout([r('a'), r('b'), r('c'), r('z')]);
		expect(expanded.get('a')).toEqual(baselineA);
		expect(expanded.get('b')).toEqual(baselineB);
		expect(expanded.get('c')).toEqual(baselineC);
		expect(expanded.has('z')).toBe(true);
	});
});
