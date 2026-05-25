// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step J.6 — auto-fit trigger gate (Finding #10 fix). Pure-
// function tests for the predicate the /topology page's
// $effect uses to decide whether to fire viewport.fitView()
// on the first non-empty data tick.
//
// The spec §5.5 calls out two distinct test shapes here:
//   - fit-on-first-data    → the predicate flips true at the
//                            empty→populated transition, and the
//                            viewport store carries the fitView
//                            output afterwards;
//   - auto-fit guard       → the predicate stays false on an
//                            empty store, no fitView fires, the
//                            viewport store stays at its initial
//                            identity transform.
//
// Both shapes are exercised below. The page-level $effect
// integration is the live J.7 smoke target; the unit tests here
// pin the predicate so a regression that re-enables "fit on
// every tick" or "fit before layout measured" can't slip through.

import { afterEach, describe, expect, it } from 'vitest';
import { shouldAutoFit } from './auto-fit';
import { viewport } from './viewport.svelte';
import { computeTopologyBBox } from './bounds';

describe('shouldAutoFit', () => {
	// Baseline: every guard satisfied → fires.
	it('fires when transitioning from zero to non-zero with measured viewport', () => {
		expect(
			shouldAutoFit({
				hasFit: false,
				routesCount: 3,
				viewportWidth: 1200,
				viewportHeight: 800
			})
		).toBe(true);
	});

	// One guard at a time — each must short-circuit independently
	// so a regression that drops or weakens any one guard is named.
	it('does not fire when hasFit is true (already fitted once)', () => {
		expect(
			shouldAutoFit({
				hasFit: true,
				routesCount: 3,
				viewportWidth: 1200,
				viewportHeight: 800
			})
		).toBe(false);
	});

	it('does not fire when routesCount is zero (empty store at mount)', () => {
		// This is the auto-fit guard from the spec: fitView() must
		// not be called against zero nodes — its bbox math would
		// produce an identity / NaN transform that's worse than the
		// pre-J.6 behaviour.
		expect(
			shouldAutoFit({
				hasFit: false,
				routesCount: 0,
				viewportWidth: 1200,
				viewportHeight: 800
			})
		).toBe(false);
	});

	it('does not fire when viewportWidth is zero (layout not measured)', () => {
		// bind:clientWidth reports 0 before the first layout flush;
		// fitView would divide by zero. The gate defuses the trap.
		expect(
			shouldAutoFit({
				hasFit: false,
				routesCount: 3,
				viewportWidth: 0,
				viewportHeight: 800
			})
		).toBe(false);
	});

	it('does not fire when viewportHeight is zero (layout not measured)', () => {
		expect(
			shouldAutoFit({
				hasFit: false,
				routesCount: 3,
				viewportWidth: 1200,
				viewportHeight: 0
			})
		).toBe(false);
	});

	it('does not fire when both viewport dimensions are zero', () => {
		expect(
			shouldAutoFit({
				hasFit: false,
				routesCount: 3,
				viewportWidth: 0,
				viewportHeight: 0
			})
		).toBe(false);
	});
});

describe('auto-fit integration (gate + viewport.fitView)', () => {
	afterEach(() => {
		// The viewport store is a module-level singleton; restore
		// identity transform between tests so a stale fit from one
		// test doesn't leak into the next.
		viewport.reset();
	});

	// Spec §5.5: "with the topology store seeded empty, then
	// populated with two routes via a simulated snapshot, the
	// viewport transform must equal fitView()'s output once and
	// only once."
	//
	// We replicate that without booting the page or the WS: drive
	// the gate manually across an empty→populated→further-tick
	// sequence and assert the viewport store moves once.
	it('fitView fires once at empty→populated transition; second tick is a no-op', () => {
		let hasFit = false;
		const dims = { viewportWidth: 1200, viewportHeight: 800 };

		// Tick 1: empty store, gate refuses, viewport stays at
		// identity (x=0, y=0, k=1).
		if (
			shouldAutoFit({ hasFit, routesCount: 0, ...dims })
		) {
			viewport.fitView(computeTopologyBBox(0), dims.viewportWidth, dims.viewportHeight, 40);
			hasFit = true;
		}
		expect(hasFit).toBe(false);
		expect(viewport.k).toBe(1);
		expect(viewport.x).toBe(0);
		expect(viewport.y).toBe(0);

		// Tick 2: 2 routes appear, gate fires, viewport updates.
		if (
			shouldAutoFit({ hasFit, routesCount: 2, ...dims })
		) {
			viewport.fitView(computeTopologyBBox(2), dims.viewportWidth, dims.viewportHeight, 40);
			hasFit = true;
		}
		expect(hasFit).toBe(true);
		// The viewport must have moved off identity — the precise
		// k value depends on computeTopologyBBox(2)'s shape, but it
		// cannot be the initial (0, 0, 1) anymore. Assert at least
		// one of {x, y, k} changed.
		const afterFirstFit = { x: viewport.x, y: viewport.y, k: viewport.k };
		expect(
			afterFirstFit.x !== 0 || afterFirstFit.y !== 0 || afterFirstFit.k !== 1
		).toBe(true);

		// Tick 3: the count climbs (3 routes), gate must NOT fire
		// again — re-fitting on every snapshot would make the
		// viewport jump every second. The store must remain at
		// the post-first-fit transform.
		if (
			shouldAutoFit({ hasFit, routesCount: 3, ...dims })
		) {
			viewport.fitView(computeTopologyBBox(3), dims.viewportWidth, dims.viewportHeight, 40);
			hasFit = true;
		}
		expect(viewport.x).toBe(afterFirstFit.x);
		expect(viewport.y).toBe(afterFirstFit.y);
		expect(viewport.k).toBe(afterFirstFit.k);
	});

	// Spec §5.5 second test: "with the store still empty after
	// mount, the viewport transform must equal its initial value —
	// fitView() must not have been called against zero nodes."
	it('viewport stays at identity when the store never populates', () => {
		let hasFit = false;
		const dims = { viewportWidth: 1200, viewportHeight: 800 };

		// Mimic three consecutive ticks with a still-empty store
		// (e.g. WebSocket connected but no routes configured yet).
		for (const _ of [1, 2, 3]) {
			if (
				shouldAutoFit({ hasFit, routesCount: 0, ...dims })
			) {
				viewport.fitView(computeTopologyBBox(0), dims.viewportWidth, dims.viewportHeight, 40);
				hasFit = true;
			}
		}

		expect(hasFit).toBe(false);
		expect(viewport.x).toBe(0);
		expect(viewport.y).toBe(0);
		expect(viewport.k).toBe(1);
	});
});
