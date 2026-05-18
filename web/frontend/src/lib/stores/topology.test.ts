// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import type { Snapshot } from '$lib/api/topology';
import {
	applyTick,
	clampErrRate,
	isActive,
	isErrorSpike,
	type RouteState
} from './topology.svelte';
import {
	ACTIVE_WINDOW_MS,
	HISTORY_CAPACITY,
	SPIKE_THRESHOLD,
	SPIKE_WINDOW_TICKS
} from './topology-constants';

const NOW = 1_700_000_000_000; // arbitrary fixed epoch ms

function snap(routes: Snapshot['routes'], t = '2026-05-18T18:00:00Z'): Snapshot {
	return { t, routes };
}

// --- clampErrRate ----------------------------------------------------------

describe('clampErrRate', () => {
	it('returns 0 for negative values', () => {
		expect(clampErrRate(-0.1)).toBe(0);
		expect(clampErrRate(-Infinity)).toBe(0);
	});
	it('returns 1 for values > 1 (spec §11.8 swap race mitigation)', () => {
		expect(clampErrRate(1.5)).toBe(1);
		expect(clampErrRate(10)).toBe(1);
	});
	it('returns the value unchanged when in [0, 1]', () => {
		expect(clampErrRate(0)).toBe(0);
		expect(clampErrRate(0.5)).toBe(0.5);
		expect(clampErrRate(1)).toBe(1);
	});
	it('returns 0 for NaN', () => {
		expect(clampErrRate(NaN)).toBe(0);
	});

	it('returns 0 for non-finite Infinity (treated as invalid)', () => {
		// Number.isFinite(Infinity) is false → guard branch returns 0
		// BEFORE the > 1 clamp triggers. This is acceptable behavior
		// since Infinity should never come from the server's wire
		// shape (Go float64 encoded as JSON would emit "Infinity" as
		// a non-standard token that JSON.parse rejects anyway).
		expect(clampErrRate(Infinity)).toBe(0);
		expect(clampErrRate(-Infinity)).toBe(0);
	});
});

// --- applyTick -------------------------------------------------------------

describe('applyTick', () => {
	it('inserts a new RouteState when seen for the first time', () => {
		const routes = new Map<string, RouteState>();
		applyTick(
			routes,
			snap([
				{
					id: 'r1',
					host: 'app.example',
					upstream: 'http://10.0.0.1:80',
					reqs: 10,
					errs: 0,
					reqPerSec: 10,
					errRate5xx: 0
				}
			]),
			NOW
		);
		const r1 = routes.get('r1');
		expect(r1).toBeDefined();
		expect(r1?.host).toBe('app.example');
		expect(r1?.upstream).toBe('http://10.0.0.1:80');
		expect(r1?.reqPerSec).toBe(10);
		expect(r1?.errRate5xx).toBe(0);
		expect(r1?.history).toEqual([{ reqs: 10, errs: 0, ts: NOW }]);
	});

	it('appends to history on subsequent ticks for the same route', () => {
		const routes = new Map<string, RouteState>();
		applyTick(routes, snap([{ id: 'r1', host: 'h', upstream: 'u', reqs: 1, errs: 0, reqPerSec: 1, errRate5xx: 0 }]), NOW);
		applyTick(routes, snap([{ id: 'r1', host: 'h', upstream: 'u', reqs: 5, errs: 1, reqPerSec: 5, errRate5xx: 0.2 }]), NOW + 1000);
		const r1 = routes.get('r1');
		expect(r1?.history).toHaveLength(2);
		expect(r1?.history[1]).toEqual({ reqs: 5, errs: 1, ts: NOW + 1000 });
		expect(r1?.reqPerSec).toBe(5);
		expect(r1?.errRate5xx).toBeCloseTo(0.2);
	});

	it('trims history to HISTORY_CAPACITY (60 ticks)', () => {
		const routes = new Map<string, RouteState>();
		// Apply HISTORY_CAPACITY + 10 ticks.
		for (let i = 0; i < HISTORY_CAPACITY + 10; i++) {
			applyTick(
				routes,
				snap([{ id: 'r1', host: 'h', upstream: 'u', reqs: i, errs: 0, reqPerSec: i, errRate5xx: 0 }]),
				NOW + i * 1000
			);
		}
		const r1 = routes.get('r1');
		expect(r1?.history).toHaveLength(HISTORY_CAPACITY);
		// Oldest entry should now correspond to tick i = 10 (the
		// first 10 dropped).
		expect(r1?.history[0].reqs).toBe(10);
		expect(r1?.history[HISTORY_CAPACITY - 1].reqs).toBe(HISTORY_CAPACITY + 10 - 1);
	});

	it('clamps errRate5xx > 1 to 1 (spec §11.8)', () => {
		const routes = new Map<string, RouteState>();
		applyTick(
			routes,
			snap([{ id: 'r1', host: 'h', upstream: 'u', reqs: 5, errs: 99, reqPerSec: 5, errRate5xx: 19.8 }]),
			NOW
		);
		expect(routes.get('r1')?.errRate5xx).toBe(1);
	});

	it('does NOT remove routes absent from the snapshot', () => {
		const routes = new Map<string, RouteState>();
		applyTick(routes, snap([{ id: 'r1', host: 'h', upstream: 'u', reqs: 1, errs: 0, reqPerSec: 1, errRate5xx: 0 }]), NOW);
		// Apply a tick that mentions only r2.
		applyTick(routes, snap([{ id: 'r2', host: 'h2', upstream: 'u2', reqs: 1, errs: 0, reqPerSec: 1, errRate5xx: 0 }]), NOW + 1000);
		expect(routes.has('r1')).toBe(true);
		expect(routes.has('r2')).toBe(true);
	});

	it('updates host/upstream when they change (route in-place update)', () => {
		// Spec §11.2: a route updated in place (same ID, new upstream)
		// keeps its history. host/upstream MUST be refreshed.
		const routes = new Map<string, RouteState>();
		applyTick(routes, snap([{ id: 'r1', host: 'old.example', upstream: 'http://old:80', reqs: 1, errs: 0, reqPerSec: 1, errRate5xx: 0 }]), NOW);
		applyTick(routes, snap([{ id: 'r1', host: 'new.example', upstream: 'http://new:80', reqs: 2, errs: 0, reqPerSec: 2, errRate5xx: 0 }]), NOW + 1000);
		const r1 = routes.get('r1');
		expect(r1?.host).toBe('new.example');
		expect(r1?.upstream).toBe('http://new:80');
		expect(r1?.history).toHaveLength(2);
	});
});

// --- isActive --------------------------------------------------------------

describe('isActive', () => {
	it('returns false on empty history', () => {
		const state: RouteState = {
			id: 'r',
			host: 'h',
			upstream: 'u',
			history: [],
			reqPerSec: 0,
			errRate5xx: 0
		};
		expect(isActive(state, NOW)).toBe(false);
	});

	it('returns true when a recent tick has reqs > 0', () => {
		const state: RouteState = {
			id: 'r',
			host: 'h',
			upstream: 'u',
			history: [{ reqs: 5, errs: 0, ts: NOW - 1000 }],
			reqPerSec: 5,
			errRate5xx: 0
		};
		expect(isActive(state, NOW)).toBe(true);
	});

	it('returns false when only old ticks had traffic', () => {
		const state: RouteState = {
			id: 'r',
			host: 'h',
			upstream: 'u',
			history: [{ reqs: 10, errs: 0, ts: NOW - ACTIVE_WINDOW_MS - 1000 }],
			reqPerSec: 0,
			errRate5xx: 0
		};
		expect(isActive(state, NOW)).toBe(false);
	});

	it('returns false when recent ticks all have reqs == 0', () => {
		const state: RouteState = {
			id: 'r',
			host: 'h',
			upstream: 'u',
			history: Array.from({ length: 30 }, (_, i) => ({ reqs: 0, errs: 0, ts: NOW - i * 1000 })),
			reqPerSec: 0,
			errRate5xx: 0
		};
		expect(isActive(state, NOW)).toBe(false);
	});
});

// --- isErrorSpike ----------------------------------------------------------

describe('isErrorSpike', () => {
	it('returns false on empty history', () => {
		const state: RouteState = {
			id: 'r',
			host: 'h',
			upstream: 'u',
			history: [],
			reqPerSec: 0,
			errRate5xx: 0
		};
		expect(isErrorSpike(state)).toBe(false);
	});

	it('returns false when window has zero total reqs', () => {
		const state: RouteState = {
			id: 'r',
			host: 'h',
			upstream: 'u',
			history: [
				{ reqs: 0, errs: 0, ts: NOW - 2000 },
				{ reqs: 0, errs: 0, ts: NOW - 1000 }
			],
			reqPerSec: 0,
			errRate5xx: 0
		};
		expect(isErrorSpike(state)).toBe(false);
	});

	it('returns false when errRate over window is below SPIKE_THRESHOLD', () => {
		// 100 reqs total, 1 err → 1% < 5%.
		const state: RouteState = {
			id: 'r',
			host: 'h',
			upstream: 'u',
			history: [
				{ reqs: 50, errs: 1, ts: NOW - 1000 },
				{ reqs: 50, errs: 0, ts: NOW }
			],
			reqPerSec: 50,
			errRate5xx: 0
		};
		expect(isErrorSpike(state)).toBe(false);
	});

	it('returns true when errRate over window exceeds SPIKE_THRESHOLD', () => {
		// 100 reqs total, 10 errs → 10% > 5%.
		const state: RouteState = {
			id: 'r',
			host: 'h',
			upstream: 'u',
			history: [
				{ reqs: 50, errs: 5, ts: NOW - 1000 },
				{ reqs: 50, errs: 5, ts: NOW }
			],
			reqPerSec: 50,
			errRate5xx: 0.1
		};
		expect(isErrorSpike(state)).toBe(true);
	});

	it('uses ONLY the last SPIKE_WINDOW_TICKS entries', () => {
		// Older ticks dominated by errors; recent ticks clean. Window
		// should NOT include the old errors.
		const old: { reqs: number; errs: number; ts: number }[] = Array.from(
			{ length: 30 },
			(_, i) => ({ reqs: 10, errs: 9, ts: NOW - (60 - i) * 1000 })
		);
		const recent: { reqs: number; errs: number; ts: number }[] = Array.from(
			{ length: SPIKE_WINDOW_TICKS },
			(_, i) => ({ reqs: 10, errs: 0, ts: NOW - (SPIKE_WINDOW_TICKS - i) * 1000 })
		);
		const state: RouteState = {
			id: 'r',
			host: 'h',
			upstream: 'u',
			history: [...old, ...recent],
			reqPerSec: 10,
			errRate5xx: 0
		};
		expect(isErrorSpike(state)).toBe(false);
	});
});

// --- Threshold boundary cases ---------------------------------------------

describe('SPIKE_THRESHOLD boundary', () => {
	it('returns false when errRate equals SPIKE_THRESHOLD exactly', () => {
		// strict > comparison per implementation: 5/100 = 0.05 == threshold → NOT a spike.
		const state: RouteState = {
			id: 'r',
			host: 'h',
			upstream: 'u',
			history: [{ reqs: 100, errs: 5, ts: NOW }],
			reqPerSec: 100,
			errRate5xx: SPIKE_THRESHOLD
		};
		expect(isErrorSpike(state)).toBe(false);
	});
});
