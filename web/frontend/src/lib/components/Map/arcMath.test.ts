// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step V.6 — pure-function tests for arc geometry +
// lifecycle math. Drives the timing + bezier code without
// touching the DOM.

import { describe, it, expect } from 'vitest';
import {
	ARC_TRAVEL_MS,
	ARC_FADE_MS,
	ARC_TOTAL_MS,
	arcControl,
	arcExpired,
	arcPathAt,
	arcProgressAt,
	bezierAt
} from './arcMath';

describe('timing constants', () => {
	it('travel + fade equal total', () => {
		expect(ARC_TRAVEL_MS + ARC_FADE_MS).toBe(ARC_TOTAL_MS);
	});

	it('travel is at least 1 s (eye-readable on busy attacks)', () => {
		expect(ARC_TRAVEL_MS).toBeGreaterThanOrEqual(1000);
	});

	it('total stays under 5 s (DOM-resident arcs stay bounded)', () => {
		expect(ARC_TOTAL_MS).toBeLessThanOrEqual(5000);
	});
});

describe('arcControl', () => {
	it('returns the midpoint lifted by ARC_ELEVATION_FACTOR (0.15 per HF2) of source→target distance', () => {
		const [cx, cy] = arcControl([0, 0], [100, 0]);
		expect(cx).toBe(50);
		// Midpoint y = 0, lifted by 15% × 100 = 15, so cy = -15.
		// (V.8.HF2: was -30 with the original 0.3 factor —
		// changed to flatten the arc after operator video
		// review surfaced an end-of-travel descent.)
		expect(cy).toBe(-15);
	});

	it('zero-distance produces the same point on x and y', () => {
		const [cx, cy] = arcControl([42, 42], [42, 42]);
		expect(cx).toBe(42);
		expect(cy).toBe(42);
	});
});

describe('bezierAt', () => {
	it('t=0 returns the source', () => {
		expect(bezierAt([10, 20], [50, 30], [90, 40], 0)).toEqual([10, 20]);
	});

	it('t=1 returns the target', () => {
		expect(bezierAt([10, 20], [50, 30], [90, 40], 1)).toEqual([90, 40]);
	});

	it('t=0.5 sits on the bezier midpoint', () => {
		// Bezier midpoint = 0.25·s + 0.5·c + 0.25·e
		const s: [number, number] = [0, 0];
		const c: [number, number] = [50, -30];
		const e: [number, number] = [100, 0];
		const [mx, my] = bezierAt(s, c, e, 0.5);
		expect(mx).toBeCloseTo(0.25 * 0 + 0.5 * 50 + 0.25 * 100, 5);
		expect(my).toBeCloseTo(0.25 * 0 + 0.5 * -30 + 0.25 * 0, 5);
	});
});

describe('arcPathAt', () => {
	it('progress < 1 truncates at the head', () => {
		const d = arcPathAt([0, 0], [100, 0], 0.5);
		// Final point is the bezier at t=0.5, not (100, 0).
		expect(d).not.toContain('100 0');
		expect(d.startsWith('M 0 0')).toBe(true);
		// Path is a quadratic (`Q`).
		expect(d).toContain('Q');
	});

	it('progress = 1 reaches the target', () => {
		const d = arcPathAt([0, 0], [100, 0], 1);
		expect(d).toContain('100 0');
		expect(d.startsWith('M 0 0')).toBe(true);
	});

	it('progress > 1 still reaches the target (clamped behavior)', () => {
		const d = arcPathAt([0, 0], [100, 0], 1.5);
		expect(d).toContain('100 0');
	});

	// V.8.HF3 regression — the partial-curve endpoint MUST
	// be bezierAt(source, ctrl, target, progress) (i.e. the
	// point ON the full source→target curve at parameter t),
	// not stuck at the source. Pin this so a future drop
	// of the De Casteljau split reverts to the old
	// "head visually stuck near source" symptom.
	it('partial-curve endpoint advances along the full curve as progress grows', () => {
		const source: [number, number] = [0, 0];
		const target: [number, number] = [100, 0];
		const ctrl = arcControl(source, target);
		// Sample the path at three progress values; each
		// rendered endpoint MUST equal bezierAt at the same t.
		for (const t of [0.25, 0.5, 0.75]) {
			const expected = bezierAt(source, ctrl, target, t);
			const d = arcPathAt(source, target, t);
			// Path ends with the final `x y` pair after the
			// last `Q ctrl_x ctrl_y end_x end_y` block.
			const tokens = d.split(/\s+/);
			const ey = Number(tokens[tokens.length - 1]);
			const ex = Number(tokens[tokens.length - 2]);
			expect(ex).toBeCloseTo(expected[0], 5);
			expect(ey).toBeCloseTo(expected[1], 5);
		}
	});

	it('progress = 0 produces a path collapsed at the source (no curve drag)', () => {
		// At spawn (progress=0), head === source AND the
		// De Casteljau sub-control === source, so the path
		// is literally `M s Q s s`. Crucially, it MUST NOT
		// extend into the canvas — the operator should see
		// nothing until the timer starts advancing.
		const d = arcPathAt([10, 20], [200, 50], 0);
		// Endpoint is the source.
		const tokens = d.split(/\s+/);
		expect(Number(tokens[tokens.length - 2])).toBeCloseTo(10, 5);
		expect(Number(tokens[tokens.length - 1])).toBeCloseTo(20, 5);
		// Control point is also at the source (no leftover
		// drag from the full-curve control).
		expect(d).toBe('M 10 20 Q 10 20 10 20');
	});

	it('partial-curve sub-control is the source→ctrl lerp (De Casteljau invariant)', () => {
		const source: [number, number] = [0, 0];
		const target: [number, number] = [100, 0];
		const ctrl = arcControl(source, target); // [50, -15] with V.8.HF2 elevation
		const t = 0.4;
		const d = arcPathAt(source, target, t);
		// Sub-control = lerp(source, ctrl, t).
		const expectedSubCtrl: [number, number] = [
			source[0] + (ctrl[0] - source[0]) * t,
			source[1] + (ctrl[1] - source[1]) * t
		];
		const tokens = d.split(/\s+/);
		// Path shape: "M sx sy Q cx cy ex ey"
		const cx = Number(tokens[4]);
		const cy = Number(tokens[5]);
		expect(cx).toBeCloseTo(expectedSubCtrl[0], 5);
		expect(cy).toBeCloseTo(expectedSubCtrl[1], 5);
	});
});

describe('arcProgressAt', () => {
	it('elapsed = 0 → progress 0, opacity 1', () => {
		const { progress, opacity } = arcProgressAt(0, 0);
		expect(progress).toBe(0);
		expect(opacity).toBe(1);
	});

	it('elapsed midway through travel → progress = midway, opacity 1', () => {
		const { progress, opacity } = arcProgressAt(0, ARC_TRAVEL_MS / 2);
		expect(progress).toBeCloseTo(0.5, 5);
		expect(opacity).toBe(1);
	});

	it('elapsed = ARC_TRAVEL_MS → progress 1, opacity 1 (just arrived)', () => {
		const { progress, opacity } = arcProgressAt(0, ARC_TRAVEL_MS);
		expect(progress).toBe(1);
		expect(opacity).toBe(1);
	});

	it('elapsed midway through fade → progress 1, opacity midway', () => {
		const { progress, opacity } = arcProgressAt(
			0,
			ARC_TRAVEL_MS + ARC_FADE_MS / 2
		);
		expect(progress).toBe(1);
		expect(opacity).toBeCloseTo(0.5, 5);
	});

	it('elapsed = ARC_TOTAL_MS → progress 1, opacity 0', () => {
		const { progress, opacity } = arcProgressAt(0, ARC_TOTAL_MS);
		expect(progress).toBe(1);
		expect(opacity).toBe(0);
	});

	it('elapsed past ARC_TOTAL_MS → opacity clamped at 0', () => {
		const { opacity } = arcProgressAt(0, ARC_TOTAL_MS + 999);
		expect(opacity).toBe(0);
	});
});

describe('arcExpired', () => {
	it('returns false during travel', () => {
		expect(arcExpired(0, ARC_TRAVEL_MS / 2)).toBe(false);
	});

	it('returns false during fade', () => {
		expect(arcExpired(0, ARC_TRAVEL_MS + 100)).toBe(false);
	});

	it('returns true exactly at ARC_TOTAL_MS', () => {
		expect(arcExpired(0, ARC_TOTAL_MS)).toBe(true);
	});

	it('returns true past ARC_TOTAL_MS', () => {
		expect(arcExpired(0, ARC_TOTAL_MS + 1)).toBe(true);
	});
});
