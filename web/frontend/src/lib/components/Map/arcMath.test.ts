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
