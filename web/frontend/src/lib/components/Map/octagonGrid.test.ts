// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { octagonCells, octagonPath } from './octagonGrid';

describe('octagonCells', () => {
	// A fake projection: screen == lon/lat (identity invert), and a square
	// "continent" between [4,4] and [16,16] in screen units.
	const invert = (p: [number, number]): [number, number] => [p[0], p[1]];
	const onLand = (ll: [number, number]): boolean =>
		ll[0] >= 4 && ll[0] <= 16 && ll[1] >= 4 && ll[1] <= 16;

	it('keeps only cells whose geographic position is on land', () => {
		const cells = octagonCells(20, 20, 4, invert, onLand);
		// Grid centers at 2,6,10,14,18 on each axis. On-land ones are those
		// with both coords in [4,16]: {6,10,14} × {6,10,14} = 9 cells.
		expect(cells.length).toBe(9);
		for (const c of cells) {
			expect(onLand([c.x, c.y])).toBe(true);
		}
		// The ocean corner (2,2) must not be present.
		expect(cells.some((c) => c.x === 2 && c.y === 2)).toBe(false);
	});

	it('drops cells the projection cannot invert (null = outside domain)', () => {
		const nullInvert = () => null;
		expect(octagonCells(20, 20, 4, nullInvert, onLand)).toHaveLength(0);
	});

	it('returns nothing for a degenerate grid', () => {
		expect(octagonCells(0, 20, 4, invert, onLand)).toHaveLength(0);
		expect(octagonCells(20, 20, 0, invert, onLand)).toHaveLength(0);
	});
});

describe('octagonPath', () => {
	it('is a closed path with 8 vertices', () => {
		const d = octagonPath(10, 10, 5);
		expect(d.startsWith('M')).toBe(true);
		expect(d.endsWith('Z')).toBe(true);
		// 8 vertices → 1 "M" + 7 "L".
		expect((d.match(/L/g) ?? []).length).toBe(7);
	});

	it('stays within the circumradius of the center', () => {
		const d = octagonPath(10, 10, 5);
		const coords = d
			.replace(/[MZ]/g, '')
			.split('L')
			.map((p) => p.split(',').map(Number));
		for (const [x, y] of coords) {
			const dist = Math.hypot(x - 10, y - 10);
			// octagonPath rounds coords to 2 decimals to keep the SVG path
			// compact, so allow a matching tolerance.
			expect(dist).toBeCloseTo(5, 2);
		}
	});
});
