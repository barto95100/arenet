// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.78 — octagon dot-matrix map style. Instead of filling country
// polygons, we sample a regular screen-space grid and keep only the cells
// that fall on land, drawing a small octagon at each. The result reads as
// continents built out of octagons (the SafeLine-style dotted map), using
// the SAME d3 projection + topojson land feature the continent style
// already has — no new dependency, no new data.
//
// Pure functions so the grid logic is unit-tested without a DOM or a real
// projection: the caller injects `invert` (projection.invert) and `onLand`
// (lonlat => d3.geoContains(land, lonlat)).

export interface OctaCell {
	/** Projected (screen) center, in viewBox units. */
	x: number;
	y: number;
}

/**
 * octagonCells walks a regular grid of spacing `stepPx` across the
 * width×height viewBox and returns the cell centers whose geographic
 * position is on land. Centers are offset by half a step so the grid is
 * symmetric and no octagon is clipped at the edges.
 *
 * `invert` maps a screen point back to [lon, lat] (or null when the point
 * is outside the projection's domain — e.g. the Mercator poles); `onLand`
 * decides whether a [lon, lat] is on land. Both are injected so this stays
 * pure and testable.
 */
export function octagonCells(
	width: number,
	height: number,
	stepPx: number,
	invert: (p: [number, number]) => [number, number] | null,
	onLand: (lonlat: [number, number]) => boolean
): OctaCell[] {
	const cells: OctaCell[] = [];
	if (stepPx <= 0 || width <= 0 || height <= 0) {
		return cells;
	}
	for (let y = stepPx / 2; y < height; y += stepPx) {
		for (let x = stepPx / 2; x < width; x += stepPx) {
			const ll = invert([x, y]);
			if (ll && onLand(ll)) {
				cells.push({ x, y });
			}
		}
	}
	return cells;
}

/**
 * nearestCellIndex returns the index of the cell whose center is closest to
 * (x, y), or -1 for an empty list. Used to light up the octagon nearest an
 * attack's projected source (v2.78.4). Linear scan — cheap at the per-event
 * rate, and squared distance avoids a sqrt per cell.
 */
export function nearestCellIndex(cells: readonly OctaCell[], x: number, y: number): number {
	let best = -1;
	let bestD2 = Infinity;
	for (let i = 0; i < cells.length; i++) {
		const dx = cells[i].x - x;
		const dy = cells[i].y - y;
		const d2 = dx * dx + dy * dy;
		if (d2 < bestD2) {
			bestD2 = d2;
			best = i;
		}
	}
	return best;
}

/**
 * maskOnLand returns a point-in-land predicate backed by a rasterised land
 * mask: RGBA pixel data (width×height) where a painted alpha (> 0) marks
 * land. Used by the octagon style's FAST path — the land is drawn once to
 * an offscreen canvas, then each grid cell is this O(1) pixel read instead
 * of a per-cell geoContains (the v2.78.0 freeze). Pure so the index math
 * (the off-by-one-prone part) is unit-tested without a canvas.
 */
export function maskOnLand(
	mask: Uint8ClampedArray | number[],
	width: number,
	height: number
): (p: [number, number]) => boolean {
	return (p: [number, number]): boolean => {
		const x = Math.round(p[0]);
		const y = Math.round(p[1]);
		if (x < 0 || y < 0 || x >= width || y >= height) return false;
		return mask[(y * width + x) * 4 + 3] > 0; // alpha channel
	};
}

/**
 * octagonPath returns an SVG path `d` for a regular octagon centered at
 * (cx, cy) with circumradius r. Vertices sit at 22.5° + k·45° so a flat
 * edge faces up — the orientation that tiles cleanly on a square grid.
 */
export function octagonPath(cx: number, cy: number, r: number): string {
	const pts: string[] = [];
	for (let k = 0; k < 8; k++) {
		const a = (Math.PI / 8) * (2 * k + 1); // 22.5°, 67.5°, …
		const x = cx + r * Math.cos(a);
		const y = cy + r * Math.sin(a);
		pts.push(`${x.toFixed(2)},${y.toFixed(2)}`);
	}
	return `M${pts.join('L')}Z`;
}
