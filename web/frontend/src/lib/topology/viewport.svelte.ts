// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Topology viewport store (Step F Chunk 4b.2). Singleton class
// instance pattern, consistent with auth.svelte.ts / theme.svelte.ts
// / topology.svelte.ts.
//
// The viewport holds the transform applied to the topology graph:
// a translation (x, y) and a uniform scale (k). The TopologySvg
// component reads these via the rune fields and writes them via
// the pan/zoom/reset/fitView methods.
//
// Coordinate convention: (x, y) are screen-space offsets (CSS px)
// applied via `transform="translate(x y) scale(k)"` on the SVG's
// inner <g>. Layout coordinates from lib/topology/layout.ts are in
// the same logical space; the transform maps them to screen pixels.
//
// No localStorage persistence — the viewport resets to identity on
// every page load. Less surprise than restoring a stale pan/zoom
// the user has forgotten about; the layout itself is stable
// enough that fitView() on mount lands the right initial frame.

/** Minimum zoom level (10× zoom-out from identity). */
export const MIN_ZOOM = 0.3;

/** Maximum zoom level (3× zoom-in from identity). */
export const MAX_ZOOM = 3;

const INITIAL_X = 0;
const INITIAL_Y = 0;
const INITIAL_K = 1;

/** Axis-aligned bounding box in topology logical coordinates. */
export interface BBox {
	minX: number;
	minY: number;
	maxX: number;
	maxY: number;
}

class ViewportStore {
	x = $state(INITIAL_X);
	y = $state(INITIAL_Y);
	k = $state(INITIAL_K);

	/** Translate the viewport by (dx, dy) in screen pixels. Used
	 *  by pointer-drag listeners — the deltas already account for
	 *  the device pixel ratio. Zoom level is untouched. */
	pan(dx: number, dy: number): void {
		this.x += dx;
		this.y += dy;
	}

	/** Multiplicative zoom around a screen-space anchor point.
	 *
	 *  Math: when zooming, the visual point under the cursor must
	 *  stay under the cursor — otherwise the user feels the graph
	 *  "running away" from them. Given a current transform (x, y, k)
	 *  and an anchor (cx, cy) in screen space, the topology-space
	 *  point under the cursor is:
	 *    px = (cx - x) / k
	 *    py = (cy - y) / k
	 *  After zooming to k', we want that same px/py under cx/cy:
	 *    cx = x' + px * k'   →   x' = cx - px * k'
	 *  Substituting px = (cx - x) / k:
	 *    x' = cx - (cx - x) * k' / k
	 *  Same for y.
	 *
	 *  `deltaScale` is a multiplicative factor (e.g., 1.1 = zoom in
	 *  10 %, 0.9 = zoom out 10 %). The new k is clamped to
	 *  [MIN_ZOOM, MAX_ZOOM]; if the clamp is hit, no work happens
	 *  (otherwise the pan would still update against an unchanged
	 *  scale and shift the graph for no reason). */
	zoom(deltaScale: number, centerX: number, centerY: number): void {
		const newK = clamp(this.k * deltaScale, MIN_ZOOM, MAX_ZOOM);
		if (newK === this.k) return;
		this.x = centerX - ((centerX - this.x) * newK) / this.k;
		this.y = centerY - ((centerY - this.y) * newK) / this.k;
		this.k = newK;
	}

	/** Reset to identity transform. */
	reset(): void {
		this.x = INITIAL_X;
		this.y = INITIAL_Y;
		this.k = INITIAL_K;
	}

	/** Center and zoom to fit a bounding box into the viewport.
	 *
	 *  `bbox` is in topology logical coordinates (the layout space).
	 *  `viewportWidth` / `viewportHeight` are the visible area in
	 *  screen pixels — passed as arguments rather than read from the
	 *  DOM so the store stays SSR-safe and easy to unit-test.
	 *  `padding` (default 80 px) leaves visual breathing room
	 *  around the bbox.
	 *
	 *  The resulting scale fits the bbox by its tighter axis; the
	 *  translation centers the bbox's midpoint in the viewport. */
	fitView(
		bbox: BBox,
		viewportWidth: number,
		viewportHeight: number,
		padding: number = 80
	): void {
		const bboxW = bbox.maxX - bbox.minX;
		const bboxH = bbox.maxY - bbox.minY;
		if (bboxW <= 0 || bboxH <= 0 || viewportWidth <= 0 || viewportHeight <= 0) {
			this.reset();
			return;
		}
		const availW = Math.max(1, viewportWidth - 2 * padding);
		const availH = Math.max(1, viewportHeight - 2 * padding);
		const k = clamp(Math.min(availW / bboxW, availH / bboxH), MIN_ZOOM, MAX_ZOOM);
		const cx = (bbox.minX + bbox.maxX) / 2;
		const cy = (bbox.minY + bbox.maxY) / 2;
		this.k = k;
		this.x = viewportWidth / 2 - cx * k;
		this.y = viewportHeight / 2 - cy * k;
	}
}

function clamp(value: number, min: number, max: number): number {
	if (value < min) return min;
	if (value > max) return max;
	return value;
}

export const viewport = new ViewportStore();
