// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step V.6 — pure geometry + timing math for the threat-
// map arc animation. Extracted from WorldMap.svelte's
// <script> block so the functions are unit-testable
// without rendering a Svelte component. Used by
// WorldMap.svelte's template (arc spawn + per-frame
// redraw) and by the test suite in arcMath.test.ts.
//
// All inputs are pixel-space (post-projection). The
// projection itself lives inside WorldMap because it
// depends on width/height/arenet props that change
// reactively; the math here is theme- and
// projection-agnostic.

/** Timing constants — see WorldMap.svelte for rationale. */
export const ARC_TRAVEL_MS = 2000;
export const ARC_FADE_MS = 1500;
export const ARC_TOTAL_MS = ARC_TRAVEL_MS + ARC_FADE_MS;

/**
 * Quadratic Bezier control point for an arc from `source`
 * to `target`. Midpoint lifted by ARC_ELEVATION_FACTOR of
 * the Euclidean distance above the line, giving each arc
 * a great-circle feel without paying for an actual
 * great-circle projection.
 *
 * V.8.HF2: factor lowered from 0.3 → 0.15 after operator
 * frame-by-frame video review (#R-MAP-arc-curve-asymmetry).
 * The original 0.3 elevation made the apparent visual
 * trajectory terminate ~25 px above the Arenet marker
 * before snapping down in the final ~10 % of animation
 * — perceived as "destination point is lower than the
 * arc's curve". 0.15 yields a flatter, more natural arc
 * that converges smoothly onto the target with no
 * end-of-travel descent.
 */
export const ARC_ELEVATION_FACTOR = 0.15;

export function arcControl(
	source: [number, number],
	target: [number, number]
): [number, number] {
	const mx = (source[0] + target[0]) / 2;
	const my = (source[1] + target[1]) / 2;
	const dist = Math.hypot(target[0] - source[0], target[1] - source[1]);
	return [mx, my - dist * ARC_ELEVATION_FACTOR];
}

/** Quadratic bezier point at parameter t ∈ [0, 1]. */
export function bezierAt(
	s: [number, number],
	c: [number, number],
	e: [number, number],
	t: number
): [number, number] {
	const u = 1 - t;
	return [
		u * u * s[0] + 2 * u * t * c[0] + t * t * e[0],
		u * u * s[1] + 2 * u * t * c[1] + t * t * e[1]
	];
}

/**
 * SVG path `d` attribute for an arc at `progress` (∈ [0,
 * 1]). During travel (progress < 1), the path truncates at
 * the bezier-interpolated head position. After arrival
 * (progress === 1), the path is the complete bezier.
 */
export function arcPathAt(
	source: [number, number],
	target: [number, number],
	progress: number
): string {
	const ctrl = arcControl(source, target);
	if (progress >= 1) {
		return `M ${source[0]} ${source[1]} Q ${ctrl[0]} ${ctrl[1]} ${target[0]} ${target[1]}`;
	}
	const head = bezierAt(source, ctrl, target, progress);
	return `M ${source[0]} ${source[1]} Q ${ctrl[0]} ${ctrl[1]} ${head[0]} ${head[1]}`;
}

/**
 * Progress + opacity for an arc at wall-clock time `t`
 * (ms since some epoch — typically performance.now()).
 * Phase 1 (travel) is progress 0 → 1 with full opacity;
 * phase 2 (fade) is progress 1 with opacity 1 → 0. Pure
 * function; the timer in WorldMap.svelte feeds this on
 * every frame.
 */
export function arcProgressAt(
	startMs: number,
	t: number
): { progress: number; opacity: number } {
	const elapsed = t - startMs;
	if (elapsed < ARC_TRAVEL_MS) {
		return { progress: elapsed / ARC_TRAVEL_MS, opacity: 1 };
	}
	const fadeElapsed = elapsed - ARC_TRAVEL_MS;
	const opacity = Math.max(0, 1 - fadeElapsed / ARC_FADE_MS);
	return { progress: 1, opacity };
}

/**
 * Whether the arc started at `startMs` has expired (past
 * its travel + fade window) at time `t`. Used by the
 * pruning pass to drop arcs from the in-DOM list.
 */
export function arcExpired(startMs: number, t: number): boolean {
	return t - startMs >= ARC_TOTAL_MS;
}
