// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Topology geometric constants + bounding-box helper (Step F Chunk
// 4b). Single source of truth for the 3-column SVG geometry shared
// by TopologySvg (which renders inside this bbox) and
// TopologyControls (which fits the viewport to it). Without this
// shared module, the two would each carry their own copy of the
// constants and drift the moment one of them is tweaked — exactly
// the bug surfaced when Chunk 4b.4 first hardcoded the bbox to
// 0..1200 × 0..600 while TopologySvg's svgHeight grows past 600
// once routes.length > 8.

import type { BBox } from './viewport.svelte';

/** SVG viewBox width. The 3-column layout fits in 1200 px and the
 *  inner <g class="viewport-content"> applies pan/zoom on top of
 *  that fixed coord system. */
export const SVG_WIDTH = 1200;

/** Minimum SVG viewBox height. Used when the routes list is short
 *  enough that the natural height (TOP_PAD + n × ROW_PITCH +
 *  BOTTOM_PAD) would be smaller than this — keeps the Clients
 *  pillar tall enough to read. */
export const MIN_SVG_HEIGHT = 600;

/** Per-route box height. Geometry constant — not a spacing token. */
export const NODE_HEIGHT = 56;
/** Vertical gap between two consecutive route boxes. */
export const NODE_GAP = 16;
/** Row pitch = height + gap. Each route occupies this much vertical space. */
export const ROW_PITCH = NODE_HEIGHT + NODE_GAP;
/** Top padding above the first route box. */
export const TOP_PAD = 20;
/** Bottom padding below the last route box. */
export const BOTTOM_PAD = 20;

/** Compute the actual SVG height for a given route count.
 *  Mirrors the $derived expression in TopologySvg.svelte; the two
 *  must remain identical (this module is now the canonical source —
 *  TopologySvg imports the constants and reads via this helper). */
export function computeSvgHeight(routesCount: number): number {
	return Math.max(MIN_SVG_HEIGHT, TOP_PAD + routesCount * ROW_PITCH + BOTTOM_PAD);
}

/** Compute the bounding box for the entire topology surface at a
 *  given route count. Used by TopologyControls.fitView and by
 *  TopologySvg's onMount fitView — same expression on both sides
 *  guarantees the fit-view button frames the same area the initial
 *  mount did. */
export function computeTopologyBBox(routesCount: number): BBox {
	return {
		minX: 0,
		minY: 0,
		maxX: SVG_WIDTH,
		maxY: computeSvgHeight(routesCount)
	};
}
