// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Topology layout (Step F Chunk 4b). Pure function that maps a list
// of RouteState to a grid of (x, y) positions. Pre-Chunk-4a the
// topology used @xyflow/svelte's built-in layout; the spike went
// NO-GO on bundle (52 kB > 30 kB budget — spec §6 FINAL DECISION),
// so this module replaces the library-side layout with a tiny
// grid-based algorithm sized for homelab usage (< 50 routes typical).
//
// The function is intentionally pure (no DOM access, no side
// effects) so it's trivial to unit-test and to swap for a
// force-directed variant later if a user reports needing it.
//
// CURRENTLY UNUSED in Chunk 4b — the user-validated "Path C" kept
// the Step E 3-column layout (Clients pillar / Routes / Upstreams)
// instead of pivoting to a grid. This module ships unconsumed but
// fully tested as infra for Phase 2 sub-graphs or alternative
// layouts (a topology view that wants a free-form grid, a
// dependency graph between routes, etc.). Removal would be a
// regression — kept here intentionally.

import type { RouteState } from '$lib/stores/topology.svelte';

/** Horizontal spacing between grid columns (px). Sized for the
 *  ~200-px-wide node card + breathing room. */
export const SPACING_X = 280;

/** Vertical spacing between grid rows (px). Sized for the
 *  ~140-px-tall node card + breathing room. */
export const SPACING_Y = 220;

/** A 2D position in the topology's logical coordinate space. The
 *  viewport store (lib/topology/viewport.svelte.ts) then maps this
 *  to screen coordinates via a transform. */
export interface Position {
	x: number;
	y: number;
}

/**
 * computeLayout maps a list of routes to grid positions.
 *
 * Algorithm:
 *   1. Sort routes by `id` (string compare) for stability — the
 *      same set of routes always lands on the same positions
 *      regardless of the input array's order. Insertions don't
 *      shift existing routes that sort earlier.
 *   2. Pick `cols = ceil(sqrt(n))` (square-ish grid).
 *   3. For each route at sorted index `i`:
 *        col = i % cols
 *        row = floor(i / cols)
 *        x = col * SPACING_X + offsetX
 *        y = row * SPACING_Y + offsetY
 *      with `offsetX` / `offsetY` centering the grid around (0, 0).
 *
 * Edge cases:
 *   - Empty list returns an empty Map.
 *   - Single route returns {id → (0, 0)}.
 *
 * Stability note: inserting a route with an id that sorts AFTER
 * all existing ids only appends — no existing position changes.
 * Inserting an id that sorts EARLIER will shift the trailing
 * routes by one cell. Acceptable for a homelab UI; deterministic
 * IDs (UUID v4) make this a non-issue in practice.
 */
export function computeLayout(routes: RouteState[]): Map<string, Position> {
	const out = new Map<string, Position>();
	if (routes.length === 0) return out;

	const sorted = [...routes].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
	const n = sorted.length;
	const cols = Math.max(1, Math.ceil(Math.sqrt(n)));
	const rows = Math.ceil(n / cols);

	// Center the grid around (0, 0): if there are 3 columns, the
	// middle column sits at x=0; the edge columns at ±SPACING_X.
	const offsetX = -((cols - 1) * SPACING_X) / 2;
	const offsetY = -((rows - 1) * SPACING_Y) / 2;

	for (let i = 0; i < n; i++) {
		const col = i % cols;
		const row = Math.floor(i / cols);
		out.set(sorted[i].id, {
			x: col * SPACING_X + offsetX,
			y: row * SPACING_Y + offsetY
		});
	}

	return out;
}
