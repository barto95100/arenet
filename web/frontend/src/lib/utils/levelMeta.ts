// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Phase Z.5.1 — centralised level taxonomy for /logs Activity log
// and any future surface that renders a severity pill.
//
// Pre-Z.5 the level→color map was a CSS-only enum scattered
// across .log-lvl.block / .detect / .warn / .info rules in
// /logs/+page.svelte. Z.5 promotes LEVEL as the carrier of
// severity color (SOURCE moves to neutral grey, see
// sourceMeta.ts) so the level enum becomes load-bearing for
// at-a-glance triage : red = something was stopped, amber
// = recoverable, blue = informational. This module is the
// single source of truth.
//
// The actual CSS lives co-located with each consumer (the
// pill styling depends on the surrounding row width / font
// metrics), but the *which color goes with which level* is
// pinned here and verified by unit tests.

/**
 * Levels surfaced on the /logs activity log. Order is
 * informal severity (descending). The 'block' and 'detect'
 * levels also drive the row-tint convention (see
 * /logs/+page.svelte .log-row.level-block / .level-detect
 * styling).
 */
export type ActivityLevel = 'block' | 'detect' | 'warn' | 'info';

export interface LevelMeta {
	/**
	 * The CSS class suffix appended to .log-lvl for the pill
	 * styling. Matches the existing convention pre-Z.5.
	 */
	slug: ActivityLevel;
	/** Operator-facing uppercase label. */
	label: string;
	/**
	 * The CSS custom property the pill resolves for its
	 * background + text color. The semantic anchor : a
	 * caller swapping to a different design token only has
	 * to touch this map. Operators reading the source see
	 * "BLOCK → status-down" and have the full mental model.
	 */
	colorVar: string;
}

/**
 * Resolve a level enum to its visible metadata. An unknown
 * value (would only happen if a sink emits an unmapped
 * level) falls back to 'info' shape with the raw string as
 * label so the regression surfaces visibly.
 */
export function levelMeta(level: string): LevelMeta {
	switch (level) {
		case 'block':
			return { slug: 'block', label: 'BLOCK', colorVar: '--status-down' };
		case 'detect':
			return { slug: 'detect', label: 'DETECT', colorVar: '--status-warn' };
		case 'warn':
			return { slug: 'warn', label: 'WARN', colorVar: '--status-warn' };
		case 'info':
			return { slug: 'info', label: 'INFO', colorVar: '--status-info' };
		default:
			return { slug: 'info', label: level.toUpperCase(), colorVar: '--status-info' };
	}
}
