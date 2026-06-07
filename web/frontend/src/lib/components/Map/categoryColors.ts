// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step V.6 — color taxonomy for the 5 GeoEvent categories
// spec §5.6 locks. Each category maps to ONE existing
// design token from tokens.css so the dark/light theme
// switch carries the map colors for free.
//
// V.5 deviation flagged: V.5's WorldMap.svelte file-
// header comment proposed mapping waf + crowdsec onto the
// same `--status-down` token (red), with the operator
// tooltip disambiguating. The V.6 brief explicitly asked
// for FIVE distinct colors. To satisfy that without
// inventing new tokens, V.6 maps:
//
//   - waf      → --status-down  (red — "request blocked
//                                 by WAF rule")
//   - crowdsec → --accent-cyan  (purple-blue — "IP banned
//                                 by reputation feed")
//
// `--accent-cyan` is the brand accent (despite the legacy
// "cyan" name; current token resolves to purple-blue —
// commit history under R.2 documents the rename in flight).
// Using the brand accent for crowdsec underlines that it
// is a NETWORK-LEVEL block, distinct from WAF's
// REQUEST-LEVEL block. Visually the two reds-on-red
// confusion the V.5 comment worried about is gone.
//
// No new tokens added in V.6. All five resolve cleanly in
// both dark and light themes (verified by grep'ing
// tokens.css for each).

import type { GeoEventCategory } from '$lib/api/types';

/**
 * SVG stroke / fill value for an arc of the given category.
 * Each value is a CSS `var(--token)` reference so the dark/
 * light theme switch picks up automatically — never hard-
 * code hex/oklch literals here.
 */
export const CATEGORY_COLORS: Record<GeoEventCategory, string> = {
	normal: 'var(--status-up)',
	throttle: 'var(--status-warn)',
	waf: 'var(--status-down)',
	crowdsec: 'var(--accent-cyan)',
	auth: 'var(--status-info)'
};

/**
 * Operator-facing French labels for each category. Used by
 * tooltips and the future legend. Kept here next to the
 * color map so adding a category requires touching one file.
 */
export const CATEGORY_LABELS_FR: Record<GeoEventCategory, string> = {
	normal: 'Requête',
	throttle: 'Throttle (429)',
	waf: 'WAF (403)',
	crowdsec: 'CrowdSec (403)',
	auth: 'Échec d’auth (401/403)'
};
