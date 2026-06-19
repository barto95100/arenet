// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Phase Z.5.1 — centralised source taxonomy for /logs Activity log.
//
// Promoted out of the inline switch that lived in
// /logs/+page.svelte after Z.4 polish. Single source of
// truth so a future source (Step AA OIDC error stream,
// Step BB backup event, ...) lands by adding one row here
// instead of editing every consuming page.
//
// Z.5.1 decision : badge color is now NEUTRAL grey across
// every source. Pre-Z.5 each source had its own pill color
// (WAF red, rate-limit amber, throttle purple, ...) which
// duplicated the semantic carried by the LEVEL column (red
// = block, amber = warn). Two color enums fighting for
// operator attention on the same row. Z.5 promotes LEVEL
// as the carrier of severity color ; SOURCE stays neutral
// and identifies the *signal kind*, not its weight.

/**
 * Sources surfaced on the /logs activity log. The string
 * values are the canonical wire-shape `source` field on
 * UnifiedRow ; the order here is documentation, not
 * runtime-significant.
 */
export type ActivitySource =
	| 'waf'
	| 'rate_limit'
	| 'throttle'
	| 'auth'
	| 'country_block'
	| 'cert';

export interface SourceMeta {
	/** Operator-facing label rendered in the SOURCE column. */
	label: string;
	/**
	 * Kebab-case CSS class suffix appended to .log-src for
	 * per-source styling hooks. Stays even though Z.5.1
	 * collapses every color to neutral grey — keeps the
	 * door open for a future per-source border-stripe or
	 * icon without re-plumbing.
	 */
	slug: string;
}

/**
 * Resolve a raw source string to its visible metadata.
 * Unknown sources fall back to an UPPERCASE label + the
 * `unknown` slug so a regression where a new sink forgets
 * to register here surfaces visibly rather than silently
 * eating the row.
 */
export function sourceMeta(source: string): SourceMeta {
	switch (source) {
		case 'waf':
			return { label: 'WAF', slug: 'waf' };
		case 'rate_limit':
			return { label: 'RATE-LIMIT', slug: 'rate-limit' };
		case 'throttle':
			return { label: 'THROTTLE', slug: 'throttle' };
		case 'auth':
			return { label: 'AUTH', slug: 'auth' };
		case 'country_block':
			return { label: 'COUNTRY', slug: 'country-block' };
		case 'cert':
			return { label: 'CERT', slug: 'cert' };
		default:
			return { label: source.toUpperCase(), slug: 'unknown' };
	}
}
