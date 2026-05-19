// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step F motion tokens — spring constants for Svelte's `spring()`
// store (or whichever animation library Chunk 3 picks).
//
// Springs are NOT CSS values; they live here, in TypeScript, so they
// can be consumed by Svelte's reactive `spring()` and tunable per-call.
// The "token" naming is conceptual — these are exported constants,
// not CSS custom properties.
//
// Values below are placeholders carried over from spec §2.6; Chunk 3
// tunes them empirically and freezes the constants. The TS module is
// the single source of truth — if a CSS-var equivalent is ever needed,
// it derives from these.
//
// Spec ref: docs/superpowers/specs/2026-05-19-step-f-design-polish.md
// §2.6 + §10.

/** Spring shape compatible with Svelte's `spring()` store options. */
export interface Spring {
	stiffness: number;
	damping: number;
}

/** Element entry — snappy arrival, quick settle. */
export const SPRING_SNAPPY: Spring = { stiffness: 0.35, damping: 0.5 };

/** Panel slide-in — softer, more deliberate. */
export const SPRING_SOFT: Spring = { stiffness: 0.18, damping: 0.6 };

/** Success / celebrate feedback — overshoots briefly. */
export const SPRING_BOUNCY: Spring = { stiffness: 0.25, damping: 0.35 };
