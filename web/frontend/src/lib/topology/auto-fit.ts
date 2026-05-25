// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step J.6 — auto-fit trigger helper. Extracted from the
// /topology page's $effect so the gate logic is pure-function
// testable without a full page render + jsdom layout dance.
//
// The page wires this as:
//
//   let hasFit = $state(false);
//   $effect(() => {
//       if (shouldAutoFit({ hasFit, routesCount, viewportWidth, viewportHeight })) {
//           viewport.fitView(...);
//           hasFit = true;
//       }
//   });
//
// Spec §5.5 (Finding #10 fix): fit fires once and only once, on
// the first transition from zero routes to non-zero with a
// measured non-zero viewport. The flag flip after the call is
// the caller's responsibility — the helper is pure.

export interface AutoFitInput {
	/** Whether fitView has already been called on this page mount. */
	hasFit: boolean;
	/** Number of routes currently in the topology store. */
	routesCount: number;
	/** Live width of the .svg-wrap surface in CSS px. Reads off
	 *  bind:clientWidth on the page. Zero on the first effect
	 *  tick because layout hasn't measured yet — that's the
	 *  classic mount-time trap this gate exists to defuse. */
	viewportWidth: number;
	/** Live height of the .svg-wrap surface in CSS px. */
	viewportHeight: number;
}

/** Returns true when the topology page should fire its
 *  one-shot auto-fit. All four guards must hold simultaneously;
 *  any zero / false short-circuits to no-op. */
export function shouldAutoFit(input: AutoFitInput): boolean {
	if (input.hasFit) return false;
	if (input.routesCount === 0) return false;
	if (input.viewportWidth <= 0) return false;
	if (input.viewportHeight <= 0) return false;
	return true;
}
