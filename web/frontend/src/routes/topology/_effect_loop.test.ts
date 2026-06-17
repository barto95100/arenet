// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Phase 3.e HOTFIX (2026-06-17) — empirical reactivity-loop pin.
//
// The page-level $effect in +page.svelte that re-rebuilds the
// graph on collapsedRoutes.collapsed change initially shipped
// WITHOUT untrack() around the rebuildGraph call. rebuildGraph
// reads `nodes` (for the diff) and writes `nodes` (for the
// first-build path) — same $state, same effect — so each
// write retriggered the effect. Svelte 5 caught it with
// effect_update_depth_exceeded; the canvas froze.
//
// This test reproduces the pattern in a tiny harness component
// and asserts that toggling the store fires the effect a
// BOUNDED number of times. Without the untrack() guard the
// effect re-fires indefinitely, Svelte throws, and the test
// catches the unhandled exception — failing loudly instead of
// shipping a frozen UI.

import { describe, it, expect, beforeEach } from 'vitest';
import { flushSync } from 'svelte';
import { mount, unmount } from 'svelte';
import Harness from './_effect_harness.test.svelte';
import { collapsedRoutes } from './_collapsed.svelte';

describe('Phase 3.e HOTFIX — collapsed $effect loop guard', () => {
	beforeEach(() => {
		collapsedRoutes.reset();
	});

	it('toggling collapsedRoutes does NOT trigger an unbounded effect re-run loop', () => {
		// Mount the harness — first effect run lands during mount.
		const target = document.createElement('div');
		document.body.appendChild(target);
		const component = mount(Harness, { target });
		// flushSync forces every pending effect to drain before we
		// inspect the count. After mount the effect should have
		// fired exactly once (the initial run).
		flushSync();
		const baseRunCount = (
			component as unknown as { getRunCount(): number }
		).getRunCount();
		expect(baseRunCount).toBeGreaterThanOrEqual(1);

		// Toggle once. With the untrack() guard, the effect re-runs
		// EXACTLY ONCE more (the tracked dep changed). Without the
		// guard, the body's write would retrigger the same effect,
		// pushing the runCount past Svelte's effect-depth ceiling
		// (default ~50) and throwing
		// effect_update_depth_exceeded.
		collapsedRoutes.toggle('r-1');
		flushSync();
		const afterToggleCount = (
			component as unknown as { getRunCount(): number }
		).getRunCount();

		// Allow a generous bound (10) — even if a future change
		// adds a couple of indirect dep re-fires, that's still
		// nowhere near the runaway loop the unfixed code produced.
		// Crucially this assertion would FAIL if Svelte threw
		// effect_update_depth_exceeded, because mount() / flushSync
		// would surface the error before this line runs.
		expect(afterToggleCount - baseRunCount).toBeLessThanOrEqual(10);

		// Sanity check the side-effecting write succeeded — the
		// harness rewrote nodes on the second run, proving the
		// rebuildGraph-shaped call path still executes under
		// untrack.
		const nodes = (component as unknown as { getNodes(): string[] }).getNodes();
		expect(nodes.length).toBeGreaterThan(0);

		unmount(component);
		target.remove();
	});

	it('multiple consecutive toggles each fire the effect a bounded number of times', () => {
		// Same reproducer as above but with 5 successive toggles.
		// The bug shape was that EVERY mutation produced an
		// unbounded chain, so this test catches it even if the
		// initial-mount run somehow stayed bounded by luck.
		const target = document.createElement('div');
		document.body.appendChild(target);
		const component = mount(Harness, { target });
		flushSync();
		const base = (component as unknown as { getRunCount(): number }).getRunCount();
		for (let i = 0; i < 5; i++) {
			collapsedRoutes.toggle(`r-${i}`);
			flushSync();
		}
		const after = (component as unknown as { getRunCount(): number }).getRunCount();
		// 5 toggles → ~5 effect runs in the bounded case. Allow
		// 25 as the upper bound (generous, but still safely below
		// Svelte's effect-depth ceiling).
		expect(after - base).toBeLessThanOrEqual(25);
		unmount(component);
		target.remove();
	});
});
