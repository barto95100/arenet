// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Sujet 1 Phase 3.e — collapsedRoutes store unit tests.
//
// Pins the contract :
//   - isCollapsed returns false for any unknown route ID (default
//     expanded).
//   - toggle flips the state — collapsed ↔ expanded on each call.
//   - collapse / expand are idempotent — calling collapse on an
//     already-collapsed route is a no-op (doesn't reset other
//     bookkeeping like a future timestamp field).
//   - reset wipes everything (test helper used between cases).
//   - Set identity changes on every mutation so Svelte 5 $state
//     picks up the change (mutating in place wouldn't trigger
//     reactivity).

import { describe, it, expect, beforeEach } from 'vitest';
import { collapsedRoutes } from './_collapsed.svelte';

describe('collapsedRoutes store', () => {
	beforeEach(() => {
		collapsedRoutes.reset();
	});

	it('isCollapsed defaults to false for unknown routes', () => {
		expect(collapsedRoutes.isCollapsed('r-unknown')).toBe(false);
	});

	it('toggle flips state from expanded to collapsed and back', () => {
		expect(collapsedRoutes.isCollapsed('r-1')).toBe(false);
		collapsedRoutes.toggle('r-1');
		expect(collapsedRoutes.isCollapsed('r-1')).toBe(true);
		collapsedRoutes.toggle('r-1');
		expect(collapsedRoutes.isCollapsed('r-1')).toBe(false);
	});

	it('collapse / expand are idempotent', () => {
		collapsedRoutes.collapse('r-1');
		collapsedRoutes.collapse('r-1');
		expect(collapsedRoutes.isCollapsed('r-1')).toBe(true);
		expect(collapsedRoutes.collapsed.size).toBe(1);
		collapsedRoutes.expand('r-1');
		collapsedRoutes.expand('r-1');
		expect(collapsedRoutes.isCollapsed('r-1')).toBe(false);
		expect(collapsedRoutes.collapsed.size).toBe(0);
	});

	it('toggle replaces the Set so Svelte $state reactivity fires', () => {
		// Svelte 5 $state on a Set type only notifies subscribers
		// when the Set REFERENCE changes; mutating in place
		// (Set.prototype.add / delete) wouldn't trigger
		// reactivity. The store's contract is to swap the Set on
		// every mutation. Pin that contract so a future
		// "optimization" doesn't break the reactivity.
		const ref1 = collapsedRoutes.collapsed;
		collapsedRoutes.toggle('r-1');
		const ref2 = collapsedRoutes.collapsed;
		expect(ref2).not.toBe(ref1);
		collapsedRoutes.toggle('r-1');
		const ref3 = collapsedRoutes.collapsed;
		expect(ref3).not.toBe(ref2);
	});

	it('isolates state per routeID', () => {
		collapsedRoutes.collapse('r-1');
		collapsedRoutes.collapse('r-2');
		collapsedRoutes.expand('r-1');
		expect(collapsedRoutes.isCollapsed('r-1')).toBe(false);
		expect(collapsedRoutes.isCollapsed('r-2')).toBe(true);
	});
});

// --- v2.47 — alias stacks arrive folded --------------------------
//
// Everything used to arrive expanded, trading verbosity for
// discovery. On a real installation a handful of routes with three or
// four aliases each turns the first column into a wall, and the shape
// of the graph — which is the whole point of the page — is lost
// behind it.

describe('collapsedRoutes — the default', () => {
	beforeEach(() => collapsedRoutes.reset());

	it('folds the routes it is given', () => {
		collapsedRoutes.seedCollapsed(['r-a', 'r-b']);
		expect(collapsedRoutes.isCollapsed('r-a')).toBe(true);
		expect(collapsedRoutes.isCollapsed('r-b')).toBe(true);
		// A route never seeded stays expanded.
		expect(collapsedRoutes.isCollapsed('r-c')).toBe(false);
	});

	// The property that matters: a poll tick must not undo a chevron
	// click. Re-seeding on every rebuild would silently re-fold what
	// the operator just opened, which is worse than the wall.
	it('never re-folds what the operator opened', () => {
		collapsedRoutes.seedCollapsed(['r-a']);
		collapsedRoutes.toggle('r-a');
		expect(collapsedRoutes.isCollapsed('r-a')).toBe(false);

		// Later ticks call the seeder again with the same routes.
		collapsedRoutes.seedCollapsed(['r-a']);
		collapsedRoutes.seedCollapsed(['r-a']);
		expect(collapsedRoutes.isCollapsed('r-a')).toBe(false);
	});

	// An installation with no aliases anywhere still consumes its one
	// seeding, so a later route gaining an alias mid-visit does not
	// fold itself under the operator.
	it('spends its single seeding even on an empty list', () => {
		collapsedRoutes.seedCollapsed([]);
		collapsedRoutes.seedCollapsed(['r-a']);
		expect(collapsedRoutes.isCollapsed('r-a')).toBe(false);
	});

	it('starts over after a reset', () => {
		collapsedRoutes.seedCollapsed(['r-a']);
		collapsedRoutes.reset();
		expect(collapsedRoutes.isCollapsed('r-a')).toBe(false);
		collapsedRoutes.seedCollapsed(['r-b']);
		expect(collapsedRoutes.isCollapsed('r-b')).toBe(true);
	});
});
