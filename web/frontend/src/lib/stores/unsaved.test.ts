// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, beforeEach } from 'vitest';
import {
	registerUnsaved,
	hasUnsaved,
	unsavedIds,
	resetUnsavedRegistry
} from './unsaved.svelte';

beforeEach(() => {
	resetUnsavedRegistry();
});

describe('unsaved registry', () => {
	it('reports nothing when no section is registered', () => {
		expect(hasUnsaved()).toBe(false);
		expect(unsavedIds()).toEqual([]);
	});

	it('is driven by the predicate, not by registration', () => {
		// Registering is "I can tell you", not "I am dirty".
		let dirty = false;
		registerUnsaved('oidc', () => dirty);
		expect(hasUnsaved()).toBe(false);
		dirty = true;
		expect(hasUnsaved()).toBe(true);
		expect(unsavedIds()).toEqual(['oidc']);
	});

	it('answers yes when any one section is dirty', () => {
		registerUnsaved('clean', () => false);
		registerUnsaved('dirty', () => true);
		expect(hasUnsaved()).toBe(true);
		expect(unsavedIds()).toEqual(['dirty']);
	});

	it('forgets a section once it unregisters', () => {
		const drop = registerUnsaved('geoip', () => true);
		expect(hasUnsaved()).toBe(true);
		drop();
		expect(hasUnsaved()).toBe(false);
	});

	it('replaces the predicate when the same id registers again', () => {
		// A remount must not leave the previous instance's closure
		// behind: that closure reads state belonging to a destroyed
		// component and would answer for it forever.
		registerUnsaved('geoip', () => true);
		registerUnsaved('geoip', () => false);
		expect(hasUnsaved()).toBe(false);
	});

	it('a stale unregister does not drop the live registration', () => {
		// Svelte can mount the replacement before tearing down the
		// previous instance. The old teardown must then be a no-op.
		const dropOld = registerUnsaved('geoip', () => false);
		registerUnsaved('geoip', () => true);
		dropOld();
		expect(hasUnsaved()).toBe(true);
	});
});

describe('unsaved registry — a broken predicate', () => {
	it('fails open instead of bricking the tab strip', () => {
		// The guard sits in front of the tab strip. A predicate that
		// throws must not cancel every switch out of that tab with no
		// dialog and no message — the operator would have no way out
		// but a reload. Found by a pre-existing settings-page test:
		// with every API stubbed to {}, a section's predicate read an
		// undefined string, threw, and the tab silently stopped
		// switching.
		registerUnsaved('broken', () => {
			throw new Error('reading a field the API never sent');
		});
		registerUnsaved('clean', () => false);

		expect(hasUnsaved()).toBe(false);
		expect(unsavedIds()).toEqual([]);
	});

	it('still reports a dirty sibling of a broken predicate', () => {
		registerUnsaved('broken', () => {
			throw new Error('nope');
		});
		registerUnsaved('dirty', () => true);

		expect(hasUnsaved()).toBe(true);
		expect(unsavedIds()).toEqual(['dirty']);
	});
});
