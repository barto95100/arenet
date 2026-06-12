// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { avatarColorKey, AVATAR_COLOR_STYLES } from './avatar-color';

describe('avatarColorKey', () => {
	it('is deterministic — same seed → same bucket', () => {
		expect(avatarColorKey('alice')).toBe(avatarColorKey('alice'));
		expect(avatarColorKey('laurent.ramos')).toBe(avatarColorKey('laurent.ramos'));
	});

	it('returns one of the 8 palette keys', () => {
		const keys = Object.keys(AVATAR_COLOR_STYLES);
		expect(keys).toHaveLength(8);
		for (const seed of ['a', 'bob', 'thomas.mercier', 'éric', 'Z']) {
			expect(keys).toContain(avatarColorKey(seed));
		}
	});

	it('handles an empty seed without throwing', () => {
		expect(() => avatarColorKey('')).not.toThrow();
		expect(AVATAR_COLOR_STYLES[avatarColorKey('')]).toBeDefined();
	});

	it('distributes — many distinct seeds use most of the palette', () => {
		const seeds = [
			'alice', 'bob', 'charlie', 'dora', 'eve', 'frank',
			'george', 'hugo', 'ines', 'jules', 'karim', 'lina',
			'marc', 'noémie', 'oscar', 'paul'
		];
		const buckets = new Set(seeds.map(avatarColorKey));
		// Don't require all 8 (sum-of-char-codes mod 8 can cluster
		// on tight seed lists), but a healthy spread proves the
		// helper isn't degenerate.
		expect(buckets.size).toBeGreaterThanOrEqual(4);
	});

	it('every palette key has a bg + fg style entry', () => {
		for (const [, styles] of Object.entries(AVATAR_COLOR_STYLES)) {
			expect(styles.bg).toMatch(/^oklch/);
			expect(styles.fg).toMatch(/^#|^oklch/);
		}
	});
});
