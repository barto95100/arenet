// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { sourceMeta } from './sourceMeta';

describe('sourceMeta', () => {
	it('resolves every known source to a stable {label, slug} pair', () => {
		// Order intentionally not alphabetical — matches the
		// rough triage priority in the operator's mental model.
		expect(sourceMeta('waf')).toEqual({ label: 'WAF', slug: 'waf' });
		expect(sourceMeta('rate_limit')).toEqual({
			label: 'RATE-LIMIT',
			slug: 'rate-limit'
		});
		expect(sourceMeta('throttle')).toEqual({ label: 'THROTTLE', slug: 'throttle' });
		expect(sourceMeta('auth')).toEqual({ label: 'AUTH', slug: 'auth' });
		expect(sourceMeta('country_block')).toEqual({
			label: 'COUNTRY',
			slug: 'country-block'
		});
		expect(sourceMeta('cert')).toEqual({ label: 'CERT', slug: 'cert' });
	});

	it('falls back to UPPERCASE label + unknown slug for unmapped sources', () => {
		// A new sink that forgets to register here should
		// surface visibly. The label preserves the raw value
		// so the operator can grep the source code from the
		// UI label.
		expect(sourceMeta('mystery')).toEqual({ label: 'MYSTERY', slug: 'unknown' });
		expect(sourceMeta('')).toEqual({ label: '', slug: 'unknown' });
	});

	it('slug strings are CSS-class safe (lowercase + dash, no underscore)', () => {
		// Z.5.1 invariant : the slug feeds .log-src.<slug>
		// CSS rules. An underscore in the slug would silently
		// break CSS matching on consumers that copy the slug
		// directly into a class attribute.
		const sources = ['waf', 'rate_limit', 'throttle', 'auth', 'country_block', 'cert'];
		for (const src of sources) {
			const slug = sourceMeta(src).slug;
			expect(slug).toMatch(/^[a-z-]+$/);
		}
	});
});
