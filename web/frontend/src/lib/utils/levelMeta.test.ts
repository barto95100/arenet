// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { levelMeta } from './levelMeta';

describe('levelMeta', () => {
	it('resolves every known level to the locked color token', () => {
		// Locked color tokens — touching these requires an
		// explicit ADR + a /dashboard + /security sweep so
		// the operator's visual vocabulary stays stable.
		expect(levelMeta('block')).toEqual({
			slug: 'block',
			label: 'BLOCK',
			colorVar: '--status-down'
		});
		expect(levelMeta('detect')).toEqual({
			slug: 'detect',
			label: 'DETECT',
			colorVar: '--status-warn'
		});
		expect(levelMeta('warn')).toEqual({
			slug: 'warn',
			label: 'WARN',
			colorVar: '--status-warn'
		});
		expect(levelMeta('info')).toEqual({
			slug: 'info',
			label: 'INFO',
			colorVar: '--status-info'
		});
	});

	it('falls back to info shape for an unmapped level', () => {
		// Operator-honest fallback : the raw value lands as
		// the label so the regression surfaces, but the slug
		// + color stay at the lowest-severity 'info' rather
		// than fabricating a "looks-like-block" rendering.
		expect(levelMeta('chaotic')).toEqual({
			slug: 'info',
			label: 'CHAOTIC',
			colorVar: '--status-info'
		});
	});

	it('block + detect map to distinct color tokens for row-tint coherence', () => {
		// Z.5.1 row-tint convention : .log-row.level-block
		// and .level-detect inherit different background tints
		// driven by these tokens. A regression where they
		// collapse to the same token would silently break the
		// at-a-glance distinction between "request stopped"
		// and "rule fired, traffic passed".
		expect(levelMeta('block').colorVar).not.toBe(levelMeta('detect').colorVar);
	});

	it('warn shares the warn token with detect (recoverable signals)', () => {
		// detect + warn both signal "something to look at" but
		// the request was not stopped. Sharing --status-warn
		// is intentional ; the level pill label still
		// distinguishes them.
		expect(levelMeta('warn').colorVar).toBe(levelMeta('detect').colorVar);
	});
});
