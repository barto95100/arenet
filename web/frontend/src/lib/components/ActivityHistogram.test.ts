// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Phase Z.5.4 — unit tests for ActivityHistogram.
// Focused on the SVG output shape (one stacked bar per
// bucket, segmented by source) without exercising the
// hover tooltip which needs jsdom event plumbing not
// worth the test weight at V1.

import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import ActivityHistogram from './ActivityHistogram.svelte';

// Anchor inside each test via a helper to avoid the
// module-load-vs-test-run time skew that can push a
// short-window bucket outside the active window when
// the test suite warms up slowly.
function isoOffset(secondsBack: number): string {
	return new Date(Date.now() - secondsBack * 1000).toISOString();
}

const SERIES = [
	{ key: 'waf', label: 'WAF', color: 'red' },
	{ key: 'rate_limit', label: 'RATE-LIMIT', color: 'orange' },
	{ key: 'auth', label: 'AUTH', color: 'cyan' }
];

describe('ActivityHistogram', () => {
	it('renders the SVG with the aria-label', () => {
		const { container, getByLabelText } = render(ActivityHistogram, {
			cells: [],
			series: SERIES,
			label: 'Test histogram'
		});
		expect(getByLabelText('Test histogram')).toBeInTheDocument();
		expect(container.querySelector('svg')).toBeInTheDocument();
	});

	it('produces zero <rect class="bar-seg"> when cells are empty', () => {
		const { container } = render(ActivityHistogram, {
			cells: [],
			series: SERIES,
			label: 'Empty'
		});
		expect(container.querySelectorAll('rect.bar-seg').length).toBe(0);
	});

	it('renders one bar segment per non-empty (bucket × source) cell', () => {
		const { container } = render(ActivityHistogram, {
			cells: [
				{ ts: isoOffset(60), source: 'waf' },
				{ ts: isoOffset(60), source: 'waf' },
				{ ts: isoOffset(60), source: 'rate_limit' },
				{ ts: isoOffset(120), source: 'auth' }
			],
			series: SERIES,
			label: 'Three bars'
		});
		const segs = container.querySelectorAll('rect.bar-seg');
		// 60s ago: 2 sources → 2 segments
		// 120s ago: 1 source → 1 segment
		// Total = 3.
		expect(segs.length).toBe(3);
	});

	it('renders bar segments with the series color (verifies stack identity)', () => {
		const { container } = render(ActivityHistogram, {
			cells: [
				{ ts: isoOffset(60), source: 'waf' },
				{ ts: isoOffset(60), source: 'rate_limit' }
			],
			series: SERIES,
			label: 'Colors'
		});
		const fills = Array.from(container.querySelectorAll('rect.bar-seg')).map(
			(el) => el.getAttribute('fill')
		);
		expect(fills).toContain('red');
		expect(fills).toContain('orange');
	});

	it('drops cells older than the window', () => {
		// 25h ago > 24h window → cell must NOT produce a bar.
		const { container } = render(ActivityHistogram, {
			cells: [{ ts: isoOffset(25 * 3600), source: 'waf' }],
			series: SERIES,
			label: 'Old cell dropped',
			windowMs: 24 * 60 * 60 * 1000
		});
		expect(container.querySelectorAll('rect.bar-seg').length).toBe(0);
	});

	it('renders axis labels (start/middle/now)', () => {
		const { getByText } = render(ActivityHistogram, {
			cells: [],
			series: SERIES,
			label: 'Axes'
		});
		// "now" tick is the right edge label.
		expect(getByText('now')).toBeInTheDocument();
	});

	it('honors a custom bucketMs (1-minute granularity)', () => {
		// Two cells under 5s apart on the same source → same
		// 1-minute bucket → exactly one stacked bar segment.
		// Tight spread to avoid the bucket-boundary edge case
		// where Date.now() can advance across the truncate
		// boundary mid-test.
		const { container } = render(ActivityHistogram, {
			cells: [
				{ ts: isoOffset(1), source: 'waf' },
				{ ts: isoOffset(3), source: 'waf' }
			],
			series: SERIES,
			label: '1-min bucket',
			bucketMs: 60 * 1000
		});
		expect(container.querySelectorAll('rect.bar-seg').length).toBe(1);
	});

	// Phase Z.5.6 — height: 'fill' mode tests.
	it('numeric height renders the SVG with the literal pixel attribute', () => {
		const { container } = render(ActivityHistogram, {
			cells: [],
			series: SERIES,
			label: 'Numeric',
			height: 240
		});
		const svg = container.querySelector('svg');
		expect(svg).not.toBeNull();
		// Z.5.6 invariant : numeric path is unchanged from
		// pre-Z.5.6 behavior. The fill mode must NOT activate
		// for callers that pass a number.
		expect(svg?.getAttribute('height')).toBe('240');
		const wrap = container.querySelector('.activity-histogram');
		expect(wrap?.classList.contains('fill')).toBe(false);
	});

	it('height: "fill" renders SVG height="100%" + fill class on wrapper', () => {
		const { container } = render(ActivityHistogram, {
			cells: [],
			series: SERIES,
			label: 'Fill',
			height: 'fill'
		});
		const svg = container.querySelector('svg');
		expect(svg?.getAttribute('height')).toBe('100%');
		const wrap = container.querySelector('.activity-histogram');
		// .fill class is what unlocks the .fill { flex:1 }
		// CSS rule on the wrapper. Pinning the class lets a
		// future regression where the wire-up drops the
		// boolean surface as a class-missing assertion.
		expect(wrap?.classList.contains('fill')).toBe(true);
	});
});
