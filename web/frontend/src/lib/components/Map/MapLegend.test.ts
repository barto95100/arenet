// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step V polish — MapLegend tests.
//
// Pins the 5-row legend shape, the per-row CSS-var swatch
// color (single source of truth = categoryColors.ts), the
// French labels, and the "à venir" marker on the
// currently-unemitted "normal" category. A future
// regression that drops a category or rewires a color
// surfaces immediately.

import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import MapLegend from './MapLegend.svelte';
import { CATEGORY_COLORS } from './categoryColors';

const CATEGORIES = ['normal', 'throttle', 'waf', 'crowdsec', 'auth'] as const;

describe('MapLegend', () => {
	it('renders all 5 category rows', () => {
		render(MapLegend);
		for (const cat of CATEGORIES) {
			expect(screen.getByTestId(`map-legend-item-${cat}`)).toBeInTheDocument();
		}
	});

	it('uses the categoryColors.ts CSS var for each row swatch', () => {
		render(MapLegend);
		for (const cat of CATEGORIES) {
			const row = screen.getByTestId(`map-legend-item-${cat}`);
			const swatch = row.querySelector('.map-legend__swatch') as HTMLElement;
			expect(swatch).not.toBeNull();
			// Inline style carries the var(--token) reference;
			// the actual color resolves at browser runtime
			// (jsdom doesn't compute CSS custom properties).
			expect(swatch.getAttribute('style') ?? '').toContain(CATEGORY_COLORS[cat]);
		}
	});

	it('renders the French operator labels', () => {
		render(MapLegend);
		// Pin a sample of the operator-meaningful copy.
		expect(screen.getByTestId('map-legend-item-throttle').textContent ?? '').toContain(
			'Rate-limit'
		);
		expect(screen.getByTestId('map-legend-item-waf').textContent ?? '').toContain(
			'Coraza'
		);
		expect(screen.getByTestId('map-legend-item-crowdsec').textContent ?? '').toContain(
			'réputation'
		);
		expect(screen.getByTestId('map-legend-item-auth').textContent ?? '').toContain(
			'authentification'
		);
	});

	it('marks "normal" as à venir (currently not emitted by the backend)', () => {
		render(MapLegend);
		const normalRow = screen.getByTestId('map-legend-item-normal');
		expect(normalRow.textContent ?? '').toContain('à venir');
	});

	it('exposes a toggle that collapses + restores the list', async () => {
		render(MapLegend);
		// Default: expanded.
		expect(screen.getByTestId('map-legend-list')).toBeInTheDocument();

		const toggle = screen.getByTestId('map-legend-toggle');
		await fireEvent.click(toggle);
		expect(screen.queryByTestId('map-legend-list')).toBeNull();
		expect(toggle.getAttribute('aria-expanded')).toBe('false');

		await fireEvent.click(toggle);
		expect(screen.getByTestId('map-legend-list')).toBeInTheDocument();
		expect(toggle.getAttribute('aria-expanded')).toBe('true');
	});

	it('has an aria-label on the root for screen-reader discoverability', () => {
		render(MapLegend);
		const root = screen.getByTestId('map-legend');
		expect(root.getAttribute('aria-label') ?? '').toMatch(/légende/i);
	});
});
