// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step V.5 — LicenseFooter component tests.
//
// The footer is pure static content; the test surface is
// to lock the attribution against accidental removal. The
// MaxMind CC BY-SA 4.0 attribution is a LICENSE
// requirement (the world-atlas CC0 credit is a courtesy
// only); a regression that drops the MaxMind line would
// silently violate the GeoLite2 redistribution terms.

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import LicenseFooter from './LicenseFooter.svelte';

describe('LicenseFooter', () => {
	it('credits MaxMind with the CC BY-SA 4.0 license token', () => {
		render(LicenseFooter);
		const root = screen.getByText(/MaxMind/).closest('footer');
		expect(root).toBeInTheDocument();
		expect(root?.textContent ?? '').toContain('CC BY-SA 4.0');
		expect(root?.textContent ?? '').toContain('GeoLite2');
	});

	it('credits world-atlas with the CC0 license token', () => {
		render(LicenseFooter);
		const root = screen.getByText(/world-atlas/).closest('footer');
		expect(root?.textContent ?? '').toContain('CC0');
	});

	it('points the MaxMind link at maxmind.com with safe rel attrs', () => {
		render(LicenseFooter);
		const link = screen.getByRole('link', { name: /GeoLite2/i }) as HTMLAnchorElement;
		expect(link.href).toContain('maxmind.com');
		expect(link.target).toBe('_blank');
		expect(link.rel).toContain('noopener');
		expect(link.rel).toContain('noreferrer');
	});

	it('points the world-atlas link at github.com/topojson with safe rel attrs', () => {
		render(LicenseFooter);
		const link = screen.getByRole('link', { name: /world-atlas/i }) as HTMLAnchorElement;
		expect(link.href).toContain('github.com/topojson/world-atlas');
		expect(link.target).toBe('_blank');
		expect(link.rel).toContain('noopener');
	});
});
