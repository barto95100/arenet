// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.22.0 — Flag.svelte contract tests.
//
// Pins the operator-visible contract used by the GeoIP /
// country-block selector (chips + search dropdown):
//   - a valid alpha-2 code → flag-icons class `fi fi-<lower>`
//     + role="img" + aria-label == the resolved country name.
//   - case-insensitive input ("fr" == "FR").
//   - an unknown / empty / malformed code → a neutral
//     placeholder span (no broken flag), mirroring the fallback
//     discipline in $lib/data/countries.ts.

import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import Flag from './Flag.svelte';
import { countryName } from '$lib/data/countries';

describe('Flag', () => {
	it('renders the flag-icons class for a valid code', () => {
		const { container } = render(Flag, { props: { code: 'FR' } });
		const span = container.querySelector('[data-testid="country-flag"]');
		expect(span).not.toBeNull();
		expect(span).toHaveClass('fi');
		expect(span).toHaveClass('fi-fr');
	});

	it('lowercases the class suffix (case-insensitive input)', () => {
		const { container } = render(Flag, { props: { code: 'fr' } });
		expect(container.querySelector('.fi-fr')).not.toBeNull();
	});

	it('exposes role="img" and the resolved country name as aria-label', () => {
		const { container } = render(Flag, { props: { code: 'FR' } });
		const span = container.querySelector('[data-testid="country-flag"]')!;
		expect(span.getAttribute('role')).toBe('img');
		expect(span.getAttribute('aria-label')).toBe(countryName('FR'));
	});

	it('renders a neutral placeholder (no fi-* class) for an empty code', () => {
		const { container } = render(Flag, { props: { code: '' } });
		const span = container.querySelector('[data-testid="country-flag"]');
		expect(span).not.toBeNull();
		expect(span).toHaveClass('flag--unknown');
		// No broken `fi fi-` flag class on the fallback.
		expect(span!.className).not.toMatch(/\bfi\b/);
	});

	it('renders a neutral placeholder for a malformed (non-2-letter) code', () => {
		const { container } = render(Flag, { props: { code: 'XYZ' } });
		const span = container.querySelector('[data-testid="country-flag"]');
		expect(span).toHaveClass('flag--unknown');
		expect(span!.className).not.toMatch(/\bfi\b/);
	});
});
