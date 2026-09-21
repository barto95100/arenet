// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import GeoRuleSentence from './GeoRuleSentence.svelte';

const names: Record<string, string> = { RU: 'Russia', JP: 'Japan', FR: 'France' };
const base = {
	continents: [] as string[],
	countries: [] as string[],
	asns: [] as number[],
	exceptionCountries: [] as string[],
	exceptionAsns: [] as number[],
	countryName: (c: string) => names[c] ?? c
};
const text = () => screen.getByTestId('geo-rule-sentence').textContent?.replace(/\s+/g, ' ').trim();

describe('GeoRuleSentence', () => {
	it('renders nothing when the filter is off', () => {
		render(GeoRuleSentence, { props: { ...base, mode: 'off', countries: ['RU'] } });
		expect(screen.queryByTestId('geo-rule-sentence')).not.toBeInTheDocument();
	});

	it('invites to fill one list when all are empty', () => {
		render(GeoRuleSentence, { props: { ...base, mode: 'deny' } });
		expect(text()).toContain('one list is enough');
	});

	it('joins continents, countries and networks with "or", then the exceptions (deny)', () => {
		render(GeoRuleSentence, {
			props: { ...base, mode: 'deny', continents: ['AS'], countries: ['RU'], asns: [14061], exceptionCountries: ['JP'], exceptionAsns: [12345] }
		});
		expect(text()).toBe('Blocked if the visitor comes from Asia or Russia or AS14061 — except Japan, AS12345');
	});

	it('states that everyone else is blocked in allow mode and ignores exceptions', () => {
		render(GeoRuleSentence, {
			props: { ...base, mode: 'allow', continents: ['EU'], countries: ['FR'], exceptionCountries: ['JP'] }
		});
		expect(text()).toBe('Allowed only if the visitor comes from Europe or France — everyone else is blocked');
	});
});
