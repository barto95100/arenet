// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { flushSync } from 'svelte';
import ContinentPicker from './ContinentPicker.svelte';

describe('ContinentPicker', () => {
	const pill = (code: string) => screen.getByTestId(`geo-continent-${code}`);
	const pressed = (code: string) => pill(code).getAttribute('aria-pressed') === 'true';

	it('renders the 7 continents as toggle pills in a labelled fieldset', () => {
		render(ContinentPicker, { props: { value: [] } });
		expect(screen.getByRole('group', { name: 'Continents' })).toBeInTheDocument();
		expect(screen.getAllByRole('button')).toHaveLength(7);
		expect(screen.getByRole('button', { name: 'South America' })).toBeInTheDocument();
	});

	it('reflects the initial value and toggles codes', async () => {
		render(ContinentPicker, { props: { value: ['AS'] } });
		expect(pressed('AS')).toBe(true);
		expect(pressed('EU')).toBe(false);
		await userEvent.click(pill('EU'));
		flushSync();
		expect(pressed('EU')).toBe(true);
		await userEvent.click(pill('AS'));
		flushSync();
		expect(pressed('AS')).toBe(false);
	});
});
