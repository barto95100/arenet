// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { flushSync } from 'svelte';
import ContinentPicker from './ContinentPicker.svelte';

describe('ContinentPicker', () => {
	it('renders the 7 continents in a labelled fieldset', () => {
		render(ContinentPicker, { props: { value: [] } });
		expect(screen.getByRole('group', { name: 'Continents' })).toBeInTheDocument();
		expect(screen.getAllByRole('checkbox')).toHaveLength(7);
		expect(screen.getByLabelText('South America')).toBeInTheDocument();
	});

	it('reflects the initial value and toggles codes', async () => {
		render(ContinentPicker, { props: { value: ['AS'] } });
		const box = (code: string) => screen.getByTestId(`geo-continent-${code}`) as HTMLInputElement;
		expect(box('AS').checked).toBe(true);
		expect(box('EU').checked).toBe(false);
		await userEvent.click(box('EU'));
		flushSync();
		expect(box('EU').checked).toBe(true);
		await userEvent.click(box('AS'));
		flushSync();
		expect(box('AS').checked).toBe(false);
	});
});
