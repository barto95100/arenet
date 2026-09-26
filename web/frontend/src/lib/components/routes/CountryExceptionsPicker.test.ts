// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { flushSync } from 'svelte';
import CountryExceptionsPicker from './CountryExceptionsPicker.svelte';

describe('CountryExceptionsPicker', () => {
	it('adds a country from the autocomplete and removes it', async () => {
		render(CountryExceptionsPicker, { props: { value: [], blocked: [] } });
		await userEvent.type(screen.getByTestId('geo-exceptions-input'), 'JP{enter}');
		flushSync();
		const chip = screen.getByTestId('geo-exception-chip');
		expect(chip.querySelector('.fi-jp')).not.toBeNull();
		await userEvent.click(screen.getByRole('button', { name: /Remove the exception/ }));
		flushSync();
		expect(screen.queryByTestId('geo-exception-chip')).not.toBeInTheDocument();
	});

	it('does not suggest a country already in the blocked list', async () => {
		render(CountryExceptionsPicker, { props: { value: [], blocked: ['JP'] } });
		await userEvent.type(screen.getByTestId('geo-exceptions-input'), 'JP');
		const codes = screen.queryAllByTestId('geo-exception-suggestion').map((li) => li.textContent);
		expect(codes.some((c) => c?.includes('JP'))).toBe(false);
	});
});
