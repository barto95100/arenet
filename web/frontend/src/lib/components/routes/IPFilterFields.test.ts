// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// IPFilterFields component tests (Task 7, path-based-rules). Behavior-based
// per the project's Toggle-neighbor test convention: render + simulate user
// interaction + assert observable outcome, no internal state peeking.
//
// IPFilterFields is a reusable, bindable component (mirrors the CountryBlock
// inline section's mode-radio + list-input pattern from routes/+page.svelte,
// but extracted as a standalone component since it's shared between the
// route-level IPFilter and each PathRule's IPFilter, per the brief).

import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import IPFilterFields from './IPFilterFields.svelte';
import type { IPFilter } from '$lib/api/types';

describe('IPFilterFields', () => {
	it('shows the CIDR list only when mode is allow or deny', () => {
		const off: IPFilter = { mode: 'off' };
		const { queryByTestId } = render(IPFilterFields, { value: off });
		expect(queryByTestId('ipfilter-cidrs')).toBeNull();

		const allow: IPFilter = { mode: 'allow', cidrs: ['1.2.3.4'] };
		const { getByTestId } = render(IPFilterFields, { value: allow });
		expect(getByTestId('ipfilter-cidrs')).toBeTruthy();
	});

	it('hides the CIDR list for the empty-string mode ("" — not yet configured)', () => {
		const empty: IPFilter = { mode: '' };
		const { queryByTestId } = render(IPFilterFields, { value: empty });
		expect(queryByTestId('ipfilter-cidrs')).toBeNull();
	});

	it('shows the CIDR list when mode is deny', () => {
		const deny: IPFilter = { mode: 'deny', cidrs: ['10.0.0.0/8'] };
		const { getByTestId } = render(IPFilterFields, { value: deny });
		expect(getByTestId('ipfilter-cidrs')).toBeTruthy();
	});

	it('renders 3 mode radio options', () => {
		const { getAllByRole } = render(IPFilterFields, { value: { mode: 'off' } });
		const radios = getAllByRole('radio');
		expect(radios).toHaveLength(3);
	});
});
