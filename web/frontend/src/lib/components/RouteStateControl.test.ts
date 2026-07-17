// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// RouteStateControl component tests (Task 8). Behavior-based per the
// project's Toggle-neighbor test convention: render + simulate user
// interaction + assert observable outcome, no internal state peeking.
//
// RouteStateControl is a controlled component (mirrors Toggle.svelte's
// contract): `value` is NOT bindable, the caller re-renders after
// `onchange` fires. Unlike Toggle (2 fixed generic options), this
// component has 3 FIXED states: active / maintenance / disabled.

import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import RouteStateControl from './RouteStateControl.svelte';

describe('RouteStateControl', () => {
	it('renders 3 radio segments with the state labels, active one aria-checked=true', () => {
		render(RouteStateControl, { value: 'active' });

		const active = screen.getByRole('radio', { name: 'Active' });
		const maintenance = screen.getByRole('radio', { name: 'Maintenance' });
		const disabled = screen.getByRole('radio', { name: 'Disabled' });

		expect(active).toBeInTheDocument();
		expect(maintenance).toBeInTheDocument();
		expect(disabled).toBeInTheDocument();

		expect(active).toHaveAttribute('aria-checked', 'true');
		expect(maintenance).toHaveAttribute('aria-checked', 'false');
		expect(disabled).toHaveAttribute('aria-checked', 'false');
	});

	it('calls onchange with "maintenance" when the maintenance segment is clicked', async () => {
		const onchange = vi.fn();
		const user = userEvent.setup();
		render(RouteStateControl, { value: 'active', onchange });

		await user.click(screen.getByRole('radio', { name: 'Maintenance' }));

		expect(onchange).toHaveBeenCalledTimes(1);
		expect(onchange).toHaveBeenCalledWith('maintenance');
	});

	it('exposes a radiogroup with the given aria-label', () => {
		render(RouteStateControl, { value: 'disabled', ariaLabel: 'Route state' });

		expect(screen.getByRole('radiogroup', { name: 'Route state' })).toBeInTheDocument();
	});
});
