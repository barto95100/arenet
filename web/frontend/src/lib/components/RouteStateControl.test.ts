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
import { t } from '$lib/i18n';
import { language } from '$lib/stores/language.svelte';

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

	// Final-review Finding #3 (v2.17.0) — i18n regression. The
	// component previously hardcoded LABELS = {active:'Active', ...}
	// in English regardless of locale, even though the
	// `routes.state.*` i18n keys exist and differ by locale
	// (fr.json disabled: "Désactivée"). The parent (+page.svelte)
	// now passes a `labels` prop built from t('routes.state.*').
	// This test renders the component the way the parent does under
	// the FR locale and asserts the FR label appears — it must FAIL
	// against the old hardcoded-English behavior (which ignores any
	// `labels` prop and always renders "Disabled").
	it('renders the FR-translated label when the parent passes labels resolved via t() under the FR locale', () => {
		language.applyLocally('fr');
		try {
			const labels = {
				active: t('routes.state.active'),
				maintenance: t('routes.state.maintenance'),
				disabled: t('routes.state.disabled')
			};
			expect(labels.disabled).toBe('Désactivée');

			render(RouteStateControl, { value: 'disabled', labels });

			expect(screen.getByRole('radio', { name: 'Désactivée' })).toBeInTheDocument();
			expect(screen.queryByRole('radio', { name: 'Disabled' })).toBeNull();
		} finally {
			language.applyLocally('en');
		}
	});
});
