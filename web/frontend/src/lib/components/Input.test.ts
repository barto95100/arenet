// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Input component tests (Step F Chunk 7.1, spec §11.3 — 2 tests).
// Behavior-based per §11.2.

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import Input from './Input.svelte';

describe('Input', () => {
	it('renders the label associated with the underlying input', () => {
		render(Input, {
			label: 'Email',
			placeholder: 'you@example.com',
			value: ''
		});

		// Label is wired by `for={id}` → the input.id, so
		// getByLabelText resolves to the input element. This proves the
		// a11y wiring is intact (clicking the label focuses the input).
		const input = screen.getByLabelText('Email');
		expect(input).toBeInTheDocument();
		expect(input).toHaveAttribute('placeholder', 'you@example.com');
		// Default type when not specified is 'text'.
		expect(input).toHaveAttribute('type', 'text');
	});

	it('shows the error message + sets aria-invalid when error prop is non-empty', () => {
		render(Input, {
			label: 'Password',
			type: 'password',
			value: '',
			error: 'Password must be at least 15 characters'
		});

		const input = screen.getByLabelText('Password');
		// Error propagates as aria-invalid="true" — screen readers get
		// the right signal even without seeing the visual.
		expect(input).toHaveAttribute('aria-invalid', 'true');
		// The error text renders in the DOM near the input.
		expect(
			screen.getByText('Password must be at least 15 characters')
		).toBeInTheDocument();
		// aria-describedby points at the error <p> id — the link
		// between input and error message is announced by AT.
		const describedBy = input.getAttribute('aria-describedby');
		expect(describedBy).toBeTruthy();
		const errorEl = describedBy ? document.getElementById(describedBy) : null;
		expect(errorEl).not.toBeNull();
		expect(errorEl?.textContent).toContain('Password must be at least 15');
	});
});
