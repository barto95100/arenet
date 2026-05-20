// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Button component tests (Step F Chunk 7.1, spec §11.3 — 4 tests).
// Behavior-based per §11.2.
//
// Button's children prop is a Svelte 5 Snippet; createRawSnippet
// from svelte builds one from raw HTML for testing. This is the
// idiomatic way to pass slot-like content to a component under test
// in Svelte 5 — no DOM-rendering helper needed in @testing-library.

import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { createRawSnippet } from 'svelte';
import Button from './Button.svelte';

/** Build a Snippet that renders the given text content. Used as the
 *  `children` prop in render() — Button reads children?.() to put
 *  the label inside the <button>. */
function textSnippet(text: string) {
	return createRawSnippet(() => ({
		render: () => `<span>${text}</span>`
	}));
}

describe('Button', () => {
	it('applies the expected variant class for each of the 4 variants', () => {
		const { rerender } = render(Button, {
			variant: 'primary',
			children: textSnippet('Save')
		});

		// `primary` → bg-cyan class. testing-library exposes the rendered
		// element via screen; we read the class list to verify the
		// variant-to-class mapping. Spec §5.4 contract.
		expect(screen.getByRole('button', { name: 'Save' })).toHaveClass('bg-cyan');

		rerender({ variant: 'secondary', children: textSnippet('Save') });
		expect(screen.getByRole('button', { name: 'Save' })).toHaveClass('bg-elevated');

		rerender({ variant: 'ghost', children: textSnippet('Save') });
		expect(screen.getByRole('button', { name: 'Save' })).toHaveClass('bg-transparent');

		rerender({ variant: 'danger', children: textSnippet('Save') });
		expect(screen.getByRole('button', { name: 'Save' })).toHaveClass('bg-down');
	});

	it('renders a Spinner and is disabled when loading=true', () => {
		render(Button, {
			loading: true,
			children: textSnippet('Save')
		});

		const button = screen.getByRole('button', { name: /save/i });
		// `disabled` HTML attribute is set when loading per Button's
		// `disabled={disabled || loading}` line.
		expect(button).toBeDisabled();
		// The Spinner has role="status" (from Spinner.svelte) — its
		// presence inside the button proves the loading branch ran.
		expect(screen.getByRole('status')).toBeInTheDocument();
	});

	it('does not call onclick when disabled', async () => {
		const onclick = vi.fn();
		const user = userEvent.setup();
		render(Button, {
			disabled: true,
			onclick,
			children: textSnippet('Save')
		});

		// userEvent.click respects the disabled attribute and skips the
		// click event the way a real browser would — onclick should
		// never fire.
		await user.click(screen.getByRole('button', { name: 'Save' }));
		expect(onclick).not.toHaveBeenCalled();
	});

	it('triggers onclick on keyboard Enter when focused', async () => {
		const onclick = vi.fn();
		const user = userEvent.setup();
		render(Button, {
			onclick,
			children: textSnippet('Submit')
		});

		const button = screen.getByRole('button', { name: 'Submit' });
		button.focus();
		expect(button).toHaveFocus();

		await user.keyboard('{Enter}');
		expect(onclick).toHaveBeenCalledTimes(1);
	});
});
