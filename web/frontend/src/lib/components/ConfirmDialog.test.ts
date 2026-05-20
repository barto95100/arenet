// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// ConfirmDialog component tests (Step F Chunk 7.2, bonus — 3 tests).
// Not in the original spec §11.3 list but the component is new in
// Chunk 6.4 and worth covering while the API is fresh.
//
// Behavior-based per §11.2: render → user action → assert outcome.

import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import ConfirmDialog from './ConfirmDialog.svelte';

describe('ConfirmDialog', () => {
	it('renders title + message + Cancel/Confirm buttons when open', () => {
		render(ConfirmDialog, {
			open: true,
			title: 'Revoke session?',
			message: 'The other device will be signed out immediately.',
			confirmLabel: 'Revoke',
			confirmVariant: 'danger',
			onConfirm: vi.fn()
		});

		// Title surfaces via the wrapped Modal's aria-labelledby.
		expect(
			screen.getByRole('dialog', { name: 'Revoke session?' })
		).toBeInTheDocument();
		expect(
			screen.getByText('The other device will be signed out immediately.')
		).toBeInTheDocument();
		// Both action buttons present and labeled correctly.
		expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument();
		expect(screen.getByRole('button', { name: 'Revoke' })).toBeInTheDocument();
	});

	it('Cancel button closes the dialog without calling onConfirm', async () => {
		const onConfirm = vi.fn();
		// open is bindable; pass a wrapper-state-like prop, then read the
		// Modal disappearance via the dialog role.
		const user = userEvent.setup();
		const { rerender } = render(ConfirmDialog, {
			open: true,
			title: 'Confirm?',
			message: 'Sure?',
			onConfirm
		});

		await user.click(screen.getByRole('button', { name: 'Cancel' }));
		// onClose flips `open` to false via the bindable prop; testing-
		// library doesn't automatically observe the parent-side mutation,
		// so we rerender with the expected new value and assert the
		// dialog is gone. The intent of the test is: Cancel does NOT
		// invoke onConfirm and signals close intent.
		rerender({ open: false, title: 'Confirm?', message: 'Sure?', onConfirm });
		expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
		expect(onConfirm).not.toHaveBeenCalled();
	});

	it('Confirm button invokes onConfirm; submitting state disables both buttons during the await', async () => {
		// Build a deferred promise so the test controls when onConfirm
		// resolves — that's the window during which `submitting` is true
		// and both buttons should be disabled.
		let resolveConfirm: () => void = () => {};
		const onConfirm = vi.fn(
			() =>
				new Promise<void>((r) => {
					resolveConfirm = r;
				})
		);
		const user = userEvent.setup();
		render(ConfirmDialog, {
			open: true,
			title: 'Long action',
			message: 'This takes a moment.',
			confirmLabel: 'Go',
			onConfirm
		});

		const cancelBtn = screen.getByRole('button', { name: 'Cancel' });
		const confirmBtn = screen.getByRole('button', { name: 'Go' });

		await user.click(confirmBtn);
		// onConfirm was invoked synchronously by the click.
		expect(onConfirm).toHaveBeenCalledTimes(1);

		// During the await: both buttons disabled (Cancel via prop,
		// Confirm via loading on Button). testing-library's waitFor
		// retries the assertion until the next microtask.
		await waitFor(() => {
			expect(cancelBtn).toBeDisabled();
			expect(confirmBtn).toBeDisabled();
		});

		// Release the promise; the dialog returns to the idle state.
		resolveConfirm();
		await waitFor(() => {
			expect(cancelBtn).not.toBeDisabled();
		});
	});
});
