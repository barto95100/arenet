// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Modal component tests (Step F Chunk 7.2, spec §11.3 — 4 tests).
// Behavior-based per §11.2.
//
// Modal's shipped API is { open, title, onClose, children, footer }.
// The spec §11.3 mentions a `closeOnOverlay={false}` prop variant —
// this prop does NOT exist in the shipped component. Modal's overlay
// click handler is always-on (the backdrop click triggers onClose
// unconditionally). The fourth test therefore exercises a different
// behavior: title is rendered with the proper aria-labelledby wiring.

import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { createRawSnippet } from 'svelte';
import Modal from './Modal.svelte';

function textSnippet(text: string) {
	return createRawSnippet(() => ({
		render: () => `<span>${text}</span>`
	}));
}

describe('Modal', () => {
	it('renders the title and children when open=true', () => {
		render(Modal, {
			open: true,
			title: 'Confirm action',
			onClose: vi.fn(),
			children: textSnippet('Are you sure?')
		});

		// role="dialog" exposes the modal; its accessible name comes
		// from aria-labelledby pointing at the title <h2>.
		const dialog = screen.getByRole('dialog', { name: 'Confirm action' });
		expect(dialog).toBeInTheDocument();
		expect(dialog).toHaveAttribute('aria-modal', 'true');
		expect(screen.getByText('Are you sure?')).toBeInTheDocument();
	});

	it('does not render any dialog when open=false', () => {
		render(Modal, {
			open: false,
			title: 'Hidden',
			onClose: vi.fn(),
			children: textSnippet('No content visible')
		});

		// {#if open} branch is false → nothing in the DOM.
		expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
		expect(screen.queryByText('No content visible')).not.toBeInTheDocument();
	});

	it('calls onClose when the Escape key is pressed', async () => {
		const onClose = vi.fn();
		const user = userEvent.setup();
		render(Modal, {
			open: true,
			title: 'Press Esc',
			onClose,
			children: textSnippet('Body')
		});

		// The Modal listens to keydown at the document level via $effect,
		// not on the dialog itself — userEvent.keyboard targets
		// document.body by default, which matches the real keyboard
		// event path.
		await user.keyboard('{Escape}');
		expect(onClose).toHaveBeenCalledTimes(1);
	});

	it('calls onClose when the backdrop (overlay) is clicked', async () => {
		const onClose = vi.fn();
		const user = userEvent.setup();
		const { container } = render(Modal, {
			open: true,
			title: 'Click outside',
			onClose,
			children: textSnippet('Body')
		});

		// The backdrop is the .modal-backdrop element; its click handler
		// checks `e.target === e.currentTarget` so only clicks on the
		// backdrop itself (not bubbled from the inner dialog) close.
		const backdrop = container.querySelector('.modal-backdrop') as HTMLElement;
		expect(backdrop).not.toBeNull();
		await user.click(backdrop);
		expect(onClose).toHaveBeenCalledTimes(1);
	});

	// AL.4.b.2 — backward-compat pin: default width = 'md'
	// must keep the pre-extension max-w-md class. If a future
	// refactor changes the default token, every existing
	// caller (ConfirmDialog, ChangePasswordModal, ...) would
	// silently get a different width — this test catches
	// that regression.
	it('renders with max-w-md by default (backward-compat for unmodified callers)', () => {
		render(Modal, {
			open: true,
			title: 'Default width',
			onClose: vi.fn(),
			children: textSnippet('Body')
		});
		const dialog = screen.getByRole('dialog');
		expect(dialog.className).toContain('max-w-md');
		expect(dialog.className).not.toContain('max-w-2xl');
		expect(dialog.className).not.toContain('max-w-4xl');
	});

	// AL.4.b.2 — width="lg" maps to max-w-2xl. Pins the
	// token → class mapping so AL.4.b.2 ChannelModal +
	// AL.4.b.3 RuleModal render at the wider layout they
	// were designed against.
	it('renders with max-w-2xl when width="lg"', () => {
		render(Modal, {
			open: true,
			title: 'Wide modal',
			onClose: vi.fn(),
			children: textSnippet('Body'),
			width: 'lg'
		});
		const dialog = screen.getByRole('dialog');
		expect(dialog.className).toContain('max-w-2xl');
		expect(dialog.className).not.toContain('max-w-md');
	});
});
