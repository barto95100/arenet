// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Tooltip component tests (Step F Chunk 7.3, spec §11.3 — 2 tests).
// Behavior-based per §11.2.
//
// Tooltip shows its label on mouseenter (hover) and focusin (keyboard
// a11y). The fade transition has duration:100 — testing-library's
// findBy* queries await the next animation frame which is enough.

import { describe, it, expect } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { createRawSnippet } from 'svelte';
import Tooltip from './Tooltip.svelte';

function buttonSnippet() {
	return createRawSnippet(() => ({
		render: () => `<button type="button">Trigger</button>`
	}));
}

describe('Tooltip', () => {
	it('shows the label when the trigger is hovered', async () => {
		const user = userEvent.setup();
		render(Tooltip, {
			label: 'Helpful hint',
			children: buttonSnippet()
		});

		// Before hover: the tooltip bubble is not in the DOM (the
		// {#if open} branch is false).
		expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();

		// Hover the trigger — mouseenter flips `open` to true on the
		// wrapper. The bubble mounts behind a fade transition; we wait
		// for it to be present.
		await user.hover(screen.getByRole('button', { name: 'Trigger' }));
		await waitFor(() => {
			expect(screen.getByRole('tooltip')).toHaveTextContent('Helpful hint');
		});
	});

	it('shows the label when the trigger receives keyboard focus', async () => {
		render(Tooltip, {
			label: 'Keyboard a11y',
			children: buttonSnippet()
		});

		// Programmatic focus on the trigger fires focusin on the wrapper
		// span (focus events bubble), which mirrors what Tab-navigating
		// would do. The tooltip then mounts with the label content.
		const trigger = screen.getByRole('button', { name: 'Trigger' });
		trigger.focus();
		expect(trigger).toHaveFocus();

		await waitFor(() => {
			expect(screen.getByRole('tooltip')).toHaveTextContent('Keyboard a11y');
		});
	});
});

// v2.72 — the two defects an outside report named, both confirmed in
// the component before anything was changed.
//
// aria-describedby sat on the wrapper <span>, a positioning container
// with no tabindex and therefore never focusable. aria-describedby
// does not inherit, so when the real trigger took focus the accessible
// description was empty: every tooltip in the app was silent to a
// screen reader while looking perfectly fine on screen.
describe('Tooltip — the description reaches the trigger', () => {
	it('points the trigger at the label, not the wrapper', async () => {
		render(Tooltip, { label: 'Helpful hint', children: buttonSnippet() });

		const trigger = screen.getByRole('button', { name: 'Trigger' });
		await waitFor(() => expect(trigger.getAttribute('aria-describedby')).toBeTruthy());

		const describedBy = trigger.getAttribute('aria-describedby') ?? '';
		const described = document.getElementById(describedBy.split(/\s+/)[0]);
		expect(described).not.toBeNull();
		expect(described?.textContent).toContain('Helpful hint');
	});

	it('describes the trigger before it is hovered', async () => {
		// The description is computed when focus lands, and `open` is
		// set by that same focus event. A conditionally-rendered target
		// may not exist yet at that moment, so it must not depend on
		// the tooltip being open.
		render(Tooltip, { label: 'Always available', children: buttonSnippet() });

		const trigger = screen.getByRole('button', { name: 'Trigger' });
		await waitFor(() => expect(trigger.getAttribute('aria-describedby')).toBeTruthy());
		// Nothing has been hovered or focused.
		expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
		const id = (trigger.getAttribute('aria-describedby') ?? '').split(/\s+/)[0];
		expect(document.getElementById(id)?.textContent).toContain('Always available');
	});

	it('keeps an id the trigger already had', async () => {
		// A trigger can legitimately be described by its own hint or
		// error text; replacing that would trade one silence for
		// another.
		render(Tooltip, {
			label: 'Ours',
			children: createRawSnippet(() => ({
				render: () =>
					`<span><button type="button" aria-describedby="theirs">Trigger</button><span id="theirs">Theirs</span></span>`
			}))
		});

		const trigger = screen.getByRole('button', { name: 'Trigger' });
		await waitFor(() =>
			expect(trigger.getAttribute('aria-describedby')).toContain('theirs')
		);
		const ids = (trigger.getAttribute('aria-describedby') ?? '').split(/\s+/);
		expect(ids).toContain('theirs');
		expect(ids.length).toBe(2);
	});

	it('makes the wrapper focusable when nothing inside can take focus', async () => {
		// A bare icon or plain text. A description nobody can reach is
		// no description.
		const { container } = render(Tooltip, {
			label: 'Icon meaning',
			children: createRawSnippet(() => ({ render: () => `<span aria-hidden="true">i</span>` }))
		});

		const wrapper = container.querySelector('.tt-wrapper');
		await waitFor(() => expect(wrapper?.getAttribute('tabindex')).toBe('0'));
		expect(wrapper?.getAttribute('aria-describedby')).toBeTruthy();
	});
});

// WCAG 2.1 SC 1.4.13 — content on hover or focus has to be
// dismissable without moving focus. Nothing closed the bubble before.
describe('Tooltip — Escape dismisses', () => {
	it('closes on Escape while the trigger keeps focus', async () => {
		render(Tooltip, { label: 'Dismiss me', children: buttonSnippet() });

		const trigger = screen.getByRole('button', { name: 'Trigger' });
		trigger.focus();
		await waitFor(() => expect(screen.getByRole('tooltip')).toBeInTheDocument());

		await fireEvent.keyDown(window, { key: 'Escape' });

		await waitFor(() => expect(screen.queryByRole('tooltip')).not.toBeInTheDocument());
		// The point of the requirement: focus has not moved.
		expect(trigger).toHaveFocus();
	});

	it('ignores Escape when nothing is open', async () => {
		// The handler is on the window, so it must not swallow an
		// Escape another component is waiting for.
		render(Tooltip, { label: 'Closed', children: buttonSnippet() });

		await fireEvent.keyDown(window, { key: 'Escape' });

		expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
	});
});
