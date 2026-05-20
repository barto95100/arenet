// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Tooltip component tests (Step F Chunk 7.3, spec §11.3 — 2 tests).
// Behavior-based per §11.2.
//
// Tooltip shows its label on mouseenter (hover) and focusin (keyboard
// a11y). The fade transition has duration:100 — testing-library's
// findBy* queries await the next animation frame which is enough.

import { describe, it, expect } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
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
