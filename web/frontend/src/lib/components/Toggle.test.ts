// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Toggle component tests (Step F Chunk 7.1, spec §11.3 — Theme group).
// Behavior-based per §11.2: render + simulate user interaction + assert
// observable outcome. Internal $state is not asserted directly.
//
// The Toggle is a controlled component (Chunk 1.6 fix): the `value`
// prop is NOT bindable; the caller drives it via re-render after
// onchange. Tests therefore assert on the onchange callback, not on
// any internal mutation of `value`.

import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import Toggle from './Toggle.svelte';

const themeOptions: [
	{ value: 'dark' | 'light'; label: string },
	{ value: 'dark' | 'light'; label: string }
] = [
	{ value: 'dark', label: 'Dark' },
	{ value: 'light', label: 'Light' }
];

describe('Toggle', () => {
	it('renders both options as accessible radio buttons', () => {
		render(Toggle, {
			options: themeOptions,
			value: 'dark',
			ariaLabel: 'Theme'
		});

		// Both options become role="radio" buttons inside a radiogroup
		// per Toggle's internal markup. Querying by name (= visible label)
		// is the user-facing path.
		const dark = screen.getByRole('radio', { name: 'Dark' });
		const light = screen.getByRole('radio', { name: 'Light' });
		expect(dark).toBeInTheDocument();
		expect(light).toBeInTheDocument();
		// The currently-active option has aria-checked="true"; the other false.
		expect(dark).toHaveAttribute('aria-checked', 'true');
		expect(light).toHaveAttribute('aria-checked', 'false');
	});

	it('calls onchange with the new value when the inactive option is clicked', async () => {
		const onchange = vi.fn();
		const user = userEvent.setup();
		render(Toggle, {
			options: themeOptions,
			value: 'dark',
			ariaLabel: 'Theme',
			onchange
		});

		await user.click(screen.getByRole('radio', { name: 'Light' }));
		expect(onchange).toHaveBeenCalledTimes(1);
		expect(onchange).toHaveBeenCalledWith('light');
	});

	it('does not call onchange when disabled', async () => {
		const onchange = vi.fn();
		const user = userEvent.setup();
		render(Toggle, {
			options: themeOptions,
			value: 'dark',
			ariaLabel: 'Theme',
			disabled: true,
			onchange
		});

		// Clicking should be a no-op when disabled — the pick() handler
		// guards with `if (disabled || v === value) return;` before
		// invoking onchange.
		await user.click(screen.getByRole('radio', { name: 'Light' }));
		expect(onchange).not.toHaveBeenCalled();
	});
});

// v2.72 — the declared role answers the keys it promises.
//
// Toggle rendered role="radiogroup" with role="radio" children and
// handled clicks only. Everything stayed REACHABLE — native <button>s
// with no negative tabindex, so Tab visited each and Enter or Space
// activated it — so the outside report's claim that a keyboard user
// "cannot move between options" was wrong. What was wrong in the
// component is that the role was a lie: a radiogroup is a SINGLE tab
// stop whose options are traversed with the arrow keys, and assistive
// tech that trusts the role tells the user to press them.
//
// The correct implementation was already in this repo, in a sibling
// with the same role — RouteStateControl, whose header comment says it
// "mirrors Toggle's click-to-select semantics". Toggle is the one that
// drifted.
describe('Toggle — the radiogroup pattern', () => {
	// The prop is a mutable fixed-length pair, so the literal is typed
	// as that tuple rather than widened to an array or frozen by
	// `as const`.
	const options: [{ value: string; label: string }, { value: string; label: string }] = [
		{ value: 'light', label: 'Light' },
		{ value: 'dark', label: 'Dark' }
	];

	it('is a single tab stop: only the checked option is reachable by Tab', () => {
		render(Toggle, { options, value: 'light', ariaLabel: 'Theme' });

		const radios = screen.getAllByRole('radio');
		expect(radios[0].getAttribute('tabindex')).toBe('0');
		expect(radios[1].getAttribute('tabindex')).toBe('-1');
	});

	it('moves the selection with the arrow keys', async () => {
		const onchange = vi.fn();
		const { container } = render(Toggle, {
			options,
			value: 'light',
			ariaLabel: 'Theme',
			onchange
		});

		await fireEvent.keyDown(container.querySelector('[role="radiogroup"]')!, {
			key: 'ArrowRight'
		});

		expect(onchange).toHaveBeenCalledWith('dark');
	});

	it('wraps around, and answers Home and End', async () => {
		const onchange = vi.fn();
		const { container } = render(Toggle, {
			options,
			value: 'light',
			ariaLabel: 'Theme',
			onchange
		});
		const group = container.querySelector('[role="radiogroup"]')!;

		// Left from the first wraps to the last.
		await fireEvent.keyDown(group, { key: 'ArrowLeft' });
		expect(onchange).toHaveBeenLastCalledWith('dark');

		await fireEvent.keyDown(group, { key: 'End' });
		expect(onchange).toHaveBeenLastCalledWith('dark');
	});

	it('ignores the arrows while disabled', async () => {
		const onchange = vi.fn();
		const { container } = render(Toggle, {
			options,
			value: 'light',
			ariaLabel: 'Theme',
			disabled: true,
			onchange
		});

		await fireEvent.keyDown(container.querySelector('[role="radiogroup"]')!, {
			key: 'ArrowRight'
		});

		expect(onchange).not.toHaveBeenCalled();
	});

	it('leaves other keys alone', async () => {
		// The handler is on the group, so it must not swallow a key
		// something else is listening for.
		const onchange = vi.fn();
		const { container } = render(Toggle, {
			options,
			value: 'light',
			ariaLabel: 'Theme',
			onchange
		});

		await fireEvent.keyDown(container.querySelector('[role="radiogroup"]')!, { key: 'a' });
		await fireEvent.keyDown(container.querySelector('[role="radiogroup"]')!, {
			key: 'Escape'
		});

		expect(onchange).not.toHaveBeenCalled();
	});
});
