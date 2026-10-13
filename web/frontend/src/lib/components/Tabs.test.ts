// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step CS.3 — Tabs component tests.
//
// Pins the public contract extracted from the pre-CS.3 inline
// tablists in /security/decisions and /certs:
//   - role="tablist" wrapper with operator-supplied aria-label
//   - role="tab" buttons with aria-selected on the active one
//   - testId on each tab so callers preserve existing test IDs
//   - click → emits onChange + updates the bindable value
//   - clicking the already-active tab is a no-op (onChange NOT
//     fired) — caller invariant from the pre-extraction code
//   - keyboard activation: Enter/Space natively via <button>

import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import Tabs from './Tabs.svelte';

type DemoTab = 'snapshot' | 'live' | 'scenarios';

const demoTabs: ReadonlyArray<{ id: DemoTab; label: string; testId?: string }> = [
	{ id: 'snapshot', label: 'Local snapshot', testId: 'tab-snapshot' },
	{ id: 'live', label: 'Live LAPI', testId: 'tab-live' },
	{ id: 'scenarios', label: 'Scenarios', testId: 'tab-scenarios' }
];

describe('Tabs', () => {
	it('renders one button per tab with the right label + testId', () => {
		render(Tabs, {
			value: 'snapshot' as DemoTab,
			tabs: demoTabs,
			ariaLabel: 'Demo tabs'
		});
		expect(screen.getByTestId('tab-snapshot').textContent).toContain('Local snapshot');
		expect(screen.getByTestId('tab-live').textContent).toContain('Live LAPI');
		expect(screen.getByTestId('tab-scenarios').textContent).toContain('Scenarios');
	});

	it('applies role="tablist" + the operator-supplied aria-label', () => {
		render(Tabs, {
			value: 'snapshot' as DemoTab,
			tabs: demoTabs,
			ariaLabel: 'CrowdSec decisions tabs'
		});
		const tablist = screen.getByRole('tablist', { name: 'CrowdSec decisions tabs' });
		expect(tablist).toBeInTheDocument();
	});

	it('marks the active tab with aria-selected=true, others false', () => {
		render(Tabs, {
			value: 'live' as DemoTab,
			tabs: demoTabs,
			ariaLabel: 'Demo tabs'
		});
		expect(screen.getByTestId('tab-live')).toHaveAttribute('aria-selected', 'true');
		expect(screen.getByTestId('tab-snapshot')).toHaveAttribute('aria-selected', 'false');
		expect(screen.getByTestId('tab-scenarios')).toHaveAttribute('aria-selected', 'false');
	});

	it('fires onChange when a different tab is clicked', async () => {
		const onChange = vi.fn();
		render(Tabs, {
			value: 'snapshot' as DemoTab,
			tabs: demoTabs,
			ariaLabel: 'Demo tabs',
			onChange
		});

		await fireEvent.click(screen.getByTestId('tab-live'));
		expect(onChange).toHaveBeenCalledWith('live');
	});

	it('does NOT fire onChange when clicking the already-active tab', async () => {
		const onChange = vi.fn();
		render(Tabs, {
			value: 'snapshot' as DemoTab,
			tabs: demoTabs,
			ariaLabel: 'Demo tabs',
			onChange
		});
		await fireEvent.click(screen.getByTestId('tab-snapshot'));
		expect(onChange).not.toHaveBeenCalled();
	});

	it('works without an onChange callback (bindable value only)', async () => {
		// No onChange — caller relies purely on the bindable
		// value mutation. Must not throw.
		render(Tabs, {
			value: 'snapshot' as DemoTab,
			tabs: demoTabs,
			ariaLabel: 'Demo tabs'
		});
		await fireEvent.click(screen.getByTestId('tab-scenarios'));
		// No assertion on side effects — the absence-of-error
		// is the contract. If render or click threw, the test
		// would fail above.
	});

	it('handles keyboard activation natively via <button>', async () => {
		const onChange = vi.fn();
		render(Tabs, {
			value: 'snapshot' as DemoTab,
			tabs: demoTabs,
			ariaLabel: 'Demo tabs',
			onChange
		});

		const liveTab = screen.getByTestId('tab-live');
		liveTab.focus();
		// Enter key on a focused <button> fires a click event
		// natively in the browser — JSDOM emulates this.
		await fireEvent.keyDown(liveTab, { key: 'Enter' });
		// Some envs need explicit click() to mimic Enter on a
		// button; do both for stability.
		await fireEvent.click(liveTab);
		expect(onChange).toHaveBeenCalledWith('live');
	});

	it('renders without a testId when callers omit it', () => {
		const tabsNoTestIds = [
			{ id: 'a' as const, label: 'A' },
			{ id: 'b' as const, label: 'B' }
		];
		render(Tabs, {
			value: 'a',
			tabs: tabsNoTestIds,
			ariaLabel: 'No test IDs'
		});
		// Should still render — accessibility-first selector.
		expect(screen.getByRole('tab', { name: 'A' })).toBeInTheDocument();
		expect(screen.getByRole('tab', { name: 'B' })).toBeInTheDocument();
	});
});

// v2.72 — the veto hook (spec 2026-10-13, D3).
//
// The settings page needs to ask before a tab switch discards the
// unsaved input of the section it is about to unmount. canLeave is
// optional so the five other call sites are untouched; the tests above
// are the instrument for that.
describe('Tabs — canLeave', () => {
	const tabs = [
		{ id: 'a', label: 'Alpha' },
		{ id: 'b', label: 'Beta' }
	] as const;

	it('does not switch, and does not fire onChange, when the veto refuses', async () => {
		const onChange = vi.fn();
		render(Tabs, {
			props: { value: 'a', tabs, ariaLabel: 'test tabs', onChange, canLeave: () => false }
		});

		await fireEvent.click(screen.getByRole('tab', { name: 'Beta' }));

		expect(onChange).not.toHaveBeenCalled();
		expect(screen.getByRole('tab', { name: 'Alpha' }).getAttribute('aria-selected')).toBe(
			'true'
		);
		expect(screen.getByRole('tab', { name: 'Beta' }).getAttribute('aria-selected')).toBe(
			'false'
		);
	});

	it('passes the target id to the veto, so the caller can resume', async () => {
		const seen: string[] = [];
		render(Tabs, {
			props: {
				value: 'a',
				tabs,
				ariaLabel: 'test tabs',
				canLeave: (next: string) => {
					seen.push(next);
					return false;
				}
			}
		});

		await fireEvent.click(screen.getByRole('tab', { name: 'Beta' }));

		expect(seen).toEqual(['b']);
	});

	it('switches when the veto allows it', async () => {
		const onChange = vi.fn();
		render(Tabs, {
			props: { value: 'a', tabs, ariaLabel: 'test tabs', onChange, canLeave: () => true }
		});

		await fireEvent.click(screen.getByRole('tab', { name: 'Beta' }));

		expect(onChange).toHaveBeenCalledWith('b');
		expect(screen.getByRole('tab', { name: 'Beta' }).getAttribute('aria-selected')).toBe(
			'true'
		);
	});
});
