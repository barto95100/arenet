// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step J.6 — Topology page header migration regression test.
//
// Spec §5.5 names three tests; the gate predicate is covered in
// lib/topology/auto-fit.test.ts. This file is the third: a
// render-level assertion that the page now uses the shared
// <PageHeader> + <StatusDot> atomic and no longer carries the
// legacy `.status-dot` page-local CSS class.
//
// We do NOT snapshot the entire DOM — a fragile snapshot would
// fail on every unrelated tweak. Instead we pin the structural
// invariants that mark the migration:
//
//   1. PageHeader's own class hooks render (`.page-header__title`,
//      `.page-header__actions`).
//   2. The page no longer emits the legacy `.status-dot-*` span
//      that used a page-scoped CSS rule.
//   3. The connection status text (statusLabel) and the
//      <StatusDot>'s ARIA label are present inside the actions
//      slot, in the order the spec mandates.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/svelte';

// $app/navigation's goto is reached when the WebSocket
// handshake 401s. Tests here never trigger that path but the
// import must resolve — provide a no-op stub.
vi.mock('$app/navigation', () => ({
	goto: vi.fn()
}));

// TopologyClient opens a real WebSocket connection in its
// constructor — replace with an inert no-op class so the page
// renders without a live server.
vi.mock('$lib/api/topology', () => {
	class TopologyClient {
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		constructor(_opts: unknown) {}
		connect(): void {}
		disconnect(): void {}
		destroy(): void {}
		attachVisibilityListener(): void {}
	}
	return { TopologyClient };
});

const { topology } = await import('$lib/stores/topology.svelte');
import Page from './+page.svelte';

beforeEach(() => {
	// Reset the topology store between tests so the "empty store"
	// branch is exercised cleanly (renders the empty-state placeholder
	// instead of the SVG, which is irrelevant to the header assertions).
	topology.setStatus('disconnected');
});

describe('Topology page — J.6 header migration', () => {
	it('renders the shared PageHeader markup', () => {
		render(Page);
		// The title is rendered by <PageHeader> with its scoped class.
		const title = document.querySelector('.page-header__title');
		expect(title).not.toBeNull();
		expect(title?.textContent).toBe('Topology');
		// The subtitle string per spec.
		expect(screen.getByText('Live network visualization.')).toBeInTheDocument();
		// The actions slot is present — PageHeader renders the
		// wrapper only when actions snippet is provided.
		expect(document.querySelector('.page-header__actions')).not.toBeNull();
	});

	it('no longer emits the legacy page-local .status-dot span', () => {
		render(Page);
		// Pre-J.6 the page wrote `.status-dot.status-dot-up|warn|down`
		// directly in the header markup. The migration drops those in
		// favour of the <StatusDot> atomic, which uses Tailwind
		// utility classes (no `.status-dot` page-scoped class). Any
		// element with the legacy class is a regression to the old
		// markup.
		expect(document.querySelector('.status-dot')).toBeNull();
		expect(document.querySelector('.status-dot-up')).toBeNull();
		expect(document.querySelector('.status-dot-warn')).toBeNull();
		expect(document.querySelector('.status-dot-down')).toBeNull();
	});

	it('connection status indicator lives inside the PageHeader actions slot', () => {
		render(Page);
		const actions = document.querySelector('.page-header__actions');
		expect(actions).not.toBeNull();
		// The <StatusDot> atomic uses `aria-label="Status: <state>"`
		// — at mount the topology store reports `disconnected`,
		// which maps to status="down" in the page's $derived.
		const dot = actions?.querySelector('[aria-label^="Status:"]');
		expect(dot).not.toBeNull();
		// The textual status label (one of connected / reconnecting…
		// / disconnected) sits next to the dot in the same `<span
		// class="status">` wrapper.
		expect(actions?.querySelector('span.status')).not.toBeNull();
	});
});
