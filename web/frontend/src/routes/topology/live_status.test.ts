// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The live indicator must say what the canvas is actually showing.
//
// Three defects, all in the same corner of the page:
//
//   1. liveStatus was initialised to 'reconnecting', so EVERY page
//      load showed an amber "reconnecting…" pill until the first tick
//      arrived — a warning about a problem that did not exist, which
//      is how a real warning stops being read.
//   2. On a dropped stream nothing dimmed and no time was shown. The
//      canvas kept rendering the last frame, with particles still
//      flowing along its edges, so a frozen graph was pixel-identical
//      to a live one. Same class as the /logs page's "No event in this
//      window" under a green pill, fixed in v2.73.
//   3. The indicator had no role, so a change of state was never
//      announced.
//
// These tests drive the page's real callbacks: connectLiveStream is
// mocked to capture BOTH of them, so a disconnect can be delivered on
// demand rather than waited for.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import type { TopologyRoute } from './_types';
import type { OnTick, SnapshotPayload } from './_api';

const apiMock = vi.hoisted(() => ({
	fetchSnapshot: vi.fn(),
	onTick: null as null | OnTick,
	onDisconnect: null as null | (() => void)
}));

vi.mock('./_api', async () => {
	const actual = await vi.importActual<typeof import('./_api')>('./_api');
	return {
		...actual,
		fetchSnapshot: (...a: unknown[]) => apiMock.fetchSnapshot(...a),
		connectLiveStream: (onTick: OnTick, onDisconnect: () => void) => {
			apiMock.onTick = onTick;
			apiMock.onDisconnect = onDisconnect;
			return () => {};
		}
	};
});

import Page from './+page.svelte';

function proxyRoute(id: string): TopologyRoute {
	return {
		id,
		host: `${id}.example.com`,
		upstreams: [
			{ id: `${id}-0`, url: 'http://10.0.0.5', status: 'healthy', reqPerSec: 3, p99LatencyMs: 12 }
		],
		lbPolicy: 'round_robin',
		reqPerSec: 3,
		p99LatencyMs: 12,
		errorRate5xx: 0,
		tlsEnabled: true,
		httpRedirect: false,
		hasHealthCheck: false,
		disabled: false
	} as unknown as TopologyRoute;
}

const ROUTES = [proxyRoute('p-1')];

function snapshot(routes: TopologyRoute[]): SnapshotPayload {
	return { generatedAt: '2026-10-15T09:00:00Z', routes };
}

beforeEach(() => {
	apiMock.fetchSnapshot.mockReset();
	apiMock.onTick = null;
	apiMock.onDisconnect = null;
	apiMock.fetchSnapshot.mockResolvedValue(snapshot(ROUTES));
	if (!globalThis.ResizeObserver) {
		globalThis.ResizeObserver = class {
			observe() {}
			unobserve() {}
			disconnect() {}
		} as unknown as typeof ResizeObserver;
	}
});

afterEach(() => {
	vi.restoreAllMocks();
});

/** The indicator, once the page has got past its loading state. */
async function indicator(): Promise<HTMLElement> {
	return await screen.findByTestId('topology-live-indicator');
}

describe('topology — the live indicator', () => {
	it('does not cry reconnecting before it has ever connected', async () => {
		render(Page);
		const el = await indicator();

		expect(el.dataset.status).toBe('connecting');
		expect(el.textContent ?? '').not.toMatch(/reconnect/i);
	});

	it('reads live once a frame has arrived', async () => {
		render(Page);
		await indicator();

		apiMock.onTick?.(ROUTES, '2026-10-15T09:00:02Z');

		await waitFor(async () => expect((await indicator()).dataset.status).toBe('live'));
	});

	it('reads stale when the stream drops, not live', async () => {
		render(Page);
		await indicator();
		apiMock.onTick?.(ROUTES, '2026-10-15T09:00:02Z');
		await waitFor(async () => expect((await indicator()).dataset.status).toBe('live'));

		apiMock.onDisconnect?.();

		await waitFor(async () => expect((await indicator()).dataset.status).toBe('stale'));
	});

	// The defect that matters: the graph keeps its last frame on
	// purpose — losing it would be worse — so the canvas itself has to
	// say the frame is old, or frozen traffic is pixel-identical to
	// live traffic.
	it('marks the canvas stale so a frozen graph does not look live', async () => {
		render(Page);
		await indicator();
		apiMock.onTick?.(ROUTES, '2026-10-15T09:00:02Z');
		await waitFor(async () => expect((await indicator()).dataset.status).toBe('live'));

		const canvas = document.querySelector('[data-testid="topology-canvas-frame"]');
		expect(canvas).not.toBeNull();
		expect(canvas?.getAttribute('data-stale')).toBe('false');

		apiMock.onDisconnect?.();

		await waitFor(() =>
			expect(
				document
					.querySelector('[data-testid="topology-canvas-frame"]')
					?.getAttribute('data-stale')
			).toBe('true')
		);
	});

	// A pill that changes meaning silently is no better than one that
	// never changes.
	it('is a live region, so the drop is announced', async () => {
		render(Page);
		expect((await indicator()).getAttribute('role')).toBe('status');
	});
});
