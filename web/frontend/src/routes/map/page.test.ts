// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step V.5 — /map page tests.
//
// Three states pinned: loading, error, degraded. The
// happy-path render (position present, not degraded) is
// covered indirectly by the WorldMap.test.ts suite +
// LicenseFooter.test.ts — duplicating it here would test
// the same pixels twice. The interesting page-level
// behavior is the state machine: fetchServerPosition
// resolves → bind into the WorldMap; rejects → show
// error banner; resolves with degraded:true → show
// degraded banner + null position into the map.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import type { ServerPosition } from '$lib/api/types';

const fetchServerPositionMock = vi.fn<() => Promise<ServerPosition>>();
vi.mock('$lib/api/security', () => ({
	fetchServerPosition: () => fetchServerPositionMock()
}));

// Stub the TopoJSON fetch globally so the WorldMap mount
// inside the page doesn't try to hit the real CDN.
beforeEach(() => {
	fetchServerPositionMock.mockReset();
	vi.spyOn(globalThis, 'fetch').mockResolvedValue(
		new Response(
			JSON.stringify({
				type: 'Topology',
				arcs: [],
				objects: { countries: { type: 'GeometryCollection', geometries: [] } }
			}),
			{ status: 200, headers: { 'Content-Type': 'application/json' } }
		)
	);
});

const { default: MapPage } = await import('./+page.svelte');

describe('/map page', () => {
	it('shows the loading state before the fetch resolves', async () => {
		// Hang the promise to lock the loading state visible.
		fetchServerPositionMock.mockImplementation(() => new Promise(() => {}));
		render(MapPage);
		expect(screen.getByTestId('map-loading')).toBeInTheDocument();
	});

	it('renders the WorldMap frame on the happy path', async () => {
		fetchServerPositionMock.mockResolvedValue({
			lat: 48.8566,
			lon: 2.3522,
			city: 'Paris',
			country: 'FR',
			mode: 'auto'
		});
		render(MapPage);
		await waitFor(() => {
			expect(screen.queryByTestId('map-loading')).toBeNull();
			expect(screen.getByTestId('map-frame')).toBeInTheDocument();
		});
		expect(screen.queryByTestId('map-degraded')).toBeNull();
		expect(screen.queryByTestId('map-error')).toBeNull();
	});

	it('renders the degraded banner AND the map (null coords) when degraded:true', async () => {
		fetchServerPositionMock.mockResolvedValue({
			lat: 0,
			lon: 0,
			city: '',
			country: '',
			mode: 'auto',
			degraded: true
		});
		render(MapPage);
		await waitFor(() => {
			expect(screen.getByTestId('map-degraded')).toBeInTheDocument();
		});
		// The frame still renders so the operator sees the
		// world map alongside the banner — better than a
		// blank page when GeoIP is absent.
		expect(screen.getByTestId('map-frame')).toBeInTheDocument();
		// Marker MUST be absent (lat/lon collapsed to null
		// by the page conditional) so a misleading pin
		// doesn't appear off the coast of Ghana.
		expect(screen.queryByTestId('worldmap-marker')).toBeNull();
	});

	it('shows the error banner on fetch failure', async () => {
		fetchServerPositionMock.mockRejectedValue(new Error('HTTP 503'));
		render(MapPage);
		await waitFor(() => {
			expect(screen.getByTestId('map-error')).toBeInTheDocument();
		});
		expect(screen.queryByTestId('map-frame')).toBeNull();
	});

	it('mentions ARENET_GEOIP_MMDB in the degraded banner help text', async () => {
		// Pin the operator-facing path the banner advertises
		// — a future copy edit that drops the env var name
		// would silently rob operators of the actionable
		// hint.
		fetchServerPositionMock.mockResolvedValue({
			lat: 0,
			lon: 0,
			city: '',
			country: '',
			mode: 'auto',
			degraded: true
		});
		render(MapPage);
		await waitFor(() => {
			expect(screen.getByTestId('map-degraded').textContent ?? '').toContain(
				'ARENET_GEOIP_MMDB'
			);
		});
	});
});
