// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step V.5 — WorldMap component tests.
//
// jsdom doesn't implement <svg> layout (getBBox returns
// zeros) and skips the D3 path render that depends on
// SVGMatrix. We assert on:
//   - the SVG element + ocean rect + countries <g> are
//     mounted;
//   - the fetch URL for the TopoJSON is hit with the
//     default path AND a custom prop override;
//   - the marker <g> appears when arenetLat/Lon are
//     supplied and is ABSENT in the null-position case
//     (V.5 degraded-mode path).
//
// The actual country paths are inserted by D3 in an
// $effect; jsdom can't render them visually but we can
// observe the path elements in the DOM after a topojson
// fetch resolves.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import WorldMap from './WorldMap.svelte';

// A minimal TopoJSON fixture with one synthetic country
// covering ~0..10 degrees — enough to drive feature() +
// path() through their happy paths without bundling the
// 700+ KB real world-atlas asset into the test environment.
const FIXTURE_TOPOJSON = {
	type: 'Topology',
	arcs: [
		[
			[0, 0],
			[10000, 0],
			[0, 10000],
			[-10000, 0]
		]
	],
	transform: {
		scale: [0.001, 0.001],
		translate: [0, 0]
	},
	objects: {
		countries: {
			type: 'GeometryCollection',
			geometries: [
				{
					type: 'Polygon',
					arcs: [[0]],
					properties: { name: 'Atlantis' }
				}
			]
		}
	}
};

beforeEach(() => {
	vi.restoreAllMocks();
});

function mockTopoJSONFetch() {
	return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input: RequestInfo | URL) => {
		const url = typeof input === 'string' ? input : input.toString();
		return new Response(JSON.stringify(FIXTURE_TOPOJSON), {
			status: 200,
			headers: { 'Content-Type': 'application/json' }
		});
	});
}

describe('WorldMap', () => {
	it('mounts the SVG container + ocean rect + countries group', async () => {
		mockTopoJSONFetch();
		render(WorldMap, { arenetLat: 48.8566, arenetLon: 2.3522 });
		expect(screen.getByTestId('worldmap-container')).toBeInTheDocument();
		expect(screen.getByTestId('worldmap-countries')).toBeInTheDocument();
		// The SVG element itself is reachable via the role.
		expect(screen.getByRole('img')).toBeInTheDocument();
	});

	it('fetches the default /world-50m.topo.json URL on mount', async () => {
		const fetchSpy = mockTopoJSONFetch();
		render(WorldMap, { arenetLat: 0, arenetLon: 0 });
		await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
		const calledWith = fetchSpy.mock.calls[0][0];
		expect(String(calledWith)).toBe('/world-50m.topo.json');
	});

	it('honors the topojsonUrl prop override', async () => {
		const fetchSpy = mockTopoJSONFetch();
		render(WorldMap, {
			arenetLat: 0,
			arenetLon: 0,
			topojsonUrl: '/test-fixtures/tiny-world.topo.json'
		});
		await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
		expect(String(fetchSpy.mock.calls[0][0])).toBe('/test-fixtures/tiny-world.topo.json');
	});

	it('renders the marker when arenet lat/lon are supplied', async () => {
		mockTopoJSONFetch();
		render(WorldMap, {
			arenetLat: 48.8566,
			arenetLon: 2.3522,
			city: 'Paris',
			country: 'FR'
		});
		expect(screen.getByTestId('worldmap-marker')).toBeInTheDocument();
	});

	it('renders the city, country label and the manual badge', async () => {
		mockTopoJSONFetch();
		render(WorldMap, {
			arenetLat: 45.764,
			arenetLon: 4.8357,
			city: 'Lyon',
			country: 'FR',
			mode: 'manual'
		});
		const marker = screen.getByTestId('worldmap-marker');
		expect(marker.textContent ?? '').toContain('Lyon');
		expect(marker.textContent ?? '').toContain('FR');
		expect(marker.textContent ?? '').toContain('(manuel)');
	});

	it('omits the (manuel) badge when mode is "auto"', async () => {
		mockTopoJSONFetch();
		render(WorldMap, {
			arenetLat: 48.8566,
			arenetLon: 2.3522,
			city: 'Paris',
			country: 'FR',
			mode: 'auto'
		});
		const marker = screen.getByTestId('worldmap-marker');
		expect(marker.textContent ?? '').not.toContain('(manuel)');
	});

	it('does NOT render the marker when arenetLat is null (degraded mode)', async () => {
		mockTopoJSONFetch();
		render(WorldMap, { arenetLat: null, arenetLon: null });
		expect(screen.queryByTestId('worldmap-marker')).toBeNull();
	});

	it('surfaces a fetch failure as a visible error banner', async () => {
		vi.spyOn(globalThis, 'fetch').mockResolvedValue(
			new Response('not found', { status: 404 })
		);
		render(WorldMap, { arenetLat: 0, arenetLon: 0 });
		await waitFor(() => {
			expect(screen.getByRole('alert').textContent ?? '').toMatch(/Carte indisponible/);
		});
	});

	it('uses width/height props for the viewBox', async () => {
		mockTopoJSONFetch();
		render(WorldMap, { width: 800, height: 400, arenetLat: 0, arenetLon: 0 });
		const svg = screen.getByRole('img') as unknown as SVGSVGElement;
		expect(svg.getAttribute('viewBox')).toBe('0 0 800 400');
	});
});
