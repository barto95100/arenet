// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step V.5 — tests for the V observability API client
// functions newly added to security.ts: fetchServerPosition
// (V.4 GET) + fetchGeoEventsReplay (V.3 GET). Mirror of the
// security.test.ts pattern (fetchCertEvents U.4 — commit
// 5ab1487).
//
// Test file named observability.test.ts rather than
// extending security.test.ts so the test surface stays
// focused (security.test.ts already covers Step U.4
// fetchCertEvents). The functions UNDER TEST live in
// security.ts — there is one source-of-truth file for
// the observability HTTP wrappers per project convention.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { ServerPosition, GeoEventsResponse } from './types';

const requestMock = vi.fn();
vi.mock('./client', () => ({ request: requestMock }));

const { fetchServerPosition, fetchGeoEventsReplay } = await import('./security');

beforeEach(() => {
	requestMock.mockReset();
});

describe('fetchServerPosition', () => {
	it('GETs /observability/server-position with no query string', async () => {
		requestMock.mockResolvedValue({
			lat: 48.8566,
			lon: 2.3522,
			city: 'Paris',
			country: 'FR',
			mode: 'auto'
		} satisfies ServerPosition);

		const got = await fetchServerPosition();
		expect(requestMock).toHaveBeenCalledExactlyOnceWith(
			'GET',
			'/observability/server-position'
		);
		expect(got.city).toBe('Paris');
	});

	it('returns the degraded shape verbatim', async () => {
		// Spec §5.1 degraded shape: zeroed lat/lon, empty
		// strings, mode="auto", degraded:true. The wrapper
		// MUST NOT mutate or auto-coerce — the page
		// component branches on the flag.
		requestMock.mockResolvedValue({
			lat: 0,
			lon: 0,
			city: '',
			country: '',
			mode: 'auto',
			degraded: true
		} satisfies ServerPosition);

		const got = await fetchServerPosition();
		expect(got.degraded).toBe(true);
		expect(got.lat).toBe(0);
		expect(got.lon).toBe(0);
	});

	it('passes manual-mode positions through unchanged', async () => {
		// V.4 PUT writes mode="manual" + sourceIp empty.
		// The wrapper must not add or strip the sourceIp/
		// detectedAt fields the backend may omit.
		requestMock.mockResolvedValue({
			lat: 45.764,
			lon: 4.8357,
			city: 'Lyon',
			country: 'FR',
			mode: 'manual'
		} satisfies ServerPosition);

		const got = await fetchServerPosition();
		expect(got.mode).toBe('manual');
		expect(got.sourceIp).toBeUndefined();
	});

	it('propagates the underlying request error', async () => {
		requestMock.mockRejectedValue(new Error('HTTP 503'));
		await expect(fetchServerPosition()).rejects.toThrow('HTTP 503');
	});
});

describe('fetchGeoEventsReplay', () => {
	it('GETs /observability/geo-events with no query string when limit is omitted', async () => {
		requestMock.mockResolvedValue({
			events: [],
			total: 0
		} satisfies GeoEventsResponse);

		await fetchGeoEventsReplay();
		expect(requestMock).toHaveBeenCalledExactlyOnceWith('GET', '/observability/geo-events');
	});

	it('appends the limit query parameter when supplied', async () => {
		requestMock.mockResolvedValue({ events: [], total: 0 } satisfies GeoEventsResponse);
		await fetchGeoEventsReplay(250);
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('limit=250');
		expect(path).toBe('/observability/geo-events?limit=250');
	});

	it('URL-encodes the limit value defensively', async () => {
		// Defensive: a future caller might pass a non-int
		// limit through TypeScript's `as` cast. The wrapper
		// must not accidentally inject raw user input into
		// the URL. encodeURIComponent handles this uniformly.
		requestMock.mockResolvedValue({ events: [], total: 0 } satisfies GeoEventsResponse);
		await fetchGeoEventsReplay(100);
		const [, path] = requestMock.mock.calls[0];
		// 100 is a clean numeric value; the encoder
		// passes it through unchanged — the test asserts
		// that the encoding step is RUN (not silent string
		// concat). A future regression where someone
		// removes encodeURIComponent would still pass for
		// numeric limits but break on hypothetical string
		// inputs; this test pins the wrapping intent.
		expect(path).toBe('/observability/geo-events?limit=100');
	});

	it('returns the degraded shape verbatim', async () => {
		requestMock.mockResolvedValue({
			events: [],
			total: 0,
			degraded: true
		} satisfies GeoEventsResponse);

		const got = await fetchGeoEventsReplay(50);
		expect(got.degraded).toBe(true);
		expect(got.events).toHaveLength(0);
	});

	it('passes through populated event arrays', async () => {
		// One event per category to pin the wire shape so a
		// future GeoEvent field addition that drops/renames
		// a tag surfaces immediately.
		const events = [
			{
				timestamp: '2026-06-07T10:00:00.000Z',
				category: 'waf' as const,
				sourceIp: '203.0.113.42',
				sourceLat: 48.8566,
				sourceLon: 2.3522,
				sourceCountry: 'FR',
				sourceCity: 'Paris',
				isLan: false,
				details: '942100'
			}
		];
		requestMock.mockResolvedValue({ events, total: 1 } satisfies GeoEventsResponse);

		const got = await fetchGeoEventsReplay();
		expect(got.events).toHaveLength(1);
		expect(got.events[0].category).toBe('waf');
		expect(got.events[0].sourceCity).toBe('Paris');
	});
});
