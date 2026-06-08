// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// W.5 — unit tests for fetchCountryBlockEvents. Mirror of
// security.test.ts shape; pins the URL parameter encoding +
// path (must be /observability/, not /security/).

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { CountryBlockEventsResponse } from './types';

const requestMock = vi.fn();
vi.mock('./client', () => ({ request: requestMock }));

const { fetchCountryBlockEvents } = await import('./security');

beforeEach(() => {
	requestMock.mockReset();
	requestMock.mockResolvedValue({
		events: [],
		total: 0,
		hasMore: false
	} satisfies CountryBlockEventsResponse);
});

describe('fetchCountryBlockEvents: URL parameter encoding', () => {
	it('hits /observability/country-block-events without query string when params are empty', async () => {
		await fetchCountryBlockEvents();
		expect(requestMock).toHaveBeenCalledWith('GET', '/observability/country-block-events');
	});

	it('hits the /observability/ path (NOT /security/)', async () => {
		// W.5 mirrors U.3's convention: lifecycle / persistence
		// observability lives under /observability/. A future
		// refactor that moves it to /security/country-block-events
		// would break the W.5 backend route mount.
		await fetchCountryBlockEvents({ limit: 10 });
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('/observability/country-block-events');
		expect(path).not.toContain('/security/country-block-events');
	});

	it('serializes numeric limit as a string', async () => {
		await fetchCountryBlockEvents({ limit: 250 });
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('limit=250');
	});

	it('forwards route + srcIp + country + mode filters verbatim', async () => {
		await fetchCountryBlockEvents({
			route: 'route-abc',
			srcIp: '203.0.113.5',
			country: 'RU',
			mode: 'deny'
		});
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('route=route-abc');
		expect(path).toContain('srcIp=203.0.113.5');
		expect(path).toContain('country=RU');
		expect(path).toContain('mode=deny');
	});

	it('forwards since/until RFC 3339 strings as-is', async () => {
		await fetchCountryBlockEvents({
			since: '2026-06-01T00:00:00Z',
			until: '2026-06-08T00:00:00Z'
		});
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('since=2026-06-01T00%3A00%3A00Z');
		expect(path).toContain('until=2026-06-08T00%3A00%3A00Z');
	});

	it('omits undefined filters from the query string', async () => {
		await fetchCountryBlockEvents({ mode: 'allow' });
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('mode=allow');
		expect(path).not.toContain('route=');
		expect(path).not.toContain('country=');
		expect(path).not.toContain('srcIp=');
		expect(path).not.toContain('since=');
	});

	it('resolves to the typed response payload', async () => {
		const ts = '2026-06-08T12:00:00Z';
		requestMock.mockResolvedValueOnce({
			events: [
				{
					id: 1,
					ts,
					routeId: 'r-1',
					srcIp: '203.0.113.5',
					country: 'RU',
					mode: 'deny',
					statusCode: 451,
					reason: 'deny-match'
				}
			],
			total: 1,
			hasMore: false
		} satisfies CountryBlockEventsResponse);

		const res = await fetchCountryBlockEvents();
		expect(res.events).toHaveLength(1);
		expect(res.events[0].country).toBe('RU');
		expect(res.events[0].mode).toBe('deny');
		expect(res.events[0].statusCode).toBe(451);
	});
});
