// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Z.1 — unit tests for fetchRateLimitEvents. Mirror of
// security_country_block.test.ts shape; pins URL parameter
// encoding + path (must be /security/, not /observability/).

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { RateLimitEventsResponse } from './types';

const requestMock = vi.fn();
vi.mock('./client', () => ({ request: requestMock }));

const { fetchRateLimitEvents } = await import('./security');

beforeEach(() => {
	requestMock.mockReset();
	requestMock.mockResolvedValue({
		events: [],
		total: 0,
		hasMore: false
	} satisfies RateLimitEventsResponse);
});

describe('fetchRateLimitEvents: URL parameter encoding', () => {
	it('hits /security/rate-limit-events without query string when params are empty', async () => {
		await fetchRateLimitEvents();
		expect(requestMock).toHaveBeenCalledWith('GET', '/security/rate-limit-events');
	});

	it('hits the /security/ path (NOT /observability/)', async () => {
		// Z.1 follows the throttle-events convention : real-
		// time security signal lives under /security/. A
		// future refactor to /observability/ would break the
		// Z.1 backend route mount.
		await fetchRateLimitEvents({ limit: 10 });
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('/security/rate-limit-events');
		expect(path).not.toContain('/observability/rate-limit-events');
	});

	it('serializes numeric limit as a string', async () => {
		await fetchRateLimitEvents({ limit: 250 });
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('limit=250');
	});

	it('forwards route + remoteIp filters verbatim', async () => {
		await fetchRateLimitEvents({
			route: 'route-abc',
			remoteIp: '203.0.113.5'
		});
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('route=route-abc');
		expect(path).toContain('remoteIp=203.0.113.5');
	});

	it('forwards since/until RFC 3339 strings (URL-encoded)', async () => {
		await fetchRateLimitEvents({
			since: '2026-06-17T00:00:00Z',
			until: '2026-06-18T00:00:00Z'
		});
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('since=2026-06-17T00%3A00%3A00Z');
		expect(path).toContain('until=2026-06-18T00%3A00%3A00Z');
	});

	it('omits undefined filters from the query string', async () => {
		await fetchRateLimitEvents({ remoteIp: '1.2.3.4' });
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('remoteIp=1.2.3.4');
		expect(path).not.toContain('route=');
		expect(path).not.toContain('since=');
		expect(path).not.toContain('until=');
	});

	it('resolves to the typed response payload', async () => {
		requestMock.mockResolvedValueOnce({
			events: [
				{
					id: 1,
					ts: '2026-06-18T12:00:00Z',
					routeId: 'r-1',
					zone: 'route-r-1',
					remoteIp: '203.0.113.5',
					waitMs: 1500
				}
			],
			total: 1,
			hasMore: false
		} satisfies RateLimitEventsResponse);
		const r = await fetchRateLimitEvents({ limit: 10 });
		expect(r.events).toHaveLength(1);
		expect(r.events[0].zone).toBe('route-r-1');
		expect(r.events[0].waitMs).toBe(1500);
	});
});
