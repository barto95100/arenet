// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Tests for the /system/health client (v2.73).
//
// The subtle half is the status mapping, which is read in
// internal/api/system_health.go:66-68 rather than assumed: healthy
// and degraded answer 200, unhealthy answers 503 WITH THE SAME JSON
// BODY. A client that treated a non-2xx as an error would therefore
// report "unknown" for the one state it most needs to report, so the
// 503 case gets its own test.
//
// The other half is that null means "could not find out" and must
// never be confused with a verdict. The topbar renders it grey, and
// the whole point of this module is that it does not fall back on the
// reassuring answer.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { fetchSystemHealth, unhealthyComponentNames } from './system-health';

function jsonResponse(status: number, body: unknown): Response {
	return {
		status,
		json: async () => body
	} as unknown as Response;
}

const realFetch = globalThis.fetch;

beforeEach(() => {
	globalThis.fetch = vi.fn() as unknown as typeof fetch;
});

afterEach(() => {
	globalThis.fetch = realFetch;
});

const healthy = {
	status: 'healthy',
	timestamp: '2026-10-14T12:00:00Z',
	version: 'v2.73.0',
	components: [{ name: 'caddy', status: 'healthy', message: 'config reloads healthy' }]
};

describe('fetchSystemHealth', () => {
	it('reads a healthy 200', async () => {
		vi.mocked(globalThis.fetch).mockResolvedValue(jsonResponse(200, healthy));
		const r = await fetchSystemHealth();
		expect(r?.status).toBe('healthy');
		expect(r?.components).toHaveLength(1);
	});

	it('reads a degraded 200', async () => {
		vi.mocked(globalThis.fetch).mockResolvedValue(
			jsonResponse(200, { ...healthy, status: 'degraded' })
		);
		expect((await fetchSystemHealth())?.status).toBe('degraded');
	});

	// The one that would break if this went through client.ts's
	// request(), which throws on any non-ok status.
	it('reads the body of a 503 instead of calling it an error', async () => {
		vi.mocked(globalThis.fetch).mockResolvedValue(
			jsonResponse(503, { ...healthy, status: 'unhealthy' })
		);
		expect((await fetchSystemHealth())?.status).toBe('unhealthy');
	});

	it('returns null on a status it has no contract for', async () => {
		vi.mocked(globalThis.fetch).mockResolvedValue(jsonResponse(500, { status: 'unhealthy' }));
		expect(await fetchSystemHealth()).toBeNull();
	});

	it('returns null when the request throws', async () => {
		vi.mocked(globalThis.fetch).mockRejectedValue(new Error('offline'));
		expect(await fetchSystemHealth()).toBeNull();
	});

	it('returns null when the body is not a report', async () => {
		vi.mocked(globalThis.fetch).mockResolvedValue(jsonResponse(200, { hello: 'world' }));
		expect(await fetchSystemHealth()).toBeNull();
	});

	it('returns null on a status string outside the enum', async () => {
		vi.mocked(globalThis.fetch).mockResolvedValue(jsonResponse(200, { status: 'fine' }));
		expect(await fetchSystemHealth()).toBeNull();
	});

	// A field added to Report on the backend must not turn the badge
	// grey, which is why only `status` is required.
	it('tolerates a report with extra fields and no components', async () => {
		vi.mocked(globalThis.fetch).mockResolvedValue(
			jsonResponse(200, { status: 'healthy', somethingNew: 42 })
		);
		const r = await fetchSystemHealth();
		expect(r?.status).toBe('healthy');
		expect(r?.components).toEqual([]);
	});

	it('asks the root path, not the /api/v1 subtree', async () => {
		vi.mocked(globalThis.fetch).mockResolvedValue(jsonResponse(200, healthy));
		await fetchSystemHealth();
		expect(vi.mocked(globalThis.fetch).mock.calls[0][0]).toBe('/system/health');
	});
});

describe('unhealthyComponentNames', () => {
	it('names only what is not healthy, in report order', () => {
		expect(
			unhealthyComponentNames({
				status: 'degraded',
				timestamp: '',
				components: [
					{ name: 'caddy', status: 'healthy', message: '' },
					{ name: 'crowdsec', status: 'degraded', message: '' },
					{ name: 'certmagic', status: 'unhealthy', message: '' }
				]
			})
		).toEqual(['crowdsec', 'certmagic']);
	});

	it('is empty for a healthy report, so the caller can omit the tooltip', () => {
		expect(
			unhealthyComponentNames({
				status: 'healthy',
				timestamp: '',
				components: [{ name: 'caddy', status: 'healthy', message: '' }]
			})
		).toEqual([]);
	});
});
