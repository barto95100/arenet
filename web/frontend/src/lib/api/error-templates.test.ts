// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step R Phase 2 — unit tests for errorTemplatesApi.
// Pins the URL encoding + HTTP method + payload pass-through
// so a backend rename surfaces as a vitest failure rather than
// a silent prod regression. Mirror of security_rate_limit.test.ts
// shape.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { ErrorTemplate, ErrorTemplateRequest } from './error-templates';

const requestMock = vi.fn();
vi.mock('./client', () => ({ request: requestMock }));

const { errorTemplatesApi, SUPPORTED_ERROR_STATUS_CODES, ERROR_PAGE_PLACEHOLDERS } =
	await import('./error-templates');

beforeEach(() => {
	requestMock.mockReset();
	requestMock.mockResolvedValue([] satisfies ErrorTemplate[]);
});

describe('errorTemplatesApi: URL + verb mapping', () => {
	it('list → GET /error-templates', async () => {
		await errorTemplatesApi.list();
		expect(requestMock).toHaveBeenCalledWith('GET', '/error-templates');
	});

	it('get → GET /error-templates/{id} (URL-encoded)', async () => {
		await errorTemplatesApi.get('abc 123');
		const [method, path] = requestMock.mock.calls[0];
		expect(method).toBe('GET');
		// encodeURIComponent : space → %20
		expect(path).toBe('/error-templates/abc%20123');
	});

	it('create → POST /error-templates with full payload', async () => {
		const req: ErrorTemplateRequest = {
			name: 'wgw',
			description: 'branding',
			pages: { '403': '<h1>x</h1>' }
		};
		await errorTemplatesApi.create(req);
		expect(requestMock).toHaveBeenCalledWith('POST', '/error-templates', req);
	});

	it('update → PUT /error-templates/{id} with payload', async () => {
		const req: ErrorTemplateRequest = {
			name: 'renamed',
			pages: { '403': '<h1>v2</h1>' }
		};
		await errorTemplatesApi.update('uuid-1', req);
		expect(requestMock).toHaveBeenCalledWith('PUT', '/error-templates/uuid-1', req);
	});

	it('delete → DELETE /error-templates/{id}', async () => {
		await errorTemplatesApi.delete('uuid-1');
		expect(requestMock).toHaveBeenCalledWith('DELETE', '/error-templates/uuid-1');
	});
});

describe('errorTemplatesApi.preview', () => {
	it('hits the raw-text endpoint via fetch (not the JSON request helper)', async () => {
		// preview() uses fetch directly because the endpoint
		// returns text/html, not the JSON envelope. We mock
		// global fetch here.
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			text: () => Promise.resolve('<h1>preview body</h1>')
		});
		const originalFetch = globalThis.fetch;
		globalThis.fetch = fetchMock as unknown as typeof fetch;
		try {
			const body = await errorTemplatesApi.preview('uuid-1', 403);
			expect(body).toBe('<h1>preview body</h1>');
			expect(fetchMock).toHaveBeenCalledWith(
				'/api/v1/error-templates/uuid-1/preview?statusCode=403',
				{ credentials: 'include' }
			);
			// The shared request mock must NOT be invoked — that's
			// the regression guard against someone "simplifying"
			// preview to use request<string>() which would break
			// the response body parsing.
			expect(requestMock).not.toHaveBeenCalled();
		} finally {
			globalThis.fetch = originalFetch;
		}
	});

	it('throws on non-OK response with the API error message', async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			ok: false,
			status: 404,
			json: () => Promise.resolve({ error: 'template not found' })
		});
		const originalFetch = globalThis.fetch;
		globalThis.fetch = fetchMock as unknown as typeof fetch;
		try {
			await expect(errorTemplatesApi.preview('ghost', 403)).rejects.toThrow(
				'template not found'
			);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});
});

describe('SUPPORTED_ERROR_STATUS_CODES', () => {
	it('matches the backend Phase 1 locked set exactly', () => {
		// Locked at storage.SupportedErrorStatusCodes (Go side).
		// Drift here vs backend would produce silent UI tabs that
		// the backend rejects at validate() — operator-confusing.
		expect([...SUPPORTED_ERROR_STATUS_CODES]).toEqual([
			401, 403, 404, 429, 500, 502, 503, 504
		]);
	});
});

describe('ERROR_PAGE_PLACEHOLDERS', () => {
	it('every placeholder token starts and ends with curly braces', () => {
		// Defence in depth : a typo like "http.error.status_code"
		// (missing braces) would render as literal text in the
		// editor's click-to-insert. Empirically a real risk
		// during the original Phase 1 spec discussion.
		for (const p of ERROR_PAGE_PLACEHOLDERS) {
			expect(p.token).toMatch(/^\{.+\}$/);
		}
	});

	it('includes time.now.year (verified Caddy v2.11.3 replacer.go:411)', () => {
		// Phase 2 audit confirmed this placeholder exists ; pinned
		// here so a future "trim the list" PR catches the
		// regression.
		const tokens = ERROR_PAGE_PLACEHOLDERS.map((p) => p.token);
		expect(tokens).toContain('{time.now.year}');
	});

	it('includes {http.reverse_proxy.status_code} (Phase 1.1 FIX 3 path)', () => {
		const tokens = ERROR_PAGE_PLACEHOLDERS.map((p) => p.token);
		expect(tokens).toContain('{http.reverse_proxy.status_code}');
	});
});
