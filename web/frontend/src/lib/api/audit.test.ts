// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, beforeEach, vi } from 'vitest';

const requestMock = vi.fn();
vi.mock('./client', () => ({ request: requestMock }));

const { auditApi } = await import('./audit');

beforeEach(() => {
	requestMock.mockReset();
	requestMock.mockResolvedValue({ events: [], nextCursor: '' });
});

describe('auditApi.list: URL parameter encoding', () => {
	it('hits /audit without query string when filter is empty', async () => {
		await auditApi.list({});
		expect(requestMock).toHaveBeenCalledWith('GET', '/audit');
	});

	it('translates camelCase fields to snake_case URL params', async () => {
		await auditApi.list({
			actorUserId: 'u-1',
			action: 'login_success',
			targetType: 'route',
			targetId: 'r-1'
		});
		expect(requestMock).toHaveBeenCalledTimes(1);
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('actor_user_id=u-1');
		expect(path).toContain('action=login_success');
		expect(path).toContain('target_type=route');
		expect(path).toContain('target_id=r-1');
	});

	it('forwards from/to RFC 3339 strings as-is', async () => {
		await auditApi.list({ from: '2026-05-01T00:00:00Z', to: '2026-05-17T00:00:00Z' });
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('from=2026-05-01T00%3A00%3A00Z');
		expect(path).toContain('to=2026-05-17T00%3A00%3A00Z');
	});

	it('serializes numeric limit as a string', async () => {
		await auditApi.list({ limit: 50 });
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('limit=50');
	});

	it('passes cursor through', async () => {
		await auditApi.list({ cursor: '0190a3f8-7d3c-7234-9abc-def012345678' });
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('cursor=0190a3f8-7d3c-7234-9abc-def012345678');
	});

	it('omits empty string filters from the URL', async () => {
		await auditApi.list({ actorUserId: '', action: 'login_failure' });
		const [, path] = requestMock.mock.calls[0];
		expect(path).not.toContain('actor_user_id=');
		expect(path).toContain('action=login_failure');
	});

	it('omits undefined limit (allows server default)', async () => {
		await auditApi.list({});
		const [, path] = requestMock.mock.calls[0];
		expect(path).not.toContain('limit=');
	});

	it('accepts limit=0 explicitly (still emitted)', async () => {
		await auditApi.list({ limit: 0 });
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('limit=0');
	});
});
