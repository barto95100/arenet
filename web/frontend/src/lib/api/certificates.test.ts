// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Task 5 — certificatesApi.deleteCertificate. Mirrors the DELETE
// /api/v1/certificates/{domain} endpoint (internal/api/certificates_delete.go):
// 200 -> {domain, deleted}; 409 -> {error, blockingRoutes} (flat body,
// NOT nested under `params` — unlike the provider_in_use family — so
// this method reads the body directly rather than routing through the
// shared request()/ApiError(.params) path).

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { certificatesApi } from './certificates';

describe('certificatesApi.deleteCertificate', () => {
	beforeEach(() => vi.restoreAllMocks());

	it('DELETEs the URL-encoded domain and returns the result', async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ domain: 'darro.ovh', deleted: 2 })
		});
		vi.stubGlobal('fetch', fetchMock);

		const res = await certificatesApi.deleteCertificate('*.darro.ovh');
		expect(res).toEqual({ domain: 'darro.ovh', deleted: 2 });
		const calledUrl = fetchMock.mock.calls[0][0] as string;
		expect(calledUrl).toContain('/certificates/' + encodeURIComponent('*.darro.ovh'));
		expect(fetchMock.mock.calls[0][1].method).toBe('DELETE');
	});

	it('throws with blockingRoutes on 409', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue({
				ok: false,
				status: 409,
				json: async () => ({ error: 'in use', blockingRoutes: ['a.example.com'] })
			})
		);
		await expect(certificatesApi.deleteCertificate('a.example.com')).rejects.toMatchObject({
			status: 409,
			blockingRoutes: ['a.example.com']
		});
	});
});
