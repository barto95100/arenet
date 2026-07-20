// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.19.0 external-certs SOCLE — unit tests for externalCertsApi.
// Pins the URL encoding + HTTP method + payload pass-through for the
// admin-only CRUD at /api/v1/certificates/external so a backend rename
// surfaces as a vitest failure rather than a silent prod regression.
//
// list/get/upload route through the shared request() helper (mocked
// here). remove() uses a dedicated fetch (like certificatesApi.delete)
// because the 409 body {error, blockingRoutes} is a FLAT field the
// shared request()/ApiError path would drop — so that method is tested
// against a stubbed global fetch instead.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { ExternalCertificate, ExternalCertUploadRequest } from './external-certs';

const requestMock = vi.fn();
vi.mock('./client', () => ({ request: requestMock }));

const { externalCertsApi } = await import('./external-certs');

const sampleCert: ExternalCertificate = {
	id: 'cert-1',
	name: 'DigiCert prod',
	description: 'enterprise CA',
	certPEM: '-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----',
	chainPEM: '',
	keyPEM: '',
	issuer: 'DigiCert Inc',
	subject: 'CN=example.com',
	serialNumber: '0A',
	keyAlgorithm: 'RSA',
	signatureAlgorithm: 'SHA256-RSA',
	notBefore: '2026-01-01T00:00:00Z',
	notAfter: '2027-01-01T00:00:00Z',
	dnsNames: ['example.com'],
	createdAt: '2026-01-01T00:00:00Z',
	updatedAt: '2026-01-01T00:00:00Z',
	warnings: []
};

describe('externalCertsApi: URL + verb mapping', () => {
	beforeEach(() => {
		requestMock.mockReset();
		requestMock.mockResolvedValue([]);
	});

	it('list → GET /certificates/external', async () => {
		await externalCertsApi.list();
		expect(requestMock).toHaveBeenCalledWith('GET', '/certificates/external');
	});

	it('get → GET /certificates/external/{id} (URL-encoded)', async () => {
		requestMock.mockResolvedValue(sampleCert);
		await externalCertsApi.get('abc 123');
		const [method, path] = requestMock.mock.calls[0];
		expect(method).toBe('GET');
		expect(path).toBe('/certificates/external/abc%20123');
	});

	it('upload → POST /certificates/external with the full body', async () => {
		requestMock.mockResolvedValue(sampleCert);
		const req: ExternalCertUploadRequest = {
			name: 'DigiCert prod',
			description: 'enterprise CA',
			certPEM: 'CERT',
			keyPEM: 'KEY',
			chainPEM: 'CHAIN'
		};
		await externalCertsApi.upload(req);
		expect(requestMock).toHaveBeenCalledWith('POST', '/certificates/external', req);
	});

	it('generateCSR POSTs to /certificates/external/csr', async () => {
		requestMock.mockResolvedValue({
			...sampleCert,
			status: 'pending_csr',
			csrPEM: '---CSR---'
		});
		const req = {
			name: 'x',
			csrSubject: { commonName: 'app.corp.local', keyAlgorithm: 'rsa_4096' as const }
		};
		const res = await externalCertsApi.generateCSR(req);
		expect(requestMock).toHaveBeenCalledWith('POST', '/certificates/external/csr', req);
		expect(res.status).toBe('pending_csr');
	});

	it('csrDownloadUrl builds the download path', () => {
		expect(externalCertsApi.csrDownloadUrl('c1')).toContain('/certificates/external/c1/csr');
	});

	it('update → PUT /certificates/external/{id} (URL-encoded) with the body', async () => {
		requestMock.mockResolvedValue({ ...sampleCert, status: '' });
		const req: ExternalCertUploadRequest = {
			name: 'DigiCert prod',
			certPEM: 'CERT',
			keyPEM: '',
			chainPEM: 'CHAIN'
		};
		await externalCertsApi.update('cert 1', req);
		const [method, path, body] = requestMock.mock.calls[0];
		expect(method).toBe('PUT');
		expect(path).toBe('/certificates/external/cert%201');
		expect(body).toBe(req);
	});
});

describe('externalCertsApi.remove', () => {
	beforeEach(() => {
		vi.restoreAllMocks();
		requestMock.mockReset();
	});

	it('DELETEs /certificates/external/{id} (URL-encoded) via fetch', async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({})
		});
		vi.stubGlobal('fetch', fetchMock);

		await externalCertsApi.remove('id 1');
		const calledUrl = fetchMock.mock.calls[0][0] as string;
		expect(calledUrl).toContain('/certificates/external/' + encodeURIComponent('id 1'));
		expect(fetchMock.mock.calls[0][1].method).toBe('DELETE');
		// remove() must NOT route through the shared request() helper —
		// that path drops the flat blockingRoutes field on a 409.
		expect(requestMock).not.toHaveBeenCalled();
	});

	it('throws with status + blockingRoutes on a 409', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue({
				ok: false,
				status: 409,
				json: async () => ({ error: 'in use', blockingRoutes: ['a.example.com'] })
			})
		);
		try {
			await externalCertsApi.remove('cert-1');
			throw new Error('expected remove() to reject');
		} catch (err) {
			const e = err as { status?: number; blockingRoutes?: string[]; message?: string };
			expect(e.status).toBe(409);
			expect(e.blockingRoutes).toEqual(['a.example.com']);
			expect(e.message).toBe('in use');
		}
	});
});
