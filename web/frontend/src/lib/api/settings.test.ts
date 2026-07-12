// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock the underlying ./client.request so we can assert the
// (method, path, body) tuple without making real HTTP calls.
const requestMock = vi.fn();
vi.mock('./client', () => ({ request: requestMock }));

const { settingsApi } = await import('./settings');

beforeEach(() => {
	requestMock.mockReset();
	requestMock.mockResolvedValue(undefined);
});

describe('settingsApi DNS provider collection: method + path + body', () => {
	it('listDNSProviders GETs /settings/dns-providers', async () => {
		requestMock.mockResolvedValue([]);
		await settingsApi.listDNSProviders();
		expect(requestMock).toHaveBeenCalledWith('GET', '/settings/dns-providers');
	});

	it('getDNSProvider GETs the id path (encoded)', async () => {
		requestMock.mockResolvedValue({});
		await settingsApi.getDNSProvider('id 1');
		expect(requestMock).toHaveBeenCalledWith('GET', '/settings/dns-providers/id%201');
	});

	it('createDNSProvider POSTs the body', async () => {
		requestMock.mockResolvedValue({});
		const body = {
			label: 'OVH perso',
			type: 'ovh',
			endpoint: 'ovh-eu',
			applicationKey: 'ak',
			applicationSecret: 'as',
			consumerKey: 'ck'
		};
		await settingsApi.createDNSProvider(body);
		expect(requestMock).toHaveBeenCalledWith('POST', '/settings/dns-providers', body);
	});

	it('updateDNSProvider PUTs to the id path', async () => {
		requestMock.mockResolvedValue({});
		await settingsApi.updateDNSProvider('id-1', {
			label: 'x',
			type: 'ovh',
			endpoint: 'ovh-eu'
		});
		expect(requestMock).toHaveBeenCalledWith('PUT', '/settings/dns-providers/id-1', {
			label: 'x',
			type: 'ovh',
			endpoint: 'ovh-eu'
		});
	});

	it('deleteDNSProvider DELETEs the id path', async () => {
		requestMock.mockResolvedValue(undefined);
		await settingsApi.deleteDNSProvider('id-1');
		expect(requestMock).toHaveBeenCalledWith('DELETE', '/settings/dns-providers/id-1');
	});
});
