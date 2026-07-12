// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, beforeEach, vi } from 'vitest';

const requestMock = vi.fn();
vi.mock('./client', () => ({ request: requestMock }));

const { systemApi } = await import('./system');

beforeEach(() => {
	requestMock.mockReset();
	requestMock.mockResolvedValue(undefined);
});

describe('systemApi', () => {
	it('getVersion GETs /system/version', async () => {
		await systemApi.getVersion();
		expect(requestMock).toHaveBeenCalledWith('GET', '/system/version');
	});

	it('checkVersion POSTs /system/version/check', async () => {
		await systemApi.checkVersion();
		expect(requestMock).toHaveBeenCalledWith('POST', '/system/version/check');
	});

	it('setVersionConfig PUTs the config body', async () => {
		await systemApi.setVersionConfig({ enabled: true, intervalOverride: '24h' });
		expect(requestMock).toHaveBeenCalledWith('PUT', '/system/version/config', {
			enabled: true,
			intervalOverride: '24h'
		});
	});
});
