// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.12.3 — system version / update-checker client. Backs the topbar
// update badge and the /settings Updates section.

import { request } from './client';

export interface SystemVersion {
	current: string;
	latest: string;
	updateAvailable: boolean;
	url: string;
	lastChecked: string;
	lastError: string;
	enabled: boolean;
}

export const systemApi = {
	getVersion: (): Promise<SystemVersion> => request<SystemVersion>('GET', '/system/version'),
	checkVersion: (): Promise<SystemVersion> =>
		request<SystemVersion>('POST', '/system/version/check'),
	setVersionConfig: (body: {
		enabled: boolean;
		intervalOverride?: string;
	}): Promise<SystemVersion> => request<SystemVersion>('PUT', '/system/version/config', body)
};
