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

// Brick 3, Task 5 — GeoIP database auto-update client. Backs the
// (future, Brick 4) /settings GeoIP updates panel.

export interface GeoIPUpdateConfig {
	enabled: boolean;
	intervalHours: number;
}

export interface GeoIPUpdateResult {
	status: string;
	error?: string;
	lastModified?: string;
}

export interface GeoIPStatus {
	lastStatus: string;
	lastError?: string;
	lastUpdated?: string;
}

export const systemApi = {
	getVersion: (): Promise<SystemVersion> => request<SystemVersion>('GET', '/system/version'),
	checkVersion: (): Promise<SystemVersion> =>
		request<SystemVersion>('POST', '/system/version/check'),
	setVersionConfig: (body: {
		enabled: boolean;
		intervalOverride?: string;
	}): Promise<SystemVersion> => request<SystemVersion>('PUT', '/system/version/config', body),

	getGeoIPUpdateConfig: (): Promise<GeoIPUpdateConfig> =>
		request<GeoIPUpdateConfig>('GET', '/system/geoip/update-config'),
	putGeoIPUpdateConfig: (body: {
		enabled: boolean;
		intervalHours?: number;
	}): Promise<GeoIPUpdateConfig> =>
		request<GeoIPUpdateConfig>('PUT', '/system/geoip/update-config', body),
	triggerGeoIPUpdate: (): Promise<GeoIPUpdateResult> =>
		request<GeoIPUpdateResult>('POST', '/system/geoip/update'),
	getGeoIPStatus: (): Promise<GeoIPStatus> => request<GeoIPStatus>('GET', '/system/geoip/status')
};
