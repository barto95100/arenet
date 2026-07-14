// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Brick 4, Task 2 — GeoIPSettingsSection tests.
//
// Mocks BOTH settingsApi (MaxMind credentials + test) and
// systemApi (GeoIP auto-update config/status/trigger), plus
// pushToast, so the combined component's two halves can be
// driven independently without touching the network. Mirrors
// CrowdSecSettingsSection.test.ts (mock scaffold) and
// settings/UpdatesSection.test.ts (system-api mock pattern).

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import type { MaxMindConfig, MaxMindRequest, MaxMindTestResult } from '$lib/api/types';
import { ApiError } from '$lib/api/types';
import type { GeoIPUpdateConfig, GeoIPUpdateResult, GeoIPStatus } from '$lib/api/system';

const getMaxMindMock = vi.fn<() => Promise<MaxMindConfig>>();
const putMaxMindMock = vi.fn<(r: MaxMindRequest) => Promise<MaxMindConfig>>();
const deleteMaxMindMock = vi.fn<() => Promise<void>>();
const testMaxMindMock =
	vi.fn<(r: MaxMindRequest & { useStored?: boolean }) => Promise<MaxMindTestResult>>();

vi.mock('$lib/api/settings', () => ({
	settingsApi: {
		getMaxMind: () => getMaxMindMock(),
		putMaxMind: (r: MaxMindRequest) => putMaxMindMock(r),
		deleteMaxMind: () => deleteMaxMindMock(),
		testMaxMind: (r: MaxMindRequest & { useStored?: boolean }) => testMaxMindMock(r)
	}
}));

const getGeoIPUpdateConfigMock = vi.fn<() => Promise<GeoIPUpdateConfig>>();
const putGeoIPUpdateConfigMock =
	vi.fn<(b: { enabled: boolean; intervalHours?: number }) => Promise<GeoIPUpdateConfig>>();
const triggerGeoIPUpdateMock = vi.fn<() => Promise<GeoIPUpdateResult>>();
const getGeoIPStatusMock = vi.fn<() => Promise<GeoIPStatus>>();

vi.mock('$lib/api/system', () => ({
	systemApi: {
		getGeoIPUpdateConfig: () => getGeoIPUpdateConfigMock(),
		putGeoIPUpdateConfig: (b: { enabled: boolean; intervalHours?: number }) =>
			putGeoIPUpdateConfigMock(b),
		triggerGeoIPUpdate: () => triggerGeoIPUpdateMock(),
		getGeoIPStatus: () => getGeoIPStatusMock()
	}
}));

const pushToastMock = vi.fn();
vi.mock('$lib/stores/toast', () => ({
	pushToast: (message: string, variant?: string) => pushToastMock(message, variant)
}));

beforeEach(() => {
	getMaxMindMock.mockReset();
	putMaxMindMock.mockReset();
	deleteMaxMindMock.mockReset();
	testMaxMindMock.mockReset();
	getGeoIPUpdateConfigMock.mockReset();
	putGeoIPUpdateConfigMock.mockReset();
	triggerGeoIPUpdateMock.mockReset();
	getGeoIPStatusMock.mockReset();
	pushToastMock.mockReset();
});

const { default: GeoIPSettingsSection } = await import('./GeoIPSettingsSection.svelte');

const notConfigured: MaxMindConfig = {
	accountId: 0,
	editionId: 'GeoLite2-City',
	configured: false
};

const configured: MaxMindConfig = {
	accountId: 1,
	editionId: 'GeoLite2-City',
	configured: true
};

const disabledUpdateCfg: GeoIPUpdateConfig = { enabled: false, intervalHours: 168 };
const enabledUpdateCfg: GeoIPUpdateConfig = { enabled: true, intervalHours: 168 };

const idleStatus: GeoIPStatus = { lastStatus: 'up_to_date', lastUpdated: '2026-07-13T00:00:00Z' };

function mockDefaults(mm: MaxMindConfig, cfg: GeoIPUpdateConfig, status: GeoIPStatus = idleStatus) {
	getMaxMindMock.mockResolvedValue(mm);
	getGeoIPUpdateConfigMock.mockResolvedValue(cfg);
	getGeoIPStatusMock.mockResolvedValue(status);
}

describe('GeoIPSettingsSection — credentials redaction', () => {
	it('leaves the license key field blank and hints "set" when configured', async () => {
		mockDefaults(configured, enabledUpdateCfg);
		render(GeoIPSettingsSection);
		await waitFor(() => {
			const key = screen.getByLabelText(/License key/i) as HTMLInputElement;
			expect(key.value).toBe('');
			expect(key.placeholder).toContain('set');
		});
	});
});

describe('GeoIPSettingsSection — save', () => {
	it('PUTs with a blank license key and shows a success toast (preserve-on-edit)', async () => {
		mockDefaults(notConfigured, disabledUpdateCfg);
		putMaxMindMock.mockResolvedValue({ ...notConfigured, accountId: 42, configured: true });

		render(GeoIPSettingsSection);
		await waitFor(() => expect(getMaxMindMock).toHaveBeenCalled());

		const accountId = screen.getByLabelText(/Account ID/i) as HTMLInputElement;
		await fireEvent.input(accountId, { target: { value: '42' } });

		const saveBtn = screen.getByRole('button', { name: /^Save$/i });
		await fireEvent.click(saveBtn);

		await waitFor(() => {
			expect(putMaxMindMock).toHaveBeenCalledTimes(1);
			const arg = putMaxMindMock.mock.calls[0][0];
			expect(arg.accountId).toBe(42);
			expect(arg.licenseKey).toBe('');
		});

		await waitFor(() => {
			expect(pushToastMock).toHaveBeenCalledWith(expect.any(String), 'success');
		});
	});

	it('surfaces backend ApiError as inline error, no toast', async () => {
		mockDefaults(notConfigured, disabledUpdateCfg);
		putMaxMindMock.mockRejectedValue(new ApiError('accountId is required', 400));

		render(GeoIPSettingsSection);
		await waitFor(() => expect(getMaxMindMock).toHaveBeenCalled());

		await fireEvent.click(screen.getByRole('button', { name: /^Save$/i }));

		await waitFor(() => {
			expect(screen.getByText(/accountId is required/i)).toBeInTheDocument();
		});
		expect(pushToastMock).not.toHaveBeenCalled();
	});
});

describe('GeoIPSettingsSection — test credentials', () => {
	it('renders role=status on reachable:true', async () => {
		mockDefaults(notConfigured, disabledUpdateCfg);
		testMaxMindMock.mockResolvedValue({ reachable: true });

		render(GeoIPSettingsSection);
		await waitFor(() => expect(getMaxMindMock).toHaveBeenCalled());

		await fireEvent.input(screen.getByLabelText(/License key/i), { target: { value: 'abc' } });
		await fireEvent.click(screen.getByRole('button', { name: /Test credentials/i }));

		await waitFor(() => {
			expect(screen.getByRole('status')).toBeInTheDocument();
		});
	});

	it('renders role=alert with the error on reachable:false', async () => {
		mockDefaults(notConfigured, disabledUpdateCfg);
		testMaxMindMock.mockResolvedValue({ reachable: false, error: '401' });

		render(GeoIPSettingsSection);
		await waitFor(() => expect(getMaxMindMock).toHaveBeenCalled());

		await fireEvent.input(screen.getByLabelText(/License key/i), { target: { value: 'bad' } });
		await fireEvent.click(screen.getByRole('button', { name: /Test credentials/i }));

		await waitFor(() => {
			const alert = screen.getByRole('alert');
			expect(alert.textContent ?? '').toContain('401');
		});
	});

	it('uses useStored=true when the license key is blank and creds are configured', async () => {
		mockDefaults(configured, enabledUpdateCfg);
		testMaxMindMock.mockResolvedValue({ reachable: true });

		render(GeoIPSettingsSection);
		await waitFor(() => expect(getMaxMindMock).toHaveBeenCalled());

		await fireEvent.click(screen.getByRole('button', { name: /Test credentials/i }));

		await waitFor(() => {
			expect(testMaxMindMock).toHaveBeenCalledWith({ useStored: true });
		});
	});
});

describe('GeoIPSettingsSection — toggle gating', () => {
	it('disables the enable checkbox and shows the hint when not configured', async () => {
		mockDefaults(notConfigured, disabledUpdateCfg);
		render(GeoIPSettingsSection);
		await waitFor(() => {
			const checkbox = screen.getByTestId('geoip-enable') as HTMLInputElement;
			expect(checkbox.disabled).toBe(true);
		});
		expect(screen.getByText(/Configure your MaxMind credentials first/i)).toBeInTheDocument();
	});

	it('shows the paused notice (not the needs-creds hint) and an unchecked box when enabled:true but creds removed', async () => {
		// Backend still has enabled:true persisted, but credentials were deleted
		// (configured:false). The box must render unchecked (honest "paused")
		// rather than checked-but-disabled, and surface the paused notice.
		mockDefaults(notConfigured, enabledUpdateCfg);
		render(GeoIPSettingsSection);
		// Wait for the paused notice — proof that load() resolved with the
		// enabled:true + configured:false combination, so the checkbox's
		// checked value below reflects the post-load state (not the initial
		// null render). Without this barrier the assertion races load().
		await waitFor(() => expect(screen.getByText(/paused/i)).toBeInTheDocument());
		const checkbox = screen.getByTestId('geoip-enable') as HTMLInputElement;
		expect(checkbox.disabled).toBe(true);
		expect(checkbox.checked).toBe(false);
		expect(
			screen.queryByText(/Configure your MaxMind credentials first/i)
		).not.toBeInTheDocument();
	});

	it('enables the checkbox when configured and PUTs enabled:true on toggle', async () => {
		mockDefaults(configured, disabledUpdateCfg);
		putGeoIPUpdateConfigMock.mockResolvedValue({ enabled: true, intervalHours: 168 });

		render(GeoIPSettingsSection);
		await waitFor(() => {
			const checkbox = screen.getByTestId('geoip-enable') as HTMLInputElement;
			expect(checkbox.disabled).toBe(false);
		});

		await fireEvent.click(screen.getByTestId('geoip-enable'));

		await waitFor(() => {
			expect(putGeoIPUpdateConfigMock).toHaveBeenCalledWith({
				enabled: true,
				intervalHours: 168
			});
		});
	});
});

describe('GeoIPSettingsSection — interval preset', () => {
	it('changing the select to Daily PUTs intervalHours:24', async () => {
		mockDefaults(configured, enabledUpdateCfg);
		putGeoIPUpdateConfigMock.mockResolvedValue({ enabled: true, intervalHours: 24 });

		render(GeoIPSettingsSection);
		await waitFor(() => expect(getMaxMindMock).toHaveBeenCalled());

		const select = screen.getByTestId('geoip-interval') as HTMLSelectElement;
		await fireEvent.change(select, { target: { value: '24' } });

		await waitFor(() => {
			expect(putGeoIPUpdateConfigMock).toHaveBeenCalledWith({
				enabled: true,
				intervalHours: 24
			});
		});
	});
});

describe('GeoIPSettingsSection — update now', () => {
	it('triggers the update, shows a success toast on status:updated, refreshes status', async () => {
		mockDefaults(configured, enabledUpdateCfg);
		triggerGeoIPUpdateMock.mockResolvedValue({ status: 'updated' });
		getGeoIPStatusMock.mockResolvedValueOnce(idleStatus).mockResolvedValueOnce({
			lastStatus: 'updated',
			lastUpdated: '2026-07-13T12:00:00Z'
		});

		render(GeoIPSettingsSection);
		await waitFor(() => expect(getMaxMindMock).toHaveBeenCalled());

		await fireEvent.click(screen.getByTestId('geoip-update-now'));

		await waitFor(() => {
			expect(triggerGeoIPUpdateMock).toHaveBeenCalledTimes(1);
		});
		await waitFor(() => {
			expect(pushToastMock).toHaveBeenCalledWith(expect.any(String), 'success');
		});
		await waitFor(() => {
			expect(getGeoIPStatusMock).toHaveBeenCalledTimes(2);
		});
	});

	it('shows an info toast on status:up_to_date', async () => {
		mockDefaults(configured, enabledUpdateCfg);
		triggerGeoIPUpdateMock.mockResolvedValue({ status: 'up_to_date' });

		render(GeoIPSettingsSection);
		await waitFor(() => expect(getMaxMindMock).toHaveBeenCalled());

		await fireEvent.click(screen.getByTestId('geoip-update-now'));

		await waitFor(() => {
			expect(pushToastMock).toHaveBeenCalledWith(expect.any(String), 'info');
		});
	});

	it('shows a danger toast containing the error on status:error', async () => {
		mockDefaults(configured, enabledUpdateCfg);
		triggerGeoIPUpdateMock.mockResolvedValue({ status: 'error', error: 'boom' });

		render(GeoIPSettingsSection);
		await waitFor(() => expect(getMaxMindMock).toHaveBeenCalled());

		await fireEvent.click(screen.getByTestId('geoip-update-now'));

		await waitFor(() => {
			expect(pushToastMock).toHaveBeenCalledWith(expect.stringContaining('boom'), 'danger');
		});
	});
});
