// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';

const { systemMock } = vi.hoisted(() => ({
	systemMock: { getVersion: vi.fn(), checkVersion: vi.fn(), setVersionConfig: vi.fn() }
}));
vi.mock('$lib/api/system', () => ({
	systemApi: {
		getVersion: (...a: unknown[]) => systemMock.getVersion(...a),
		checkVersion: (...a: unknown[]) => systemMock.checkVersion(...a),
		setVersionConfig: (...a: unknown[]) => systemMock.setVersionConfig(...a)
	}
}));

import UpdatesSection from './UpdatesSection.svelte';

function version(over: Record<string, unknown> = {}) {
	return {
		current: 'v2.12.3', latest: 'v2.12.3', updateAvailable: false,
		url: '', lastChecked: '2026-07-13T00:00:00Z', lastError: '', enabled: false, ...over
	};
}

beforeEach(() => {
	systemMock.getVersion.mockReset();
	systemMock.checkVersion.mockReset();
	systemMock.setVersionConfig.mockReset();
});

describe('UpdatesSection', () => {
	it('shows current version and up-to-date state', async () => {
		systemMock.getVersion.mockResolvedValue(version());
		render(UpdatesSection);
		await waitFor(() => expect(screen.getByTestId('updates-current').textContent).toContain('v2.12.3'));
		expect(screen.getByTestId('updates-latest').textContent?.toLowerCase()).toMatch(/up to date|à jour/i);
	});

	it('enable toggle calls setVersionConfig(true)', async () => {
		systemMock.getVersion.mockResolvedValue(version({ enabled: false }));
		systemMock.setVersionConfig.mockResolvedValue(version({ enabled: true }));
		render(UpdatesSection);
		await waitFor(() => screen.getByTestId('updates-enable'));
		await fireEvent.click(screen.getByTestId('updates-enable'));
		await waitFor(() =>
			expect(systemMock.setVersionConfig).toHaveBeenCalledWith({ enabled: true })
		);
	});

	it('"check now" calls checkVersion', async () => {
		systemMock.getVersion.mockResolvedValue(version());
		systemMock.checkVersion.mockResolvedValue(version({ updateAvailable: true, latest: 'v2.12.4', url: 'u' }));
		render(UpdatesSection);
		await waitFor(() => screen.getByTestId('updates-check-now'));
		await userEvent.click(screen.getByTestId('updates-check-now'));
		await waitFor(() => expect(systemMock.checkVersion).toHaveBeenCalled());
	});

	it('renders the last-error line when lastError is set', async () => {
		systemMock.getVersion.mockResolvedValue(version({ lastError: 'network' }));
		render(UpdatesSection);
		await waitFor(() => expect(screen.getByTestId('updates-lasterror')).toBeInTheDocument());
	});
});
