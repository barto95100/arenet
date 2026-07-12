// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, waitFor } from '@testing-library/svelte';

const { systemMock } = vi.hoisted(() => ({
	systemMock: { getVersion: vi.fn() }
}));
vi.mock('$lib/api/system', () => ({
	systemApi: { getVersion: (...a: unknown[]) => systemMock.getVersion(...a) }
}));

import UpdateBadge from './UpdateBadge.svelte';

function version(over: Record<string, unknown> = {}) {
	return {
		current: 'v2.12.3',
		latest: 'v2.12.4',
		updateAvailable: false,
		url: 'https://github.com/x/releases/v2.12.4',
		lastChecked: '',
		lastError: '',
		enabled: true,
		...over
	};
}

beforeEach(() => systemMock.getVersion.mockReset());

describe('UpdateBadge', () => {
	it('renders nothing when no update is available', async () => {
		systemMock.getVersion.mockResolvedValue(version({ updateAvailable: false }));
		const { queryByTestId } = render(UpdateBadge);
		await waitFor(() => expect(systemMock.getVersion).toHaveBeenCalled());
		expect(queryByTestId('update-badge')).toBeNull();
	});

	it('renders a link to the release when an update is available', async () => {
		systemMock.getVersion.mockResolvedValue(version({ updateAvailable: true }));
		const { getByTestId } = render(UpdateBadge);
		await waitFor(() => expect(getByTestId('update-badge')).toBeInTheDocument());
		const link = getByTestId('update-badge') as HTMLAnchorElement;
		expect(link.href).toContain('v2.12.4');
	});
});
