// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Topbar tests — the gateway badge (v2.73).
//
// First test file for this component. It exists because the badge was
// three lines of static markup: a dot hard-wired to var(--status-up)
// and the literal topbar.statusHealthy, with no fetch, no store read
// and no prop anywhere in the component. It read "Gateway healthy" in
// green on every page, in every state, including with Caddy down —
// while GET /system/health had been serving the real answer since
// Step AL.3a.
//
// A component with no inputs cannot be tested into honesty, which is
// why there was no test file here to begin with. These four assert the
// four readings the badge now has, and the fourth is the one that
// matters: an unreachable backend must read "unknown", not "healthy".

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';

vi.mock('$app/state', () => ({
	page: {
		url: new URL('http://localhost/routes')
	}
}));

const { healthMock } = vi.hoisted(() => ({
	healthMock: {
		fetchSystemHealth: vi.fn(),
		unhealthyComponentNames: vi.fn()
	}
}));

vi.mock('$lib/api/system-health', () => healthMock);

import Topbar from './Topbar.svelte';

/** Minimal report in the wire shape of systemhealth.Report. */
function report(
	status: 'healthy' | 'degraded' | 'unhealthy',
	components: { name: string; status: string; message: string }[] = []
) {
	return {
		status,
		timestamp: '2026-10-14T12:00:00Z',
		version: 'v2.73.0',
		components
	};
}

beforeEach(() => {
	healthMock.fetchSystemHealth.mockReset();
	healthMock.unhealthyComponentNames.mockReset();
	healthMock.unhealthyComponentNames.mockImplementation(
		(r: { components: { name: string; status: string }[] }) =>
			r.components.filter((c) => c.status !== 'healthy').map((c) => c.name)
	);
});

describe('Topbar — the gateway badge reads the gateway', () => {
	it('reads healthy when the report is healthy', async () => {
		healthMock.fetchSystemHealth.mockResolvedValue(report('healthy'));
		render(Topbar);

		const badge = await screen.findByTestId('topbar-health');
		await waitFor(() => expect(badge.dataset.status).toBe('healthy'));
		expect(badge.textContent ?? '').toMatch(/Gateway healthy/);
	});

	it('reads degraded when the report is degraded', async () => {
		healthMock.fetchSystemHealth.mockResolvedValue(
			report('degraded', [{ name: 'crowdsec', status: 'degraded', message: 'LAPI unreachable' }])
		);
		render(Topbar);

		const badge = await screen.findByTestId('topbar-health');
		await waitFor(() => expect(badge.dataset.status).toBe('degraded'));
		expect(badge.textContent ?? '').toMatch(/Gateway degraded/);
		expect(badge.textContent ?? '').not.toMatch(/Gateway healthy/);
	});

	it('reads unhealthy when the report is unhealthy', async () => {
		healthMock.fetchSystemHealth.mockResolvedValue(
			report('unhealthy', [{ name: 'caddy', status: 'unhealthy', message: 'caddy not started' }])
		);
		render(Topbar);

		const badge = await screen.findByTestId('topbar-health');
		await waitFor(() => expect(badge.dataset.status).toBe('unhealthy'));
		expect(badge.textContent ?? '').toMatch(/Gateway unhealthy/);
	});

	// The defect, in one assertion. Before this change the answer
	// here was a green "Gateway healthy".
	it('reads unknown — never healthy — when the gateway cannot be reached', async () => {
		healthMock.fetchSystemHealth.mockResolvedValue(null);
		render(Topbar);

		const badge = await screen.findByTestId('topbar-health');
		await waitFor(() => expect(badge.dataset.status).toBe('unknown'));
		expect(badge.textContent ?? '').toMatch(/unknown/i);
		expect(badge.textContent ?? '').not.toMatch(/Gateway healthy/);
	});

	it('names the complaining components in the tooltip, and only then', async () => {
		healthMock.fetchSystemHealth.mockResolvedValue(
			report('degraded', [
				{ name: 'caddy', status: 'healthy', message: 'ok' },
				{ name: 'crowdsec', status: 'degraded', message: 'LAPI unreachable' },
				{ name: 'certmagic', status: 'degraded', message: 'cert expiring' }
			])
		);
		render(Topbar);

		const badge = await screen.findByTestId('topbar-health');
		await waitFor(() => expect(badge.getAttribute('title')).toBe('crowdsec, certmagic'));
	});

	it('leaves the tooltip off a healthy badge', async () => {
		healthMock.fetchSystemHealth.mockResolvedValue(
			report('healthy', [{ name: 'caddy', status: 'healthy', message: 'ok' }])
		);
		render(Topbar);

		const badge = await screen.findByTestId('topbar-health');
		await waitFor(() => expect(badge.dataset.status).toBe('healthy'));
		expect(badge.getAttribute('title')).toBeNull();
	});

	// An aria-label on a role-less div is dropped by assistive tech,
	// so the label that used to sit here never reached anyone — and
	// now that the reading changes, the change is worth announcing.
	it('is a live region, so a change of state is announced', async () => {
		healthMock.fetchSystemHealth.mockResolvedValue(report('healthy'));
		render(Topbar);

		const badge = await screen.findByTestId('topbar-health');
		expect(badge.getAttribute('role')).toBe('status');
	});
});
