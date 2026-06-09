// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// /security/decisions page tests — Step CS.2.A.
//
// Validates the 3-tab refactor:
//   - Tab 1 (Local snapshot) — pre-CS.2 behaviour preserved.
//   - Tab 2 (Live LAPI) — new live-poll proxy + filter + error states.
//   - Tab 3 (Scenarios) — placeholder until CS.2.C lands.
//
// Polling cadence is not exercised by clock-faking — the
// initial-fetch + manual-refresh paths cover the same data
// flow and avoid the d3.timer-class import-time caching trap
// (Lesson 7 in ENGINEERING-PRACTICES.md). Manual refresh is
// triggered via the refresh button.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import type {
	Decision,
	DecisionsResponse,
	LAPIDecisionsResponse
} from '$lib/api/types';
import { ApiError } from '$lib/api/types';

const { toastMock, securityMock } = vi.hoisted(() => ({
	toastMock: { pushToast: vi.fn() },
	securityMock: {
		fetchDecisions: vi.fn(),
		fetchLAPIDecisions: vi.fn(),
		fetchScenarios: vi.fn()
	}
}));

vi.mock('$lib/stores/toast', () => toastMock);
vi.mock('$lib/api/security', () => securityMock);

import Page from './+page.svelte';

beforeEach(() => {
	toastMock.pushToast.mockReset();
	securityMock.fetchDecisions.mockReset();
	securityMock.fetchLAPIDecisions.mockReset();
	securityMock.fetchScenarios.mockReset();
});

// --- Fixtures -----------------------------------------------

const sampleSnapshot: DecisionsResponse = {
	events: [
		{
			id: 1,
			uuid: 'snap-1',
			ts: new Date(Date.now() - 5 * 60_000).toISOString(),
			scope: 'ip',
			value: '1.2.3.4',
			type: 'ban',
			scenario: 'crowdsecurity/http-cve',
			expiresAt: new Date(Date.now() + 3600_000).toISOString(),
			durationSeconds: 3600
		}
	]
};

function sampleLAPI(decisions: number = 3): LAPIDecisionsResponse {
	const ds = [
		{
			id: 1,
			duration: '168h',
			origin: 'CAPI',
			scenario: 'crowdsecurity/community-blocklist',
			scope: 'ip',
			type: 'ban',
			value: '1.2.3.4',
			expiresAt: new Date(Date.now() + 7 * 86400_000).toISOString()
		},
		{
			id: 2,
			duration: '24h',
			origin: 'CAPI',
			scenario: 'crowdsecurity/community-blocklist',
			scope: 'range',
			type: 'ban',
			value: '5.6.7.0/24',
			expiresAt: new Date(Date.now() + 86400_000).toISOString()
		},
		{
			id: 3,
			duration: '1h',
			origin: 'cscli',
			scenario: 'manual',
			scope: 'ip',
			type: 'ban',
			value: '192.0.2.42',
			expiresAt: new Date(Date.now() + 3600_000).toISOString()
		}
	].slice(0, decisions);
	const byOrigin: Record<string, number> = {};
	for (const d of ds) byOrigin[d.origin] = (byOrigin[d.origin] ?? 0) + 1;
	return {
		decisions: ds,
		meta: { total: ds.length, totalByOrigin: byOrigin, limit: 100, offset: 0 }
	};
}

// --- Tab navigation -----------------------------------------

describe('decisions page — tabs', () => {
	it('renders all three tabs with Local snapshot active by default', async () => {
		securityMock.fetchDecisions.mockResolvedValue(sampleSnapshot);
		render(Page);
		await waitFor(() => expect(securityMock.fetchDecisions).toHaveBeenCalled());
		expect(screen.getByTestId('tab-snapshot')).toHaveAttribute('aria-selected', 'true');
		expect(screen.getByTestId('tab-live')).toHaveAttribute('aria-selected', 'false');
		expect(screen.getByTestId('tab-scenarios')).toHaveAttribute('aria-selected', 'false');
	});

	it('switches to Live LAPI tab and triggers the proxy fetch', async () => {
		securityMock.fetchDecisions.mockResolvedValue(sampleSnapshot);
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI());
		render(Page);
		await waitFor(() => expect(securityMock.fetchDecisions).toHaveBeenCalled());

		await fireEvent.click(screen.getByTestId('tab-live'));
		await waitFor(() => {
			expect(securityMock.fetchLAPIDecisions).toHaveBeenCalled();
		});
		expect(screen.getByTestId('tab-live')).toHaveAttribute('aria-selected', 'true');
	});

	it('switches to Scenarios tab and triggers the fetchScenarios call', async () => {
		securityMock.fetchDecisions.mockResolvedValue(sampleSnapshot);
		securityMock.fetchScenarios.mockResolvedValue({
			scenarios: [],
			meta: { totalAlerts: 0, windowHours: 24 }
		});
		render(Page);
		await waitFor(() => expect(securityMock.fetchDecisions).toHaveBeenCalled());

		await fireEvent.click(screen.getByTestId('tab-scenarios'));
		await waitFor(() => {
			expect(securityMock.fetchScenarios).toHaveBeenCalled();
		});
	});

	it('does not fetch LAPI decisions until the Live tab is opened', async () => {
		securityMock.fetchDecisions.mockResolvedValue(sampleSnapshot);
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI());
		render(Page);
		await waitFor(() => expect(securityMock.fetchDecisions).toHaveBeenCalled());
		// Local snapshot tab was the initial state; LAPI shouldn't be polled.
		expect(securityMock.fetchLAPIDecisions).not.toHaveBeenCalled();
	});
});

// --- Local snapshot tab -------------------------------------

describe('decisions page — Local snapshot tab', () => {
	it('renders snapshot rows after fetch', async () => {
		securityMock.fetchDecisions.mockResolvedValue(sampleSnapshot);
		render(Page);
		await waitFor(() => {
			expect(screen.getByText('1.2.3.4')).toBeInTheDocument();
		});
	});

	it('renders the disabled state when /security/decisions returns disabled=true', async () => {
		securityMock.fetchDecisions.mockResolvedValue({ disabled: true, events: [] });
		render(Page);
		await waitFor(() => {
			expect(screen.getByText(/non configuré/i)).toBeInTheDocument();
		});
	});
});

// --- Live LAPI tab ------------------------------------------

describe('decisions page — Live LAPI tab', () => {
	async function openLiveTab(): Promise<void> {
		securityMock.fetchDecisions.mockResolvedValue(sampleSnapshot);
		render(Page);
		await waitFor(() => expect(securityMock.fetchDecisions).toHaveBeenCalled());
		await fireEvent.click(screen.getByTestId('tab-live'));
	}

	it('renders live decisions in the table after the proxy fetch resolves', async () => {
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI());
		await openLiveTab();

		await waitFor(() => {
			expect(screen.getByText('5.6.7.0/24')).toBeInTheDocument();
			expect(screen.getByText('192.0.2.42')).toBeInTheDocument();
		});
	});

	it('renders the origin breakdown chips from meta.totalByOrigin', async () => {
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI());
		await openLiveTab();

		await waitFor(() => {
			const breakdown = screen.getByTestId('live-breakdown');
			expect(breakdown.textContent ?? '').toContain('CAPI');
			expect(breakdown.textContent ?? '').toContain('cscli');
		});
	});

	it('filters by source when a breakdown chip is clicked', async () => {
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI());
		await openLiveTab();

		await waitFor(() => expect(screen.getByTestId('live-breakdown')).toBeInTheDocument());

		// Find a chip for "cscli" and click it.
		const breakdown = screen.getByTestId('live-breakdown');
		const cscliChip = Array.from(breakdown.querySelectorAll('button')).find(
			(b) => (b.textContent ?? '').includes('cscli')
		);
		expect(cscliChip).toBeDefined();

		// The next fetchLAPIDecisions call after the click
		// should carry source=cscli.
		securityMock.fetchLAPIDecisions.mockClear();
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI(1));
		await fireEvent.click(cscliChip!);

		await waitFor(() => {
			expect(securityMock.fetchLAPIDecisions).toHaveBeenCalledWith(
				expect.objectContaining({ source: 'cscli' })
			);
		});
	});

	it('shows the not-configured CTA on a 404 from the proxy', async () => {
		securityMock.fetchLAPIDecisions.mockRejectedValue(
			new ApiError('crowdsec bouncer not configured', 404)
		);
		await openLiveTab();

		await waitFor(() => {
			expect(screen.getByTestId('live-not-configured')).toBeInTheDocument();
		});
		// Link to settings page.
		expect(screen.getByRole('link', { name: /Settings/i })).toBeInTheDocument();
	});

	it('shows the unreachable banner + Retry button on a 502', async () => {
		securityMock.fetchLAPIDecisions.mockRejectedValue(
			new ApiError('connection refused (LAPI not running)', 502)
		);
		await openLiveTab();

		await waitFor(() => {
			const banner = screen.getByTestId('live-unreachable');
			expect(banner.textContent ?? '').toContain('LAPI inaccessible');
			expect(banner.textContent ?? '').toContain('connection refused');
		});
		expect(screen.getByRole('button', { name: /Réessayer/i })).toBeInTheDocument();
	});

	it('retries the fetch when the Réessayer button is clicked', async () => {
		// First call fails, second succeeds.
		securityMock.fetchLAPIDecisions
			.mockRejectedValueOnce(new ApiError('timeout', 502))
			.mockResolvedValueOnce(sampleLAPI());
		await openLiveTab();

		await waitFor(() => {
			expect(screen.getByTestId('live-unreachable')).toBeInTheDocument();
		});

		await fireEvent.click(screen.getByRole('button', { name: /Réessayer/i }));

		await waitFor(() => {
			expect(screen.getByText('5.6.7.0/24')).toBeInTheDocument();
			expect(screen.queryByTestId('live-unreachable')).toBeNull();
		});
	});

	it('shows the empty state when LAPI returns zero decisions', async () => {
		securityMock.fetchLAPIDecisions.mockResolvedValue({
			decisions: [],
			meta: { total: 0, totalByOrigin: {}, limit: 100, offset: 0 }
		});
		await openLiveTab();

		await waitFor(() => {
			expect(screen.getByTestId('live-empty')).toBeInTheDocument();
		});
	});

	it('changing the scope filter re-fetches with the scope query param', async () => {
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI());
		await openLiveTab();

		await waitFor(() => expect(securityMock.fetchLAPIDecisions).toHaveBeenCalled());

		securityMock.fetchLAPIDecisions.mockClear();
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI(1));

		const scopeSelect = screen.getByTestId('live-scope-filter') as HTMLSelectElement;
		await fireEvent.change(scopeSelect, { target: { value: 'range' } });

		await waitFor(() => {
			expect(securityMock.fetchLAPIDecisions).toHaveBeenCalledWith(
				expect.objectContaining({ scope: 'range' })
			);
		});
	});
});

// --- Scenarios tab (CS.2.C) ---------------------------------

const sampleScenariosOK = {
	scenarios: [
		{
			name: 'crowdsecurity/http-cve',
			alerts24h: 12,
			lastSeen: new Date(Date.now() - 5 * 60_000).toISOString(),
			sampleScope: 'Ip',
			sampleValue: '203.0.113.42'
		},
		{
			name: 'crowdsecurity/http-bf',
			alerts24h: 4,
			lastSeen: new Date(Date.now() - 30 * 60_000).toISOString(),
			sampleScope: 'Ip',
			sampleValue: '198.51.100.7'
		},
		{
			name: 'manual',
			alerts24h: 1,
			lastSeen: new Date(Date.now() - 90 * 60_000).toISOString(),
			sampleScope: 'Ip',
			sampleValue: '192.0.2.1'
		}
	],
	meta: { totalAlerts: 17, windowHours: 24 }
};

describe('decisions page — Scenarios tab', () => {
	async function openScenariosTab(): Promise<void> {
		securityMock.fetchDecisions.mockResolvedValue(sampleSnapshot);
		render(Page);
		await waitFor(() => expect(securityMock.fetchDecisions).toHaveBeenCalled());
		await fireEvent.click(screen.getByTestId('tab-scenarios'));
	}

	it('renders the table with aggregated rows on 200', async () => {
		securityMock.fetchScenarios.mockResolvedValue(sampleScenariosOK);
		await openScenariosTab();

		await waitFor(() => {
			expect(screen.getByText('http-cve')).toBeInTheDocument();
			expect(screen.getByText('http-bf')).toBeInTheDocument();
			expect(screen.getByText('manual')).toBeInTheDocument();
		});
		// Alerts 24h count rendered.
		expect(screen.getByText('12')).toBeInTheDocument();
	});

	it('renders the Security-Automation CTA on 412', async () => {
		securityMock.fetchScenarios.mockRejectedValue(
			new ApiError('security automation not configured', 412)
		);
		await openScenariosTab();

		await waitFor(() => {
			expect(screen.getByTestId('scenarios-not-configured')).toBeInTheDocument();
		});
		// Must link to /settings so the operator has a direct path.
		const links = screen.getAllByRole('link', { name: /Security Automation/i });
		expect(links.length).toBeGreaterThan(0);
	});

	it('renders the unreachable banner + Retry on 502', async () => {
		securityMock.fetchScenarios.mockRejectedValue(
			new ApiError('machine credentials rejected by LAPI', 502)
		);
		await openScenariosTab();

		await waitFor(() => {
			const banner = screen.getByTestId('scenarios-unreachable');
			expect(banner.textContent ?? '').toContain('LAPI inaccessible');
			expect(banner.textContent ?? '').toContain('machine credentials rejected');
		});
		expect(screen.getByRole('button', { name: /Réessayer/i })).toBeInTheDocument();
	});

	it('retries on Réessayer click after a 502', async () => {
		securityMock.fetchScenarios
			.mockRejectedValueOnce(new ApiError('timeout', 502))
			.mockResolvedValueOnce(sampleScenariosOK);
		await openScenariosTab();

		await waitFor(() => {
			expect(screen.getByTestId('scenarios-unreachable')).toBeInTheDocument();
		});

		await fireEvent.click(screen.getByRole('button', { name: /Réessayer/i }));

		await waitFor(() => {
			expect(screen.getByText('http-cve')).toBeInTheDocument();
			expect(screen.queryByTestId('scenarios-unreachable')).toBeNull();
		});
	});

	it('renders the empty state when LAPI has no recent alerts', async () => {
		securityMock.fetchScenarios.mockResolvedValue({
			scenarios: [],
			meta: { totalAlerts: 0, windowHours: 24 }
		});
		await openScenariosTab();

		await waitFor(() => {
			expect(screen.getByTestId('scenarios-empty')).toBeInTheDocument();
		});
	});

	it('opens the inspect modal with hub link + cscli command on row click', async () => {
		securityMock.fetchScenarios.mockResolvedValue(sampleScenariosOK);
		await openScenariosTab();

		await waitFor(() => {
			expect(screen.getByText('http-cve')).toBeInTheDocument();
		});

		// Click the first row.
		const rows = screen.getAllByTestId('scenario-row');
		await fireEvent.click(rows[0]);

		await waitFor(() => {
			const modal = screen.getByTestId('scenario-modal');
			expect(modal.textContent ?? '').toContain('crowdsecurity/http-cve');
			expect(modal.textContent ?? '').toContain('cscli scenarios inspect crowdsecurity/http-cve');
		});

		// Namespaced scenario → hub link visible.
		const hubLink = screen.getByTestId('modal-hub-link') as HTMLAnchorElement;
		expect(hubLink.href).toContain('hub.crowdsec.net');
		expect(hubLink.href).toContain('crowdsecurity');
		expect(hubLink.href).toContain('http-cve');
	});

	it('hides the hub link for non-namespaced scenarios (e.g. manual)', async () => {
		securityMock.fetchScenarios.mockResolvedValue(sampleScenariosOK);
		await openScenariosTab();

		await waitFor(() => {
			expect(screen.getByText('manual')).toBeInTheDocument();
		});

		// Click the manual row (the 3rd / last).
		const rows = screen.getAllByTestId('scenario-row');
		await fireEvent.click(rows[2]);

		await waitFor(() => {
			expect(screen.getByTestId('scenario-modal')).toBeInTheDocument();
		});
		expect(screen.queryByTestId('modal-hub-link')).toBeNull();
	});

	it('does NOT re-fetch on tab re-open if data already loaded', async () => {
		securityMock.fetchScenarios.mockResolvedValue(sampleScenariosOK);
		await openScenariosTab();

		await waitFor(() => expect(securityMock.fetchScenarios).toHaveBeenCalledTimes(1));

		// Hop to snapshot tab, then back to scenarios.
		await fireEvent.click(screen.getByTestId('tab-snapshot'));
		await fireEvent.click(screen.getByTestId('tab-scenarios'));

		// Refresh button is the explicit re-fetch path; tab
		// re-open is NOT supposed to re-fire.
		expect(securityMock.fetchScenarios).toHaveBeenCalledTimes(1);
	});
});
