// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// #R-DASHBOARD-WAF-COUNTERS-ZERO + #R-WAF-EVENT-LABEL-INCONSISTENT
// — frontend tests for the dashboard.
//
// Pre-fix the dashboard had:
//   (a) one "WAF BLOCKS / H" KPI sourced from
//       totalWafBlocked which stayed at zero on
//       wafMode=detect routes (the homelab default).
//   (b) hardcoded "block" / "BLOCK 403" labels in the WAF
//       events feed, ignoring the per-event ev.action.
//
// Post-fix we pin:
//   1. Two separate WAF KPI tiles (BLOCKED + DETECTED) with
//      the right values projected to /h.
//   2. Top Routes table renders the new WAF detect column.
//   3. Recent WAF events surface DETECT label on detect-
//      mode rows, BLOCK on block-mode rows. Status code on
//      detect events renders as "—" (the operator-honest
//      "no value" answer for an upstream the WAF didn't
//      observe).

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen } from '@testing-library/svelte';

const { metricsMock, securityMock, clientMock, toastMock } = vi.hoisted(() => ({
	metricsMock: {
		fetchSummary: vi.fn(),
		fetchTimeseries: vi.fn()
	},
	securityMock: {
		fetchEvents: vi.fn()
	},
	clientMock: {
		listRoutes: vi.fn()
	},
	toastMock: { pushToast: vi.fn() }
}));

vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$lib/stores/toast', () => ({ pushToast: toastMock.pushToast }));
vi.mock('$lib/api/metrics', () => ({
	fetchSummary: (...a: unknown[]) => metricsMock.fetchSummary(...a),
	fetchTimeseries: (...a: unknown[]) => metricsMock.fetchTimeseries(...a)
}));
vi.mock('$lib/api/security', () => ({
	fetchEvents: (...a: unknown[]) => securityMock.fetchEvents(...a)
}));
vi.mock('$lib/api/client', () => ({
	listRoutes: (...a: unknown[]) => clientMock.listRoutes(...a)
}));

import Page from './+page.svelte';
import type { SummaryResponse, WafEvent } from '$lib/api/types';

function makeSummary(overrides: Partial<SummaryResponse> = {}): SummaryResponse {
	return {
		generatedAt: '2026-06-10T22:00:00Z',
		windowSeconds: 60,
		totalReq: 60,
		totalFourXx: 2,
		totalFiveXx: 1,
		totalWafBlocked: 0,
		totalWafDetected: 0,
		totalThrottle: 0,
		totalAuthFailures: 0,
		attackerIpsUnique: 0,
		totalCrowdSecDecisions: 0,
		activeCrowdSecIpsUnique: 0,
		wafBlocksByCategory: {},
		wafDetectsByCategory: {},
		globalP95LatencyMs: 12,
		activeRouteCount: 1,
		topRoutes: [],
		topAttackedRoute: null,
		...overrides
	};
}

beforeEach(() => {
	metricsMock.fetchSummary.mockReset();
	metricsMock.fetchTimeseries.mockReset();
	securityMock.fetchEvents.mockReset();
	clientMock.listRoutes.mockReset();
	toastMock.pushToast.mockReset();

	metricsMock.fetchTimeseries.mockResolvedValue({ points: [] });
	securityMock.fetchEvents.mockResolvedValue({ events: [] });
	clientMock.listRoutes.mockResolvedValue([{
		id: 'r1', host: 'ha.example.com', upstreams: [{ url: 'http://10.0.0.10', weight: 1 }]
	}]);
});

describe('Dashboard — WAF KPI split (#R-DASHBOARD-WAF-COUNTERS-ZERO)', () => {
	it('renders both BLOQUÉ and DÉTECTÉ tiles independently from the summary', async () => {
		metricsMock.fetchSummary.mockResolvedValue(
			makeSummary({
				totalWafBlocked: 4,
				totalWafDetected: 11
			})
		);
		render(Page);
		// Wait for mount + async fetches.
		await tick();
		await tick();
		await tick();

		const blocked = screen.getByTestId('kpi-waf-blocked');
		const detected = screen.getByTestId('kpi-waf-detected');
		// #R-WAF-METRICS-WINDOW-1MIN-PROJECTION — post-fix the
		// dashboard reads the 24h total directly (no ×60
		// projection). The tiles show raw 4 / 11.
		expect(blocked.textContent).toContain('4');
		expect(detected.textContent).toContain('11');
	});

	it('reads zero for the detect tile when the wire field is absent (graceful default)', async () => {
		// Simulate a stale summary response where the new
		// field is missing: the tile must render 0, not NaN.
		metricsMock.fetchSummary.mockResolvedValue(
			makeSummary({
				totalWafBlocked: 6,
				// totalWafDetected intentionally omitted
				totalWafDetected: undefined as unknown as number
			})
		);
		render(Page);
		await tick();
		await tick();
		await tick();

		const detected = screen.getByTestId('kpi-waf-detected');
		expect(detected.textContent).toMatch(/\b0\b/);
		expect(detected.textContent).not.toContain('NaN');
	});
});

describe('Dashboard — WAF event label fix (#R-WAF-EVENT-LABEL-INCONSISTENT)', () => {
	const blockEvent: WafEvent = {
		id: 1,
		ts: '2026-06-10T22:00:00Z',
		routeId: 'r1',
		ruleId: '942100',
		category: 'SQLi',
		severity: 5,
		srcIp: '1.1.1.1',
		requestMethod: 'POST',
		requestPath: '/login',
		payloadSample: "' OR 1=1",
		action: 'BLOCK',
		statusCode: 403
	};
	const detectEvent: WafEvent = {
		id: 2,
		ts: '2026-06-10T22:00:00Z',
		routeId: 'r1',
		ruleId: '930100',
		category: 'LFI',
		severity: 5,
		srcIp: '2.2.2.2',
		requestMethod: 'GET',
		requestPath: '/index.php?file=../etc/passwd',
		payloadSample: '../etc/passwd',
		action: 'DETECT',
		statusCode: 0
	};

	it('renders BLOCK label + status code on block-mode events', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		securityMock.fetchEvents.mockResolvedValue({ events: [blockEvent] });
		render(Page);
		await tick();
		await tick();
		await tick();

		const recent = screen.getByTestId('recent-event-1');
		expect(recent.textContent?.toLowerCase()).toContain('block');
		const tail = screen.getByTestId('tail-event-1');
		expect(tail.textContent).toContain('BLOCK');
		// Status code 403 must surface (no hardcoded fallback).
		expect(tail.textContent).toContain('403');
	});

	it('renders DETECT label + dash status on detect-mode events', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		securityMock.fetchEvents.mockResolvedValue({ events: [detectEvent] });
		render(Page);
		await tick();
		await tick();
		await tick();

		const recent = screen.getByTestId('recent-event-2');
		expect(recent.textContent?.toLowerCase()).toContain('detect');
		// Must NOT carry the misleading "block" label that pre-fix
		// silently rendered on detect events.
		expect(recent.textContent?.toLowerCase()).not.toContain('block');

		const tail = screen.getByTestId('tail-event-2');
		expect(tail.textContent).toContain('DETECT');
		// statusCode 0 renders as "—" (no value at WAF time).
		expect(tail.textContent).toContain('—');
		expect(tail.textContent).not.toContain('403');
	});

	it('renders both labels correctly when mixed events are in the feed', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		securityMock.fetchEvents.mockResolvedValue({
			events: [blockEvent, detectEvent]
		});
		render(Page);
		await tick();
		await tick();
		await tick();

		const recent1 = screen.getByTestId('recent-event-1');
		const recent2 = screen.getByTestId('recent-event-2');
		expect(recent1.textContent?.toLowerCase()).toContain('block');
		expect(recent2.textContent?.toLowerCase()).toContain('detect');
	});
});

describe('Dashboard — Top Routes WAF detect column (#R-DASHBOARD-WAF-COUNTERS-ZERO)', () => {
	it('renders the new wafDetected column with per-route values', async () => {
		metricsMock.fetchSummary.mockResolvedValue(
			makeSummary({
				topRoutes: [
					{
						routeId: 'r1',
						host: 'ha.example.com',
						reqs: 60,
						fourxx: 0,
						fivexx: 0,
						wafBlocked: 1,
						wafDetected: 7
					}
				],
				activeRouteCount: 1
			})
		);
		render(Page);
		await tick();
		await tick();
		await tick();

		const headers = screen.getAllByRole('columnheader');
		const labels = headers.map((h) => h.textContent?.trim() ?? '');
		expect(labels).toContain('WAF block');
		expect(labels).toContain('WAF detect');
		// The row's detect cell shows 7; the row's block cell
		// shows 1. Pin both so a swap regression would catch.
		const row = screen.getByText('ha.example.com').closest('tr')!;
		const cells = row.querySelectorAll('td.mono.right');
		// Order: Req/min, 4xx/min, 5xx/min, block, detect.
		expect(cells[3].textContent?.trim()).toBe('1');
		expect(cells[4].textContent?.trim()).toBe('7');
	});
});
