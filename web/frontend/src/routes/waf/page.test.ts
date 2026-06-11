// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// #R-DASHBOARD-WAF-COUNTERS-ZERO — frontend tests for the
// /sécurité/waf page.
//
// Pre-fix the page had:
//   (a) one "Blocked" KPI sourced from totalWafBlocked
//       only — detect-mode activity was invisible.
//   (b) one count cell per CRS category, fed by
//       wafBlocksByCategory which silently aggregated
//       BLOCK and DETECT under a misleading "blocks" label.
//
// Post-fix we pin:
//   1. Two KPI tiles (Blocked + Detected) sourced from the
//      respective wire fields.
//   2. Each CRS category row renders TWO numbers: block24h
//      (red) and detect24h (amber). The split makes the
//      semantics honest.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen } from '@testing-library/svelte';

const { metricsMock, toastMock } = vi.hoisted(() => ({
	metricsMock: { fetchSummary: vi.fn() },
	toastMock: { pushToast: vi.fn() }
}));

vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$lib/stores/toast', () => ({ pushToast: toastMock.pushToast }));
vi.mock('$lib/api/metrics', () => ({
	fetchSummary: (...a: unknown[]) => metricsMock.fetchSummary(...a)
}));

import Page from './+page.svelte';
import type { SummaryResponse } from '$lib/api/types';

function makeSummary(overrides: Partial<SummaryResponse> = {}): SummaryResponse {
	return {
		generatedAt: '2026-06-10T22:00:00Z',
		windowSeconds: 60,
		totalReq: 60,
		totalFourXx: 0,
		totalFiveXx: 0,
		totalWafBlocked: 0,
		totalWafDetected: 0,
		totalThrottle: 0,
		totalAuthFailures: 0,
		attackerIpsUnique: 0,
		totalCrowdSecDecisions: 0,
		activeCrowdSecIpsUnique: 0,
		wafBlocksByCategory: {},
		wafDetectsByCategory: {},
		globalP95LatencyMs: null,
		activeRouteCount: 1,
		topRoutes: [],
		topAttackedRoute: null,
		...overrides
	};
}

beforeEach(() => {
	metricsMock.fetchSummary.mockReset();
	toastMock.pushToast.mockReset();
});

describe('WAF page — Blocked + Detected KPI split (#R-DASHBOARD-WAF-COUNTERS-ZERO)', () => {
	it('renders both KPI tiles with raw 24h totals (no rate projection post-#R-WAF-METRICS-WINDOW-1MIN-PROJECTION)', async () => {
		metricsMock.fetchSummary.mockResolvedValue(
			makeSummary({
				totalWafBlocked: 2880,
				totalWafDetected: 7200
			})
		);
		render(Page);
		await tick();
		await tick();
		await tick();

		const blocked = screen.getByTestId('kpi-blocked');
		const detected = screen.getByTestId('kpi-detected');
		// Post-#R-WAF-METRICS-WINDOW-1MIN-PROJECTION the wire emits 24h totals. 2/min × 60 × 24 = 2,880; 5/min × 60 × 24 = 7,200.
		expect(blocked.textContent?.replace(/[\s,  ]/g, '')).toContain('2880');
		expect(detected.textContent?.replace(/[\s,  ]/g, '')).toContain('7200');
	});
});

describe('WAF page — Per-category block + detect split (#R-DASHBOARD-WAF-COUNTERS-ZERO)', () => {
	it('renders BLOCK count from wafBlocksByCategory and DETECT count from wafDetectsByCategory per CRS category row', async () => {
		metricsMock.fetchSummary.mockResolvedValue(
			makeSummary({
				wafBlocksByCategory: { SQLi: 1440 },
				wafDetectsByCategory: { LFI: 4320 }
			})
		);
		render(Page);
		await tick();
		await tick();
		await tick();

		// SQLi row: 1440 block / 0 detect (raw 24h counts).
		const sqli = screen.getByTestId('cat-row-SQLi');
		expect(sqli.textContent?.replace(/[\s,  ]/g, '')).toContain('1440');

		// LFI row: 0 block / 4320 detect (raw 24h counts).
		const lfi = screen.getByTestId('cat-row-LFI');
		expect(lfi.textContent?.replace(/[\s,  ]/g, '')).toContain('4320');
		// Sanity: LFI block stays at 0 (not silently aggregated
		// with the detect count as it was pre-fix).
		// The presence of "blocks / 24h" label + the "0" value
		// in the same row is the structural assertion.
		const blockCells = lfi.querySelectorAll('.cat-meta-block');
		expect(blockCells.length).toBe(1);
		expect(blockCells[0].textContent?.replace(/[\s,  ]/g, '')).toBe('0');
	});

	it('renders zero for both counts when a category has no events at all', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		render(Page);
		await tick();
		await tick();
		await tick();

		const xss = screen.getByTestId('cat-row-XSS');
		const block = xss.querySelector('.cat-meta-block');
		const detect = xss.querySelector('.cat-meta-detect');
		expect(block?.textContent?.trim()).toBe('0');
		expect(detect?.textContent?.trim()).toBe('0');
	});
});
