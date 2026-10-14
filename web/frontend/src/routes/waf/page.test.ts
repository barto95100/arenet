// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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

const { metricsMock, securityMock, toastMock, clientMock } = vi.hoisted(() => ({
	metricsMock: { fetchSummary: vi.fn() },
	securityMock: { fetchEventsByRule: vi.fn() },
	toastMock: { pushToast: vi.fn() },
	clientMock: { listRoutes: vi.fn() }
}));

vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$lib/stores/toast', () => ({ pushToast: toastMock.pushToast }));
vi.mock('$lib/api/metrics', () => ({
	fetchSummary: (...a: unknown[]) => metricsMock.fetchSummary(...a)
}));
vi.mock('$lib/api/security', () => ({
	fetchEventsByRule: (...a: unknown[]) => securityMock.fetchEventsByRule(...a)
}));
// v2.73 — the Mode and Paranoia tiles read the route list now.
vi.mock('$lib/api/client', () => ({
	listRoutes: (...a: unknown[]) => clientMock.listRoutes(...a)
}));

import Page from './+page.svelte';
import type { Route, SummaryResponse } from '$lib/api/types';
import { makeRoute } from '$lib/test-support/route-fixture';

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
		totalRateLimitExceeded: 0,
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
	securityMock.fetchEventsByRule.mockReset();
	toastMock.pushToast.mockReset();
	clientMock.listRoutes.mockReset();
	clientMock.listRoutes.mockResolvedValue([]);
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

// --- Phase Y — 25-category taxonomy + family grouping +
// drill-down + cleanup tests ------------------------------

import { userEvent } from '@testing-library/user-event';

describe('WAF page — Phase Y taxonomy + drill-down', () => {
	it('renders the 5 family sections', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		render(Page);
		await tick();
		await tick();
		expect(screen.getByTestId('fam-request-attack')).toBeInTheDocument();
		expect(screen.getByTestId('fam-protocol-behaviour')).toBeInTheDocument();
		expect(screen.getByTestId('fam-aggregator')).toBeInTheDocument();
		expect(screen.getByTestId('fam-data-leak')).toBeInTheDocument();
		expect(screen.getByTestId('fam-infrastructure')).toBeInTheDocument();
	});

	it('renders the Phase Y category cards (split RCE/PHP/Java, split LFI/RFI, split Protocol family)', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		render(Page);
		await tick();
		await tick();
		// Pre-Y had RCE alone aggregating 932+933+934+944.
		// Phase Y splits them — verify each is its own card.
		expect(screen.getByTestId('cat-row-RCE')).toBeInTheDocument();
		expect(screen.getByTestId('cat-row-PHP')).toBeInTheDocument();
		expect(screen.getByTestId('cat-row-JAVA')).toBeInTheDocument();
		expect(screen.getByTestId('cat-row-GENERIC')).toBeInTheDocument();
		// LFI / RFI split.
		expect(screen.getByTestId('cat-row-LFI')).toBeInTheDocument();
		expect(screen.getByTestId('cat-row-RFI')).toBeInTheDocument();
		// Protocol split into METHOD / PROTOCOL / PROTOCOL_ATK /
		// MULTIPART (+ SCANNER, SESSION in behaviour family).
		expect(screen.getByTestId('cat-row-METHOD')).toBeInTheDocument();
		expect(screen.getByTestId('cat-row-PROTOCOL')).toBeInTheDocument();
		expect(screen.getByTestId('cat-row-PROTOCOL_ATK')).toBeInTheDocument();
		expect(screen.getByTestId('cat-row-MULTIPART')).toBeInTheDocument();
		// OTHER previously hid SCANNER + SESSION + data-leak +
		// anomaly aggregators ; Phase Y promotes each.
		expect(screen.getByTestId('cat-row-SCANNER')).toBeInTheDocument();
		expect(screen.getByTestId('cat-row-SESSION')).toBeInTheDocument();
		expect(screen.getByTestId('cat-row-ANOMALY_REQ')).toBeInTheDocument();
		expect(screen.getByTestId('cat-row-DATA_LEAK_SQL')).toBeInTheDocument();
		expect(screen.getByTestId('cat-row-WEBSHELL')).toBeInTheDocument();
	});

	it('removes the misleading "Per-route rate limits" link (no per-route rate limit feature exists)', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		render(Page);
		await tick();
		await tick();
		// The "/routes" link with the "Per-route rate limits"
		// blurb is GONE in Phase Y. The CrowdSec link stays.
		expect(screen.queryByText(/Per-route rate limits/)).toBeNull();
		expect(screen.getByText(/Active CrowdSec decisions/)).toBeInTheDocument();
	});

	it('clicking a category card opens the drill-down and calls fetchEventsByRule with category + window', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		securityMock.fetchEventsByRule.mockResolvedValue({
			rows: [
				{
					ruleId: '942100',
					category: 'SQLi',
					count: 12,
					lastSeen: '2026-06-18T10:00:00Z'
				},
				{
					ruleId: '942130',
					category: 'SQLi',
					count: 5,
					lastSeen: '2026-06-18T09:30:00Z'
				}
			]
		});
		const user = userEvent.setup();
		render(Page);
		await tick();
		await tick();

		const toggle = screen.getByTestId('cat-toggle-SQLi');
		await user.click(toggle);
		await tick();
		await tick();
		await tick();

		expect(securityMock.fetchEventsByRule).toHaveBeenCalledTimes(1);
		const callArg = securityMock.fetchEventsByRule.mock.calls[0][0];
		expect(callArg).toMatchObject({ category: 'SQLi', window: '24h' });

		// Drill table contains the rule IDs.
		const drill = screen.getByTestId('cat-drill-SQLi');
		expect(drill.textContent ?? '').toContain('942100');
		expect(drill.textContent ?? '').toContain('942130');
	});

	it('clicking the same category twice toggles closed without a second fetch', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		securityMock.fetchEventsByRule.mockResolvedValue({ rows: [] });
		const user = userEvent.setup();
		render(Page);
		await tick();
		await tick();

		const toggle = screen.getByTestId('cat-toggle-XSS');
		await user.click(toggle);
		await tick();
		await tick();
		expect(screen.getByTestId('cat-drill-XSS')).toBeInTheDocument();
		await user.click(toggle);
		await tick();
		expect(screen.queryByTestId('cat-drill-XSS')).toBeNull();
		// Single fetch — the close path uses the cached result.
		expect(securityMock.fetchEventsByRule).toHaveBeenCalledTimes(1);
	});

	it('shows a friendly empty-state when the API returns no rules for the category', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		securityMock.fetchEventsByRule.mockResolvedValue({ rows: [] });
		const user = userEvent.setup();
		render(Page);
		await tick();
		await tick();
		await user.click(screen.getByTestId('cat-toggle-CORRELATION'));
		await tick();
		await tick();
		const drill = screen.getByTestId('cat-drill-CORRELATION');
		// v2.9.20 i18n Phase 3 batch 4 — drill empty-state copy
		// migrated to t() → "No rule triggered in this category…"
		// in the EN bundle (test boot default).
		expect(drill.textContent ?? '').toMatch(/no rule triggered/i);
	});

	it('shows an error state when fetchEventsByRule rejects', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		securityMock.fetchEventsByRule.mockRejectedValue(new Error('boom'));
		const user = userEvent.setup();
		render(Page);
		await tick();
		await tick();
		await user.click(screen.getByTestId('cat-toggle-WEBSHELL'));
		await tick();
		await tick();
		const drill = screen.getByTestId('cat-drill-WEBSHELL');
		expect(drill.textContent ?? '').toContain('failed to load rules');
	});
});

// The two tiles that described a posture they could not know (v2.73).
//
// The Mode tile rendered t('waf.kpiModeBlocking') + t('waf.kpiModeFoot')
// — "Blocking" and "detection + block enabled" — with no data input at
// all; the page did not even load the route list. But wafMode is
// PER-ROUTE, and the documented recommended default is detect. So an
// operator whose every route sat in detect, blocking nothing, read
// "Mode: Blocking · detection + block enabled" on the WAF page.
//
// The Paranoia tile rendered a literal value={2}. The applied level is
// 1: in the pinned coraza-coreruleset v4.25.0, rule 900000 is
// commented out in rules/@crs-setup.conf.example:186, so rule 901120
// in REQUEST-901-INITIALIZATION.conf:54-61 fires on
// "&TX:blocking_paranoia_level @eq 0" and sets 1. Arenet sets no
// paranoia level of its own anywhere.
describe('WAF page — the Mode and Paranoia tiles read the routes', () => {
	function withRoutes(routes: Route[]): void {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		clientMock.listRoutes.mockResolvedValue(routes);
	}

	it('says Detect when every route is in detect, not Blocking', async () => {
		withRoutes([
			makeRoute({ id: 'a', wafMode: 'detect' }),
			makeRoute({ id: 'b', wafMode: 'detect' })
		]);
		render(Page);

		const tile = await screen.findByTestId('kpi-waf-mode');
		await vi.waitFor(() => expect(tile.textContent ?? '').toMatch(/Detect/));
		expect(tile.textContent ?? '').not.toMatch(/Blocking/);
	});

	it('says Mixed when the routes disagree, and breaks the count down', async () => {
		withRoutes([
			makeRoute({ id: 'a', wafMode: 'block' }),
			makeRoute({ id: 'b', wafMode: 'detect' }),
			makeRoute({ id: 'c', wafMode: 'detect' }),
			makeRoute({ id: 'd', wafMode: 'off' })
		]);
		render(Page);

		const tile = await screen.findByTestId('kpi-waf-mode');
		await vi.waitFor(() => expect(tile.textContent ?? '').toMatch(/Mixed/));
		expect(tile.textContent ?? '').toMatch(/1 blocking · 2 detect · 1 off/);
	});

	it('says Blocking only when every route really blocks', async () => {
		withRoutes([
			makeRoute({ id: 'a', wafMode: 'block' }),
			makeRoute({ id: 'b', wafMode: 'block' })
		]);
		render(Page);

		const tile = await screen.findByTestId('kpi-waf-mode');
		await vi.waitFor(() => expect(tile.textContent ?? '').toMatch(/Blocking/));
	});

	it('admits it does not know when the route list fails', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		clientMock.listRoutes.mockRejectedValue(new Error('boom'));
		render(Page);

		const tile = await screen.findByTestId('kpi-waf-mode');
		await vi.waitFor(() =>
			expect(tile.textContent ?? '').toMatch(/route list unavailable/)
		);
		expect(tile.textContent ?? '').not.toMatch(/Blocking/);
	});

	it('reports the paranoia level CRS actually applies, which is 1', async () => {
		withRoutes([makeRoute({ id: 'a', wafMode: 'block' })]);
		render(Page);

		const tile = await screen.findByTestId('kpi-waf-paranoia');
		// Anchored on the "N/ 4" reading rather than a bare digit:
		// the hint names CRS rule 901120, which contains a 2.
		await vi.waitFor(() => expect(tile.textContent ?? '').toMatch(/1\/\s*4/));
		expect(tile.textContent ?? '').not.toMatch(/2\/\s*4/);
	});

	// A route CAN move it in custom SecLang, so the tile counts the
	// overrides rather than quietly contradicting them.
	it('reports how many routes override it in SecLang', async () => {
		withRoutes([
			makeRoute({ id: 'a' }),
			makeRoute({
				id: 'b',
				wafSecLang: 'SecAction "id:1,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=3"'
			})
		]);
		render(Page);

		const tile = await screen.findByTestId('kpi-waf-paranoia');
		await vi.waitFor(() =>
			expect(tile.textContent ?? '').toMatch(/1 SecLang override/)
		);
	});
});
