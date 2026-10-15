// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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
import userEvent from '@testing-library/user-event';

const { metricsMock, securityMock, clientMock, certificatesMock, toastMock } = vi.hoisted(() => ({
	metricsMock: {
		fetchSummary: vi.fn(),
		fetchTimeseries: vi.fn()
	},
	securityMock: {
		fetchEvents: vi.fn(),
		// Phase 5 — dashboard loader calls fetchCertEventsAggregate
		// twice (30d window for the chart, 7d window for the
		// failed-7d KPI). Default stub returns the empty-buckets
		// shape so tests that don't care about cert data just
		// get a clean empty render.
		fetchCertEventsAggregate: vi.fn()
	},
	clientMock: {
		listRoutes: vi.fn()
	},
	certificatesMock: {
		list: vi.fn()
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
	fetchEvents: (...a: unknown[]) => securityMock.fetchEvents(...a),
	fetchCertEventsAggregate: (...a: unknown[]) => securityMock.fetchCertEventsAggregate(...a)
}));
vi.mock('$lib/api/client', () => ({
	listRoutes: (...a: unknown[]) => clientMock.listRoutes(...a)
}));
vi.mock('$lib/api/certificates', () => ({
	certificatesApi: {
		list: (...a: unknown[]) => certificatesMock.list(...a)
	}
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
		totalRateLimitExceeded: 0,
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
	securityMock.fetchCertEventsAggregate.mockReset();
	clientMock.listRoutes.mockReset();
	certificatesMock.list.mockReset();
	toastMock.pushToast.mockReset();

	metricsMock.fetchTimeseries.mockResolvedValue({ points: [] });
	securityMock.fetchEvents.mockResolvedValue({ events: [] });
	// Phase 5 — default to empty cert state so existing tests
	// (WAF KPIs / Top routes / Recent events) stay focused on
	// the surfaces they care about. Individual cert-KPI tests
	// override below.
	securityMock.fetchCertEventsAggregate.mockResolvedValue({ buckets: [] });
	certificatesMock.list.mockResolvedValue([]);
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

// --- Phase 5 — cert KPI tiles + lifecycle panel ----------------------------
//
// Three KPI tiles (total / expiring-30d / failed-7d) + a chart
// panel ("Cycle de vie des certificats") that mounts the
// MultiSeriesTimelineChart component. These tests pin the
// loader's wiring: each tile reads its derived value from a
// distinct source (certificatesApi.list for total + expiring,
// fetchCertEventsAggregate window=7d for failed-7d), and the
// chart panel renders even on an empty buckets payload.

describe('Dashboard — Phase 5 cert KPI tiles', () => {
	function inHorizonISO(daysAhead: number): string {
		return new Date(Date.now() + daysAhead * 24 * 60 * 60 * 1000).toISOString();
	}

	it('"Total certs" tile counts the certificates list length', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		certificatesMock.list.mockResolvedValue([
			{ domain: 'a.example', notAfter: inHorizonISO(60) },
			{ domain: 'b.example', notAfter: inHorizonISO(45) },
			{ domain: 'c.example', notAfter: inHorizonISO(80) }
		]);

		render(Page);
		await tick();
		await tick();
		await tick();

		const tile = screen.getByTestId('kpi-cert-total');
		expect(tile.textContent).toContain('3');
	});

	it('"Expirent dans 30j" tile counts only certs with notAfter inside the 30d horizon', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		certificatesMock.list.mockResolvedValue([
			{ domain: 'soon-a.example', notAfter: inHorizonISO(10) }, // counts
			{ domain: 'soon-b.example', notAfter: inHorizonISO(28) }, // counts
			{ domain: 'far.example', notAfter: inHorizonISO(60) } // doesn't count
		]);

		render(Page);
		await tick();
		await tick();
		await tick();

		const tile = screen.getByTestId('kpi-cert-expiring');
		expect(tile.textContent).toContain('2');
	});

	it('"Failed last 7d" tile sums failed counts across the 7d aggregate', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		// First call (30d for chart) → empty buckets.
		// Second call (7d for failed-7d KPI) → buckets that sum to 5.
		securityMock.fetchCertEventsAggregate
			.mockResolvedValueOnce({ buckets: [] })
			.mockResolvedValueOnce({
				buckets: [
					{ bucketStart: '2026-06-08T00:00:00Z', issued: 0, renewed: 0, failed: 2 },
					{ bucketStart: '2026-06-09T00:00:00Z', issued: 0, renewed: 0, failed: 3 }
				]
			});

		render(Page);
		await tick();
		await tick();
		await tick();

		const tile = screen.getByTestId('kpi-cert-failed-7d');
		expect(tile.textContent).toContain('5');
	});

	it('renders the cert lifecycle panel on every dashboard load', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());

		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('cert-lifecycle-panel')).toBeTruthy();
	});

	it('cert KPI tiles default to zero when /certificates fails (best-effort)', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		certificatesMock.list.mockRejectedValue(new Error('boot failure'));

		render(Page);
		await tick();
		await tick();
		await tick();

		// .catch fallback → empty list → zero counts. Dashboard
		// stays renderable instead of toasting an error.
		expect(screen.getByTestId('kpi-cert-total').textContent).toContain('0');
		expect(screen.getByTestId('kpi-cert-expiring').textContent).toContain('0');
	});
});

// The chart said things the data did not support (v2.73).
//
// Two separate defects in the same card.
//
// The unit: req_per_sec / four_xx_rate / five_xx_rate carry per-bucket
// COUNTS, not rates — metrics_handlers.go:968-976 returns
// float64(row.ReqCount) and friends straight out of the bucket — while
// the button read "Req/s". On the 24h window (1-minute buckets) every
// value was 60x off; on 30d (1-hour buckets), 3600x. "1 200 req/s" was
// 1 200 requests in a minute.
//
// The race: switchMetric assigned chartMetric and only then awaited, so
// the title and the colour changed at the click. Click "Latency" while
// the API is failing and the request-count series stayed drawn under
// the latency title, in the latency colour — requests read as
// milliseconds.
describe('dashboard — the traffic chart describes its own data', () => {
	// The file-wide beforeEach resets fetchSummary without giving it a
	// default, so every test supplies its own; the chart card only
	// renders once the page's load() resolves.
	beforeEach(() => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
	});

	// Scoped to the traffic card's heading. A document-wide getByText
	// matched twice — the heading's unit span AND the chart's own
	// accessible name, which carries the same unit by design.
	function trafficHeading(): HTMLElement {
		return screen.getByRole('heading', { name: /Traffic/ });
	}

	// Waits for the first series to be drawn, without reading the unit
	// label: the race tests must not fail when the unit changes.
	async function chartDrawn(): Promise<void> {
		await vi.waitFor(() =>
			expect(document.querySelector('.chart-wrap title')?.textContent).toMatch(/Requests/)
		);
	}

	function timeseries(metric: string, bucketSizeSeconds: number, values: number[]) {
		return {
			routeId: 'all',
			metric,
			window: '24h',
			bucketSizeSeconds,
			// The loader drops the trailing in-progress bucket, so pad.
			points: [
				...values.map((v, i) => ({ ts: `2026-10-14T12:${String(i).padStart(2, '0')}:00Z`, value: v })),
				{ ts: '2026-10-14T13:00:00Z', value: 0 }
			]
		};
	}

	it('names the bucket width instead of claiming per-second', async () => {
		metricsMock.fetchTimeseries.mockResolvedValue(timeseries('req_per_sec', 60, [1200, 1300]));
		render(Page);

		await vi.waitFor(() => expect(trafficHeading().textContent).toMatch(/per minute/));
	});

	it('says per hour on an hour-wide bucket', async () => {
		metricsMock.fetchTimeseries.mockResolvedValue(timeseries('req_per_sec', 3600, [42]));
		render(Page);

		await vi.waitFor(() => expect(trafficHeading().textContent).toMatch(/per hour/));
	});

	it('no longer offers a Req/s button, because that is not the unit', async () => {
		metricsMock.fetchTimeseries.mockResolvedValue(timeseries('req_per_sec', 60, [1]));
		render(Page);

		await vi.waitFor(() => expect(screen.getByText('Requests')).toBeTruthy());
		expect(screen.queryByText('Req/s')).toBeNull();
	});

	// The race, in one assertion: the failed switch must leave the
	// chart describing the data it still shows.
	it('keeps the old label when the new metric fails to load', async () => {
		metricsMock.fetchTimeseries.mockResolvedValue(timeseries('req_per_sec', 60, [1200]));
		render(Page);
		await chartDrawn();

		// Now the API starts failing, and the operator asks for latency.
		metricsMock.fetchTimeseries.mockRejectedValue(new Error('boom'));
		await userEvent.click(screen.getByText('Latency'));
		await tick();

		// Still the request series. Asserted on what the chart says
		// it is drawing, not on the unit text, so a change to the
		// label cannot make this test fail for the wrong reason.
		expect(document.querySelector('.chart-wrap')?.getAttribute('data-metric')).toBe(
			'req_per_sec'
		);
	});

	it('relabels once the new metric does load', async () => {
		metricsMock.fetchTimeseries.mockResolvedValue(timeseries('req_per_sec', 60, [1200]));
		render(Page);
		await chartDrawn();

		metricsMock.fetchTimeseries.mockResolvedValue(
			timeseries('p95_latency_ms', 60, [48])
		);
		await userEvent.click(screen.getByText('Latency'));

		await vi.waitFor(() =>
			expect(document.querySelector('.chart-wrap')?.getAttribute('data-metric')).toBe(
				'p95_latency_ms'
			)
		);
	});

	// The accessible label used to be `Series for ${chartMetric}` — an
	// English literal built from the raw wire name, so a screen reader
	// heard "Series for five_xx_rate".
	it('gives the chart a translated accessible name, not the wire name', async () => {
		metricsMock.fetchTimeseries.mockResolvedValue(timeseries('req_per_sec', 60, [1200]));
		render(Page);

		await vi.waitFor(() => {
			const labelled = document.querySelector('[aria-label*="Requests"]');
			expect(labelled).not.toBeNull();
		});
		expect(document.querySelector('[aria-label*="req_per_sec"]')).toBeNull();
	});
});

// The three claims the page made that its data did not support
// (v2.73). All low-harm next to the chart's unit, all the same class.
describe('dashboard — it is as live as it claims', () => {
	beforeEach(() => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		metricsMock.fetchTimeseries.mockResolvedValue({
			routeId: 'all',
			metric: 'req_per_sec',
			window: '24h',
			bucketSizeSeconds: 60,
			points: [
				{ ts: '2026-10-15T12:00:00Z', value: 10 },
				{ ts: '2026-10-15T12:01:00Z', value: 0 }
			]
		});
	});

	// The subtitle has always said "Real-time traffic across your N
	// routes". load() ran once, from onMount, so a dashboard left open
	// overnight showed yesterday's numbers under that sentence.
	it('says when it last refreshed, so "real-time" is checkable', async () => {
		render(Page);
		await vi.waitFor(() =>
			expect(document.body.textContent ?? '').toMatch(/updated \d+s ago/)
		);
	});

	// The tail column was toISOString().substring(11, 19) — UTC, with
	// nothing saying so, against a /logs page that has always shown
	// local time.
	// The timezone is forced, so this test has teeth on a UTC CI
	// runner too. Read against the host's own zone it would pass with
	// the bug whenever that zone is UTC — the assertion that matters
	// is the negative one: the cell must NOT read the UTC rendering.
	// process.env.TZ is honoured at runtime by Node; probed before
	// relying on it.
	it('shows the tail time in local time, not UTC', async () => {
		const realTZ = process.env.TZ;
		process.env.TZ = 'Asia/Tokyo';
		try {
			await tailTimeAssertions();
		} finally {
			process.env.TZ = realTZ;
		}
	});

	async function tailTimeAssertions(): Promise<void> {
		const iso = '2026-10-15T12:00:00Z';
		const d = new Date(iso);
		const p = (n: number) => String(n).padStart(2, '0');
		const expected = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
		const utcRendering = iso.substring(11, 19);
		// Guard the guard: if the forced zone ever stops taking
		// effect, the test would silently lose its point.
		expect(expected).not.toBe(utcRendering);

		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 1,
					ts: iso,
					routeId: 'r1',
					ruleId: '942100',
					category: 'SQLi',
					severity: 4,
					srcIp: '203.0.113.9',
					requestMethod: 'GET',
					requestPath: '/',
					payloadSample: 'x',
					action: 'BLOCK',
					statusCode: 403
				}
			]
		});
		render(Page);

		await vi.waitFor(() => {
			const cells = Array.from(document.querySelectorAll('.log-time')).map(
				(e) => e.textContent?.trim() ?? ''
			);
			expect(cells).toContain(expected);
			expect(cells).not.toContain(utcRendering);
		});
	}

	// The card sliced to 8 with no sign the rest existed. The meta
	// count was always honest, which is what made the list's silence
	// easy to miss.
	it('says how many upstreams it is not showing', async () => {
		clientMock.listRoutes.mockResolvedValue(
			Array.from({ length: 11 }, (_, i) => ({
				id: `r${i}`,
				host: `h${i}.example.com`,
				upstreams: [{ url: `http://10.0.0.${i}`, weight: 1 }]
			}))
		);
		render(Page);

		// findByTestId, not vi.waitFor(querySelector): querySelector
		// returning null does not throw, so waitFor resolves on the
		// first attempt with null and the assertion runs against ''.
		const note = await screen.findByTestId('upstreams-truncated');
		expect(note.textContent ?? '').toMatch(/\+3 more/);
		expect(note.textContent ?? '').toMatch(/8 of 11/);
	});

	it('says nothing about truncation when nothing is truncated', async () => {
		clientMock.listRoutes.mockResolvedValue([
			{ id: 'r1', host: 'h.example.com', upstreams: [{ url: 'http://10.0.0.1', weight: 1 }] }
		]);
		render(Page);
		await vi.waitFor(() => expect(metricsMock.fetchSummary).toHaveBeenCalled());

		expect(document.querySelector('[data-testid="upstreams-truncated"]')).toBeNull();
	});
});
