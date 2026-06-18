// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// /logs page tests — pins the Step U.5 contract: the unified
// table aggregator integrates cert lifecycle events as a 4th
// source alongside WAF, throttle, and auth-failure. First test
// file for this route; created in U.5 to cover the cert
// integration end-to-end (mapper → row render → filter →
// search).
//
// Existing 3 sources (WAF/throttle/auth) are exercised
// indirectly by these tests because they share the same load()
// codepath; this file does NOT attempt to back-fill page-test
// coverage for the pre-U.5 sources.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import type {
	AuthFailureRecentEvent,
	CertEvent,
	ThrottleEvent,
	WafEvent
} from '$lib/api/types';

// Mocks — same vi.hoisted pattern as the certs page tests so the
// module imports happen after the mock factories are in place.
const { toastMock, securityMock, clientMock } = vi.hoisted(() => ({
	toastMock: { pushToast: vi.fn() },
	securityMock: {
		fetchEvents: vi.fn(),
		fetchThrottleEvents: vi.fn(),
		fetchAuthFailures: vi.fn(),
		fetchCertEvents: vi.fn(),
		// W.5 — 5th source (country-block events).
		fetchCountryBlockEvents: vi.fn(),
		// Z.2 — 6th source (rate-limit 429 events).
		fetchRateLimitEvents: vi.fn()
	},
	// W.7 follow-up — routes API for routeId → host
	// resolution. Default returns an empty list so rows
	// with a routeId fall back to the <RouteHost>
	// truncated-UUID rendering; individual tests
	// override to test the happy path.
	clientMock: {
		listRoutes: vi.fn()
	}
}));

vi.mock('$lib/stores/toast', () => toastMock);
vi.mock('$lib/api/security', () => securityMock);
vi.mock('$lib/api/client', () => clientMock);

import Page from './+page.svelte';

// Anchor "now" for fixture timestamps so ts ordering is
// deterministic. Cert events sit at varying offsets from this
// anchor; the most-recent cert event ends up at the top of
// the merged feed.
const NOW = new Date('2026-06-06T12:00:00Z');

function isoOffset(seconds: number): string {
	return new Date(NOW.getTime() + seconds * 1000).toISOString();
}

beforeEach(() => {
	toastMock.pushToast.mockReset();
	securityMock.fetchEvents.mockReset();
	securityMock.fetchThrottleEvents.mockReset();
	securityMock.fetchAuthFailures.mockReset();
	securityMock.fetchCertEvents.mockReset();
	securityMock.fetchCountryBlockEvents.mockReset();
	securityMock.fetchRateLimitEvents.mockReset();

	// Defaults: every source returns empty. Individual tests
	// override what they need.
	securityMock.fetchEvents.mockResolvedValue({ events: [] });
	securityMock.fetchThrottleEvents.mockResolvedValue({ events: [] });
	securityMock.fetchAuthFailures.mockResolvedValue({
		window: '24h',
		timeseries: [],
		recent: []
	});
	securityMock.fetchCertEvents.mockResolvedValue({
		events: [],
		total: 0,
		hasMore: false
	});
	securityMock.fetchCountryBlockEvents.mockResolvedValue({
		events: [],
		total: 0,
		hasMore: false
	});
	securityMock.fetchRateLimitEvents.mockResolvedValue({
		events: [],
		total: 0,
		hasMore: false
	});
	clientMock.listRoutes.mockReset();
	clientMock.listRoutes.mockResolvedValue([]);
});

afterEach(() => {
	// The page sets up a setInterval poll on mount; cleanup is
	// the testing-library's auto-cleanup which dispatches
	// onDestroy. No explicit timer-clear needed because the
	// page calls clearInterval in onDestroy.
	vi.clearAllMocks();
});

const certFixture = (overrides: Partial<CertEvent> = {}): CertEvent => ({
	timestamp: isoOffset(0),
	level: 'INFO',
	eventType: 'cert_obtained',
	domain: 'example.com',
	issuer: "Let's Encrypt",
	challenge: 'DNS-01',
	renewal: false,
	error: '',
	details: '',
	...overrides
});

describe('/logs — cert events render in the unified table', () => {
	it('cert_obtained row appears with INFO level + "cert.obtained" detail', async () => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				certFixture({
					eventType: 'cert_obtained',
					domain: '*.example.com',
					issuer: "Let's Encrypt",
					challenge: 'DNS-01',
					renewal: true
				})
			],
			total: 1,
			hasMore: false
		});

		render(Page);
		// Wait for the row to mount. The filter card renders
		// immediately; the row arrives post-load.
		const row = await screen.findByText(/cert\.obtained/);
		expect(row).toBeInTheDocument();
		// Domain in the path column.
		expect(screen.getByText(/\*\.example\.com/)).toBeInTheDocument();
		// Issuer and challenge included.
		expect(row.textContent ?? '').toMatch(/Let's Encrypt/);
		expect(row.textContent ?? '').toMatch(/DNS-01/);
		// Renewal marker.
		expect(row.textContent ?? '').toMatch(/renouvellement/);
	});

	it('cert_failed row appears with WARN level + truncated error', async () => {
		const longError =
			"subject 'test.local' does not qualify for a public certificate because the TLD is not on the public suffix list";
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				certFixture({
					eventType: 'cert_failed',
					level: 'ERROR',
					domain: 'test.local',
					issuer: '',
					challenge: '',
					error: longError
				})
			],
			total: 1,
			hasMore: false
		});

		render(Page);
		const row = await screen.findByText(/cert\.failed/);
		expect(row).toBeInTheDocument();
		// Truncated to ~60 chars + ellipsis. The "does not
		// qualify" prefix is in the first 60 chars of the
		// fixture's error.
		expect(row.textContent ?? '').toMatch(/does not qualify/);
		// The truncated marker is present.
		expect(row.textContent ?? '').toMatch(/\.\.\./);
	});

	it('cert_ocsp_revoked row appears with WARN level + "révocation OCSP"', async () => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				certFixture({
					eventType: 'cert_ocsp_revoked',
					level: 'ERROR',
					domain: 'revoked.example.com'
				})
			],
			total: 1,
			hasMore: false
		});

		render(Page);
		const row = await screen.findByText(/cert\.revoked/);
		expect(row).toBeInTheDocument();
		expect(row.textContent ?? '').toMatch(/révocation OCSP/);
	});

	it('cert events render with method=ACME and srcIp=(interne) for system-emitted rows', async () => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [certFixture()],
			total: 1,
			hasMore: false
		});
		render(Page);
		await screen.findByText(/cert\.obtained/);
		expect(screen.getByText('ACME')).toBeInTheDocument();
		// (interne) marker for system-emitted source IP.
		expect(screen.getByText(/\(interne\)/)).toBeInTheDocument();
	});
});

describe('/logs — level taxonomy mapping for cert events', () => {
	it('cert ERROR rows surface under the warn filter (no Error filter exists)', async () => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				certFixture({
					eventType: 'cert_failed',
					level: 'ERROR',
					domain: 'broken.example.com',
					error: 'simulated failure'
				})
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		await screen.findByText(/cert\.failed/);

		// Click the "Warn" segmented button.
		const warnBtn = screen.getByRole('button', { name: /^warn$/i });
		await userEvent.click(warnBtn);

		// Row still visible after filter — cert ERROR is
		// pragmatically mapped to 'warn' per the LevelTag
		// union (no 'error' value exists today).
		expect(screen.getByText(/cert\.failed/)).toBeInTheDocument();
	});

	it('cert INFO rows surface under the info filter', async () => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				certFixture({
					eventType: 'cert_obtained',
					level: 'INFO',
					domain: 'good.example.com'
				})
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		await screen.findByText(/cert\.obtained/);

		const infoBtn = screen.getByRole('button', { name: /^info$/i });
		await userEvent.click(infoBtn);

		expect(screen.getByText(/cert\.obtained/)).toBeInTheDocument();
	});

	it('cert rows hidden under the block filter (no cert events are HTTP blocks)', async () => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				certFixture({
					eventType: 'cert_obtained',
					level: 'INFO'
				}),
				certFixture({
					eventType: 'cert_failed',
					level: 'ERROR',
					domain: 'bad.example.com',
					error: 'boom',
					timestamp: isoOffset(-60)
				})
			],
			total: 2,
			hasMore: false
		});
		render(Page);
		await screen.findByText(/cert\.obtained/);

		const blockBtn = screen.getByRole('button', { name: /^block$/i });
		await userEvent.click(blockBtn);

		expect(screen.queryByText(/cert\.obtained/)).not.toBeInTheDocument();
		expect(screen.queryByText(/cert\.failed/)).not.toBeInTheDocument();
	});
});

describe('/logs — search across cert content', () => {
	beforeEach(() => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				certFixture({
					eventType: 'cert_obtained',
					domain: 'foo.example.com',
					issuer: "Let's Encrypt",
					challenge: 'DNS-01'
				}),
				certFixture({
					eventType: 'cert_failed',
					level: 'ERROR',
					domain: 'broken.test',
					error: 'DNS lookup failed',
					timestamp: isoOffset(-30)
				}),
				certFixture({
					eventType: 'cert_obtained',
					domain: 'bar.example.com',
					issuer: 'ZeroSSL',
					timestamp: isoOffset(-60)
				})
			],
			total: 3,
			hasMore: false
		});
	});

	it('search "cert" surfaces all 3 cert rows via the detail field', async () => {
		render(Page);
		await screen.findAllByText(/cert\./);
		const searchInput = screen.getByLabelText('Filter events');
		await userEvent.type(searchInput, 'cert');

		// All 3 cert rows visible (detail contains "cert.").
		expect(screen.getAllByText(/cert\.obtained/).length).toBe(2);
		expect(screen.getAllByText(/cert\.failed/).length).toBe(1);
	});

	it('search "Let\'s Encrypt" matches only Let\'s Encrypt-issued rows', async () => {
		render(Page);
		await screen.findAllByText(/cert\./);
		const searchInput = screen.getByLabelText('Filter events');
		await userEvent.type(searchInput, "Let's Encrypt");

		// Only foo.example.com (LE-issued) survives.
		expect(screen.getByText(/foo\.example\.com/)).toBeInTheDocument();
		expect(screen.queryByText(/bar\.example\.com/)).not.toBeInTheDocument();
		// broken.test has no issuer (Failed events) so the
		// search "let's encrypt" excludes it.
		expect(screen.queryByText(/broken\.test/)).not.toBeInTheDocument();
	});

	it('search by domain string filters cert rows by path column', async () => {
		render(Page);
		await screen.findAllByText(/cert\./);
		const searchInput = screen.getByLabelText('Filter events');
		await userEvent.type(searchInput, 'foo.example');

		expect(screen.getByText(/foo\.example\.com/)).toBeInTheDocument();
		expect(screen.queryByText(/bar\.example\.com/)).not.toBeInTheDocument();
		expect(screen.queryByText(/broken\.test/)).not.toBeInTheDocument();
	});

	it('search by issuer "ZeroSSL" matches the ZeroSSL-issued row', async () => {
		render(Page);
		await screen.findAllByText(/cert\./);
		const searchInput = screen.getByLabelText('Filter events');
		await userEvent.type(searchInput, 'ZeroSSL');

		expect(screen.getByText(/bar\.example\.com/)).toBeInTheDocument();
		expect(screen.queryByText(/foo\.example\.com/)).not.toBeInTheDocument();
	});
});

describe('/logs — multi-source merge + cert source resilience', () => {
	it('merges cert events alongside WAF rows, sorted ts-desc', async () => {
		const wafTs = isoOffset(-120);
		const certTs = isoOffset(0); // most recent
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 1,
					ts: wafTs,
					routeId: 'r-1',
					ruleId: '942100',
					category: 'SQLi',
					severity: 4,
					srcIp: '1.2.3.4',
					requestMethod: 'GET',
					requestPath: '/?id=1',
					payloadSample: 'id=1',
					action: 'BLOCK',
					statusCode: 403
				} satisfies WafEvent
			]
		});
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [certFixture({ timestamp: certTs })],
			total: 1,
			hasMore: false
		});

		render(Page);
		// Both rows visible: cert (ts=NOW) + WAF (ts=NOW-2m).
		// The cert row sits above the WAF row in the DOM.
		await screen.findByText(/cert\.obtained/);
		expect(screen.getByText(/cert\.obtained/)).toBeInTheDocument();
		expect(screen.getByText(/WAF rule 942100/)).toBeInTheDocument();
	});

	it('cert-events rejection does NOT break the other sources', async () => {
		// fetchCertEvents throws; WAF still returns a row.
		securityMock.fetchCertEvents.mockRejectedValue(
			new Error('simulated 503 from /observability/cert-events')
		);
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 1,
					ts: isoOffset(0),
					routeId: 'r-1',
					ruleId: '941100',
					category: 'XSS',
					severity: 3,
					srcIp: '5.6.7.8',
					requestMethod: 'POST',
					requestPath: '/search',
					payloadSample: '<script>',
					action: 'BLOCK',
					statusCode: 403
				} satisfies WafEvent
			]
		});

		render(Page);
		// WAF row renders despite the cert source failing —
		// Promise.allSettled isolates failures.
		expect(await screen.findByText(/WAF rule 941100/)).toBeInTheDocument();
		// No cert rows visible.
		expect(screen.queryByText(/cert\.obtained/)).not.toBeInTheDocument();
	});

	it('cert-events degraded response (degraded=true, empty events) renders without crash', async () => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [],
			total: 0,
			hasMore: false,
			degraded: true
		});
		// Add a throttle row so the page has SOMETHING to render
		// once the cert source comes back empty.
		securityMock.fetchThrottleEvents.mockResolvedValue({
			events: [
				{
					id: 99,
					ts: isoOffset(0),
					tier: 1,
					srcIp: '9.9.9.9',
					attemptedUsername: 'admin',
					blockedUntil: isoOffset(900),
					blockDurationSeconds: 900
				} satisfies ThrottleEvent
			]
		});

		render(Page);
		// Throttle row renders.
		expect(await screen.findByText(/Rate-limit tier 1/)).toBeInTheDocument();
		// No cert rows.
		expect(screen.queryByText(/cert\.obtained/)).not.toBeInTheDocument();
		expect(screen.queryByText(/cert\.failed/)).not.toBeInTheDocument();
	});

	it('merge order is purely ts-desc — most recent at top regardless of source', async () => {
		// Cert at ts=NOW-30s, WAF at ts=NOW. WAF should sort
		// above cert.
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 1,
					ts: isoOffset(0),
					routeId: 'r-1',
					ruleId: '942999',
					category: 'OTHER',
					severity: 4,
					srcIp: '1.2.3.4',
					requestMethod: 'GET',
					requestPath: '/abuse',
					payloadSample: '',
					action: 'BLOCK',
					statusCode: 403
				} satisfies WafEvent
			]
		});
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [certFixture({ timestamp: isoOffset(-30) })],
			total: 1,
			hasMore: false
		});

		render(Page);
		await screen.findByText(/942999/);
		// Both rows visible.
		expect(screen.getByText(/WAF rule 942999/)).toBeInTheDocument();
		expect(screen.getByText(/cert\.obtained/)).toBeInTheDocument();
	});
});

describe('/logs — W.bugfix Fix #1 mode-aware WAF labels', () => {
	it('renders a DETECT-mode WAF row with the DETECT level + "—" status', async () => {
		// Pre-fix every WAF row rendered as level="block" + code="403"
		// regardless of what the WAF actually did. Operators in detect
		// mode saw "BLOCK 403" entries while their requests passed
		// through the upstream unimpeded — the source of the original
		// false-positive bug report. Post-fix the row renders with
		// the DETECT pill + "—" for the code (the WAF doesn't capture
		// the upstream's actual status at callback time).
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 1,
					ts: isoOffset(0),
					routeId: 'r-detect',
					ruleId: '920420',
					category: 'PROTOCOL',
					severity: 3,
					srcIp: '203.0.113.5',
					requestMethod: 'GET',
					requestPath: '/auth/login_flow',
					payloadSample: 'User-Agent: shellshock-probe',
					action: 'DETECT',
					statusCode: 0
				} satisfies WafEvent
			]
		});

		render(Page);
		// Detail still renders the rule + category.
		await screen.findByText(/WAF rule 920420/);
		// Level pill says DETECT, not BLOCK.
		expect(screen.getByText('DETECT')).toBeInTheDocument();
		expect(screen.queryByText('BLOCK')).not.toBeInTheDocument();
		// Status column renders "—" instead of "403".
		expect(screen.getByText('—')).toBeInTheDocument();
		expect(screen.queryByText('403')).not.toBeInTheDocument();
	});

	it('renders a BLOCK-mode WAF row with the BLOCK level + 403 status', async () => {
		// Symmetric to the DETECT case. Pin the post-fix contract
		// for block-mode rows so a future regression to "always
		// detect" or "always block" is caught.
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 2,
					ts: isoOffset(0),
					routeId: 'r-block',
					ruleId: '942100',
					category: 'SQLi',
					severity: 2,
					srcIp: '203.0.113.5',
					requestMethod: 'POST',
					requestPath: '/api/search',
					payloadSample: "' OR 1=1 --",
					action: 'BLOCK',
					statusCode: 403
				} satisfies WafEvent
			]
		});

		render(Page);
		await screen.findByText(/WAF rule 942100/);
		expect(screen.getByText('BLOCK')).toBeInTheDocument();
		expect(screen.getByText('403')).toBeInTheDocument();
	});
});

describe('/logs — existing 3-source aggregation still works (regression)', () => {
	it('renders a WAF + throttle + auth row alongside cert events', async () => {
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 1,
					ts: isoOffset(0),
					routeId: 'r-1',
					ruleId: '942100',
					category: 'SQLi',
					severity: 4,
					srcIp: '1.2.3.4',
					requestMethod: 'GET',
					requestPath: '/?id=1',
					payloadSample: '',
					action: 'BLOCK',
					statusCode: 403
				} satisfies WafEvent
			]
		});
		securityMock.fetchThrottleEvents.mockResolvedValue({
			events: [
				{
					id: 2,
					ts: isoOffset(-10),
					tier: 2,
					srcIp: '5.6.7.8',
					attemptedUsername: 'root',
					blockedUntil: isoOffset(3590),
					blockDurationSeconds: 3600
				} satisfies ThrottleEvent
			]
		});
		securityMock.fetchAuthFailures.mockResolvedValue({
			window: '24h',
			timeseries: [],
			recent: [
				{
					ts: isoOffset(-20),
					action: 'login_failure',
					username: 'tester',
					srcIp: '7.7.7.7',
					message: 'bad password'
				} satisfies AuthFailureRecentEvent
			]
		});
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [certFixture({ timestamp: isoOffset(-30) })],
			total: 1,
			hasMore: false
		});

		render(Page);
		await screen.findByText(/WAF rule 942100/);
		// All 4 sources represented in the merged table.
		expect(screen.getByText(/WAF rule 942100/)).toBeInTheDocument();
		expect(screen.getByText(/Rate-limit tier 2/)).toBeInTheDocument();
		expect(screen.getByText(/login_failure/)).toBeInTheDocument();
		expect(screen.getByText(/cert\.obtained/)).toBeInTheDocument();
	});
});

describe('/logs — duplicate-tuple regression (Svelte each_key_duplicate)', () => {
	// Operator-reported regression: the page threw Svelte's
	// each_key_duplicate when two cert events with the same
	// (timestamp, domain, eventType) tuple — or two auth
	// failures with the same (ts, srcIp, username) — landed
	// in the same fetch. Burst login retries hit this
	// trivially (5 failures/second from the same IP at the
	// same username), as do certmagic OBTAIN+FAILED races.
	// Fix: append a source-local array index to the key so
	// the natural-tuple prefix stays stable across polls but
	// uniqueness is guaranteed within a single batch.

	it('renders two cert events sharing (timestamp, domain, eventType) without throwing', async () => {
		const sharedTs = isoOffset(-1);
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				certFixture({
					timestamp: sharedTs,
					domain: 'example.com',
					eventType: 'cert_failed',
					level: 'ERROR',
					error: 'first failure'
				}),
				certFixture({
					timestamp: sharedTs,
					domain: 'example.com',
					eventType: 'cert_failed',
					level: 'ERROR',
					error: 'second failure (same second, same domain)'
				})
			],
			total: 2,
			hasMore: false
		});

		render(Page);
		// Both rows must mount — a duplicate-key throw would
		// either render nothing (boot crashed) or render only
		// one row (Svelte silently drops the dup before HMR).
		await screen.findByText(/first failure/);
		expect(screen.getByText(/first failure/)).toBeInTheDocument();
		expect(screen.getByText(/second failure/)).toBeInTheDocument();
	});

	it('renders two auth failures sharing (ts, srcIp, username) without throwing', async () => {
		const sharedTs = isoOffset(-1);
		securityMock.fetchAuthFailures.mockResolvedValue({
			window: '24h',
			timeseries: [],
			recent: [
				{
					ts: sharedTs,
					action: 'login_failure',
					username: 'admin',
					srcIp: '203.0.113.42',
					message: 'wrong password'
				} satisfies AuthFailureRecentEvent,
				{
					ts: sharedTs,
					action: 'login_failure',
					username: 'admin',
					srcIp: '203.0.113.42',
					message: 'wrong password (retry)'
				} satisfies AuthFailureRecentEvent
			]
		});

		render(Page);
		// Two distinct rows from the same (ts, srcIp, username)
		// tuple must both mount. The message column carries
		// the disambiguator that lets us assert on both.
		await screen.findByText(/wrong password \(retry\)/);
		expect(screen.getByText(/wrong password \(retry\)/)).toBeInTheDocument();
		// The first row's message is "wrong password" — used
		// as a substring it would match the retry row too,
		// so use a stricter regex that excludes the suffix.
		expect(screen.getByText(/wrong password$/)).toBeInTheDocument();
	});
});

describe('/logs — W.5 country-block source (W.7 follow-up: humanized + host-resolved)', () => {
	it('renders a country-block row with COUNTRY pill + status + humanized French detail + host badge', async () => {
		// W.5 introduced the country-block row; W.7 follow-
		// up replaced the raw "deny-deny-match" detail with
		// the humanized "pays interdit" + routes the host
		// badge through <RouteHost> resolving routeId →
		// hostname via listRoutes(). Both changes are
		// asserted here; the W.7-follow-up describe block
		// below adds the fallback + WAF coverage tests.
		clientMock.listRoutes.mockResolvedValue([
			{ id: 'route-uuid-1', host: 'ha.example.test' }
		]);
		securityMock.fetchCountryBlockEvents.mockResolvedValue({
			events: [
				{
					id: 7,
					ts: isoOffset(0),
					routeId: 'route-uuid-1',
					srcIp: '203.0.113.5',
					country: 'RU',
					mode: 'deny',
					statusCode: 451,
					reason: 'deny-match'
				}
			],
			total: 1,
			hasMore: false
		});

		render(Page);
		// Host badge replaces the raw UUID — operator sees
		// the friendly hostname.
		await screen.findByText('ha.example.test');
		// Pill says COUNTRY (not BLOCK, which is the WAF label).
		expect(screen.getByText('COUNTRY')).toBeInTheDocument();
		// Status code from the persisted row, not hardcoded.
		expect(screen.getByText('451')).toBeInTheDocument();
		// Humanized French detail string (W.7 follow-up).
		expect(screen.getByText(/RU · pays interdit/)).toBeInTheDocument();
		// Raw "deny-deny-match" must NOT be visible body text.
		expect(
			screen.queryByText(/deny-deny-match/)
		).not.toBeInTheDocument();
		// Source IP from the persisted row.
		expect(screen.getByText('203.0.113.5')).toBeInTheDocument();
	});
});

describe('/logs — W.7 follow-up: humanize reason + host resolution', () => {
	it('allow-miss → "pays non autorisé"', async () => {
		clientMock.listRoutes.mockResolvedValue([
			{ id: 'route-uuid-allow', host: 'app.example.test' }
		]);
		securityMock.fetchCountryBlockEvents.mockResolvedValue({
			events: [
				{
					id: 8,
					ts: isoOffset(0),
					routeId: 'route-uuid-allow',
					srcIp: '203.0.113.6',
					country: 'IN',
					mode: 'allow',
					statusCode: 403,
					reason: 'allow-miss'
				}
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		await screen.findByText('app.example.test');
		expect(screen.getByText(/IN · pays non autorisé/)).toBeInTheDocument();
	});

	it('raw reason stays in title tooltip on the detail span', async () => {
		clientMock.listRoutes.mockResolvedValue([
			{ id: 'route-uuid-1', host: 'ha.example.test' }
		]);
		securityMock.fetchCountryBlockEvents.mockResolvedValue({
			events: [
				{
					id: 9,
					ts: isoOffset(0),
					routeId: 'route-uuid-1',
					srcIp: '203.0.113.5',
					country: 'RU',
					mode: 'deny',
					statusCode: 403,
					reason: 'deny-match'
				}
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		const detail = await screen.findByText(/RU · pays interdit/);
		// title="" carries the raw mode-reason for
		// forensic ops that grep journalctl by code.
		expect(detail).toHaveAttribute('title', 'deny-match');
	});

	it('falls back to truncated UUID when route was deleted', async () => {
		// listRoutes returns an empty list — the routeId
		// in the event row is "deleted" from the operator's
		// perspective. <RouteHost> should render a
		// truncated UUID + the full UUID as the title.
		clientMock.listRoutes.mockResolvedValue([]);
		securityMock.fetchCountryBlockEvents.mockResolvedValue({
			events: [
				{
					id: 10,
					ts: isoOffset(0),
					routeId: 'gone-uuid-xxxxxxxx-yyyyyy',
					srcIp: '203.0.113.7',
					country: 'BR',
					mode: 'deny',
					statusCode: 403,
					reason: 'deny-match'
				}
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		// Truncated UUID renders: first 8 chars + ellipsis.
		const host = await screen.findByTestId('route-host');
		expect(host.textContent?.trim()).toBe('gone-uui…');
		expect(host).toHaveAttribute('title', 'gone-uuid-xxxxxxxx-yyyyyy');
		// Fallback CSS hook present so styling can pick
		// up the muted variant.
		expect(host).toHaveClass('route-host--fallback');
	});

	it('WAF events also render the host badge (shared component)', async () => {
		// The same <RouteHost> resolver runs across per-
		// route log sources. WAF events carry routeId
		// already; W.7 follow-up wires it through the
		// mapWaf path so operators see "ha.example.test"
		// instead of grep'ing the UUID.
		clientMock.listRoutes.mockResolvedValue([
			{ id: 'route-waf-1', host: 'waf.example.test' }
		]);
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 11,
					ts: isoOffset(0),
					routeId: 'route-waf-1',
					ruleId: '942100',
					category: 'SQLi',
					severity: 4,
					srcIp: '1.2.3.4',
					requestMethod: 'GET',
					requestPath: '/?id=1',
					payloadSample: '',
					action: 'BLOCK',
					statusCode: 403
				}
			]
		});
		render(Page);
		await screen.findByText('waf.example.test');
		// The technical request path is still visible — host
		// badge + path render side-by-side for WAF rows.
		expect(screen.getByText(/\/\?id=1/)).toBeInTheDocument();
	});

	it('routeMap refresh failures do not crash the page', async () => {
		// Routes API hiccup → routeMap stays empty →
		// rows fall back gracefully. Page must render
		// without throwing.
		clientMock.listRoutes.mockRejectedValue(new Error('boom'));
		securityMock.fetchCountryBlockEvents.mockResolvedValue({
			events: [
				{
					id: 12,
					ts: isoOffset(0),
					routeId: 'route-uuid-1',
					srcIp: '203.0.113.5',
					country: 'RU',
					mode: 'deny',
					statusCode: 403,
					reason: 'deny-match'
				}
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		// Row still mounts via the fallback path.
		await screen.findByText(/RU · pays interdit/);
		expect(screen.getByTestId('route-host')).toHaveClass(
			'route-host--fallback'
		);
	});
});
