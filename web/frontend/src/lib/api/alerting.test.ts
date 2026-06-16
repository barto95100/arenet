// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, beforeEach, vi } from 'vitest';

const requestMock = vi.fn();
vi.mock('./client', () => ({ request: requestMock }));

const {
	alertingApi,
	severityToken,
	severityLabelFR,
	severityBadgeVariant,
	severityTooltip,
	SEVERITY_TOKENS
} = await import('./alerting');

beforeEach(() => {
	requestMock.mockReset();
	requestMock.mockResolvedValue({ events: [], nextCursor: '' });
});

describe('alertingApi.listAlertEvents: query encoding', () => {
	it('hits /observability/alert-events without query string when filter is empty', async () => {
		await alertingApi.listAlertEvents({});
		expect(requestMock).toHaveBeenCalledWith('GET', '/observability/alert-events');
	});

	it('translates camelCase fields to snake_case URL params', async () => {
		await alertingApi.listAlertEvents({
			ruleId: 'rule-1',
			severity: 2,
			category: 'waf',
			since: '2026-06-15T00:00:00Z',
			until: '2026-06-16T00:00:00Z',
			limit: 25,
			cursor: 'opaque-token'
		});
		expect(requestMock).toHaveBeenCalledTimes(1);
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('rule_id=rule-1');
		expect(path).toContain('severity=2');
		expect(path).toContain('category=waf');
		expect(path).toContain('since=2026-06-15T00%3A00%3A00Z');
		expect(path).toContain('until=2026-06-16T00%3A00%3A00Z');
		expect(path).toContain('limit=25');
		expect(path).toContain('cursor=opaque-token');
	});

	it('passes severity=0 (info) — pointer-vs-unset distinction preserved on the wire', async () => {
		await alertingApi.listAlertEvents({ severity: 0 });
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('severity=0');
	});

	it('omits severity entirely when undefined', async () => {
		await alertingApi.listAlertEvents({ ruleId: 'rule-1' });
		const [, path] = requestMock.mock.calls[0];
		expect(path).not.toContain('severity=');
	});
});

describe('alertingApi: channel + rule CRUD URL shape', () => {
	it('listChannels hits /settings/alerting/channels', async () => {
		await alertingApi.listChannels();
		expect(requestMock).toHaveBeenCalledWith('GET', '/settings/alerting/channels');
	});

	it('testChannel hits /settings/alerting/channels/{id}/test', async () => {
		await alertingApi.testChannel('ch-123');
		expect(requestMock).toHaveBeenCalledWith('POST', '/settings/alerting/channels/ch-123/test');
	});

	it('listRules hits /settings/alerting/rules', async () => {
		await alertingApi.listRules();
		expect(requestMock).toHaveBeenCalledWith('GET', '/settings/alerting/rules');
	});

	it('testRule hits /settings/alerting/rules/{id}/test', async () => {
		await alertingApi.testRule('rule-xyz');
		expect(requestMock).toHaveBeenCalledWith('POST', '/settings/alerting/rules/rule-xyz/test');
	});
});

describe('severity helpers', () => {
	it('maps int → wire token', () => {
		expect(severityToken(0)).toBe('info');
		expect(severityToken(1)).toBe('warning');
		expect(severityToken(2)).toBe('critical');
		expect(severityToken(3)).toBe('emergency');
		expect(severityToken(-1)).toBe('unknown');
		expect(severityToken(4)).toBe('unknown');
	});

	it('maps int → French label', () => {
		expect(severityLabelFR(0)).toBe('Info');
		expect(severityLabelFR(1)).toBe('Avertissement');
		expect(severityLabelFR(2)).toBe('Critique');
		expect(severityLabelFR(3)).toBe('Urgence');
		expect(severityLabelFR(99)).toBe('Inconnu');
	});

	it('maps int → Badge variant', () => {
		expect(severityBadgeVariant(0)).toBe('status-info');
		expect(severityBadgeVariant(1)).toBe('status-warn');
		expect(severityBadgeVariant(2)).toBe('status-down');
		expect(severityBadgeVariant(3)).toBe('status-down');
		expect(severityBadgeVariant(99)).toBe('neutral');
	});

	it('exposes SEVERITY_TOKENS in the correct order', () => {
		expect(SEVERITY_TOKENS).toEqual(['info', 'warning', 'critical', 'emergency']);
	});

	// AL.5 — tooltip mapping pinned so the operator-facing
	// hover always surfaces the correct level + int + role
	// description (matters when reading the API directly).
	it('returns a level-prefixed tooltip for each valid severity', () => {
		expect(severityTooltip(0)).toMatch(/Info \(niveau 0\)/);
		expect(severityTooltip(1)).toMatch(/Avertissement \(niveau 1\)/);
		expect(severityTooltip(2)).toMatch(/Critique \(niveau 2\)/);
		expect(severityTooltip(3)).toMatch(/Urgence \(niveau 3\)/);
	});

	it('returns an out-of-range tooltip for unknown severities', () => {
		expect(severityTooltip(-1)).toMatch(/Inconnu/);
		expect(severityTooltip(99)).toMatch(/Inconnu/);
	});
});
