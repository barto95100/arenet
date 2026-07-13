// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { notificationHref } from './notification-href';
import type { AlertEvent } from '$lib/api/alerting';

function ev(over: Partial<AlertEvent> = {}): AlertEvent {
	return {
		eventId: 'e1', timestamp: '2026-07-13T10:00:00Z', ruleId: 'r1',
		ruleName: 'rule', severity: 0, category: '', subject: 's',
		channelsFired: [], ...over
	};
}

describe('notificationHref', () => {
	it('uses context.url as an external link when present', () => {
		const r = notificationHref(ev({ context: { url: 'https://github.com/x/releases/v1' } }));
		expect(r).toEqual({ href: 'https://github.com/x/releases/v1', external: true });
	});
	it('routes cert events to /certs', () => {
		expect(notificationHref(ev({ category: 'cert_expiry' })).href).toBe('/certs');
	});
	it('routes waf events to /security', () => {
		expect(notificationHref(ev({ category: 'waf' })).href).toBe('/security');
	});
	it('routes update events (no url) to /settings', () => {
		expect(notificationHref(ev({ ruleName: 'update available' })).href).toBe('/settings');
	});
	it('routes system_health events to /', () => {
		expect(notificationHref(ev({ category: 'system_health' })).href).toBe('/');
	});
	it('falls back to /alerting for unknown categories', () => {
		expect(notificationHref(ev({ category: 'mystery' })).href).toBe('/alerting');
	});
	it('internal links are not external', () => {
		expect(notificationHref(ev({ category: 'cert_expiry' })).external).toBe(false);
	});
});
