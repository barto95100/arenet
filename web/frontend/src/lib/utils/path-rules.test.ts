// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { sanitizePathRules } from './path-rules';
import type { PathRule } from '$lib/api/types';

describe('sanitizePathRules', () => {
	it('drops a rule with no active protection (ipFilter off, no basic auth)', () => {
		// This is the exact operator-reported shape: mode "off" with a
		// residual CIDR and no basicAuth block — the backend 500'd on
		// this before the fix; now it must never even be sent.
		const rules: PathRule[] = [
			{
				pathPrefix: '/metrics-zabbix',
				ipFilter: { mode: 'off', cidrs: ['8.8.8.8'] }
			}
		];
		expect(sanitizePathRules(rules)).toEqual([]);
	});

	it('drops a rule whose basicAuth is present but has an empty username', () => {
		const rules: PathRule[] = [
			{
				pathPrefix: '/empty-toggle',
				basicAuth: { username: '', password: '' },
				ipFilter: { mode: 'off', cidrs: [] }
			}
		];
		expect(sanitizePathRules(rules)).toEqual([]);
	});

	it('keeps a rule with an active ipFilter (allow/deny) and clears nothing', () => {
		const rules: PathRule[] = [
			{ pathPrefix: '/metrics', ipFilter: { mode: 'allow', cidrs: ['192.168.1.5'] } }
		];
		expect(sanitizePathRules(rules)).toEqual([
			{ pathPrefix: '/metrics', ipFilter: { mode: 'allow', cidrs: ['192.168.1.5'] } }
		]);
	});

	it('keeps a rule with configured basic auth (non-empty username)', () => {
		const rules: PathRule[] = [
			{
				pathPrefix: '/docs',
				basicAuth: { username: 'doc', password: 'somePlainPassword' },
				ipFilter: { mode: 'off', cidrs: [] }
			}
		];
		expect(sanitizePathRules(rules)).toEqual([
			{
				pathPrefix: '/docs',
				basicAuth: { username: 'doc', password: 'somePlainPassword' },
				ipFilter: { mode: 'off', cidrs: [] }
			}
		]);
	});

	it('clears cidrs on a kept rule whose ipFilter mode is "off"', () => {
		// A rule kept because of active basic auth, but which also
		// carries a residual (meaningless) CIDR list under mode "off" —
		// must be cleared on the wire.
		const rules: PathRule[] = [
			{
				pathPrefix: '/admin',
				basicAuth: { username: 'admin', password: 'secret' },
				ipFilter: { mode: 'off', cidrs: ['10.0.0.0/8', '8.8.8.8'] }
			}
		];
		expect(sanitizePathRules(rules)).toEqual([
			{
				pathPrefix: '/admin',
				basicAuth: { username: 'admin', password: 'secret' },
				ipFilter: { mode: 'off', cidrs: [] }
			}
		]);
	});

	it('keeps a rule with both active protections untouched', () => {
		const rules: PathRule[] = [
			{
				pathPrefix: '/both',
				basicAuth: { username: 'admin', password: 'secret' },
				ipFilter: { mode: 'deny', cidrs: ['1.2.3.4'] }
			}
		];
		expect(sanitizePathRules(rules)).toEqual(rules);
	});

	it('does not mutate the input array or its elements', () => {
		const rules: PathRule[] = [
			{
				pathPrefix: '/admin',
				basicAuth: { username: 'admin', password: 'secret' },
				ipFilter: { mode: 'off', cidrs: ['8.8.8.8'] }
			}
		];
		const snapshot = JSON.parse(JSON.stringify(rules));
		sanitizePathRules(rules);
		expect(rules).toEqual(snapshot);
	});

	it('returns an empty array for an empty input', () => {
		expect(sanitizePathRules([])).toEqual([]);
	});

	it('drops dead rules while keeping active ones in a mixed list', () => {
		const rules: PathRule[] = [
			{ pathPrefix: '/dead', ipFilter: { mode: 'off', cidrs: ['8.8.8.8'] } },
			{ pathPrefix: '/alive', ipFilter: { mode: 'deny', cidrs: ['1.2.3.4'] } }
		];
		expect(sanitizePathRules(rules)).toEqual([
			{ pathPrefix: '/alive', ipFilter: { mode: 'deny', cidrs: ['1.2.3.4'] } }
		]);
	});

	it('keeps a rule that has ONLY an upstream pool (pure routing)', () => {
		const rules = [
			{ pathPrefix: '/v1', upstreams: [{ url: 'http://a:8080', weight: 1 }], lbPolicy: 'round_robin' as const }
		];
		const out = sanitizePathRules(rules as any);
		expect(out).toHaveLength(1);
		expect(out[0].pathPrefix).toBe('/v1');
	});

	it('drops a rule with an EMPTY upstream pool and no protection', () => {
		const rules = [{ pathPrefix: '/v1', upstreams: [] }];
		const out = sanitizePathRules(rules as any);
		expect(out).toHaveLength(0);
	});

	it('keeps a rule with upstream + off-mode ipFilter and clears its residual cidrs', () => {
		const rules = [
			{ pathPrefix: '/v1', upstreams: [{ url: 'http://a:8080', weight: 1 }], ipFilter: { mode: 'off' as const, cidrs: ['8.8.8.8'] } }
		];
		const out = sanitizePathRules(rules as any);
		expect(out).toHaveLength(1);
		expect(out[0].ipFilter?.cidrs).toEqual([]);
	});
});
