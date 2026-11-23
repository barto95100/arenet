// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import {
	parseEntriesText,
	isValidCidrOrIp,
	entriesToText,
	type AllowlistEntry
} from './allowlists';

describe('isValidCidrOrIp', () => {
	it('accepts IPv4, IPv6 and CIDR', () => {
		expect(isValidCidrOrIp('10.0.0.1')).toBe(true);
		expect(isValidCidrOrIp('10.0.0.0/24')).toBe(true);
		expect(isValidCidrOrIp('2001:db8::1')).toBe(true);
		expect(isValidCidrOrIp('2001:db8::/32')).toBe(true);
	});
	it('rejects malformed and out-of-range', () => {
		expect(isValidCidrOrIp('not-an-ip')).toBe(false);
		expect(isValidCidrOrIp('300.1.1.1')).toBe(false);
		expect(isValidCidrOrIp('10.0.0.0/33')).toBe(false);
		expect(isValidCidrOrIp('2001:db8::/129')).toBe(false);
		expect(isValidCidrOrIp('10.0.0.1/-1')).toBe(false);
		expect(isValidCidrOrIp('')).toBe(false);
	});
});

describe('parseEntriesText', () => {
	it('parses one entry per line with optional notes', () => {
		const { entries, invalidLines } = parseEntriesText(
			'10.0.0.0/24 LAN\n203.0.113.9 # VPN gateway\n\n192.168.1.1'
		);
		expect(invalidLines).toEqual([]);
		expect(entries).toEqual<AllowlistEntry[]>([
			{ cidr: '10.0.0.0/24', note: 'LAN' },
			{ cidr: '203.0.113.9', note: 'VPN gateway' },
			{ cidr: '192.168.1.1', note: '' }
		]);
	});
	it('reports invalid lines by 1-based number and skips blanks', () => {
		const { entries, invalidLines } = parseEntriesText('10.0.0.1\nnope\n\n10.0.0.0/99');
		expect(invalidLines).toEqual([2, 4]);
		expect(entries).toEqual<AllowlistEntry[]>([{ cidr: '10.0.0.1', note: '' }]);
	});
});

describe('entriesToText', () => {
	it('round-trips through parseEntriesText', () => {
		const text = '10.0.0.0/24 LAN\n203.0.113.9';
		const { entries } = parseEntriesText(text);
		expect(entriesToText(entries)).toBe('10.0.0.0/24 LAN\n203.0.113.9');
	});
	it('is empty for null', () => {
		expect(entriesToText(null)).toBe('');
	});
});
