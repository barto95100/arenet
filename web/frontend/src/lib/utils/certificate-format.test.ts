// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Unit tests for the Step T T.4 certificate-format helpers. The
// status → badge variant mapping is the AC #10 LOCKED contract;
// the labels are part of the spec vocabulary. Both pinned here.

import { describe, it, expect } from 'vitest';
import type { Certificate } from '$lib/api/types';
import {
	certificateSourceLabel,
	certificateStatusLabel,
	certificateStatusToBadgeVariant,
	daysUntilExpiry,
	dominantIssuer,
	inferChallengeLabel,
	isExpiringSoon,
	RENEWAL_WINDOW_DAYS,
} from './certificate-format';

const NOW = new Date('2026-06-05T12:00:00Z');

function mkCert(overrides: Partial<Certificate>): Certificate {
	return {
		domain: 'x.example.com',
		sanList: ['x.example.com'],
		issuer: "Let's Encrypt",
		notBefore: new Date(NOW.getTime() - 30 * 86400000).toISOString(),
		notAfter: new Date(NOW.getTime() + 60 * 86400000).toISOString(),
		status: 'VALID',
		source: 'specific',
		...overrides,
	};
}

describe('certificateStatusToBadgeVariant', () => {
	it('maps VALID to status-up', () => {
		expect(certificateStatusToBadgeVariant('VALID')).toBe('status-up');
	});
	it('maps RENEWAL_PENDING to status-warn', () => {
		expect(certificateStatusToBadgeVariant('RENEWAL_PENDING')).toBe('status-warn');
	});
	it('maps EXPIRED to status-down', () => {
		expect(certificateStatusToBadgeVariant('EXPIRED')).toBe('status-down');
	});
	it('maps OBTAIN_FAILED to status-down', () => {
		expect(certificateStatusToBadgeVariant('OBTAIN_FAILED')).toBe('status-down');
	});
	it('maps UNKNOWN to neutral', () => {
		expect(certificateStatusToBadgeVariant('UNKNOWN')).toBe('neutral');
	});
});

describe('certificateStatusLabel', () => {
	it('maps each status to the French operator label', () => {
		expect(certificateStatusLabel('VALID')).toBe('VALIDE');
		expect(certificateStatusLabel('RENEWAL_PENDING')).toBe('RENOUV. AUTO');
		expect(certificateStatusLabel('EXPIRED')).toBe('EXPIRÉ');
		expect(certificateStatusLabel('OBTAIN_FAILED')).toBe('ÉCHEC');
		expect(certificateStatusLabel('UNKNOWN')).toBe('—');
	});
});

describe('certificateSourceLabel', () => {
	it('maps each source to the French label', () => {
		expect(certificateSourceLabel('wildcard')).toBe('wildcard');
		expect(certificateSourceLabel('apex')).toBe('apex');
		expect(certificateSourceLabel('specific')).toBe('spécifique');
	});
});

describe('inferChallengeLabel', () => {
	it('returns DNS-01 for wildcards (the only path certmagic uses)', () => {
		expect(inferChallengeLabel('wildcard')).toBe('DNS-01');
	});
	it('returns HTTP-01 for specific and apex (the default)', () => {
		expect(inferChallengeLabel('specific')).toBe('HTTP-01');
		expect(inferChallengeLabel('apex')).toBe('HTTP-01');
	});
});

describe('daysUntilExpiry', () => {
	it('returns positive whole days for future expiries', () => {
		const c = mkCert({
			notAfter: new Date(NOW.getTime() + 10 * 86400000).toISOString(),
		});
		expect(daysUntilExpiry(c, NOW)).toBe(10);
	});
	it('returns negative whole days for past expiries', () => {
		const c = mkCert({
			notAfter: new Date(NOW.getTime() - 5 * 86400000).toISOString(),
		});
		expect(daysUntilExpiry(c, NOW)).toBe(-5);
	});
	it('returns 0 when notAfter is malformed', () => {
		const c = mkCert({ notAfter: 'not-a-date' });
		expect(daysUntilExpiry(c, NOW)).toBe(0);
	});
});

describe('isExpiringSoon', () => {
	it('flags certs inside the renewal window', () => {
		const c = mkCert({
			notAfter: new Date(NOW.getTime() + 15 * 86400000).toISOString(),
		});
		expect(isExpiringSoon(c, NOW)).toBe(true);
	});
	it('does NOT flag certs beyond the renewal window', () => {
		const c = mkCert({
			notAfter: new Date(NOW.getTime() + (RENEWAL_WINDOW_DAYS + 5) * 86400000).toISOString(),
		});
		expect(isExpiringSoon(c, NOW)).toBe(false);
	});
	it('flags already-expired certs (operator wants to see them too)', () => {
		const c = mkCert({
			notAfter: new Date(NOW.getTime() - 3 * 86400000).toISOString(),
		});
		expect(isExpiringSoon(c, NOW)).toBe(true);
	});
});

describe('dominantIssuer', () => {
	it('returns the most common issuer string', () => {
		const certs: Certificate[] = [
			mkCert({ issuer: "Let's Encrypt" }),
			mkCert({ issuer: "Let's Encrypt" }),
			mkCert({ issuer: 'ZeroSSL' }),
		];
		expect(dominantIssuer(certs)).toBe("Let's Encrypt");
	});
	it('returns — for an empty list', () => {
		expect(dominantIssuer([])).toBe('—');
	});
	it('ties break alphabetically (deterministic)', () => {
		const certs: Certificate[] = [
			mkCert({ issuer: 'B-CA' }),
			mkCert({ issuer: 'A-CA' }),
		];
		expect(dominantIssuer(certs)).toBe('A-CA');
	});
});
