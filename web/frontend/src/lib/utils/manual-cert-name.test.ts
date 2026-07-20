// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { manualCertDisplayName } from './manual-cert-name';
import type { ExternalCertificate } from '$lib/api/types';

function cert(partial: Partial<ExternalCertificate>): ExternalCertificate {
	return {
		id: 'c1',
		name: 'SCCNF',
		description: '',
		certPEM: '',
		chainPEM: '',
		keyPEM: '',
		issuer: '',
		subject: '',
		serialNumber: '',
		keyAlgorithm: 'RSA',
		signatureAlgorithm: 'SHA256-RSA',
		notBefore: '2026-01-01T00:00:00Z',
		notAfter: '2027-01-01T00:00:00Z',
		dnsNames: [],
		createdAt: '2026-01-01T00:00:00Z',
		updatedAt: '2026-01-01T00:00:00Z',
		warnings: [],
		...partial,
	};
}

describe('manualCertDisplayName', () => {
	it('returns undefined for an absent cert_id', () => {
		expect(manualCertDisplayName(undefined, [])).toBeUndefined();
		expect(manualCertDisplayName(null, [])).toBeUndefined();
		expect(manualCertDisplayName('', [])).toBeUndefined();
	});

	it('returns undefined when the cert_id is not in the list (orphaned)', () => {
		expect(manualCertDisplayName('missing', [cert({ id: 'c1' })])).toBeUndefined();
	});

	it('returns the cert name for a non-wildcard cert', () => {
		expect(
			manualCertDisplayName('c1', [cert({ id: 'c1', name: 'SCCNF', dnsNames: ['app.corp.local'] })])
		).toBe('SCCNF');
	});

	it('returns the "*.apex" SAN when the cert is a wildcard', () => {
		expect(
			manualCertDisplayName('c1', [
				cert({ id: 'c1', name: 'Wildcard prod', dnsNames: ['*.worldgeekwide.fr'] }),
			])
		).toBe('*.worldgeekwide.fr');
	});

	it('prefers the wildcard SAN even when other SANs are present', () => {
		expect(
			manualCertDisplayName('c1', [
				cert({ id: 'c1', name: 'Multi', dnsNames: ['app.corp.local', '*.worldgeekwide.fr'] }),
			])
		).toBe('*.worldgeekwide.fr');
	});

	it('ignores a bare "*." with no apex (defensive)', () => {
		expect(
			manualCertDisplayName('c1', [cert({ id: 'c1', name: 'Odd', dnsNames: ['*.'] })])
		).toBe('Odd');
	});
});
