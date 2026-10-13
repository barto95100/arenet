// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { splitApiErrorCode, resolveApiError } from './api-error-code';

describe('splitApiErrorCode', () => {
	it('splits a code with an English detail', () => {
		expect(
			splitApiErrorCode('key_does_not_match_cert: crypto/tls: private key does not match')
		).toEqual({
			code: 'key_does_not_match_cert',
			detail: 'crypto/tls: private key does not match'
		});
	});

	it('reads a bare code', () => {
		// cn_required, cert_required and invalid_country all arrive
		// with no detail at all.
		expect(splitApiErrorCode('invalid_country')).toEqual({
			code: 'invalid_country',
			detail: ''
		});
	});

	it('refuses to read a sentence as a code', () => {
		// Otherwise "Network error" or a proxy's HTML would be treated
		// as a code and looked up, and a near-miss could resolve to the
		// wrong translated sentence.
		const msg = 'The certificate could not be stored: disk full';
		expect(splitApiErrorCode(msg)).toEqual({ code: null, detail: msg });
	});

	it('rejects a code that is not lower_snake', () => {
		expect(splitApiErrorCode('Invalid_Country: nope').code).toBeNull();
		expect(splitApiErrorCode('503: upstream').code).toBeNull();
	});
});

describe('resolveApiError', () => {
	const keys = { invalid_country: 'errors.invalidCountry' };
	const t = (k: string) => `translated(${k})`;

	it('translates a known code', () => {
		expect(resolveApiError('invalid_country', keys, t)).toEqual({
			message: 'translated(errors.invalidCountry)',
			code: 'invalid_country'
		});
	});

	it('shows an unmapped code as it arrived, rather than hiding it', () => {
		expect(resolveApiError('some_new_code: with detail', keys, t)).toEqual({
			message: 'some_new_code: with detail',
			code: null
		});
	});

	it('leaves a plain message alone', () => {
		expect(resolveApiError('Network error', keys, t)).toEqual({
			message: 'Network error',
			code: null
		});
	});
});
