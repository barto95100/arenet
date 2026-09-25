// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.46 — server refusals in the operator's language.
//
// What matters here is the fallback as much as the translation: an
// unknown code must show the server's readable sentence, never a bare
// i18n key. That is what makes the catalogue safe to grow one message
// at a time.

import { describe, it, expect, beforeEach } from 'vitest';
import { ApiError } from './types';
import { serverErrorMessage } from './server-errors';
import { language } from '$lib/stores/language.svelte';

function refusal(code: string | undefined, params?: Record<string, unknown>, msg = 'english sentence') {
	return new ApiError(msg, 400, 'validation', undefined, code, params);
}

beforeEach(() => {
	language.current = 'en';
});

describe('serverErrorMessage', () => {
	it('translates a known code and substitutes its parameters', () => {
		const shown = serverErrorMessage(refusal('redirect_self_loop', { host: 'toto.example.com' }));
		expect(shown).toContain('toto.example.com');
		expect(shown).not.toBe('english sentence');
	});

	it('speaks French when French is chosen', () => {
		language.current = 'fr';
		const shown = serverErrorMessage(refusal('redirect_self_loop', { host: 'toto.example.com' }));
		// The French wording, not the English one.
		expect(shown).toMatch(/destination/i);
		expect(shown).toContain('toto.example.com');
	});

	it('falls back to the server sentence for a code it does not know', () => {
		const shown = serverErrorMessage(refusal('something_invented_later', { x: '1' }));
		expect(shown).toBe('english sentence');
		// Never a bare key.
		expect(shown).not.toContain('errors.server');
	});

	it('falls back for a refusal with no code at all', () => {
		expect(serverErrorMessage(refusal(undefined))).toBe('english sentence');
	});

	it('survives something that is not an ApiError', () => {
		expect(serverErrorMessage(new Error('boom'))).toBe('boom');
		expect(serverErrorMessage('plain string')).toBe('plain string');
	});

	it('translates the path-rule uppercase refusal, offering the fix', () => {
		language.current = 'fr';
		const shown = serverErrorMessage(
			refusal('path_rule_uppercase', { path: '/Admin', lower: '/admin' })
		);
		expect(shown).toContain('/Admin');
		expect(shown).toContain('/admin');
		expect(shown).toMatch(/majuscule/i);
	});
});
