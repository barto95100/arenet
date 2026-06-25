// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.9.11 i18n Phase 1 — LanguageStore unit tests. Mirror of the
// theme store's behaviour: set/applyLocally/persistLocally/
// reconcileFromServer + revert-on-network-failure.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Mock the authApi module BEFORE importing the store under test —
// otherwise the store grabs the real authApi reference at import
// time and our spy reassignment never lands. Same pattern used by
// every other store test in this codebase.
vi.mock('$lib/api/auth', () => ({
	authApi: {
		setLanguage: vi.fn().mockResolvedValue(undefined)
	}
}));

// Mock toast so failure-revert tests don't depend on the real
// toast container being mounted.
vi.mock('$lib/stores/toast', () => ({
	pushToast: vi.fn()
}));

import { language } from './language.svelte';
import { authApi } from '$lib/api/auth';
import { pushToast } from '$lib/stores/toast';

describe('LanguageStore', () => {
	beforeEach(() => {
		// Reset state between cases — the singleton survives test
		// boundaries in module-cache scope.
		language.applyLocally('en');
		vi.clearAllMocks();
		localStorage.clear();
	});

	afterEach(() => {
		vi.clearAllMocks();
	});

	it('set("fr") updates current, sets html lang, persists localStorage, posts to backend', async () => {
		await language.set('fr');
		expect(language.current).toBe('fr');
		expect(document.documentElement.lang).toBe('fr');
		expect(localStorage.getItem('arenet_language')).toBe('fr');
		expect(authApi.setLanguage).toHaveBeenCalledWith('fr');
	});

	it('set("en") on already-en is a no-op (no network call)', async () => {
		await language.set('en');
		expect(authApi.setLanguage).not.toHaveBeenCalled();
	});

	it('set() reverts on backend failure and toasts in English', async () => {
		vi.mocked(authApi.setLanguage).mockRejectedValueOnce(new Error('500'));
		await expect(language.set('fr')).rejects.toThrow();
		// Reverted: current is still en, dataset lang back to en,
		// localStorage written back to en.
		expect(language.current).toBe('en');
		expect(document.documentElement.lang).toBe('en');
		expect(localStorage.getItem('arenet_language')).toBe('en');
		expect(pushToast).toHaveBeenCalledWith(
			'Failed to save language preference',
			'danger'
		);
	});

	it('reconcileFromServer("fr") swaps silently when server differs', () => {
		expect(language.current).toBe('en');
		language.reconcileFromServer('fr');
		expect(language.current).toBe('fr');
		expect(document.documentElement.lang).toBe('fr');
		// Reconcile MUST NOT POST back to the server — it's a sync,
		// not a write.
		expect(authApi.setLanguage).not.toHaveBeenCalled();
	});

	it('reconcileFromServer("") maps to "en" (pre-v2.9.11 user)', () => {
		language.reconcileFromServer('');
		expect(language.current).toBe('en');
	});

	it('reconcileFromServer("garbage") normalises to "en"', () => {
		language.reconcileFromServer('Spanish');
		expect(language.current).toBe('en');
	});

	it('reconcileFromServer with matching value is a no-op', () => {
		language.reconcileFromServer('en'); // already en
		expect(language.current).toBe('en');
	});

	it('applyLocally("fr") updates without touching network or storage', () => {
		language.applyLocally('fr');
		expect(language.current).toBe('fr');
		expect(document.documentElement.lang).toBe('fr');
		expect(authApi.setLanguage).not.toHaveBeenCalled();
		// localStorage may or may not be empty — applyLocally is the
		// non-persist path. Verify the persist did NOT happen.
		expect(localStorage.getItem('arenet_language')).toBeNull();
	});
});
