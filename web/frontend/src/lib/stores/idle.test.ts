// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

vi.mock('$lib/api/auth', async () => {
	const actual = await vi.importActual<typeof import('$lib/api/auth')>('$lib/api/auth');
	return { ...actual, authApi: {} as Record<string, never> };
});

const { auth } = await import('./auth.svelte');
const { idle, IDLE_TIMEOUT_MS } = await import('./idle.svelte');

beforeEach(() => {
	vi.useFakeTimers();
	auth.user = null;
	auth.state = 'unknown';
});

afterEach(() => {
	idle.stop();
	vi.useRealTimers();
});

describe('IdleStore.reset', () => {
	it('is a no-op when auth.state !== authenticated', () => {
		auth.state = 'anonymous';
		idle.reset();
		// Advance way past the timeout; nothing should happen.
		vi.advanceTimersByTime(IDLE_TIMEOUT_MS + 1000);
		expect(auth.state).toBe('anonymous');
	});

	it('schedules a timer that locks after IDLE_TIMEOUT_MS when authenticated', () => {
		auth.state = 'authenticated';
		idle.reset();
		// Just before the timeout: still authenticated.
		vi.advanceTimersByTime(IDLE_TIMEOUT_MS - 1);
		expect(auth.state).toBe('authenticated');
		// One tick more: setLocked fires.
		vi.advanceTimersByTime(1);
		expect(auth.state).toBe('locked');
	});

	it('reset() restarts the countdown', () => {
		auth.state = 'authenticated';
		idle.reset();
		vi.advanceTimersByTime(IDLE_TIMEOUT_MS - 1000);
		idle.reset(); // restart
		vi.advanceTimersByTime(IDLE_TIMEOUT_MS - 1);
		expect(auth.state).toBe('authenticated');
		vi.advanceTimersByTime(1);
		expect(auth.state).toBe('locked');
	});

	it('stop() cancels the pending timer', () => {
		auth.state = 'authenticated';
		idle.reset();
		idle.stop();
		vi.advanceTimersByTime(IDLE_TIMEOUT_MS + 1000);
		expect(auth.state).toBe('authenticated');
	});

	it('once auth state moves to locked, subsequent reset() is a no-op', () => {
		auth.state = 'authenticated';
		idle.reset();
		vi.advanceTimersByTime(IDLE_TIMEOUT_MS);
		expect(auth.state).toBe('locked');
		// Tampering: someone calls reset while locked. Must NOT
		// re-arm a timer that could transition out of locked.
		idle.reset();
		vi.advanceTimersByTime(IDLE_TIMEOUT_MS + 1000);
		expect(auth.state).toBe('locked');
	});
});

describe('IdleStore.start / stop', () => {
	it('start() arms the timer immediately', () => {
		auth.state = 'authenticated';
		idle.start();
		vi.advanceTimersByTime(IDLE_TIMEOUT_MS);
		expect(auth.state).toBe('locked');
	});

	it('start() then stop() prevents the timer from firing', () => {
		auth.state = 'authenticated';
		idle.start();
		idle.stop();
		vi.advanceTimersByTime(IDLE_TIMEOUT_MS + 1000);
		expect(auth.state).toBe('authenticated');
	});
});
