// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Idle store: client-side counterpart of the 15-minute server-side
// inactivity check (spec §6.3). Its purpose is to trigger the lock
// screen client-side BEFORE the next API request gets a 403, providing
// immediate UX feedback.
//
// Defense in depth: this timer is the UX layer. The server's
// LastActivity check (in hard-auth middleware) is the security layer.
// If a user disables JavaScript or tampers with the timer, the server
// still enforces the lock at the next API call.

import { auth } from './auth.svelte';

export const IDLE_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes

class IdleStore {
	private timerId: ReturnType<typeof setTimeout> | null = null;
	lastReset = $state(Date.now());

	start(): void {
		this.reset();
		if (typeof document !== 'undefined') {
			document.addEventListener('visibilitychange', this.onVisibilityChange);
		}
	}

	stop(): void {
		if (this.timerId !== null) {
			clearTimeout(this.timerId);
			this.timerId = null;
		}
		if (typeof document !== 'undefined') {
			document.removeEventListener('visibilitychange', this.onVisibilityChange);
		}
	}

	/**
	 * Reset the idle timer. Called by the API client on every successful
	 * server interaction (decision Q3bis: activity = server action only,
	 * NOT mouse/keyboard events).
	 *
	 * No-op when auth.state !== 'authenticated'. This prevents wasted
	 * timers on unauthenticated views and accidental transitions out
	 * of locked state.
	 */
	reset(): void {
		if (auth.state !== 'authenticated') {
			return;
		}
		this.lastReset = Date.now();
		if (this.timerId !== null) {
			clearTimeout(this.timerId);
		}
		this.timerId = setTimeout(() => {
			auth.setLocked();
			this.timerId = null;
		}, IDLE_TIMEOUT_MS);
	}

	private onVisibilityChange = (): void => {
		// Tab visibility transition does not reset the timer. If the tab
		// is hidden and the timer fires, the user returns to find the
		// session already locked — matches user intuition (spec §6.3).
	};
}

export const idle = new IdleStore();
