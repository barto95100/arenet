// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Auth store: current user identity + authentication state. Exposed as
// Svelte 5 runes for fine-grained reactivity (spec §6.2).
//
// Singleton class instance pattern, consistent with Step C's toast.ts
// and loading.ts. The `unknown` state signals that bootstrap has not
// yet completed; the layout shell displays a spinner during that window
// to avoid flashing the login page.

import { authApi, type User } from '$lib/api/auth';
import { ApiError } from '$lib/api/types';

export type AuthState = 'unknown' | 'anonymous' | 'authenticated' | 'locked';

class AuthStore {
	user = $state<User | null>(null);
	state = $state<AuthState>('unknown');
	isBootstrapping = $state(false);

	async bootstrap(): Promise<void> {
		this.isBootstrapping = true;
		try {
			const me = await authApi.me();
			this.user = me;
			this.state = me.locked ? 'locked' : 'authenticated';
		} catch (err) {
			if (err instanceof ApiError && err.status === 401) {
				this.state = 'anonymous';
				this.user = null;
			} else {
				// Network or 5xx error — leave state as 'unknown' so the
				// layout shows the spinner. The user can refresh.
				console.error('auth bootstrap failed:', err);
			}
		} finally {
			this.isBootstrapping = false;
		}
	}

	async login(username: string, password: string, rememberMe: boolean): Promise<void> {
		const user = await authApi.login(username, password, rememberMe);
		this.user = user;
		this.state = 'authenticated';
	}

	async logout(): Promise<void> {
		try {
			await authApi.logout();
		} catch (err) {
			// Even if the server fails, clear local state.
			console.warn('logout request failed (clearing local state anyway):', err);
		}
		this.user = null;
		this.state = 'anonymous';
	}

	async unlock(password: string): Promise<void> {
		await authApi.unlock(password);
		this.state = 'authenticated';
		// The user object is still valid; only the state changes.
	}

	// setLocked is idempotent: it only transitions from 'authenticated'.
	// Trying to lock from 'anonymous' or 'unknown' is a no-op, preventing
	// race conditions during page transitions (spec §6.2 design notes).
	setLocked(): void {
		if (this.state === 'authenticated') {
			this.state = 'locked';
		}
	}

	// clear is called by the API client's 401 interceptor (spec §6.4).
	clear(): void {
		this.user = null;
		this.state = 'anonymous';
	}
}

export const auth = new AuthStore();
