// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Typed wrappers for the /api/v1/auth/* endpoints (spec §6.5). Wire
// shapes mirror the Go handlers in internal/api/auth_handlers.go.

import { request } from './client';
import type { OIDCStatus, UserRole } from './types';

export interface User {
	id: string;
	username: string;
	displayName: string;
	locked: boolean;
	passwordCompromised: boolean;
	hibpCheckStatus: 'pending' | 'clean' | 'compromised' | 'skipped';
	// "" means "no preference yet" (legacy pre-Step-F user). The theme
	// store treats "" identically to "dark" per spec §4.2. Step F §3.1.
	themePreference: '' | 'dark' | 'light';
	/**
	 * Step K.2 — role on the admin surface. "admin" gets full
	 * CRUD; "viewer" sees a read-only UI. The frontend gates
	 * action buttons on this; the backend gates the underlying
	 * routes via RequireAdminMiddleware (defence in depth).
	 */
	role: UserRole;
	/**
	 * Step K.2 — provenance of the credentials backing this
	 * session. "local" → username+password (and Settings → "Change
	 * password" works); "oidc" → SSO via IdP (password rotation
	 * disabled — the user changes their password at the IdP).
	 */
	authSource: 'local' | 'oidc';
}

export interface Session {
	id: string;
	issuedAt: string;
	lastActivity: string;
	expiresAt: string;
	ip: string;
	userAgent: string;
	rememberMe: boolean;
	isCurrent: boolean;
}

export const authApi = {
	setup(
		setupToken: string,
		username: string,
		displayName: string,
		password: string
	): Promise<User> {
		return request<User>('POST', '/auth/setup', {
			setupToken,
			username,
			displayName,
			password
		});
	},

	login(username: string, password: string, rememberMe: boolean): Promise<User> {
		return request<User>('POST', '/auth/login', { username, password, rememberMe });
	},

	logout(): Promise<void> {
		return request<void>('POST', '/auth/logout');
	},

	me(): Promise<User> {
		return request<User>('GET', '/auth/me');
	},

	unlock(password: string): Promise<{ unlocked: boolean }> {
		return request<{ unlocked: boolean }>('POST', '/auth/unlock', { password });
	},

	heartbeat(): Promise<void> {
		return request<void>('POST', '/auth/heartbeat');
	},

	listSessions(): Promise<{ sessions: Session[] }> {
		return request<{ sessions: Session[] }>('GET', '/auth/sessions');
	},

	deleteSession(id: string): Promise<void> {
		return request<void>('DELETE', `/auth/sessions/${id}`);
	},

	// changePassword returns 204 on success and revokes all OTHER sessions
	// of this user. The current session cookie remains valid (spec §4.9bis).
	changePassword(currentPassword: string, newPassword: string): Promise<void> {
		return request<void>('POST', '/auth/me/password', { currentPassword, newPassword });
	},

	// setTheme persists the user's theme preference (Step F §3.3, §4.5).
	// 204 on success; the server also refreshes the arenet_theme cookie
	// so the FOUC bootstrap picks up the new value on the next paint.
	setTheme(theme: 'dark' | 'light'): Promise<void> {
		return request<void>('POST', '/auth/me/theme', { theme });
	},

	// Step K.2 — anonymous OIDC status probe. Login page calls
	// this to decide whether to render the "Continue with SSO"
	// button. Response is tiny and carries no operational details.
	oidcStatus(): Promise<OIDCStatus> {
		return request<OIDCStatus>('GET', '/auth/oidc/status');
	}
};
