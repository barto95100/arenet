// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Typed wrappers for the /api/v1/auth/* endpoints (spec §6.5). Wire
// shapes mirror the Go handlers in internal/api/auth_handlers.go.

import { request } from './client';

export interface User {
	id: string;
	username: string;
	displayName: string;
	locked: boolean;
	passwordCompromised: boolean;
	hibpCheckStatus: 'pending' | 'clean' | 'compromised' | 'skipped';
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
	}
};
