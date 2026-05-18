// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Typed wrapper for GET /api/v1/audit (spec §6.6). Translates the
// camelCase TypeScript filter into the snake_case URL parameters
// expected by the server (spec §4.10).

import { request } from './client';

export interface AuditEvent {
	id: string;
	timestamp: string;
	actorUserId: string;
	actorUsernameSnapshot: string;
	action: string;
	targetType: string;
	targetId: string;
	beforeJson: unknown | null;
	afterJson: unknown | null;
	message: string;
	ip: string;
	userAgent: string;
}

export interface AuditFilter {
	actorUserId?: string;
	action?: string;
	targetType?: string;
	targetId?: string;
	from?: string; // RFC 3339
	to?: string; // RFC 3339
	limit?: number;
	cursor?: string;
}

export interface AuditListResponse {
	events: AuditEvent[];
	nextCursor: string;
}

export const auditApi = {
	list(filter: AuditFilter): Promise<AuditListResponse> {
		const params = new URLSearchParams();
		if (filter.actorUserId) params.set('actor_user_id', filter.actorUserId);
		if (filter.action) params.set('action', filter.action);
		if (filter.targetType) params.set('target_type', filter.targetType);
		if (filter.targetId) params.set('target_id', filter.targetId);
		if (filter.from) params.set('from', filter.from);
		if (filter.to) params.set('to', filter.to);
		if (filter.limit !== undefined) params.set('limit', String(filter.limit));
		if (filter.cursor) params.set('cursor', filter.cursor);
		const query = params.toString();
		return request<AuditListResponse>('GET', `/audit${query ? '?' + query : ''}`);
	}
};
