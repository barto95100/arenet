// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

export interface Route {
	id: string;
	host: string;
	upstreamUrl: string;
	tlsEnabled: boolean;
	wafEnabled: boolean;
	createdAt: string;
	updatedAt: string;
}

export interface RouteRequest {
	host: string;
	upstreamUrl: string;
	tlsEnabled: boolean;
	wafEnabled: boolean;
}

/**
 * Discriminated kind of an ApiError so the UI can decide between inline
 * (validation) and toast (system) presentation per spec §10.5.
 */
export type ErrorKind = 'validation' | 'system';

export class ApiError extends Error {
	status: number;
	kind: ErrorKind;
	constructor(message: string, status: number) {
		super(message);
		this.status = status;
		this.kind = status === 400 || status === 409 ? 'validation' : 'system';
	}
}
