// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// #364 — typed wrappers for the AreNET allowlist CRUD endpoints.
//   - GET    /api/v1/security/allowlists          (viewer)
//   - GET    /api/v1/security/allowlists/{slug}   (viewer)
//   - POST   /api/v1/security/allowlists          (admin)
//   - PUT    /api/v1/security/allowlists/{slug}   (admin)
//   - DELETE /api/v1/security/allowlists/{slug}   (admin)
//
// Backend mirror: internal/api/allowlists.go (wire shape pinned by
// TestAllowlistWire_CreateAndList_G).

import { request } from './client';

/** One IP/CIDR entry within an allowlist. */
export interface AllowlistEntry {
	cidr: string;
	note: string;
}

/**
 * Wire shape of an allowlist. Fields map 1-to-1 to the backend
 * allowlist.Allowlist camelCase JSON tags. `entries` is null-safe: the
 * backend may omit it for an empty allowlist, so treat `?? []`.
 */
export interface Allowlist {
	slug: string;
	name: string;
	description: string;
	enabled: boolean;
	scopeBlock: boolean;
	scopeThrottle: boolean;
	scopeAudit: boolean;
	entries: AllowlistEntry[] | null;
	createdAt: string;
	updatedAt: string;
}

/** Create/update payload. Scope + enabled default to true server-side. */
export interface AllowlistInput {
	name: string;
	description: string;
	enabled: boolean;
	scopeBlock: boolean;
	scopeThrottle: boolean;
	scopeAudit: boolean;
	entries: AllowlistEntry[];
}

/** List every allowlist. */
export async function listAllowlists(): Promise<Allowlist[]> {
	const res = await request<{ allowlists: Allowlist[] | null }>('GET', '/security/allowlists');
	return res.allowlists ?? [];
}

/** Get one allowlist by slug. */
export async function getAllowlist(slug: string): Promise<Allowlist> {
	return request<Allowlist>('GET', `/security/allowlists/${encodeURIComponent(slug)}`);
}

/** Create a new allowlist. */
export async function createAllowlist(input: AllowlistInput): Promise<Allowlist> {
	return request<Allowlist>('POST', '/security/allowlists', input);
}

/** Replace an allowlist's fields and entries. */
export async function updateAllowlist(slug: string, input: AllowlistInput): Promise<Allowlist> {
	return request<Allowlist>('PUT', `/security/allowlists/${encodeURIComponent(slug)}`, input);
}

/** Delete an allowlist. */
export async function deleteAllowlist(slug: string): Promise<void> {
	return request<void>('DELETE', `/security/allowlists/${encodeURIComponent(slug)}`);
}

/**
 * parseEntriesText turns the textarea (one IP/CIDR per line, optional
 * `  # note` or `  note` suffix after whitespace) into entries, and reports
 * the 1-based line numbers that fail client-side IP/CIDR validation. The
 * server re-validates — this is UX, not the authority.
 */
export function parseEntriesText(text: string): { entries: AllowlistEntry[]; invalidLines: number[] } {
	const entries: AllowlistEntry[] = [];
	const invalidLines: number[] = [];
	const lines = text.split('\n');
	for (let i = 0; i < lines.length; i++) {
		const raw = lines[i].trim();
		if (raw === '') continue;
		// Split the CIDR token from an optional note (first whitespace).
		const m = raw.match(/^(\S+)(?:\s+(.*))?$/);
		const token = m ? m[1] : raw;
		const note = m && m[2] ? m[2].replace(/^#\s*/, '').trim() : '';
		if (!isValidCidrOrIp(token)) {
			invalidLines.push(i + 1);
			continue;
		}
		entries.push({ cidr: token, note });
	}
	return { entries, invalidLines };
}

/**
 * isValidCidrOrIp is a pragmatic client-side check for an IPv4/IPv6
 * address or CIDR. Deliberately conservative: the server's net/netip
 * parse is the authority, this only flags obvious typos live.
 */
export function isValidCidrOrIp(s: string): boolean {
	const slash = s.indexOf('/');
	let addr = s;
	if (slash >= 0) {
		const bitsStr = s.slice(slash + 1);
		addr = s.slice(0, slash);
		if (!/^\d+$/.test(bitsStr)) return false;
		const bits = Number(bitsStr);
		const isV6 = addr.includes(':');
		if (bits < 0 || bits > (isV6 ? 128 : 32)) return false;
	}
	return isValidIPv4(addr) || isValidIPv6(addr);
}

function isValidIPv4(s: string): boolean {
	const parts = s.split('.');
	if (parts.length !== 4) return false;
	return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

function isValidIPv6(s: string): boolean {
	// Accept the common forms (incl. :: compression) without being a full
	// RFC parser; the server is authoritative.
	if (!s.includes(':')) return false;
	if (!/^[0-9a-fA-F:]+$/.test(s)) return false;
	const doubleColon = s.split('::').length - 1;
	if (doubleColon > 1) return false;
	return true;
}

/** Render entries back to textarea text (cidr + optional note). */
export function entriesToText(entries: AllowlistEntry[] | null): string {
	if (!entries) return '';
	return entries.map((e) => (e.note ? `${e.cidr} ${e.note}` : e.cidr)).join('\n');
}
