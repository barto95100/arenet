// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.80 — read-only access-log viewer (admin-only).
//
// Two bounded GET endpoints behind the admin group:
//   - tail: the last N lines of the current access-log file;
//   - search: a uuid / IP / path lookup across the current file and its
//     rotated (and, on a hot-tier miss, gzipped) siblings.
//
// The page calls NOTHING on mount — these run only on an explicit
// operator action — so opening Logs never loads the file.

import { request } from './client';

/** One parsed access-log line, display-ready; `raw` is the on-disk JSON. */
export interface AccessLogEntry {
	ts: number;
	method: string;
	uri: string;
	clientIp: string;
	status: number;
	uuid?: string;
	/** The Arenet gate that refused the request (arenet_denied), if any. */
	denied?: string;
	raw: string;
}

/** The field a search matches against. */
export type AccessLogField = 'uuid' | 'ip' | 'path';

export interface AccessLogTailResponse {
	enabled: boolean;
	reason?: string;
	path: string;
	lines: AccessLogEntry[];
}

export interface AccessLogSearchResponse {
	enabled: boolean;
	reason?: string;
	path: string;
	field: string;
	query: string;
	lines: AccessLogEntry[];
	filesScanned: number;
	bytesScanned: number;
	truncated: boolean;
	/** True when the cold (.gz) tier was searched — the hot tier missed. */
	searchedCompressed: boolean;
	elapsedMs: number;
}

/** Last `lines` lines of the current access-log file (server-clamped). */
export function tailAccessLog(lines = 200): Promise<AccessLogTailResponse> {
	return request<AccessLogTailResponse>(
		'GET',
		`/admin/access-log/tail?lines=${encodeURIComponent(lines)}`
	);
}

/** Search the access log by field; the server bounds and clamps the rest. */
export function searchAccessLog(
	field: AccessLogField,
	q: string,
	max = 200
): Promise<AccessLogSearchResponse> {
	const qs = new URLSearchParams({ field, q, max: String(max) });
	return request<AccessLogSearchResponse>('GET', `/admin/access-log/search?${qs.toString()}`);
}
