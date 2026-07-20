// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

// v2.20.0 CSR generation (Task 10) — age-bucket helper for the Pending
// CSR tab of ExternalCertsPanel. A pending_csr row is inert (no leaf,
// serving nothing) until the operator re-imports a signed cert, so the
// UI surfaces how long a CSR has been waiting on a CA via a threshold
// badge computed from `createdAt`.

/** One day, in milliseconds. */
const DAY_MS = 86_400_000;

/** Age buckets, in whole days since `createdAt`. */
const RECENT_MAX_DAYS = 3; // 0-3d
const WAITING_MAX_DAYS = 14; // 4-14d
const OLD_MAX_DAYS = 30; // 15-30d
// >30d = stale

/**
 * Age bucket for a pending CSR's `createdAt` timestamp, used to pick
 * the badge variant/label in the Pending CSR tab.
 *
 *   recent   0-3 days old
 *   waiting  4-14 days old
 *   old      15-30 days old
 *   stale    31+ days old
 *
 * An unparseable/empty timestamp fails safe to 'stale' — the loudest
 * bucket — rather than silently rendering as fresh.
 */
export function csrAgeBadge(createdAt: string): 'recent' | 'waiting' | 'old' | 'stale' {
	const ts = Date.parse(createdAt);
	if (Number.isNaN(ts)) return 'stale';

	const days = Math.floor((Date.now() - ts) / DAY_MS);
	if (days <= RECENT_MAX_DAYS) return 'recent';
	if (days <= WAITING_MAX_DAYS) return 'waiting';
	if (days <= OLD_MAX_DAYS) return 'old';
	return 'stale';
}
