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

// v2.20.0 CSR generation (Task 10) — pure age-bucket helper for the
// Pending CSR tab. Thresholds (whole days since createdAt):
//   recent  <4d
//   waiting 4-14d
//   old     15-30d
//   stale   30d+ (i.e. >30d — 30d itself is still "old")

import { describe, it, expect, vi, afterEach } from 'vitest';
import { csrAgeBadge } from './csr-age';

const NOW = new Date('2026-07-20T12:00:00Z');

function daysAgo(days: number): string {
	return new Date(NOW.getTime() - days * 86_400_000).toISOString();
}

afterEach(() => {
	vi.useRealTimers();
});

describe('csrAgeBadge', () => {
	it('boundary values', () => {
		vi.useFakeTimers({ toFake: ['Date'] });
		vi.setSystemTime(NOW);

		expect(csrAgeBadge(daysAgo(0))).toBe('recent');
		expect(csrAgeBadge(daysAgo(3))).toBe('recent');
		expect(csrAgeBadge(daysAgo(4))).toBe('waiting');
		expect(csrAgeBadge(daysAgo(14))).toBe('waiting');
		expect(csrAgeBadge(daysAgo(15))).toBe('old');
		expect(csrAgeBadge(daysAgo(30))).toBe('old');
		expect(csrAgeBadge(daysAgo(31))).toBe('stale');
	});

	it('returns "stale" for an unparseable timestamp (fail safe, never silently "recent")', () => {
		expect(csrAgeBadge('not-a-date')).toBe('stale');
		expect(csrAgeBadge('')).toBe('stale');
	});
});
