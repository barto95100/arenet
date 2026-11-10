// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.80 — AccessLogPanel tests.
//
// The load-bearing behaviour is "lazy": mounting the panel must NOT hit
// the network — the operator's explicit constraint that opening the Logs
// page never streams the access-log file. The rest asserts that each
// control calls the matching endpoint with the chosen arguments.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import type { AccessLogSearchResponse, AccessLogTailResponse } from '$lib/api/accessLog';

const tailMock = vi.fn<(n: number) => Promise<AccessLogTailResponse>>();
const searchMock = vi.fn<(f: string, q: string, m: number) => Promise<AccessLogSearchResponse>>();

vi.mock('$lib/api/accessLog', () => ({
	tailAccessLog: (n: number) => tailMock(n),
	searchAccessLog: (f: string, q: string, m: number) => searchMock(f, q, m)
}));

const { default: AccessLogPanel } = await import('./AccessLogPanel.svelte');

beforeEach(() => {
	tailMock.mockReset();
	searchMock.mockReset();
	tailMock.mockResolvedValue({
		enabled: true,
		path: '/data/logs/access.log',
		lines: [
			{
				ts: 1699999999.5,
				method: 'GET',
				uri: '/latest-hit',
				clientIp: '10.0.0.2',
				status: 403,
				denied: 'waf',
				raw: '{"uri":"/latest-hit"}'
			}
		]
	});
	searchMock.mockResolvedValue({
		enabled: true,
		path: '/data/logs/access.log',
		field: 'ip',
		query: '10.0.0.2',
		lines: [],
		filesScanned: 1,
		bytesScanned: 42,
		truncated: false,
		searchedCompressed: false,
		elapsedMs: 3
	});
});

async function openPanel(): Promise<void> {
	await fireEvent.click(screen.getByRole('button', { name: /Access log/i }));
}

describe('AccessLogPanel', () => {
	it('fetches nothing on mount', () => {
		render(AccessLogPanel);
		expect(tailMock).not.toHaveBeenCalled();
		expect(searchMock).not.toHaveBeenCalled();
	});

	it('still fetches nothing when merely expanded', async () => {
		render(AccessLogPanel);
		await openPanel();
		expect(tailMock).not.toHaveBeenCalled();
		expect(searchMock).not.toHaveBeenCalled();
	});

	it('calls the tail endpoint once on "Show latest" and renders the line', async () => {
		render(AccessLogPanel);
		await openPanel();
		await fireEvent.click(screen.getByRole('button', { name: /Show latest/i }));

		await waitFor(() => expect(tailMock).toHaveBeenCalledTimes(1));
		expect(tailMock).toHaveBeenCalledWith(200);
		expect(searchMock).not.toHaveBeenCalled();
		expect(await screen.findByText('/latest-hit')).toBeInTheDocument();
	});

	it('calls search with the chosen field and query', async () => {
		render(AccessLogPanel);
		await openPanel();

		await fireEvent.change(screen.getByLabelText(/Search by/i), { target: { value: 'ip' } });
		await fireEvent.input(screen.getByLabelText(/^Value$/i), { target: { value: '10.0.0.2' } });
		await fireEvent.click(screen.getByRole('button', { name: /^Search$/i }));

		await waitFor(() => expect(searchMock).toHaveBeenCalledTimes(1));
		expect(searchMock).toHaveBeenCalledWith('ip', '10.0.0.2', 200);
		expect(tailMock).not.toHaveBeenCalled();
	});

	// v2.80 bugfix — the Logs page is a strict viewport-fit (no page
	// scroll); the panel sits below a flex:1 area, so when it expands
	// its results render under the fold with no way to reach them. The
	// fix reverts the shell to natural scroll via a `:has()` selector
	// that keys off an `is-open` class on the panel root. This guards
	// that load-bearing hook: lose the class and the CSS unlock dies
	// silently (jsdom cannot prove the layout, only the hook).
	it('marks the root with "is-open" only while expanded', async () => {
		render(AccessLogPanel);
		const region = screen.getByRole('region', { name: /Access log/i });
		expect(region).toHaveClass('access-log-panel');
		expect(region).not.toHaveClass('is-open');

		await openPanel();
		expect(region).toHaveClass('is-open');

		await openPanel();
		expect(region).not.toHaveClass('is-open');
	});
});
