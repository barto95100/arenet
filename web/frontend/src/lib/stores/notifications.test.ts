// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { AlertEvent } from '$lib/api/alerting';

const { alertMock, systemMock } = vi.hoisted(() => ({
	alertMock: { load: vi.fn(), state: { events: [] as AlertEvent[], loading: false, loadError: '' } },
	systemMock: { getVersion: vi.fn() }
}));
vi.mock('$lib/stores/alerting.svelte', () => ({
	alertEventsStore: {
		load: (...a: unknown[]) => alertMock.load(...a),
		get state() { return alertMock.state; }
	}
}));
vi.mock('$lib/api/system', () => ({
	systemApi: { getVersion: (...a: unknown[]) => systemMock.getVersion(...a) }
}));

function evt(ts: string, over: Partial<AlertEvent> = {}): AlertEvent {
	return { eventId: ts, timestamp: ts, ruleId: 'r', ruleName: 'n', severity: 0,
		category: 'c', subject: 's', channelsFired: [], ...over };
}
function version(over: Record<string, unknown> = {}) {
	return { current: 'v1', latest: 'v2', updateAvailable: false, url: 'https://x/v2', ...over };
}

beforeEach(() => {
	localStorage.clear();
	alertMock.load.mockReset().mockResolvedValue(undefined);
	alertMock.state = { events: [], loading: false, loadError: '' };
	systemMock.getVersion.mockReset().mockResolvedValue(version());
});

// import fresh each test so store module state resets
async function freshStore() {
	vi.resetModules();
	return (await import('./notifications.svelte')).notificationsStore;
}

describe('notificationsStore', () => {
	it('first visit initializes lastSeen to newest event → unreadCount 0', async () => {
		alertMock.state.events = [evt('2026-07-13T10:00:00Z'), evt('2026-07-13T09:00:00Z')];
		const s = await freshStore();
		await s.load();
		expect(s.unreadCount).toBe(0);
	});

	it('counts events strictly newer than a stored lastSeen', async () => {
		localStorage.setItem('arenet.notifications.lastSeen', '2026-07-13T09:30:00Z');
		alertMock.state.events = [evt('2026-07-13T10:00:00Z'), evt('2026-07-13T09:00:00Z')];
		const s = await freshStore();
		await s.load();
		expect(s.unreadCount).toBe(1);
	});

	it('markAllRead resets unreadCount to 0 and persists', async () => {
		localStorage.setItem('arenet.notifications.lastSeen', '2026-07-13T00:00:00Z');
		alertMock.state.events = [evt('2026-07-13T10:00:00Z')];
		const s = await freshStore();
		await s.load();
		expect(s.unreadCount).toBe(1);
		s.markAllRead();
		expect(s.unreadCount).toBe(0);
		expect(localStorage.getItem('arenet.notifications.lastSeen')).toBe('2026-07-13T10:00:00Z');
	});

	it('caps recent at PANEL_LIMIT', async () => {
		alertMock.state.events = Array.from({ length: 30 }, (_, i) =>
			evt(`2026-07-13T${String(10 + Math.floor(i / 60)).padStart(2, '0')}:${String(i % 60).padStart(2, '0')}:00Z`));
		const s = await freshStore();
		await s.load();
		expect(s.recent.length).toBe(15);
	});

	it('injects a synthetic update item when updateAvailable', async () => {
		systemMock.getVersion.mockResolvedValue(version({ updateAvailable: true, latest: 'v2.12.6', url: 'https://x/v2.12.6' }));
		const s = await freshStore();
		await s.load();
		const synth = s.recent.find((e) => e.eventId === 'synthetic:update');
		expect(synth).toBeTruthy();
		expect(synth?.context?.url).toBe('https://x/v2.12.6');
	});

	it('no synthetic item when updateAvailable is false', async () => {
		systemMock.getVersion.mockResolvedValue(version({ updateAvailable: false }));
		const s = await freshStore();
		await s.load();
		expect(s.recent.find((e) => e.eventId === 'synthetic:update')).toBeFalsy();
	});

	it('keeps synthetic timestamp stable across polls (no perpetual unread)', async () => {
		systemMock.getVersion.mockResolvedValue(version({ updateAvailable: true }));
		const s = await freshStore();
		await s.load();
		const first = s.recent.find((e) => e.eventId === 'synthetic:update')?.timestamp;
		s.markAllRead();
		await s.load(); // second poll, still available
		const second = s.recent.find((e) => e.eventId === 'synthetic:update')?.timestamp;
		expect(second).toBe(first);
		expect(s.unreadCount).toBe(0);
	});

	it('swallows a failed getVersion without setting loadError', async () => {
		systemMock.getVersion.mockRejectedValue(new Error('boom'));
		alertMock.state.events = [evt('2026-07-13T10:00:00Z')];
		const s = await freshStore();
		await s.load();
		expect(s.loadError).toBe('');
		expect(s.recent.length).toBe(1);
	});
});
