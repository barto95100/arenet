// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import type { AlertEvent } from '$lib/api/alerting';

const { store } = vi.hoisted(() => ({
	store: {
		recent: [] as AlertEvent[],
		unreadCount: 0,
		loading: false,
		loadError: '',
		load: vi.fn().mockResolvedValue(undefined),
		markAllRead: vi.fn()
	}
}));
vi.mock('$lib/stores/notifications.svelte', () => ({
	notificationsStore: store,
	PANEL_LIMIT: 15,
	SYNTHETIC_UPDATE_ID: 'synthetic:update'
}));

import NotificationBell from './NotificationBell.svelte';

function evt(over: Partial<AlertEvent> = {}): AlertEvent {
	return { eventId: 'e', timestamp: '2026-07-13T10:00:00Z', ruleId: 'r', ruleName: 'n',
		severity: 0, category: 'c', subject: 'Something happened', channelsFired: [], ...over };
}

beforeEach(() => {
	store.recent = [];
	store.unreadCount = 0;
	store.loading = false;
	store.loadError = '';
	store.load.mockClear();
	store.markAllRead.mockClear();
});

describe('NotificationBell', () => {
	it('renders the label and no badge when unreadCount is 0', () => {
		const { getByText, queryByTestId } = render(NotificationBell);
		expect(getByText('Notifications')).toBeTruthy();
		expect(queryByTestId('notif-count')).toBeNull();
	});

	it('shows the count badge when unreadCount > 0', () => {
		store.unreadCount = 3;
		const { getByTestId } = render(NotificationBell);
		expect(getByTestId('notif-count').textContent).toContain('3');
	});

	it('caps the badge at 99+', () => {
		store.unreadCount = 150;
		const { getByTestId } = render(NotificationBell);
		expect(getByTestId('notif-count').textContent).toContain('99+');
	});

	it('calls load() when the panel opens', async () => {
		const { getByTestId } = render(NotificationBell);
		await fireEvent.click(getByTestId('notif-trigger'));
		await waitFor(() => expect(store.load).toHaveBeenCalled());
	});

	it('renders the empty-state CTA when there are no items', async () => {
		const { getByTestId, getByText } = render(NotificationBell);
		await fireEvent.click(getByTestId('notif-trigger'));
		expect(getByText('Set up alerts in Alerting →')).toBeTruthy();
	});

	it('lists items and marks all read on button click', async () => {
		store.recent = [evt({ subject: 'Cert expiring' })];
		store.unreadCount = 1;
		const { getByTestId, getByText } = render(NotificationBell);
		await fireEvent.click(getByTestId('notif-trigger'));
		expect(getByText('Cert expiring')).toBeTruthy();
		await fireEvent.click(getByTestId('notif-markread'));
		expect(store.markAllRead).toHaveBeenCalled();
	});
});
