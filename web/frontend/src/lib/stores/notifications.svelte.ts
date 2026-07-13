// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Notification panel state. Layers over alertEventsStore (rule-driven
// alert history) and adds a synthetic "update available" item read
// directly from /system/version so the update signal survives with
// zero alerting config. Unread is tracked in localStorage.

import { alertEventsStore } from '$lib/stores/alerting.svelte';
import type { AlertEvent } from '$lib/api/alerting';
import { systemApi } from '$lib/api/system';

export const PANEL_LIMIT = 15;
export const SYNTHETIC_UPDATE_ID = 'synthetic:update';

const LAST_SEEN_KEY = 'arenet.notifications.lastSeen';
const UPDATE_FIRST_SEEN_KEY = 'arenet.notifications.updateFirstSeen';

function lsGet(key: string): string {
	if (typeof localStorage === 'undefined') return '';
	try { return localStorage.getItem(key) ?? ''; } catch { return ''; }
}
function lsSet(key: string, val: string): void {
	if (typeof localStorage === 'undefined') return;
	try { localStorage.setItem(key, val); } catch { /* ignore */ }
}
function lsDel(key: string): void {
	if (typeof localStorage === 'undefined') return;
	try { localStorage.removeItem(key); } catch { /* ignore */ }
}

interface NotifState {
	lastSeen: string;
	updateItem: AlertEvent | null;
}

function createNotificationsStore() {
	const state = $state<NotifState>({
		lastSeen: lsGet(LAST_SEEN_KEY),
		updateItem: null
	});

	// recent merges the synthetic update item (if any) with the alert
	// events, sorts newest-first, and caps at PANEL_LIMIT. The sort makes
	// ordering correct regardless of the events' incoming order; the
	// pre-sort slice assumes the alert-events API returns newest-first
	// (it is called with {limit: PANEL_LIMIT}), so the newest PANEL_LIMIT
	// events are the ones considered.
	const recent = $derived.by<AlertEvent[]>(() => {
		const events = alertEventsStore.state.events.slice(0, PANEL_LIMIT);
		const merged = state.updateItem ? [state.updateItem, ...events] : events;
		return merged
			.slice()
			.sort((a, b) => (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0))
			.slice(0, PANEL_LIMIT);
	});

	const unreadCount = $derived(
		recent.filter((e) => e.timestamp > state.lastSeen).length
	);

	function newestTimestamp(): string {
		return recent.length > 0 ? recent[0].timestamp : new Date().toISOString();
	}

	async function refreshUpdateItem(): Promise<void> {
		try {
			const v = await systemApi.getVersion();
			if (v.updateAvailable) {
				let firstSeen = lsGet(UPDATE_FIRST_SEEN_KEY);
				if (!firstSeen) {
					firstSeen = new Date().toISOString();
					lsSet(UPDATE_FIRST_SEEN_KEY, firstSeen);
				}
				state.updateItem = {
					eventId: SYNTHETIC_UPDATE_ID,
					timestamp: firstSeen,
					ruleId: '',
					ruleName: 'update available',
					severity: 0,
					category: 'update',
					subject: '', // rendered by the component via i18n with v.latest
					context: { url: v.url, version: v.latest },
					channelsFired: []
				};
			} else {
				state.updateItem = null;
				lsDel(UPDATE_FIRST_SEEN_KEY);
			}
		} catch {
			// Swallow — a version-check failure must not break the panel.
		}
	}

	async function load(): Promise<void> {
		await Promise.all([
			alertEventsStore.load({ limit: PANEL_LIMIT }, true),
			refreshUpdateItem()
		]);
		if (!lsGet(LAST_SEEN_KEY)) {
			// First-ever visit (no persisted marker): treat existing items
			// as read. After this, LAST_SEEN_KEY is set, so later loads
			// skip this branch.
			state.lastSeen = newestTimestamp();
			lsSet(LAST_SEEN_KEY, state.lastSeen);
		}
	}

	function markAllRead(): void {
		state.lastSeen = newestTimestamp();
		lsSet(LAST_SEEN_KEY, state.lastSeen);
	}

	return {
		get recent() { return recent; },
		get unreadCount() { return unreadCount; },
		get lastSeen() { return state.lastSeen; },
		get loading() { return alertEventsStore.state.loading; },
		get loadError() { return alertEventsStore.state.loadError; },
		load,
		markAllRead
	};
}

export const notificationsStore = createNotificationsStore();
