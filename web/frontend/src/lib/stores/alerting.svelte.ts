// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// AL.4.b.1 — Alerting page state stores. Svelte 5 runes.
//
// alertEventsStore drives the History tab; ships in full
// here. channelsStore + rulesStore are stubbed so the
// stub tabs can import them without TypeScript errors —
// they get fleshed out in AL.4.b.2 / .3 (full CRUD,
// optimistic updates, /test integration).

import {
	alertingApi,
	type AlertChannel,
	type AlertEvent,
	type AlertEventsFilter,
	type AlertRule
} from '$lib/api/alerting';
import { ApiError } from '$lib/api/types';

// --- alertEventsStore --------------------------------------

interface AlertEventsState {
	events: AlertEvent[];
	nextCursor: string;
	loading: boolean;
	loadMoreLoading: boolean;
	loadError: string;
	degraded: boolean;
}

function createAlertEventsStore() {
	const state = $state<AlertEventsState>({
		events: [],
		nextCursor: '',
		loading: false,
		loadMoreLoading: false,
		loadError: '',
		degraded: false
	});

	async function load(filter: AlertEventsFilter, reset: boolean): Promise<void> {
		if (reset) {
			state.loading = true;
		} else {
			state.loadMoreLoading = true;
		}
		state.loadError = '';
		const req: AlertEventsFilter = { ...filter };
		if (!reset && state.nextCursor) req.cursor = state.nextCursor;
		try {
			const res = await alertingApi.listAlertEvents(req);
			state.events = reset ? res.events : [...state.events, ...res.events];
			state.nextCursor = res.nextCursor;
			state.degraded = res.degraded ?? false;
		} catch (err) {
			if (reset) {
				state.loadError =
					err instanceof ApiError ? err.message : 'Échec du chargement des événements';
				state.events = [];
			}
			// On loadMore failure we keep the existing list and
			// surface a transient error; the History tab toast-
			// pushes for non-reset failures.
			throw err;
		} finally {
			state.loading = false;
			state.loadMoreLoading = false;
		}
	}

	return {
		get state() {
			return state;
		},
		load
	};
}

export const alertEventsStore = createAlertEventsStore();

// --- channelsStore (stub for AL.4.b.2) ---------------------

interface ChannelsState {
	channels: AlertChannel[];
	loading: boolean;
	loadError: string;
}

function createChannelsStore() {
	const state = $state<ChannelsState>({
		channels: [],
		loading: false,
		loadError: ''
	});

	async function load(): Promise<void> {
		state.loading = true;
		state.loadError = '';
		try {
			state.channels = await alertingApi.listChannels();
		} catch (err) {
			state.loadError =
				err instanceof ApiError ? err.message : 'Échec du chargement des canaux';
		} finally {
			state.loading = false;
		}
	}

	return {
		get state() {
			return state;
		},
		load
	};
}

export const channelsStore = createChannelsStore();

// --- rulesStore (stub for AL.4.b.3) ------------------------

interface RulesState {
	rules: AlertRule[];
	loading: boolean;
	loadError: string;
}

function createRulesStore() {
	const state = $state<RulesState>({
		rules: [],
		loading: false,
		loadError: ''
	});

	async function load(): Promise<void> {
		state.loading = true;
		state.loadError = '';
		try {
			state.rules = await alertingApi.listRules();
		} catch (err) {
			state.loadError =
				err instanceof ApiError ? err.message : 'Échec du chargement des règles';
		} finally {
			state.loading = false;
		}
	}

	return {
		get state() {
			return state;
		},
		load
	};
}

export const rulesStore = createRulesStore();
