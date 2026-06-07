// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

/**
 * Step V.6 — WebSocket client for /api/v1/ws/geo-events
 * (spec §5.5).
 *
 * Mirrors the topology stream client at
 * src/routes/topology/_api.ts:connectLiveStream — same
 * backoff schedule, same close discipline, same vite proxy
 * dependency (ws: true on /api). The two clients are kept
 * SEPARATE rather than refactored into a generic helper
 * because:
 *
 *   1. Each WS endpoint has a different payload shape
 *      (TopologySnapshot vs GeoEvent) so the generic helper
 *      would need a type parameter + a parsing callback,
 *      adding indirection for two consumers.
 *   2. The topology client is co-located with its route;
 *      moving it would touch a shipped surface for no V.6
 *      win.
 *
 * If a third WS client lands, extract the shared shape
 * THEN. Until then, parallel implementations + a clear
 * code reference are the cheaper choice.
 *
 * The handle exposes:
 *   - close() — operator-initiated teardown. Stops any
 *     pending reconnect and closes the socket with code
 *     1000 (normal closure) so the backend's WS handler
 *     unsubscribes cleanly from the V.3 bus.
 *   - state — reactive connection state for the page's
 *     status indicator. Four values: connecting / open /
 *     reconnecting / closed.
 *
 * `onEvent` fires per V.3 frame (one GeoEvent per WS
 * message — no envelope per spec §5.5). Malformed frames
 * are dropped silently (defensive against a future
 * protocol change).
 */

import type { GeoEvent } from '$lib/api/types';

const STREAM_PATH = '/api/v1/ws/geo-events';

/**
 * Connection state of a geo-events WS handle. Surfaces in
 * the /map page's status pill.
 *
 *   - 'connecting'   first attempt in flight.
 *   - 'open'         socket open, frames flowing.
 *   - 'reconnecting' socket closed, backoff in flight.
 *   - 'closed'       caller invoked close(). Terminal.
 */
export type GeoEventStreamState = 'connecting' | 'open' | 'reconnecting' | 'closed';

/** Handle returned by {@link openGeoEventStream}. */
export interface GeoEventStreamHandle {
	/** Close the stream. Idempotent; safe to call from onDestroy. */
	close(): void;
	/** Current connection state. Read-only. */
	readonly state: GeoEventStreamState;
}

/** Optional callback fired on connection-state transitions. */
export type OnStateChange = (state: GeoEventStreamState) => void;

// Backoff schedule (ms): 1 s, 2 s, 5 s, 10 s, 10 s, …
// Capped at 10 s for the same reason topology caps:
// long outages must not stretch the next attempt to
// half a minute.
const RECONNECT_BACKOFF_MS = [1_000, 2_000, 5_000, 10_000];

/**
 * Derive the WS origin from the current page's location.
 * http → ws, https → wss. Same dev-proxy caveats as the
 * topology client — vite.config.ts's /api proxy MUST
 * declare ws: true (it does, verified at V.6 recon).
 */
function wsBaseURL(): string {
	if (typeof window === 'undefined') {
		// SSR / build-time safety: openGeoEventStream is
		// only invoked from onMount, browser-only. The
		// type-checker doesn't know that.
		return '';
	}
	const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
	return `${proto}//${window.location.host}`;
}

/**
 * Open a geo-events live stream. The handler `onEvent` is
 * called once per GeoEvent frame the V.3 broadcaster pushes.
 *
 * On disconnect, the client automatically reconnects with
 * the {@link RECONNECT_BACKOFF_MS} schedule. The caller
 * MUST invoke {@link GeoEventStreamHandle.close} on
 * component unmount, otherwise an orphaned reconnect timer
 * keeps trying after the page is gone.
 *
 * Returns the handle. The handle's `state` is mutable from
 * inside the closure but exposed as readonly to callers.
 */
export function openGeoEventStream(
	onEvent: (event: GeoEvent) => void,
	onStateChange?: OnStateChange
): GeoEventStreamHandle {
	const url = `${wsBaseURL()}${STREAM_PATH}`;

	let socket: WebSocket | null = null;
	let attempt = 0;
	let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
	let closed = false;

	// Reactive state surface. Mutated from inside the
	// closure; the handle returned below shadows it as
	// readonly via a getter.
	let currentState: GeoEventStreamState = 'connecting';
	function setState(next: GeoEventStreamState): void {
		if (next === currentState) return;
		currentState = next;
		if (onStateChange) {
			try {
				onStateChange(next);
			} catch {
				// Caller threw in the state-change handler —
				// not our problem to surface; swallow so the
				// reconnect machinery isn't tripped.
			}
		}
	}

	function scheduleReconnect(): void {
		if (closed) return;
		setState('reconnecting');
		const delay = RECONNECT_BACKOFF_MS[Math.min(attempt, RECONNECT_BACKOFF_MS.length - 1)];
		attempt++;
		reconnectTimer = setTimeout(open, delay);
	}

	function open(): void {
		if (closed) return;
		reconnectTimer = null;
		try {
			socket = new WebSocket(url);
		} catch {
			// Constructor throws synchronously on malformed
			// URL only; schedule a retry rather than
			// propagating.
			scheduleReconnect();
			return;
		}
		socket.onopen = () => {
			// Reset backoff so the NEXT disconnect starts at
			// 1 s, not wherever the previous chain ended.
			attempt = 0;
			setState('open');
		};
		socket.onmessage = (ev) => {
			try {
				const payload = JSON.parse(ev.data as string) as GeoEvent;
				onEvent(payload);
			} catch {
				// Malformed frame — silently drop. Defensive
				// against a future V.x protocol change; the
				// V.3 backend produces well-formed JSON
				// (verified by ws_geo_events_test.go).
			}
		};
		socket.onerror = () => {
			// onerror fires before onclose on most close
			// conditions; we let onclose drive the reconnect
			// so the state transition is single-sourced.
		};
		socket.onclose = () => {
			socket = null;
			if (closed) {
				// Operator-initiated close — terminal state.
				setState('closed');
				return;
			}
			scheduleReconnect();
		};
	}

	open();

	return {
		close(): void {
			if (closed) return;
			closed = true;
			if (reconnectTimer !== null) {
				clearTimeout(reconnectTimer);
				reconnectTimer = null;
			}
			if (socket !== null) {
				try {
					// 1000 = normal closure. The V.3 backend
					// observes a clean close frame, calls
					// the bus unsubscribe defer, tears down.
					socket.close(1000, 'client unmount');
				} catch {
					// close() can throw if the socket is
					// already in CLOSING / CLOSED — swallow.
				}
				socket = null;
			}
			setState('closed');
		},
		get state(): GeoEventStreamState {
			return currentState;
		}
	};
}
