// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

/**
 * Topology Phase 2 live data feed client.
 *
 * Two surfaces:
 *
 *   - fetchSnapshot()      → one-shot GET /api/v1/topology/snapshot
 *   - connectLiveStream()  → WebSocket subscription to
 *                            /api/v1/topology/stream, fired on connect
 *                            and on each emit tick
 *
 * Both ship the session cookie (credentials: 'include' for the HTTP
 * GET; the browser auto-attaches cookies to WS upgrades on the
 * same origin). Server-side hard-auth gates both endpoints; an
 * unauthorised caller gets HTTP 401 on the snapshot path and 401
 * BEFORE the WS upgrade on the stream path — see docs/api/
 * topology.md "Stage A limitations" §Auth.
 *
 * Spec: docs/api/topology.md.
 */

import type { TopologyRoute } from './_types';

// BASE mirrors lib/api/client.ts: empty in prod (binary serves both
// API and SPA on the same origin), VITE_API_BASE_URL in dev when
// the SPA runs on Vite:5173 cross-origin from the API at :8001.
// We re-derive here rather than importing from client.ts to keep
// the topology route's dependency surface minimal — _api.ts has
// no other reason to pull in the full HTTP client + ApiError +
// auth/loading/toast stores.
const BASE: string = import.meta.env.DEV
	? ((import.meta.env.VITE_API_BASE_URL ?? '') as string)
	: '';

const SNAPSHOT_PATH = '/api/v1/topology/snapshot';
const STREAM_PATH = '/api/v1/topology/stream';

/** Payload shape the snapshot endpoint returns. Mirrors the
 *  backend's topology.SnapshotResponse — strictly the fields the
 *  frontend consumes (no envelope, no rewrapping). */
export interface SnapshotPayload {
	generatedAt: string; // RFC 3339 UTC with Z suffix
	routes: TopologyRoute[];
}

/** Error thrown by fetchSnapshot on non-2xx or network failure.
 *  We don't reuse the lib/api/client ApiError because this module
 *  intentionally has no dependency on the rest of the API client
 *  stack — it stays self-contained inside the topology route. */
export class TopologyFetchError extends Error {
	public readonly status: number;
	constructor(message: string, status: number) {
		super(message);
		this.name = 'TopologyFetchError';
		this.status = status;
	}
}

/**
 * Fetch the current topology snapshot. Used on page mount and as
 * a manual retry trigger from the error state.
 *
 * Throws TopologyFetchError on non-2xx or network failure. The
 * caller is expected to surface a UI message and offer retry.
 */
export async function fetchSnapshot(signal?: AbortSignal): Promise<SnapshotPayload> {
	let res: Response;
	try {
		res = await fetch(`${BASE}${SNAPSHOT_PATH}`, {
			method: 'GET',
			credentials: 'include',
			signal,
		});
	} catch (err) {
		// fetch() throws on network errors; surface as a generic
		// fetch error with status 0 so the caller can distinguish
		// "server returned X" from "couldn't reach the server".
		const msg = err instanceof Error ? err.message : String(err);
		throw new TopologyFetchError(`network error: ${msg}`, 0);
	}
	if (!res.ok) {
		// Try to surface the server's error message body when present;
		// fall back to the status text. The snapshot handler returns
		// plain text on errors via http.Error, so we read text.
		let body = '';
		try {
			body = await res.text();
		} catch {
			// ignore — fall back to status text below
		}
		const msg = body.trim() || res.statusText || `HTTP ${res.status}`;
		throw new TopologyFetchError(msg, res.status);
	}
	return (await res.json()) as SnapshotPayload;
}

/** Callback fired on each WS emit. Receives the parsed routes
 *  list ready to feed into buildProtocolGraph / buildServiceToBackendGraph. */
export type OnTick = (routes: TopologyRoute[], generatedAt: string) => void;

/** Optional disconnect callback — the page uses it to flip the
 *  connection-status indicator while reconnect attempts are in
 *  flight. */
export type OnDisconnect = () => void;

/** wsBaseURL derives the WebSocket origin from the current page's
 *  location, swapping http→ws / https→wss. In prod (binary serves
 *  the SPA and the API on the same origin) this matches the API
 *  origin trivially. In dev (Vite at :5173, API at :8001) Vite's
 *  proxy forwards the WS upgrade to :8001 ONLY because vite.config.ts
 *  declares the /api proxy in the full-object form with `ws: true`.
 *  The shorthand `'/api': 'http://localhost:8001'` form does NOT
 *  forward WebSocket upgrades — only plain HTTP — so the upgrade
 *  hits Vite's dev server and silently fails. If you ever see the
 *  topology page stuck on "reconnecting…" in dev, verify the
 *  vite.config.ts proxy block still has `ws: true`. */
function wsBaseURL(): string {
	if (typeof window === 'undefined') {
		// SSR/build-time safety. Should never be hit at runtime —
		// connectLiveStream is called from onMount, which is
		// browser-only — but the type-checker doesn't know that.
		return '';
	}
	const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
	return `${proto}//${window.location.host}`;
}

// Reconnect backoff schedule (in seconds): 1, 2, 5, 10, 10, 10, ...
// We cap at 10 s so a long outage doesn't make the operator wait
// half a minute for the next attempt once the backend comes back.
const RECONNECT_BACKOFF_MS = [1_000, 2_000, 5_000, 10_000];

/**
 * Open a live-stream subscription. The handler is fired:
 *   - On initial connect: the server's first emit happens
 *     immediately on connection (spec contract).
 *   - On every subsequent emit tick (default 2 s cadence).
 *
 * Returns a close function the caller MUST invoke on unmount.
 * The close function:
 *   - Sets a "no reconnect" flag so any in-flight backoff stops.
 *   - Closes the underlying WebSocket if open.
 *
 * On connection drop, an automatic reconnect runs with the
 * RECONNECT_BACKOFF_MS schedule. The page's UI is expected to
 * surface a disconnect indicator via the optional onDisconnect
 * callback — invoked when the socket closes (whether the close
 * was clean or abrupt).
 */
export function connectLiveStream(
	onTick: OnTick,
	onDisconnect?: OnDisconnect
): () => void {
	let socket: WebSocket | null = null;
	let attempt = 0;
	let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
	let closed = false; // operator-initiated close — stop reconnecting

	const url = `${wsBaseURL()}${STREAM_PATH}`;

	function scheduleReconnect(): void {
		if (closed) return;
		const delay =
			RECONNECT_BACKOFF_MS[Math.min(attempt, RECONNECT_BACKOFF_MS.length - 1)];
		attempt++;
		reconnectTimer = setTimeout(open, delay);
	}

	function open(): void {
		if (closed) return;
		reconnectTimer = null;
		try {
			socket = new WebSocket(url);
		} catch (_err) {
			// Constructor throws synchronously on malformed URL only;
			// schedule a retry rather than propagating.
			scheduleReconnect();
			return;
		}
		socket.onopen = () => {
			// Reset the backoff counter so the next disconnect
			// starts at 1 s again rather than wherever the
			// previous chain ended.
			attempt = 0;
		};
		socket.onmessage = (ev) => {
			try {
				const payload = JSON.parse(ev.data as string) as SnapshotPayload;
				onTick(payload.routes ?? [], payload.generatedAt ?? '');
			} catch {
				// Malformed frame — silently drop. The server
				// produces well-formed JSON; this branch is
				// defensive against a future protocol change.
			}
		};
		socket.onerror = () => {
			// onerror fires before onclose on most close conditions;
			// we don't act here — onclose drives the reconnect.
		};
		socket.onclose = () => {
			socket = null;
			if (onDisconnect) {
				try {
					onDisconnect();
				} catch {
					// Caller threw in the disconnect handler — not
					// our problem to surface; swallow so the
					// reconnect machinery isn't tripped.
				}
			}
			scheduleReconnect();
		};
	}

	open();

	return () => {
		closed = true;
		if (reconnectTimer !== null) {
			clearTimeout(reconnectTimer);
			reconnectTimer = null;
		}
		if (socket !== null) {
			// 1000 == normal closure. The server sees a clean close
			// frame, unsubscribes from the broadcaster, and tears
			// down the connection.
			try {
				socket.close(1000, 'client unmount');
			} catch {
				// If close() throws (very rare — e.g. already in
				// CLOSING state), the connection is going away
				// anyway.
			}
			socket = null;
		}
	};
}
