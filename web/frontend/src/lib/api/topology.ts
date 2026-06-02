// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Typed wrapper + WebSocket client for the live-metrics topology
// endpoint (spec §5). Connects to /api/v1/ws/topology, drains 1 Hz
// Snapshot frames, and exposes them via a subscribe(handler) API.
// Reconnect lifecycle per spec §5.5 (exponential backoff, visibility
// handling, unauthorized → /login).

import {
	RECONNECT_MIN_MS,
	RECONNECT_MAX_MS,
	RECONNECT_DISCONNECTED_THRESHOLD
} from '$lib/stores/topology-constants';

/** Mirror of internal/metrics.RouteSnapshot (Go wire shape §5.2). */
export interface RouteSnapshot {
	id: string;
	host: string;
	upstream: string;
	reqs: number;
	errs: number;
	reqPerSec: number;
	errRate5xx: number;
}

/** Mirror of internal/metrics.Snapshot (Go wire shape §5.2). */
export interface Snapshot {
	t: string; // RFC 3339 UTC, server-side wall clock
	routes: RouteSnapshot[];
}

/** Connection status surfaced to the UI (spec §6.8). */
export type ConnectionStatus = 'connected' | 'reconnecting' | 'disconnected';

/** Callback signature for snapshot subscribers. */
export type SnapshotHandler = (snap: Snapshot) => void;

/** Callback signature for connection-status changes. */
export type StatusHandler = (status: ConnectionStatus) => void;

/** Callback for the handshake-401 case (spec §5.5). The page is
 *  expected to redirect to /login. */
export type UnauthorizedHandler = () => void;

interface TopologyClientOptions {
	/** Snapshot handler — called on every successful frame. */
	onSnapshot: SnapshotHandler;

	/** Optional status handler — called whenever the connection
	 *  status transitions. */
	onStatus?: StatusHandler;

	/** Optional unauthorized handler — called when the handshake
	 *  returns 401. The default implementation logs and stays
	 *  disconnected. */
	onUnauthorized?: UnauthorizedHandler;

	/** Override the WebSocket constructor. For tests only. */
	webSocketImpl?: typeof WebSocket;

	/** Override the WS URL builder. For tests only. Default uses
	 *  VITE_API_BASE_URL or window.location.origin. */
	url?: string;
}

const PATH = '/api/v1/ws/topology';

/**
 * Compute the WebSocket URL from the API base. Mirrors client.ts's
 * VITE_API_BASE_URL convention: if set, derive ws(s)://host:port/PATH
 * from it; otherwise fall back to the current page's origin.
 *
 * Exported for direct testing.
 */
export function buildWSURL(apiBase: string | undefined): string {
	const base =
		(apiBase && apiBase.length > 0)
			? apiBase
			: typeof window !== 'undefined'
				? window.location.origin
				: '';
	if (!base) {
		// No base and no window — should never happen in normal app
		// flow. Return a dummy that will fail-fast on dial.
		return 'ws://localhost' + PATH;
	}
	// Replace http(s):// with ws(s)://.
	if (base.startsWith('https://')) return 'wss://' + base.slice('https://'.length) + PATH;
	if (base.startsWith('http://')) return 'ws://' + base.slice('http://'.length) + PATH;
	// base may already be host:port without scheme — assume ws://
	return 'ws://' + base + PATH;
}

/**
 * TopologyClient encapsulates the live-metrics WebSocket lifecycle:
 *
 *   - connect() opens the WS, registers handlers.
 *   - On a clean close (server shutdown 1001 or normal 1000), schedule
 *     a reconnect with exponential backoff (spec §5.5).
 *   - On a handshake 401 (read from the close code 4401 emitted by
 *     gorilla on auth failure handshake, or inferred from a non-101
 *     response), fire onUnauthorized and STOP reconnecting.
 *   - visibilitychange → hidden: actively close, pause reconnect.
 *   - visibilitychange → visible: immediate reconnect.
 *   - disconnect(): close + cancel timers.
 *
 * The client is single-shot per instance: you can call connect/
 * disconnect repeatedly, but typical usage is one instance per page.
 */
export class TopologyClient {
	private readonly opts: TopologyClientOptions;
	private readonly WS: typeof WebSocket;
	private readonly url: string;

	private socket: WebSocket | null = null;
	private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
	private reconnectAttempts = 0;
	private status: ConnectionStatus = 'disconnected';
	private destroyed = false;
	private wantConnected = false;

	constructor(opts: TopologyClientOptions) {
		this.opts = opts;
		this.WS = opts.webSocketImpl ?? (typeof WebSocket !== 'undefined' ? WebSocket : (undefined as never));
		// Step #S-21: same gate as client.ts — VITE_API_BASE_URL is a
		// dev-only override (see vite.config proxy); in prod let
		// buildWSURL fall back to window.location.origin so the WS
		// connects to the same origin the page was loaded from.
		this.url = opts.url ?? buildWSURL(
			import.meta.env.DEV
				? (import.meta.env?.VITE_API_BASE_URL as string | undefined)
				: undefined
		);
	}

	/** Begin the connection lifecycle. Idempotent — calling twice
	 *  while connected is a no-op. */
	connect(): void {
		if (this.destroyed) return;
		this.wantConnected = true;
		if (this.socket !== null) return;
		this.open();
	}

	/** Close any open socket and cancel pending reconnect timers.
	 *  Idempotent. After disconnect(), the client can be reused via
	 *  connect(). */
	disconnect(): void {
		this.wantConnected = false;
		this.cancelReconnect();
		this.closeSocket(1000, 'client disconnect');
		this.setStatus('disconnected');
	}

	/** Tear down the client permanently (e.g., page unmount).
	 *  After destroy(), connect() is a no-op and visibilitychange
	 *  listeners are removed. */
	destroy(): void {
		this.destroyed = true;
		this.disconnect();
		this.detachVisibilityListener();
	}

	/** Wire up the document.visibilitychange listener. Idempotent;
	 *  attaches at most once. Called by the consumer (typically the
	 *  page) explicitly so SSR / non-browser environments stay opt-in.
	 */
	attachVisibilityListener(): void {
		if (typeof document === 'undefined') return;
		document.addEventListener('visibilitychange', this.onVisibilityChange);
	}

	detachVisibilityListener(): void {
		if (typeof document === 'undefined') return;
		document.removeEventListener('visibilitychange', this.onVisibilityChange);
	}

	/** Current connection status — useful for testing. */
	getStatus(): ConnectionStatus {
		return this.status;
	}

	// --- internals ---------------------------------------------------

	private open(): void {
		if (this.destroyed) return;
		if (!this.WS) {
			console.error('topology: no WebSocket implementation available');
			this.setStatus('disconnected');
			return;
		}
		this.setStatus(this.reconnectAttempts > 0 ? 'reconnecting' : 'reconnecting');

		const ws = new this.WS(this.url);
		this.socket = ws;

		ws.onopen = () => {
			this.reconnectAttempts = 0;
			this.setStatus('connected');
		};

		ws.onmessage = (ev: MessageEvent) => {
			try {
				const data = typeof ev.data === 'string' ? ev.data : '';
				if (!data) return;
				const parsed = JSON.parse(data) as Snapshot;
				if (parsed && Array.isArray(parsed.routes)) {
					this.opts.onSnapshot(parsed);
				}
			} catch (err) {
				console.warn('topology: malformed frame, ignoring', err);
			}
		};

		ws.onerror = () => {
			// Error events don't carry useful info in browsers; the
			// authoritative signal is the subsequent onclose.
		};

		ws.onclose = (ev: CloseEvent) => {
			this.socket = null;

			// 4401 is the convention we adopt for "unauthorized after
			// upgrade" — gorilla itself does not emit it for handshake
			// rejection (the handshake never upgrades on 401). For
			// handshake rejection, code 1006 is observed instead;
			// future-proof by treating 4401 explicitly AND triggering
			// onUnauthorized when we know we're unauthorized.
			if (ev.code === 4401) {
				this.handleUnauthorized();
				return;
			}

			if (this.destroyed || !this.wantConnected) {
				this.setStatus('disconnected');
				return;
			}

			this.scheduleReconnect();
		};
	}

	private closeSocket(code: number, reason: string): void {
		if (this.socket === null) return;
		try {
			this.socket.close(code, reason);
		} catch {
			// ignore
		}
		this.socket = null;
	}

	private scheduleReconnect(): void {
		if (this.destroyed || !this.wantConnected) return;

		const attempt = this.reconnectAttempts;
		const delay = Math.min(RECONNECT_MIN_MS * Math.pow(2, attempt), RECONNECT_MAX_MS);

		// Spec §6.8: ≥ 5 consecutive failures → "disconnected" status.
		if (attempt >= RECONNECT_DISCONNECTED_THRESHOLD) {
			this.setStatus('disconnected');
		} else {
			this.setStatus('reconnecting');
		}

		this.reconnectAttempts = attempt + 1;
		this.cancelReconnect();
		this.reconnectTimer = setTimeout(() => {
			this.reconnectTimer = null;
			this.open();
		}, delay);
	}

	private cancelReconnect(): void {
		if (this.reconnectTimer !== null) {
			clearTimeout(this.reconnectTimer);
			this.reconnectTimer = null;
		}
	}

	private setStatus(s: ConnectionStatus): void {
		if (s === this.status) return;
		this.status = s;
		this.opts.onStatus?.(s);
	}

	private handleUnauthorized(): void {
		this.wantConnected = false;
		this.cancelReconnect();
		this.setStatus('disconnected');
		if (this.opts.onUnauthorized) {
			this.opts.onUnauthorized();
		} else {
			console.warn('topology: unauthorized; redirect to /login expected');
		}
	}

	private onVisibilityChange = (): void => {
		if (typeof document === 'undefined') return;
		if (document.hidden) {
			// Per spec §5.5: actively close on hidden, pause reconnect.
			this.cancelReconnect();
			this.closeSocket(1000, 'tab hidden');
			this.setStatus('disconnected');
		} else if (this.wantConnected) {
			// Per spec §5.5: re-open immediately on visible, no backoff.
			this.reconnectAttempts = 0;
			this.cancelReconnect();
			this.open();
		}
	};
}
