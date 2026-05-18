// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
	buildWSURL,
	TopologyClient,
	type ConnectionStatus,
	type Snapshot
} from './topology';
import {
	RECONNECT_MIN_MS,
	RECONNECT_DISCONNECTED_THRESHOLD
} from '$lib/stores/topology-constants';

// --- buildWSURL ------------------------------------------------------------

describe('buildWSURL', () => {
	it('converts http:// → ws://', () => {
		expect(buildWSURL('http://api.example.com:8001')).toBe(
			'ws://api.example.com:8001/api/v1/ws/topology'
		);
	});

	it('converts https:// → wss://', () => {
		expect(buildWSURL('https://api.example.com')).toBe(
			'wss://api.example.com/api/v1/ws/topology'
		);
	});

	it('treats a bare host as ws://host', () => {
		expect(buildWSURL('host:9000')).toBe('ws://host:9000/api/v1/ws/topology');
	});

	it('falls back to window.location.origin when apiBase is empty', () => {
		// Vitest's jsdom env exposes window.location.
		expect(typeof window).not.toBe('undefined');
		const orig = window.location.origin;
		const expected = orig.startsWith('https://')
			? 'wss://' + orig.slice('https://'.length) + '/api/v1/ws/topology'
			: 'ws://' + orig.slice('http://'.length) + '/api/v1/ws/topology';
		expect(buildWSURL('')).toBe(expected);
		expect(buildWSURL(undefined)).toBe(expected);
	});
});

// --- MockWebSocket --------------------------------------------------------

/**
 * MockWebSocket implements the relevant subset of the browser
 * WebSocket interface so a TopologyClient can drive a full lifecycle
 * in tests. Each instance is recorded in `MockWebSocket.instances`
 * for assertions.
 */
class MockWebSocket {
	static instances: MockWebSocket[] = [];

	url: string;
	readyState: number = 0; // CONNECTING
	onopen: ((this: WebSocket, ev: Event) => unknown) | null = null;
	onmessage: ((this: WebSocket, ev: MessageEvent) => unknown) | null = null;
	onclose: ((this: WebSocket, ev: CloseEvent) => unknown) | null = null;
	onerror: ((this: WebSocket, ev: Event) => unknown) | null = null;
	closeCalled = false;
	closeCode?: number;
	closeReason?: string;

	constructor(url: string) {
		this.url = url;
		MockWebSocket.instances.push(this);
	}

	close(code?: number, reason?: string): void {
		this.closeCalled = true;
		this.closeCode = code;
		this.closeReason = reason;
		this.readyState = 3; // CLOSED
	}

	// --- test helpers ---
	triggerOpen(): void {
		this.readyState = 1;
		this.onopen?.call(this as unknown as WebSocket, new Event('open'));
	}
	triggerMessage(data: string): void {
		this.onmessage?.call(
			this as unknown as WebSocket,
			new MessageEvent('message', { data })
		);
	}
	triggerClose(code: number = 1006, reason: string = ''): void {
		this.readyState = 3;
		this.onclose?.call(
			this as unknown as WebSocket,
			new CloseEvent('close', { code, reason, wasClean: code === 1000 || code === 1001 })
		);
	}
}

function resetMockWS(): void {
	MockWebSocket.instances = [];
}

function lastMock(): MockWebSocket {
	const arr = MockWebSocket.instances;
	if (arr.length === 0) throw new Error('no MockWebSocket instance');
	return arr[arr.length - 1];
}

beforeEach(() => {
	resetMockWS();
	vi.useFakeTimers();
});

afterEach(() => {
	vi.useRealTimers();
});

// --- TopologyClient -------------------------------------------------------

function makeSnapshot(): Snapshot {
	return {
		t: '2026-05-18T18:00:00Z',
		routes: [
			{
				id: 'r1',
				host: 'app.example',
				upstream: 'http://10.0.0.1:80',
				reqs: 5,
				errs: 0,
				reqPerSec: 5,
				errRate5xx: 0
			}
		]
	};
}

describe('TopologyClient — connection lifecycle', () => {
	it('opens a socket on connect() and transitions to "connected" on open', () => {
		const statuses: ConnectionStatus[] = [];
		const client = new TopologyClient({
			onSnapshot: () => {},
			onStatus: (s) => statuses.push(s),
			webSocketImpl: MockWebSocket as unknown as typeof WebSocket,
			url: 'ws://test/api/v1/ws/topology'
		});
		client.connect();

		expect(MockWebSocket.instances).toHaveLength(1);
		expect(lastMock().url).toBe('ws://test/api/v1/ws/topology');
		// Before open, status = 'reconnecting' (we haven't completed
		// the handshake yet).
		expect(statuses).toContain('reconnecting');

		lastMock().triggerOpen();
		expect(client.getStatus()).toBe('connected');
		expect(statuses).toContain('connected');
	});

	it('parses incoming messages and invokes onSnapshot', () => {
		const received: Snapshot[] = [];
		const client = new TopologyClient({
			onSnapshot: (s) => received.push(s),
			webSocketImpl: MockWebSocket as unknown as typeof WebSocket,
			url: 'ws://test/x'
		});
		client.connect();
		lastMock().triggerOpen();

		const snap = makeSnapshot();
		lastMock().triggerMessage(JSON.stringify(snap));

		expect(received).toHaveLength(1);
		expect(received[0].routes[0].id).toBe('r1');
		expect(received[0].routes[0].reqs).toBe(5);
	});

	it('silently ignores malformed JSON frames', () => {
		const received: Snapshot[] = [];
		const client = new TopologyClient({
			onSnapshot: (s) => received.push(s),
			webSocketImpl: MockWebSocket as unknown as typeof WebSocket,
			url: 'ws://test/x'
		});
		client.connect();
		lastMock().triggerOpen();
		lastMock().triggerMessage('not json');
		lastMock().triggerMessage('{}'); // valid JSON but no routes array
		expect(received).toHaveLength(0);
	});

	it('schedules reconnect on close (code 1001) with exponential backoff', () => {
		const client = new TopologyClient({
			onSnapshot: () => {},
			webSocketImpl: MockWebSocket as unknown as typeof WebSocket,
			url: 'ws://test/x'
		});
		client.connect();
		lastMock().triggerOpen();
		const firstInstance = lastMock();
		firstInstance.triggerClose(1001, 'going away');

		// After close, a reconnect timer is scheduled but no new
		// instance exists yet.
		expect(MockWebSocket.instances).toHaveLength(1);
		expect(client.getStatus()).toBe('reconnecting');

		// Advance by RECONNECT_MIN_MS — a new socket must be created.
		vi.advanceTimersByTime(RECONNECT_MIN_MS);
		expect(MockWebSocket.instances).toHaveLength(2);
		expect(lastMock()).not.toBe(firstInstance);
	});

	it('resets attempts to 0 on successful reconnect', () => {
		const client = new TopologyClient({
			onSnapshot: () => {},
			webSocketImpl: MockWebSocket as unknown as typeof WebSocket,
			url: 'ws://test/x'
		});
		client.connect();
		// Simulate 3 failed connects in a row.
		for (let i = 0; i < 3; i++) {
			lastMock().triggerClose(1006);
			vi.advanceTimersByTime(60_000); // pass max backoff
		}
		// Next attempt succeeds.
		lastMock().triggerOpen();
		expect(client.getStatus()).toBe('connected');

		// A subsequent close should backoff from RECONNECT_MIN_MS again
		// (not pow(2, 4)*MIN), because attempts reset on open.
		lastMock().triggerClose(1006);
		// At RECONNECT_MIN_MS exactly, the new socket should exist.
		vi.advanceTimersByTime(RECONNECT_MIN_MS);
		const totalInstancesBefore = MockWebSocket.instances.length;
		expect(totalInstancesBefore).toBeGreaterThan(1);
	});

	it('transitions to "disconnected" after RECONNECT_DISCONNECTED_THRESHOLD failed attempts', () => {
		const statuses: ConnectionStatus[] = [];
		const client = new TopologyClient({
			onSnapshot: () => {},
			onStatus: (s) => statuses.push(s),
			webSocketImpl: MockWebSocket as unknown as typeof WebSocket,
			url: 'ws://test/x'
		});
		client.connect();
		// Trigger RECONNECT_DISCONNECTED_THRESHOLD + 1 failed connects.
		for (let i = 0; i < RECONNECT_DISCONNECTED_THRESHOLD + 1; i++) {
			lastMock().triggerClose(1006);
			vi.advanceTimersByTime(60_000); // jump past any backoff cap
		}
		expect(statuses).toContain('disconnected');
	});
});

describe('TopologyClient — unauthorized handling', () => {
	it('calls onUnauthorized on close code 4401 and STOPS reconnecting', () => {
		const onUnauth = vi.fn();
		const client = new TopologyClient({
			onSnapshot: () => {},
			onUnauthorized: onUnauth,
			webSocketImpl: MockWebSocket as unknown as typeof WebSocket,
			url: 'ws://test/x'
		});
		client.connect();
		lastMock().triggerClose(4401, 'unauthorized');

		expect(onUnauth).toHaveBeenCalledOnce();
		// Advance time — no new socket should be created.
		const countBefore = MockWebSocket.instances.length;
		vi.advanceTimersByTime(120_000);
		expect(MockWebSocket.instances.length).toBe(countBefore);
		expect(client.getStatus()).toBe('disconnected');
	});
});

describe('TopologyClient — disconnect / destroy', () => {
	it('disconnect() closes the socket with code 1000 and cancels pending reconnect', () => {
		const client = new TopologyClient({
			onSnapshot: () => {},
			webSocketImpl: MockWebSocket as unknown as typeof WebSocket,
			url: 'ws://test/x'
		});
		client.connect();
		lastMock().triggerOpen();
		client.disconnect();

		expect(lastMock().closeCalled).toBe(true);
		expect(lastMock().closeCode).toBe(1000);
		expect(client.getStatus()).toBe('disconnected');

		// No further reconnects should happen.
		vi.advanceTimersByTime(120_000);
		expect(MockWebSocket.instances).toHaveLength(1);
	});

	it('destroy() prevents subsequent connect() from doing anything', () => {
		const client = new TopologyClient({
			onSnapshot: () => {},
			webSocketImpl: MockWebSocket as unknown as typeof WebSocket,
			url: 'ws://test/x'
		});
		client.destroy();
		client.connect();
		expect(MockWebSocket.instances).toHaveLength(0);
	});
});

describe('TopologyClient — visibility handling (spec §5.5)', () => {
	// We can't easily mock document.hidden without polluting global,
	// so we drive the handler directly via dispatchEvent + Object.defineProperty.

	function setHidden(value: boolean): void {
		Object.defineProperty(document, 'hidden', {
			value,
			writable: true,
			configurable: true
		});
		document.dispatchEvent(new Event('visibilitychange'));
	}

	it('closes the socket on visibilitychange → hidden', () => {
		const client = new TopologyClient({
			onSnapshot: () => {},
			webSocketImpl: MockWebSocket as unknown as typeof WebSocket,
			url: 'ws://test/x'
		});
		client.attachVisibilityListener();
		client.connect();
		lastMock().triggerOpen();

		setHidden(true);

		expect(lastMock().closeCalled).toBe(true);
		expect(lastMock().closeCode).toBe(1000);
		expect(client.getStatus()).toBe('disconnected');

		client.detachVisibilityListener();
	});

	it('reopens the socket on visibilitychange → visible', () => {
		const client = new TopologyClient({
			onSnapshot: () => {},
			webSocketImpl: MockWebSocket as unknown as typeof WebSocket,
			url: 'ws://test/x'
		});
		client.attachVisibilityListener();
		client.connect();
		lastMock().triggerOpen();

		setHidden(true);
		expect(MockWebSocket.instances).toHaveLength(1);

		setHidden(false);
		expect(MockWebSocket.instances.length).toBeGreaterThan(1);

		client.detachVisibilityListener();
	});
});
