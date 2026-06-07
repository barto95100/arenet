// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step V.6 — geo-events-stream tests.
//
// Strategy: replace the global WebSocket constructor with
// a hand-rolled stub that exposes the same surface
// (onopen, onmessage, onclose, close) plus test hooks the
// test drives directly (simulateOpen, simulateClose,
// simulateMessage). vi.useFakeTimers() controls the
// setTimeout the reconnect backoff uses.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { openGeoEventStream } from './geo-events-stream';
import type { GeoEvent } from '$lib/api/types';

// Minimal WebSocket stub. Implements just enough of the
// real API for openGeoEventStream to drive it.
class FakeWebSocket {
	static instances: FakeWebSocket[] = [];
	static lastUrl = '';

	url: string;
	readyState: number = 0; // CONNECTING
	onopen: ((ev: Event) => void) | null = null;
	onmessage: ((ev: MessageEvent) => void) | null = null;
	onclose: ((ev: CloseEvent) => void) | null = null;
	onerror: ((ev: Event) => void) | null = null;
	closeCalled = false;
	closeCode: number | undefined;
	closeReason: string | undefined;

	constructor(url: string) {
		this.url = url;
		FakeWebSocket.lastUrl = url;
		FakeWebSocket.instances.push(this);
	}

	// Test hooks — drive the lifecycle from the test code.
	simulateOpen() {
		this.readyState = 1; // OPEN
		this.onopen?.(new Event('open'));
	}
	simulateMessage(data: unknown) {
		this.onmessage?.(new MessageEvent('message', { data: JSON.stringify(data) }));
	}
	simulateRawMessage(raw: string) {
		this.onmessage?.(new MessageEvent('message', { data: raw }));
	}
	simulateClose() {
		this.readyState = 3; // CLOSED
		this.onclose?.(new CloseEvent('close'));
	}

	close(code?: number, reason?: string) {
		this.closeCalled = true;
		this.closeCode = code;
		this.closeReason = reason;
		this.readyState = 3;
	}

	static reset() {
		FakeWebSocket.instances = [];
		FakeWebSocket.lastUrl = '';
	}
}

const originalWebSocket = globalThis.WebSocket;
const originalWindow = globalThis.window;

beforeEach(() => {
	FakeWebSocket.reset();
	// @ts-expect-error — install our stub
	globalThis.WebSocket = FakeWebSocket;
	// Stub window.location so wsBaseURL() builds a URL.
	// jsdom provides window by default; we just ensure
	// location is reachable from the stream module.
	if (!globalThis.window) {
		Object.defineProperty(globalThis, 'window', {
			configurable: true,
			value: { location: { protocol: 'http:', host: 'localhost:5173' } }
		});
	}
	vi.useFakeTimers();
});

afterEach(() => {
	vi.useRealTimers();
	globalThis.WebSocket = originalWebSocket;
	if (originalWindow === undefined) {
		delete (globalThis as { window?: unknown }).window;
	}
});

function lastSocket(): FakeWebSocket {
	expect(FakeWebSocket.instances.length).toBeGreaterThan(0);
	return FakeWebSocket.instances[FakeWebSocket.instances.length - 1];
}

const sampleEvent: GeoEvent = {
	timestamp: '2026-06-07T10:00:00.000Z',
	category: 'waf',
	sourceIp: '203.0.113.42',
	sourceLat: 48.8566,
	sourceLon: 2.3522,
	sourceCountry: 'FR',
	sourceCity: 'Paris',
	isLan: false,
	details: '942100'
};

describe('openGeoEventStream', () => {
	it('opens a WebSocket against /api/v1/ws/geo-events on construction', () => {
		const handle = openGeoEventStream(() => {});
		// jsdom's default location host varies (3000 / 5173)
		// across vitest versions; pin the path + protocol
		// only. The url-shape regression that mattered for
		// V.5 (ws:// vs http://, /api/v1/ws/geo-events path)
		// is what we want to lock here.
		expect(FakeWebSocket.lastUrl).toMatch(/^ws:\/\/[^/]+\/api\/v1\/ws\/geo-events$/);
		expect(handle.state).toBe('connecting');
		handle.close();
	});

	it('transitions to "open" on socket open', () => {
		const states: string[] = [];
		const handle = openGeoEventStream(
			() => {},
			(s) => {
				states.push(s);
			}
		);
		lastSocket().simulateOpen();
		expect(handle.state).toBe('open');
		expect(states).toContain('open');
		handle.close();
	});

	it('delivers parsed GeoEvents to onEvent', () => {
		const received: GeoEvent[] = [];
		const handle = openGeoEventStream((ev) => {
			received.push(ev);
		});
		lastSocket().simulateOpen();
		lastSocket().simulateMessage(sampleEvent);
		expect(received).toHaveLength(1);
		expect(received[0].sourceIp).toBe('203.0.113.42');
		handle.close();
	});

	it('silently drops malformed JSON frames', () => {
		const received: GeoEvent[] = [];
		const handle = openGeoEventStream((ev) => {
			received.push(ev);
		});
		lastSocket().simulateOpen();
		// Drop a frame with a partial JSON shape — must not
		// throw and must not deliver to onEvent.
		lastSocket().simulateRawMessage('{ not valid json');
		expect(received).toHaveLength(0);
		// Subsequent valid frame still delivered.
		lastSocket().simulateMessage(sampleEvent);
		expect(received).toHaveLength(1);
		handle.close();
	});

	it('reconnects on unexpected close with exponential backoff', async () => {
		const states: string[] = [];
		const handle = openGeoEventStream(
			() => {},
			(s) => {
				states.push(s);
			}
		);
		// First connect.
		lastSocket().simulateOpen();
		expect(handle.state).toBe('open');
		// Simulate disconnect — schedules reconnect.
		lastSocket().simulateClose();
		expect(handle.state).toBe('reconnecting');
		// Backoff: first attempt is 1 s. Advance timers.
		await vi.advanceTimersByTimeAsync(1000);
		expect(FakeWebSocket.instances.length).toBe(2);
		// Second connect succeeds.
		lastSocket().simulateOpen();
		expect(handle.state).toBe('open');
		handle.close();
	});

	it('resets the backoff after a successful reconnect', async () => {
		const handle = openGeoEventStream(() => {});
		// Drop + reconnect twice to drive the backoff past 1 s,
		// then a successful open must reset it for the next cycle.
		lastSocket().simulateOpen();
		lastSocket().simulateClose();
		await vi.advanceTimersByTimeAsync(1000); // 1st backoff = 1 s
		lastSocket().simulateOpen();
		// Cycle 2: another drop. The backoff is back to 1 s.
		lastSocket().simulateClose();
		await vi.advanceTimersByTimeAsync(1000);
		expect(FakeWebSocket.instances.length).toBe(3);
		handle.close();
	});

	it('escalates the backoff on repeated failed reconnects', async () => {
		const handle = openGeoEventStream(() => {});
		// Initial socket.
		expect(FakeWebSocket.instances.length).toBe(1);
		// Drop without ever opening. Reconnect schedule:
		// 1 s → 2 s → 5 s → 10 s.
		lastSocket().simulateClose();
		await vi.advanceTimersByTimeAsync(1000);
		expect(FakeWebSocket.instances.length).toBe(2);
		lastSocket().simulateClose();
		await vi.advanceTimersByTimeAsync(2000);
		expect(FakeWebSocket.instances.length).toBe(3);
		lastSocket().simulateClose();
		await vi.advanceTimersByTimeAsync(5000);
		expect(FakeWebSocket.instances.length).toBe(4);
		lastSocket().simulateClose();
		await vi.advanceTimersByTimeAsync(10000);
		expect(FakeWebSocket.instances.length).toBe(5);
		handle.close();
	});

	it('does NOT reconnect after explicit close', async () => {
		const handle = openGeoEventStream(() => {});
		lastSocket().simulateOpen();
		handle.close();
		expect(handle.state).toBe('closed');
		// Advance well beyond the maximum backoff — no new
		// socket must be created.
		await vi.advanceTimersByTimeAsync(60_000);
		expect(FakeWebSocket.instances.length).toBe(1);
	});

	it('emits CLOSE code 1000 on explicit close', () => {
		const handle = openGeoEventStream(() => {});
		lastSocket().simulateOpen();
		handle.close();
		expect(lastSocket().closeCalled).toBe(true);
		expect(lastSocket().closeCode).toBe(1000);
	});

	it('is idempotent — close() twice is a no-op', () => {
		const handle = openGeoEventStream(() => {});
		lastSocket().simulateOpen();
		handle.close();
		expect(() => handle.close()).not.toThrow();
		expect(handle.state).toBe('closed');
	});

	it('swallows onStateChange callback errors', () => {
		// A misbehaving caller must not trip the reconnect
		// machinery. Pin the contract so a future refactor
		// can't drop the try/catch silently.
		const handle = openGeoEventStream(
			() => {},
			() => {
				throw new Error('handler explosion');
			}
		);
		expect(() => lastSocket().simulateOpen()).not.toThrow();
		handle.close();
	});
});
