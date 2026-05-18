// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Topology store — client-side state for /topology page (spec §6.7).
//
// Owns the rolling history per route + the connection status, exposed
// as Svelte 5 runes for fine-grained reactivity. Subscribes to the
// TopologyClient (lib/api/topology.ts) which handles the WebSocket
// lifecycle.
//
// Helpers (applyTick / isActive / isErrorSpike / clampErrRate) are
// exported as pure functions for unit testing without rendering
// Svelte. Spec §6.4 / §6.5 thresholds come from topology-constants.ts.

import {
	ACTIVE_WINDOW_MS,
	HISTORY_CAPACITY,
	SPIKE_THRESHOLD,
	SPIKE_WINDOW_TICKS
} from './topology-constants';
import type {
	ConnectionStatus,
	RouteSnapshot,
	Snapshot
} from '$lib/api/topology';

/** A single observation for one route at one tick. */
export interface RouteTick {
	reqs: number;
	errs: number;
	/** Timestamp of the tick in ms epoch (Date.now()-style). */
	ts: number;
}

/** Per-route state retained client-side (spec §6.7). */
export interface RouteState {
	id: string;
	host: string;
	upstream: string;
	history: RouteTick[];
	/** Last tick's reqs (= reqs/sec since TICK_INTERVAL_MS is 1 s). */
	reqPerSec: number;
	/** Last tick's errRate5xx, clamped to [0, 1] (spec §11.8). */
	errRate5xx: number;
}

/**
 * clampErrRate clamps the server-provided errRate5xx to [0, 1].
 *
 * Spec §11.8 documents a rare race where errs > reqs in a single tick
 * (the snapshot's (reqs, errs) swap is not paired-atomic). The client
 * MUST clamp to mask the cosmetic spike; we do it here as part of
 * applyTick so anywhere `state.errRate5xx` is read, the invariant
 * already holds.
 */
export function clampErrRate(value: number): number {
	if (!Number.isFinite(value) || value < 0) return 0;
	if (value > 1) return 1;
	return value;
}

/**
 * applyTick merges one snapshot into the routes map.
 *
 * For each route in the snapshot:
 *   - find or create the RouteState entry;
 *   - push a RouteTick onto its history;
 *   - trim history to HISTORY_CAPACITY (drop oldest);
 *   - update reqPerSec and errRate5xx from the last tick.
 *
 * Routes present in the map but absent from this snapshot are NOT
 * removed by applyTick — the server's full-state ticks (§5.2)
 * normally list every route. Callers that want to prune disappeared
 * routes can do so by comparing the snapshot's route IDs to the
 * map's keys; this helper deliberately doesn't to keep the contract
 * predictable.
 *
 * `nowMs` is supplied so tests can drive a deterministic clock; in
 * production it defaults to Date.now().
 */
export function applyTick(
	routes: Map<string, RouteState>,
	snap: Snapshot,
	nowMs: number = Date.now()
): void {
	for (const r of snap.routes) {
		const existing = routes.get(r.id);
		const tick: RouteTick = { reqs: r.reqs, errs: r.errs, ts: nowMs };
		if (existing) {
			existing.history.push(tick);
			if (existing.history.length > HISTORY_CAPACITY) {
				existing.history.splice(0, existing.history.length - HISTORY_CAPACITY);
			}
			existing.host = r.host;
			existing.upstream = r.upstream;
			existing.reqPerSec = r.reqPerSec;
			existing.errRate5xx = clampErrRate(r.errRate5xx);
		} else {
			routes.set(r.id, {
				id: r.id,
				host: r.host,
				upstream: r.upstream,
				history: [tick],
				reqPerSec: r.reqPerSec,
				errRate5xx: clampErrRate(r.errRate5xx)
			});
		}
	}
}

/**
 * isActive returns true if the route saw ≥ 1 request in the last
 * ACTIVE_WINDOW_MS (spec §6.5 / §8 activeWindow). Used by the UI
 * to dim idle nodes.
 */
export function isActive(state: RouteState, nowMs: number = Date.now()): boolean {
	const cutoff = nowMs - ACTIVE_WINDOW_MS;
	return state.history.some((t) => t.reqs > 0 && t.ts >= cutoff);
}

/**
 * isErrorSpike returns true if, over the most recent SPIKE_WINDOW_TICKS
 * (10 ticks ≈ 10 s), the aggregate 5xx ratio exceeds SPIKE_THRESHOLD
 * (5 %). Spec §6.5 / §8.
 *
 * Returns false if the window has zero reqs (no traffic ⇒ no spike).
 */
export function isErrorSpike(state: RouteState): boolean {
	const window = state.history.slice(-SPIKE_WINDOW_TICKS);
	if (window.length === 0) return false;
	let reqs = 0;
	let errs = 0;
	for (const t of window) {
		reqs += t.reqs;
		errs += t.errs;
	}
	if (reqs === 0) return false;
	return errs / reqs > SPIKE_THRESHOLD;
}

/**
 * Singleton topology store. Exposed as $state runes so consumers
 * (the /topology page and its child components) re-render on tick.
 *
 * Following the Step D pattern (auth.svelte.ts / idle.svelte.ts), a
 * class instance is exported as a const. Tests of the *helpers*
 * import them directly; tests of the *store* import the singleton
 * and rely on Vitest's module caching for isolation.
 */
class TopologyStore {
	routes = $state(new Map<string, RouteState>());
	connectionStatus = $state<ConnectionStatus>('disconnected');
	lastTickAt = $state<Date | null>(null);

	/** Apply one Snapshot frame. Called by the page after the
	 *  TopologyClient delivers a JSON tick. */
	apply(snap: Snapshot): void {
		applyTick(this.routes, snap);
		this.lastTickAt = new Date();
	}

	/** Update the connection status (called by the page on every
	 *  status transition from the TopologyClient). */
	setStatus(s: ConnectionStatus): void {
		this.connectionStatus = s;
	}

	/** Reset to empty state — used on page unmount and in tests. */
	clear(): void {
		this.routes = new Map<string, RouteState>();
		this.connectionStatus = 'disconnected';
		this.lastTickAt = null;
	}

	/** Convenience accessor: number of routes currently tracked. */
	size(): number {
		return this.routes.size;
	}

	/** Convenience accessor: returns the RouteState for a given id,
	 *  or undefined. Used by TopologyDetailPanel in Chunk 5. */
	get(id: string): RouteState | undefined {
		return this.routes.get(id);
	}

	/** Snapshot for unit tests / debugging — flattens the map into a
	 *  RouteState[] (stable order = map insertion order). */
	list(): RouteState[] {
		return Array.from(this.routes.values());
	}

	/** Last-known traffic helper for the Clients pillar (spec §6.2)
	 *  — sum of every route's last-tick reqs. */
	totalReqPerSec(): number {
		let total = 0;
		for (const r of this.routes.values()) total += r.reqPerSec;
		return total;
	}
}

export const topology = new TopologyStore();

/** Re-export RouteSnapshot so consumers needn't reach into $lib/api. */
export type { RouteSnapshot, Snapshot, ConnectionStatus };
