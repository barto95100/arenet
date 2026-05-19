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

import { SvelteMap } from 'svelte/reactivity';
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
 *   - build a NEW RouteState object (immutable replace pattern);
 *   - copy host / upstream / reqPerSec / errRate5xx from the wire;
 *   - append the new tick onto a FRESH history array (preserving the
 *     old entries) and trim to HISTORY_CAPACITY;
 *   - put the new object back via `routes.set(r.id, newObj)`.
 *
 * IMPORTANT — IMMUTABLE REPLACE PATTERN (regression guard for the
 * v0.3.0-step-e smoke session).
 *
 * Earlier versions mutated the existing RouteState's fields in
 * place (`existing.reqPerSec = r.reqPerSec`). Plain-object property
 * assignment is NOT reactive in Svelte 5 — only `$state` rune
 * fields and `SvelteMap` / `SvelteSet` mutations emit signals.
 * Consumers that read `route.reqPerSec` inside a `$derived` were
 * stuck on the value they observed at first render, even though
 * the field had been mutated.
 *
 * Replacing the entire object via `routes.set(r.id, newObj)`
 * triggers SvelteMap's per-key source notification: any consumer
 * that read this key (or iterated the map) gets invalidated and
 * picks up the fresh object reference, which carries the new
 * reqPerSec / errRate5xx / history. Cost: one extra Object
 * allocation per route per tick. Acceptable at 1 Hz.
 *
 * History is also copied (rather than mutated in place) so the
 * old object's history array stays stable for any consumer still
 * holding a reference (sparkline component, etc.) until they
 * pick up the new one.
 *
 * Routes present in the map but absent from this snapshot are NOT
 * removed by applyTick — the server's full-state ticks (§5.2)
 * normally list every route. Callers that want to prune
 * disappeared routes can do so by comparing the snapshot's route
 * IDs to the map's keys; this helper deliberately doesn't to keep
 * the contract predictable.
 *
 * `nowMs` is supplied so tests can drive a deterministic clock;
 * in production it defaults to Date.now().
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
			// Build a fresh history array (immutable push + trim).
			const newHistory =
				existing.history.length >= HISTORY_CAPACITY
					? [...existing.history.slice(existing.history.length - HISTORY_CAPACITY + 1), tick]
					: [...existing.history, tick];
			// Replace the entire RouteState — fresh object reference
			// is what triggers SvelteMap's per-key notification.
			routes.set(r.id, {
				id: r.id,
				host: r.host,
				upstream: r.upstream,
				history: newHistory,
				reqPerSec: r.reqPerSec,
				errRate5xx: clampErrRate(r.errRate5xx)
			});
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
 * Singleton topology store.
 *
 * REACTIVITY PATTERN — EXPLICIT VERSION COUNTER. Read this before
 * touching the class.
 *
 * Background. During the v0.3.0-step-e smoke session, every
 * idiomatic Svelte 5 reactivity pattern failed to propagate Map
 * mutations from this module to the consumer page:
 *
 *   - `routes = $state(new Map())` field, read from
 *     `$derived(topology.list())` method calls in the page;
 *   - `list = $derived(Array.from(this.routes.values()))` field;
 *   - `list = $derived.by(() => Array.from(...))` field;
 *   - `get list()` getter, read from
 *     `$derived.by(() => topology.list)` in the page;
 *   - `routes = new SvelteMap()` explicit (skipping the
 *     auto-conversion of `$state(new Map())`), iterated DIRECTLY
 *     in the page's `$derived(Array.from(topology.routes.values()))`.
 *
 * All five patterns produced the same symptom: the page's
 * `$derived` was evaluated once at mount and never invalidated by
 * subsequent `routes.set()` calls, even though `topology.routes.size`
 * inspected directly in DevTools reflected the mutation.
 *
 * Empirical conclusion: Svelte 5.55 (the version pinned in this
 * project) does not reliably surface SvelteMap mutation signals
 * across module boundaries when the SvelteMap lives on a class
 * instance imported from a `.svelte.ts` module. The underlying
 * version source is incremented inside SvelteMap, but the
 * subscriber graph linking it to the consumer's `$derived` is not
 * set up — likely a runtime caveat around how class fields are
 * initialized vs how `$state` is wired by the compiler.
 *
 * Workaround. We add an explicit `$state` counter — `version` —
 * incremented in every mutator. Consumers' `$derived` blocks read
 * `void this.version` at the top, which subscribes them to the
 * counter (a plain `$state(number)`, which IS reliably reactive
 * cross-module). On the next access after a mutation, the counter
 * has incremented, the consumer's `$derived` invalidates, and the
 * iteration that follows reads the fresh Map state.
 *
 * Aesthetic cost: a `void this.version;` line at the top of each
 * consuming `$derived`. Architectural cost: every mutator must
 * bump `this.version`. Both are acceptable to unblock the smoke;
 * a future Svelte upgrade or a different store pattern (signal
 * library, manual subscription) may eliminate the need.
 *
 * `clear()` uses `routes.clear()` (in-place mutation) rather than
 * reassigning a fresh SvelteMap, to keep any external references
 * stable and avoid invalidating the cross-class wiring twice.
 *
 * The `list`, `size`, `totalReqPerSec` getters and the `get(id)`
 * method stay for non-reactive callers (tests, console debugging)
 * — they read the current Map state directly.
 */
class TopologyStore {
	routes = new SvelteMap<string, RouteState>();
	connectionStatus = $state<ConnectionStatus>('disconnected');
	lastTickAt = $state<Date | null>(null);

	/**
	 * Monotonic version counter incremented by every mutator.
	 * Consumers' `$derived` blocks must read `void topology.version`
	 * to subscribe — see the doc-comment block above for the full
	 * rationale.
	 */
	version = $state(0);

	/** Snapshot for the UI (and for tests). Non-reactive read of
	 *  the current Map. Reactive consumers MUST pair this with a
	 *  `void topology.version` subscription. */
	get list(): RouteState[] {
		return Array.from(this.routes.values());
	}

	/** Number of routes currently tracked. Non-reactive. */
	get size(): number {
		return this.routes.size;
	}

	/** Aggregate req/s across all routes. Spec §6.2 — used by the
	 *  Clients pillar. Non-reactive; pair with `version` in the
	 *  consumer. */
	get totalReqPerSec(): number {
		let total = 0;
		for (const r of this.routes.values()) total += r.reqPerSec;
		return total;
	}

	/** Apply one Snapshot frame. Called by the page after the
	 *  TopologyClient delivers a JSON tick. Bumps `version`.
	 *
	 *  Step F §7.1 — Orphan prune. Servers send full-state ticks
	 *  (spec §5.2): every active route appears in every snapshot.
	 *  A route present in the store but absent from this snapshot
	 *  has therefore been removed via the routes API (or otherwise
	 *  gone). We delete it so the topology page doesn't keep dead
	 *  nodes until a full reload.
	 *
	 *  The prune lives on the *store* `apply` method, not on the
	 *  `applyTick` pure helper, deliberately: the helper's contract
	 *  (doc-comment lines 97-102) promises it does NOT remove
	 *  missing routes, and an existing test enforces that contract.
	 *  Pruning here gives the page the behavior it needs without
	 *  breaking helper-level consumers (none today, but the
	 *  separation is cheap to keep).
	 *
	 *  The single `version++` after both operations is enough — a
	 *  prune-only tick (snapshot with one fewer route, no other
	 *  field changes) still bumps `version`, so consumers'
	 *  `$derived` blocks re-evaluate and pick up the shrunken map. */
	apply(snap: Snapshot): void {
		applyTick(this.routes, snap);
		// Orphan prune (§7.1) — must run AFTER applyTick (which may
		// have inserted ids carried by the snapshot) so we only drop
		// routes that are genuinely absent.
		const snapshotIds = new Set(snap.routes.map((r) => r.id));
		for (const id of this.routes.keys()) {
			if (!snapshotIds.has(id)) {
				this.routes.delete(id);
			}
		}
		this.version++;
		this.lastTickAt = new Date();
	}

	/** Update the connection status (called by the page on every
	 *  status transition from the TopologyClient). */
	setStatus(s: ConnectionStatus): void {
		this.connectionStatus = s;
	}

	/** Reset to empty state — used on page unmount and in tests.
	 *  Bumps `version` so consumers re-evaluate. Uses an in-place
	 *  `clear()` rather than reassigning a new SvelteMap to keep
	 *  the cross-class reference stable. */
	clear(): void {
		this.routes.clear();
		this.version++;
		this.connectionStatus = 'disconnected';
		this.lastTickAt = null;
	}

	/** Returns the RouteState for a given id, or undefined. Callers
	 *  (e.g., TopologyDetailPanel via selectedRoute in +page.svelte)
	 *  wrap this in their own `$derived` so the read happens in
	 *  their reactive context. */
	get(id: string): RouteState | undefined {
		return this.routes.get(id);
	}
}

export const topology = new TopologyStore();

/** Re-export RouteSnapshot so consumers needn't reach into $lib/api. */
export type { RouteSnapshot, Snapshot, ConnectionStatus };
