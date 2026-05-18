// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step E topology constants — TypeScript counterpart of
// internal/metrics/constants.go (spec §8). Both files MUST stay in
// sync; any divergence is a bug. CI does not yet enforce this.
//
// All values are spec §8 verbatim except the ones marked otherwise.

/** Server tick cadence in ms. Spec §8 tickInterval = 1 s. */
export const TICK_INTERVAL_MS = 1000;

/** Per-edge particle spawn cap. Spec §8 particleDensityCap. */
export const PARTICLE_DENSITY_CAP = 50;

/** Particle travel time per edge in ms. Spec §8 particleTravelMs. */
export const PARTICLE_TRAVEL_MS = 2000;

/** Threshold above which any 5xx rate displays a warning color.
 *  Spec §8 colorWarnThreshold "> 0". */
export const COLOR_WARN_THRESHOLD = 0;

/** Threshold above which the 5xx rate displays the danger color.
 *  Spec §8 colorErrorThreshold = 0.05 (5 %). */
export const COLOR_ERROR_THRESHOLD = 0.05;

/** Active-state window: a route is "active" if it had ≥ 1 req in
 *  the last N ms. Spec §8 activeWindow = 60 s. */
export const ACTIVE_WINDOW_MS = 60_000;

/** Error-spike sliding window for client-side node state.
 *  Spec §8 spikeWindow = 10 s (10 ticks at 1 Hz). */
export const SPIKE_WINDOW_TICKS = 10;

/** Error-spike threshold over SPIKE_WINDOW_TICKS. Spec §8
 *  spikeThreshold = 0.05. */
export const SPIKE_THRESHOLD = 0.05;

/** Maximum number of ticks retained in each route's client-side
 *  history buffer (~1 min at 1 Hz). Spec §8 historyCapacity = 60. */
export const HISTORY_CAPACITY = 60;

/** Reconnect backoff bounds (ms). Spec §8 reconnectMinMs /
 *  reconnectMaxMs. */
export const RECONNECT_MIN_MS = 1000;
export const RECONNECT_MAX_MS = 30_000;

/** Consecutive failed reconnect attempts before transitioning the
 *  UI connection status from "reconnecting…" to "disconnected".
 *  Spec §6.8 mentions "≥ 5 attempts in a row". */
export const RECONNECT_DISCONNECTED_THRESHOLD = 5;
