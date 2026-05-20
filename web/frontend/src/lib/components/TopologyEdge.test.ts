// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// TopologyEdge component tests (Step F Chunk 7.4, spec §11.3
// "Regression guard B — MetricEdge spawn pause on disconnect").
// Behavior-based per §11.2.
//
// Naming note: spec §11.3 referred to "MetricEdge.test.ts" but the
// shipped component is `TopologyEdge.svelte` (the name comes from
// Step E + Chunk 2 history). Same logic, different file name.
//
// The two tests are explicit regression guards for the Chunk 2 §7.2
// fix: TopologyEdge's restartSpawnTimer must bail BEFORE calling
// setInterval when topology.connectionStatus is anything other than
// 'connected'. Without this guard, a WebSocket outage left the
// frozen reqPerSec value driving a runaway spawn loop (the
// "everything looks fine" illusion).
//
// Assertion strategy: spy on window.setInterval. The regression
// guard is a runtime branch INSIDE restartSpawnTimer — its observable
// effect is whether setInterval is invoked at all. We could try to
// count <circle> elements in the rendered DOM, but TopologyParticle's
// `visible = true` flip depends on requestAnimationFrame +
// path.getTotalLength() inside onMount, both of which behave poorly
// in jsdom and would force a more complex animation stub. Spying on
// setInterval reads the regression guard directly without coupling
// to the particle render pipeline.
//
// TopologyEdge renders an SVG <g>, so it needs an <svg> parent —
// TopologyEdgeFixture.test.svelte provides one.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render } from '@testing-library/svelte';
import { tick } from 'svelte';
import { topology } from '$lib/stores/topology.svelte';
import Fixture from './TopologyEdgeFixture.test.svelte';

describe('TopologyEdge spawn-pause regression guards (Chunk 2 §7.2)', () => {
	let setIntervalSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		// Reset the singleton store so tests start clean. The Chunk 4b
		// topology.svelte.ts exports `topology` as a class instance.
		topology.clear();
		// Spy on setInterval — the assertion target. Use `as never` to
		// match Vitest's spyOn return-shape inference; we read .mock
		// not call the underlying function.
		setIntervalSpy = vi.spyOn(window, 'setInterval');
	});

	afterEach(() => {
		setIntervalSpy.mockRestore();
		topology.clear();
	});

	it('calls setInterval (spawn loop starts) when topology.connectionStatus is connected', async () => {
		// Set connection BEFORE render so the $effect that mounts the
		// spawn timer sees the right value on first run.
		topology.setStatus('connected');

		render(Fixture, {
			reqPerSec: 10,
			errRate5xx: 0,
			reducedMotion: false
		});

		// Flush Svelte effects so the $effect that calls
		// restartSpawnTimer runs.
		await tick();

		// restartSpawnTimer calls setInterval with intervalMs = 1000/10
		// = 100 ms after the connectionStatus guard passes.
		expect(setIntervalSpy).toHaveBeenCalled();
		// First positional arg is the callback fn, second is the interval.
		// Assert the interval matches the reqPerSec → interval math
		// so we know the right code path ran.
		const calls = setIntervalSpy.mock.calls as unknown as Array<[unknown, number]>;
		const intervalArgs = calls.map((c) => c[1]);
		expect(intervalArgs).toContain(100);
	});

	it('does NOT call setInterval when topology.connectionStatus is disconnected (the §7.2 guard)', async () => {
		// Pre-render: not connected. The guard
		//   if (topology.connectionStatus !== 'connected') return;
		// inside restartSpawnTimer must bail BEFORE setInterval is called.
		topology.setStatus('disconnected');

		render(Fixture, {
			reqPerSec: 10,
			errRate5xx: 0,
			reducedMotion: false
		});

		// Same effect flush as the positive test.
		await tick();

		// The spawn loop never started — this is the §7.2 regression
		// guard's whole job. If a future refactor accidentally removes
		// the guard, this assertion fails immediately.
		expect(setIntervalSpy).not.toHaveBeenCalled();
	});
});
