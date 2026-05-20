// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Smoke check for the Chunk 7 test infrastructure. Mounts a real
// Svelte 5 component via @testing-library/svelte, asserts on the
// rendered DOM via jest-dom matchers, and proves the
// matchMedia shim covers the prefersReducedMotion path. If this
// breaks, every component test downstream breaks too — keeping it
// in-tree as the canary.
//
// This file lives in src/test/ rather than alongside a specific
// component so it stays infra-coverage and isn't deleted with any
// individual component refactor.

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import Spinner from '$lib/components/Spinner.svelte';

describe('test infra (Chunk 7.0)', () => {
	it('mounts a Svelte 5 component via @testing-library/svelte', () => {
		render(Spinner);
		// Spinner renders an SVG with role="status" — jest-dom's
		// `toBeInTheDocument` proves the matchers wire is live.
		expect(screen.getByRole('status')).toBeInTheDocument();
	});

	it('window.matchMedia is shimmed (would crash otherwise)', () => {
		// The shim returns matches=false by default. Any test that
		// imports a file touching svelte/motion#prefersReducedMotion
		// depends on this not throwing.
		const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
		expect(mq.matches).toBe(false);
		expect(typeof mq.addEventListener).toBe('function');
	});
});
