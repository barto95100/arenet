// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Vitest global setup. Stubs $app/navigation (provided by SvelteKit at
// runtime but absent from the test resolver), wires testing-library's
// jest-dom matchers (Chunk 7 §11.1), and provides a minimal jsdom
// shim for window.matchMedia (used by Svelte 5's prefersReducedMotion
// MediaQuery rune in Settings + TopologySvg).

import { vi } from 'vitest';
import '@testing-library/jest-dom/vitest';

// Stub $app/navigation: goto is a no-op spy that tests can read to
// verify redirect behavior of the 401 interceptor (spec §6.4).
vi.mock('$app/navigation', () => ({
	goto: vi.fn(() => Promise.resolve())
}));

// jsdom doesn't ship window.matchMedia. Svelte 5's
// `svelte/motion#prefersReducedMotion` constructs a MediaQuery at
// module load time, so any test that imports a file touching the
// motion module would crash without this shim. Default to "no
// preference" (matches=false) so tests run the animated paths
// unless a test overrides this for its own scope.
if (typeof window !== 'undefined' && !window.matchMedia) {
	window.matchMedia = vi.fn().mockImplementation((query: string) => ({
		matches: false,
		media: query,
		onchange: null,
		addListener: vi.fn(), // deprecated but referenced by some libs
		removeListener: vi.fn(), // deprecated
		addEventListener: vi.fn(),
		removeEventListener: vi.fn(),
		dispatchEvent: vi.fn()
	}));
}

// Auto-cleanup is wired by the svelteTesting() Vitest plugin
// (see vitest.config.ts). No explicit afterEach(cleanup) needed.
