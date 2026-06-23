// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';
import path from 'node:path';

export default defineConfig({
	// svelteTesting() resolves .svelte modules in client mode for
	// jsdom so testing-library's render() can mount components.
	// Without it, mount() fails with "lifecycle_function_unavailable"
	// because the default plugin output is server-side. It also
	// registers auto-setup/cleanup hooks, so we don't need to wire
	// afterEach(cleanup) manually in setup.ts.
	plugins: [svelte(), svelteTesting()],
	resolve: {
		alias: {
			$lib: path.resolve(__dirname, './src/lib'),
			$app: path.resolve(__dirname, './node_modules/@sveltejs/kit/src/runtime/app')
		}
	},
	test: {
		environment: 'jsdom',
		globals: false,
		include: ['src/**/*.{test,spec}.ts'],
		setupFiles: ['./src/test/setup.ts'],
		// pool=forks fixes a flaky-under-load issue observed
		// 2026-06-23 : the default 'threads' pool let test files
		// share Svelte's module registry across workers, causing
		// random failures (Button/Modal/dashboard/logs/routes
		// suites would fail 5-8 tests under high parallel
		// pressure, then pass cleanly when re-run alone). Forks
		// isolate each suite in its own process, eliminating the
		// shared-registry contention. Trade-off : ~3x slower
		// startup (55s full sweep vs ~18s threads), justified by
		// the reliability win — 842/842 stable across retries.
		// Operators iterating locally on a single test file
		// still get sub-second feedback via `vitest <file>`.
		pool: 'forks',
		coverage: {
			// Chunk 7 §11 + AC #8: measure coverage on lib/components/
			// (>= 70 % target). The pre-Step F config only included .ts
			// files which trivially excluded every component; we now
			// pull .svelte in too so the AC can be verified.
			provider: 'v8',
			reporter: ['text', 'html'],
			include: ['src/lib/**/*.{ts,svelte}'],
			exclude: [
				'src/lib/**/*.test.ts',
				'src/lib/**/*.spec.ts',
				'src/lib/**/*.d.ts'
			],
			// Soft per-area thresholds — fail the suite if we drop below.
			// Components only; stores + api have their own pure-TS suites
			// already at high coverage.
			thresholds: {
				'src/lib/components/**/*.svelte': {
					lines: 70,
					functions: 70,
					branches: 70,
					statements: 70
				}
			}
		}
	}
});
