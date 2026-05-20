// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { execSync } from 'node:child_process';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// Resolve the project version at build/dev startup (Step F Chunk 6.3).
// `git describe --tags --always` produces:
//   - 'v0.4.0-step-f' on a clean tag,
//   - 'v0.4.0-step-f-3-g7471243' three commits past a tag,
//   - '7471243' when no tag is reachable.
// Wrapped in try/catch so a CI / Docker environment without git
// installed (or a project shipped without a .git directory) still
// builds — it just shows 'unknown' in the About section.
function resolveAppVersion(): string {
	try {
		return execSync('git describe --tags --always', {
			stdio: ['ignore', 'pipe', 'ignore']
		})
			.toString()
			.trim();
	} catch {
		return 'unknown';
	}
}

const APP_VERSION = resolveAppVersion();

// Dev proxy: SvelteKit on :5173 has no route for /api/v1/*, so any
// fetch (login, /me, /me/theme, /logout, ...) would 404 against the
// dev server. Forward /api to the Go binary on :8001 — same-origin
// from the browser's point of view, no CORS, cookies (arenet_session
// + arenet_theme) pass through transparently.
//
// The binary's admin port is set with `./arenet --admin-port :8001`
// (the default since Step D). Change the target here if you run the
// binary on a different port.
export default defineConfig({
	plugins: [sveltekit()],
	define: {
		// Inlined at build time: every reference to
		// import.meta.env.VITE_APP_VERSION in the source becomes a
		// literal string. Consumers see it as a string constant; no
		// runtime env var lookup.
		'import.meta.env.VITE_APP_VERSION': JSON.stringify(APP_VERSION)
	},
	server: {
		port: 5173,
		strictPort: true,
		proxy: {
			'/api': 'http://localhost:8001'
		}
	}
});
