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
// Phase 2 #R-TOPO-v2 — the topology stream WebSocket lives under
// the same /api prefix (/api/v1/topology/stream). Vite's shorthand
// proxy form ('/api': 'http://localhost:8001') does NOT forward
// WebSocket upgrades — only plain HTTP. The full-object form with
// `ws: true` is required so the upgrade handshake reaches the Go
// binary. Without it, the browser opens a WS to :5173, Vite
// returns the SvelteKit dev-server's HTML index, the upgrade fails
// silently, and the page sits in "reconnecting…" forever.
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
			'/api': {
				target: 'http://localhost:8001',
				// WebSocket forwarding for /api/v1/topology/stream
				// (and any future WS endpoint under /api). Required
				// — see the block comment above.
				ws: true,
				// NOTE: changeOrigin was tried (2026-06-03) and
				// removed. Symptom: Vite reported
				// `ws proxy error: write EPIPE` immediately on
				// every WS upgrade attempt, browser stayed in
				// reconnecting state. Root cause suspected:
				// changeOrigin's header rewriting interfered with
				// the gorilla WS Upgrader's Origin check (the
				// backend in --dev mode accepts only Origin:
				// http://localhost:5173 — see
				// internal/api/topology_stream.go:127 CheckOrigin).
				// Without changeOrigin the browser's original
				// Origin header passes through unchanged, the
				// backend accepts it, the upgrade completes.
			},
		},
	},
});
