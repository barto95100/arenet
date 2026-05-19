// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

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
	server: {
		port: 5173,
		strictPort: true,
		proxy: {
			'/api': 'http://localhost:8001'
		}
	}
});
