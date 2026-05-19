// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Theme store (Step F §4). Singleton class instance pattern,
// consistent with auth.svelte.ts and topology.svelte.ts.
//
// `current` mirrors the `<html data-theme>` attribute. The bootstrap
// script in app.html (§4.3) sets the attribute before the first
// paint to avoid FOUC; this store takes over once the app boots.
//
// Phase 1 (this Sub-task 1.2): `set()` updates the DOM and persists
// to localStorage. The server round-trip is wired in Sub-task 1.5
// once POST /api/v1/auth/me/theme exists (Sub-task 1.4 implements
// the backend). Keeping `isApplying` here so the Toggle component
// can already render its busy state — it just never flips true
// until 1.5 lands.

export type Theme = 'dark' | 'light';

/** Normalize any input (including '', null, undefined, garbage) to
 *  a strict Theme value. Per spec §4.2: only the exact string
 *  `'light'` returns `'light'`; everything else falls back to dark. */
function normalize(t: unknown): Theme {
	return t === 'light' ? 'light' : 'dark';
}

class ThemeStore {
	current = $state<Theme>('dark');
	isApplying = $state(false);

	/** Apply a theme to the DOM and persist it locally. In Phase 1
	 *  the server round-trip is a no-op; Sub-task 1.5 wires it. */
	async set(t: Theme): Promise<void> {
		const next = normalize(t);
		this.applyLocally(next);
		if (typeof localStorage !== 'undefined') {
			try {
				localStorage.setItem('arenet_theme', next);
			} catch (_) {
				// Private browsing / quota — ignore, the cookie + server
				// (1.5) remain authoritative.
			}
		}
	}

	/** Apply WITHOUT touching localStorage or the server. Used by the
	 *  Phase 2 reconciliation step after /auth/me resolves (§4.3),
	 *  where the server's value is already authoritative. */
	applyLocally(t: Theme): void {
		const next = normalize(t);
		this.current = next;
		if (typeof document !== 'undefined') {
			document.documentElement.dataset.theme = next;
		}
	}
}

export const theme = new ThemeStore();
