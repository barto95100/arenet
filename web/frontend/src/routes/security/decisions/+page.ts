// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// HF on a5fbb52 (CS.3 Commit A) — stale-URL 404 guard.
//
// CS.3 Commit A deleted the /security/decisions route, but
// /security/[routeId] is still in place (it's the per-route
// security drill-down). SvelteKit's routing matches the
// dynamic [routeId] against the stale URL "decisions" and
// produces a misleading "Route introuvable — la route
// `decisions` n'existe pas" panel that conflates two distinct
// concepts (stale UI URL vs missing reverse-proxy routing
// config).
//
// Per operator review of the bug (option A — smallest scope):
// surface a clean 404 by throwing here. SvelteKit's specificity
// ranking favours this static `/security/decisions/` path over
// the dynamic `/security/[routeId]/`, so the [routeId] page no
// longer intercepts the stale URL. No +page.svelte sibling is
// needed — throwing error(404) makes SvelteKit render its
// built-in default error page directly (we don't ship a
// custom +error.svelte at the app root).
//
// Note for future hygiene: this file exists ONLY to neutralise
// the post-CS.3 collision. If someone later re-introduces a
// /security/decisions surface, delete this file (the new
// +page.svelte sibling will take its place naturally).

import { error } from '@sveltejs/kit';

export const prerender = false;

export function load(): never {
	throw error(404, 'Not Found');
}
