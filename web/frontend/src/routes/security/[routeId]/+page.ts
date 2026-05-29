// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Disable prerender for the dynamic per-route security drill-
// down. Same reasoning as observability/[routeId]/+page.ts —
// the parent layout sets prerender=true app-wide, but a
// [routeId] dynamic segment can't be statically crawled at
// build time (route IDs only exist at runtime in BoltDB). The
// page is fully client-rendered and fetches its data from the
// API on mount.
export const prerender = false;
