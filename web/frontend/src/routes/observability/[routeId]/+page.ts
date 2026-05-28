// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Disable prerender for the dynamic per-route drill-down. The
// parent +layout.ts sets prerender=true app-wide, but a
// [routeId] dynamic page can't be statically crawled at build
// time — the route IDs only exist at runtime in BoltDB. The
// page is fully client-rendered and fetches its data from the
// API on mount (ssr=false inherited from the layout), so
// dropping prerender is the correct fix.
export const prerender = false;
