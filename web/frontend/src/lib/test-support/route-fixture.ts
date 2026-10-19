// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Shared Route fixture for page tests.
//
// Lifted verbatim out of routes/page.test.ts when the /waf page
// started needing a route list too (v2.73). A Route carries about
// forty fields, most of them with a "strict default" that a specific
// test overrides, and a second hand-maintained copy of that would
// drift from the wire shape the moment a field was added — which is
// exactly the class of defect these fixtures exist to catch.
//
// Add a field here when storage.Route gains one, with the default the
// backend's toResponse actually emits.

import type { Route } from '$lib/api/types';

// Helper: build a server Route response in the wire shape the
// page consumes (camelCase, healthCheck non-optional, etc.).
export function makeRoute(overrides: Partial<Route> = {}): Route {
	return {
		id: 'route-fixture-1',
		host: 'fixture.example.com',
		upstreams: [{ url: 'http://127.0.0.1:9000', weight: 1 }],
		lbPolicy: 'round_robin',
		tlsEnabled: false,
		redirectToHttps: false,
		aliases: [],
		authMode: 'none',
		basicAuth: { username: '', passwordSet: false },
		forwardAuth: { providerName: '' },
		requestHeaders: {},
		responseHeaders: {},
		wafMode: 'off',
		acmeChallenge: 'http-01',
		healthCheck: {
			enabled: false,
			uri: '',
			method: '',
			interval: '',
			timeout: '',
			expectStatus: 0,
			expectBody: '',
			passes: 0,
			fails: 0
		},
		createdAt: '2026-05-25T10:00:00.000Z',
		updatedAt: '2026-05-25T10:00:00.000Z',
		// Critique 11 Pack A defaults — match the no-HC-configured
		// path (the gate forces unknown with healthy=0).
		aggregateStatus: 'unknown',
		healthyUpstreamCount: 0,
		totalUpstreamCount: 1,
		// W.5 — country-block default to the disabled state.
		// toResponse normalises a storage zero-value to
		// {mode:"off", countryList:[], statusCode:0}; tests
		// that need the gate active override via the partial
		// Route overrides.
		countryBlock: { mode: 'off', countryList: [], continents: [], asns: [], exceptions: { countries: [], asns: [] }, statusCode: 0 },
		healthNotify: { enabled: false, channelId: '', reminderMinutes: 0 },
		// Step #R-PROXMOX-HTTPS-LOOP — strict default. Tests
		// exercising the disclosure / toggle override via the
		// partial Route overrides.
		insecureSkipVerify: false,
		upstreamTlsServerName: '',
		// Phase 4.5 — strict default; tests that exercise the
		// streaming toggle override via the partial Route
		// overrides parameter.
		uploadStreamingMode: false,
		// v2.77 (#317) — strict default; the response-streaming toggle
		// test overrides via the partial Route overrides parameter.
		responseStreamingMode: false,
		// Step X.2 — strict default ; tests exercising the
		// disable-CRS toggle override via the partial Route
		// overrides parameter (zero-value false = CRS loaded).
		wafDisableCRS: false,
		// Step X Option (c) — strict default empty exclusion
		// list ; tests exercising the per-rule exclusion input
		// override via the partial Route overrides parameter.
		wafExcludeRules: [],
		// Step X Option (e) — strict default empty tag exclusion
		// list ; tests exercising the per-tag input override via
		// the partial Route overrides parameter.
		wafExcludeTags: [],
		wafTargetedExclusions: [],
		wafCustomRules: [],
		wafSecLang: '',
		// Step Q — strict default no rate limit ; tests
		// exercising the rate-limit section override via the
		// partial Route overrides parameter set a non-null
		// value to populate the form.
		rateLimit: null,
		...overrides
	};
}
