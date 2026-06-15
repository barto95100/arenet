<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import {
		listRoutes,
		createRoute,
		updateRoute,
		deleteRoute,
		testUpstream
	} from '$lib/api/client';
	import { settingsApi } from '$lib/api/settings';
	import type {
		ACMEChallenge,
		CountryBlockRequest,
		DNSProviderOVH,
		ForwardAuthProvider,
		HealthCheck,
		LBPolicy,
		ManagedDomain,
		Route,
		RouteRequest,
		TestUpstreamResponse,
		Upstream
	} from '$lib/api/types';
	import { countryName, matchCountries, type CountryMatch } from '$lib/data/countries';
	import { ApiError } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import { auth } from '$lib/stores/auth.svelte';
	import Button from '$lib/components/Button.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import StatCard from '$lib/components/StatCard.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import Input from '$lib/components/Input.svelte';
	import Checkbox from '$lib/components/Checkbox.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';

	let routes = $state<Route[]>([]);
	let loading = $state(true);
	let loadError = $state<string | null>(null);

	type FormMode = 'create' | 'edit';
	let formOpen = $state(false);
	let formMode = $state<FormMode>('create');
	let editingId = $state<string | null>(null);
	let submitting = $state(false);
	let formError = $state<string | null>(null);

	// Phase 1 split layout (2026-06-02) — list filter state.
	// The search input filters by host / matcher / upstream URL
	// substring. The segmented tab is a UX placeholder for the
	// per-route health filter; "All" is the only functional
	// option in Phase 1.
	//
	// TODO Phase 2: wire "Healthy" / "Alerts" once the API
	// surfaces a per-route health field (today the data plane
	// only tracks health per UPSTREAM via Caddy's active health
	// checks; there is no per-route aggregated rollup on the
	// wire). Until then, the two non-default tabs are no-ops
	// with a tooltip explaining the deferral.
	type ListTab = 'all' | 'healthy' | 'alerts';
	let listFilter = $state('');
	let listTab = $state<ListTab>('all');

	// Step J.3: §5.2 default values. Source of truth on the client
	// for the four defaultable text/number placeholders + the
	// initial `method` select value. Must stay in sync with §1.3
	// decision 4 (Arenet-owned defaults) and validation.go's
	// defaultHC* constants. uri and expectStatus placeholders are
	// illustrative — not in this object — because they are not
	// server-defaultable.
	const HEALTH_CHECK_DEFAULTS = {
		method: 'GET',
		interval: '30s',
		timeout: '5s',
		passes: 1,
		fails: 1
	} as const;

	// Step J.3: minimal duration regex matching Go's
	// time.ParseDuration shape ("30s", "1m30s", "500ms", etc.).
	// Client-side pre-check; server validation is authoritative.
	const DURATION_RE = /^(\d+(?:\.\d+)?(?:ns|us|µs|μs|ms|s|m|h))+$/;

	// Step J.3: form state. The Step I.5 BasicAuth password is
	// write-only on the wire; the rest of the form is bound 1:1 to
	// the storage shape, with the J.3 additions for the upstream
	// pool, LB policy, and health check.
	//
	// `healthCheckTouched` tracks whether the user opened the
	// health-check sub-form during this edit session. When false on
	// submit, we OMIT the healthCheck key from the payload so the
	// server takes the preserve-previous path (J.2 decision: PUT
	// without healthCheck preserves the stored value). When true,
	// we ship the complete 9-field block (full replacement).
	type FormData = Omit<RouteRequest, 'healthCheck' | 'countryBlock' | 'insecureSkipVerify' | 'uploadStreamingMode'> & {
		healthCheck: HealthCheck;
		// W.5 — narrow to the non-optional shape. The form
		// always carries a CountryBlockRequest (mode="off"
		// when disabled); the wire optionality lives on
		// the RouteRequest side for callers that want
		// preserve-previous semantics.
		countryBlock: CountryBlockRequest;
		// Step #R-PROXMOX-HTTPS-LOOP — narrowed to a non-
		// optional boolean. The form always carries a
		// definite value; the on-wire optionality
		// (preserve-on-omit semantic) is reapplied at
		// payload-assembly time below.
		insecureSkipVerify: boolean;
		// Phase 4.5 — same narrowing pattern as
		// insecureSkipVerify: form holds a definite bool,
		// payload re-introduces undefined for preserve-on-
		// omit semantics on PUT.
		uploadStreamingMode: boolean;
	};
	let formData = $state<FormData>(emptyFormData());
	let healthCheckTouched = $state(false);

	function emptyFormData(): FormData {
		return {
			host: '',
			upstreams: [{ url: '', weight: 1 }],
			lbPolicy: 'round_robin',
			tlsEnabled: false,
			redirectToHttps: false,
			aliases: [],
			authMode: 'none',
			basicAuth: { username: '', password: '' },
			forwardAuth: { providerName: '' },
			requestHeaders: {},
			responseHeaders: {},
			wafMode: 'detect',
			acmeChallenge: 'http-01',
			useDedicatedCert: false,
			// Step #R-PROXMOX-HTTPS-LOOP — strict default on
			// create. The disclosure that exposes this toggle
			// is itself hidden until the upstream pool uses
			// `https://`, so an operator must (1) type https://
			// in at least one upstream and (2) explicitly tick
			// the toggle to flip this true. Self-heal $effect
			// below also resets it to false on every https→http
			// scheme transition so the on-screen + storage
			// states stay aligned.
			insecureSkipVerify: false,
			// Phase 4.5 — strict default. Opt-in only: the
			// toggle is visible in the WAF settings block and
			// the operator must tick it explicitly to skip
			// body inspection + Caddy buffering. Independent
			// from wafMode (any combination is valid).
			uploadStreamingMode: false,
			// W.5 — country-block defaults to disabled. The form
			// surface lives in the country-block details block
			// further down; operators opting in pick a mode +
			// type ISO 3166-1 alpha-2 codes (FR / DE / RU / ...).
			countryBlock: {
				mode: 'off' as 'off' | 'allow' | 'deny',
				countryList: [] as string[],
				statusCode: 0
			},
			healthCheck: {
				enabled: false,
				uri: '',
				// Method is deliberately pre-set to GET (a binary
				// select offers no useful blank state — §5.3
				// contained exception). Server uppercases on the
				// way in, but we send the explicit value.
				method: HEALTH_CHECK_DEFAULTS.method,
				// Four defaultable fields stay blank on create so
				// the server materialises them and the form
				// surfaces the §1.3 values as placeholders only.
				interval: '',
				timeout: '',
				expectStatus: 0,
				expectBody: '',
				passes: 0,
				fails: 0
			}
		};
	}

	// Step I.5: tracked separately from formData because it reflects
	// the SERVER state (does a hash exist on the route being edited),
	// not the form's write-only password input.
	let basicAuthPasswordSet = $state(false);

	// Step I.6 — header repeater state. Tuples here, converted to
	// Record<string,string> at submit (see tuplesToRecord).
	let requestHeaderRows = $state<Array<[string, string]>>([]);
	let responseHeaderRows = $state<Array<[string, string]>>([]);

	function addRequestHeader() {
		requestHeaderRows = [...requestHeaderRows, ['', '']];
	}
	function removeRequestHeader(i: number) {
		requestHeaderRows = requestHeaderRows.filter((_, idx) => idx !== i);
	}
	function addResponseHeader() {
		responseHeaderRows = [...responseHeaderRows, ['', '']];
	}
	function removeResponseHeader(i: number) {
		responseHeaderRows = responseHeaderRows.filter((_, idx) => idx !== i);
	}

	function tuplesToRecord(rows: Array<[string, string]>): Record<string, string> {
		const out: Record<string, string> = {};
		for (const [k, v] of rows) {
			const key = k.trim();
			if (key === '') continue;
			out[key] = v;
		}
		return out;
	}

	function recordToTuples(rec: Record<string, string>): Array<[string, string]> {
		return Object.entries(rec ?? {});
	}

	// Step J.3: upstream pool repeater helpers.
	function addUpstream() {
		formData.upstreams = [...formData.upstreams, { url: '', weight: 1 }];
	}
	function removeUpstream(i: number) {
		// Server enforces "at least one upstream"; we mirror it on
		// the client by disabling the remove button on the last row
		// (see markup below). Defensive: refuse to remove the last
		// row if we are ever called with len == 1.
		if (formData.upstreams.length <= 1) return;
		formData.upstreams = formData.upstreams.filter((_, idx) => idx !== i);
		// Step #R-PROXMOX-HTTPS-LOOP commit 3 — drop the
		// matching test-state entry so the chip doesn't
		// orphan a now-removed row's result. Indices shift
		// after the splice; rebuild the map cleanly.
		const shifted: Record<number, UpstreamTestState> = {};
		for (const [k, v] of Object.entries(upstreamTests)) {
			const idx = Number(k);
			if (idx < i) shifted[idx] = v;
			else if (idx > i) shifted[idx - 1] = v;
		}
		upstreamTests = shifted;
	}

	// Step #R-PROXMOX-HTTPS-LOOP commit 3 — per-row probe
	// state. Indexed by upstream-row index (0-based). The
	// shape mirrors a state machine:
	//   undefined → never tested (chip hidden)
	//   { running: true }                  → spinner
	//   { running: false, result, error? } → outcome chip
	//
	// Cleared on form close (closePanel) so a stale result
	// from a previous edit doesn't bleed into the next.
	type UpstreamTestState =
		| { running: true }
		| { running: false; result?: TestUpstreamResponse; error?: string };
	let upstreamTests = $state<Record<number, UpstreamTestState>>({});

	async function runUpstreamTest(i: number) {
		const url = formData.upstreams[i]?.url?.trim() ?? '';
		if (url === '') return;
		upstreamTests = { ...upstreamTests, [i]: { running: true } };
		try {
			const result = await testUpstream({
				url,
				// Mirror the route-level toggle ONLY when the
				// pool is https — on http pools the backend
				// would self-heal anyway, and sending true on
				// an http URL would be a misleading user
				// signal. Storage-layer alignment with the
				// route's saved posture.
				insecureSkipVerify:
					poolScheme === 'https' ? formData.insecureSkipVerify : false
			});
			upstreamTests = {
				...upstreamTests,
				[i]: { running: false, result }
			};
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : String(err);
			upstreamTests = {
				...upstreamTests,
				[i]: { running: false, error: msg }
			};
		}
	}

	// "Tester tous" — parallelise pool > 1 via Promise.all
	// so the operator sees every chip update concurrently
	// (wall-clock bounded by the slowest dial). Skips empty
	// URL rows (no probe to run).
	async function runAllUpstreamTests() {
		const targets: number[] = [];
		formData.upstreams.forEach((u, i) => {
			if (u.url.trim() !== '') targets.push(i);
		});
		if (targets.length === 0) return;
		await Promise.all(targets.map((i) => runUpstreamTest(i)));
	}

	let confirmTarget = $state<Route | null>(null);
	let deleting = $state(false);

	// Step J.3: errors map keyed by formData field path. Replaces
	// the per-field $state<string> pattern from Step I (hostError,
	// upstreamError) — that pattern doesn't scale to the ~13 new
	// J.1/J.2 fields. formError remains as a top-of-form banner
	// for non-field-attributable messages.
	let errors = $state<Record<string, string>>({});

	function resetFormErrors() {
		formError = null;
		errors = {};
	}

	// Phase 1 split layout — close/cancel the right panel and
	// return to the empty state. Used by the "Cancel" button in
	// the panel footer. The route stays in the list; only the
	// selection + form state are dropped.
	function closePanel() {
		formOpen = false;
		formMode = 'create';
		editingId = null;
		formError = null;
		errors = {};
		// Step #R-PROXMOX-HTTPS-LOOP commit 3 — clear per-row
		// probe state so a stale result from a previous edit
		// session doesn't bleed into the next form open.
		upstreamTests = {};
	}

	// DOM refs for the click-outside action (C11 Pack A polish
	// round 3, 2026-06-06). panelEl bounds the inspector; tableEl
	// bounds the routes table — clicks inside either are ignored
	// by the outside-close logic. Clicks inside the table are
	// handled by the per-row onclick (which calls
	// selectOrToggleRoute), so the outside-close handler doesn't
	// fight with row-targeted interactions.
	let panelEl = $state<HTMLDivElement | null>(null);
	let tableEl = $state<HTMLTableElement | null>(null);

	// W.7 — country-block autocomplete state. The input
	// value is held locally (not bound to formData) so the
	// dropdown can preview matches without polluting the
	// committed country list until the operator picks an
	// entry. activeIndex drives keyboard navigation (Arrow
	// Up/Down + Enter). cbInputEl is the focus target for
	// the "+ Ajouter un pays" CTA below.
	let cbInputValue = $state('');
	let cbDropdownOpen = $state(false);
	let cbActiveIndex = $state(0);
	let cbInputEl = $state<HTMLInputElement | null>(null);

	// W.7 follow-up — the section's open/closed state is
	// tracked SEPARATELY from formData.countryBlock.mode.
	// The W.7 polish initially tied <details open={...}>
	// to (mode !== 'off'), which made the section collapse
	// out of view the instant the operator clicked
	// "Désactivé" — they made a deliberate choice and lost
	// the UI confirmation of it. The fix: cbSectionOpen
	// holds the operator's open/close intent (toggled via
	// the summary click); mode flips never touch it.
	//
	// Auto-open shorthand: when the operator picks Allow
	// or Deny from a closed section, force-open it so the
	// newly-revealed input + chip list aren't hidden
	// behind a collapsed details. Going off → on is a
	// deliberate "I want to configure this" signal; going
	// on → off is "I want this off but I'm still looking
	// at the section to confirm". Both should keep the
	// section visible.
	let cbSectionOpen = $state(false);

	// Pick mode + force-open helper bundled together so
	// every mode button calls the same code path. Used by
	// both the 3-button toggle and any future shortcut
	// affordance.
	function cbPickMode(next: 'off' | 'allow' | 'deny'): void {
		formData.countryBlock.mode = next;
		cbSectionOpen = true;
	}

	// Derived autocomplete matches, excluding codes already
	// in the chip list (no point re-suggesting a code that
	// is already added). Empty when the input is empty AND
	// the dropdown isn't explicitly open (clicking the CTA
	// opens it without text — surfaces the first 8 codes
	// alphabetically for "I don't know what I want" browsing).
	const cbSuggestions = $derived<CountryMatch[]>(
		cbDropdownOpen
			? matchCountries(cbInputValue, formData.countryBlock.countryList)
			: []
	);

	// W.7 — counter label tied to mode. The brief asked
	// for "{N} pays {bloqué(s)|autorisé(s)}" matching the
	// active mode; the singular/plural pluralization
	// matches French agreement.
	const cbCounterLabel = $derived.by(() => {
		const n = formData.countryBlock.countryList.length;
		if (n === 0) return '';
		if (formData.countryBlock.mode === 'allow') {
			return `${n} pays autorisé${n > 1 ? 's' : ''}`;
		}
		if (formData.countryBlock.mode === 'deny') {
			return `${n} pays bloqué${n > 1 ? 's' : ''}`;
		}
		return `${n} pays`;
	});

	// W.7 — add a country code to the list if not already
	// present + close the dropdown. Shared by the keyboard
	// Enter handler, the click-on-suggestion handler, and
	// the CTA button's quick-add path. Trim + uppercase
	// applied at the boundary so the chip list is always
	// canonical.
	function cbAddCode(rawCode: string): void {
		const code = rawCode.trim().toUpperCase();
		if (!/^[A-Z]{2}$/.test(code)) return;
		if (formData.countryBlock.countryList.includes(code)) {
			cbInputValue = '';
			return;
		}
		formData.countryBlock.countryList = [
			...formData.countryBlock.countryList,
			code
		];
		cbInputValue = '';
		cbActiveIndex = 0;
		cbDropdownOpen = false;
	}

	function cbRemoveCode(code: string): void {
		formData.countryBlock.countryList =
			formData.countryBlock.countryList.filter((c) => c !== code);
	}

	function cbOpenDropdown(): void {
		cbDropdownOpen = true;
		cbActiveIndex = 0;
		// requestAnimationFrame is the canonical way to focus
		// after Svelte reactive paint; the input may have just
		// been rendered if the mode toggle revealed the field.
		requestAnimationFrame(() => cbInputEl?.focus());
	}

	function cbInputKeydown(e: KeyboardEvent): void {
		// Operator may pick from the dropdown OR type the
		// 2-char code raw + Enter. Both paths must add the
		// code; the dropdown takes precedence (the operator's
		// arrow-selected match) so an ambiguous "FR" → Enter
		// with the dropdown active selects the highlighted
		// suggestion.
		if (e.key === 'Enter') {
			e.preventDefault();
			if (cbDropdownOpen && cbSuggestions.length > 0) {
				cbAddCode(cbSuggestions[cbActiveIndex]?.code ?? cbInputValue);
			} else {
				cbAddCode(cbInputValue);
			}
			return;
		}
		if (e.key === ',') {
			// Comma is the secondary delimiter so an operator
			// pasting "FR,DE,RU" can chain entries quickly. We
			// add the buffer + clear; the next paste segment
			// re-triggers the dropdown for visual confirmation.
			e.preventDefault();
			cbAddCode(cbInputValue);
			return;
		}
		if (e.key === 'Escape') {
			cbDropdownOpen = false;
			return;
		}
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			if (cbSuggestions.length === 0) return;
			cbActiveIndex = (cbActiveIndex + 1) % cbSuggestions.length;
			return;
		}
		if (e.key === 'ArrowUp') {
			e.preventDefault();
			if (cbSuggestions.length === 0) return;
			cbActiveIndex =
				(cbActiveIndex - 1 + cbSuggestions.length) % cbSuggestions.length;
			return;
		}
	}

	function cbInputOnInput(e: Event): void {
		cbInputValue = (e.currentTarget as HTMLInputElement).value;
		cbDropdownOpen = true;
		cbActiveIndex = 0;
	}

	// Svelte action: bind to the panel root, listens on document
	// mousedown for the lifetime of the node, calls closePanel
	// when the event target is outside BOTH the panel and the
	// table. mousedown (not click) so the listener wins the race
	// against any same-target click handlers — and because
	// mousedown more naturally maps to "dismiss the inspector"
	// (matches macOS list inspectors).
	function clickOutsideToClose(node: HTMLElement) {
		function handle(event: MouseEvent) {
			if (!formOpen) return;
			const target = event.target;
			if (!(target instanceof Node)) return;
			if (node.contains(target)) return;
			if (tableEl?.contains(target)) return;
			closePanel();
		}
		document.addEventListener('mousedown', handle, true);
		return {
			destroy() {
				document.removeEventListener('mousedown', handle, true);
			},
		};
	}

	function openCreate() {
		formMode = 'create';
		editingId = null;
		formData = emptyFormData();
		basicAuthPasswordSet = false;
		healthCheckTouched = false;
		requestHeaderRows = [];
		responseHeaderRows = [];
		// W.7 follow-up — country-block section starts
		// closed for a fresh create form (matches the
		// healthCheck details discipline; mode=off doesn't
		// auto-expand). The operator can open it via the
		// summary click whenever they want to see the
		// three modes.
		cbSectionOpen = false;
		resetFormErrors();
		formOpen = true;
		// Step J.4: refresh provider status whenever the form opens
		// so the inline hint reflects any provider changes the
		// operator may have just made in Settings.
		void loadDNSProvider();
		void loadForwardAuthProviders();
		// Step O.4: refresh managed-domains too — operator may
		// have just declared a new apex; the form's contextual
		// inheritance badge needs the up-to-date list.
		void loadManagedDomainsForRoutes();
	}

	// Row click semantics (C11 Pack A polish round 3, 2026-06-06):
	// clicking the already-selected row toggles the panel closed —
	// macOS-Finder-list behaviour. Clicking any other row (or the
	// same row when nothing is selected) opens the edit panel
	// against it via openEdit. The keyboard Enter/Space path uses
	// the same helper so the toggle is reachable without a mouse.
	function selectOrToggleRoute(r: Route) {
		if (editingId === r.id && formOpen) {
			closePanel();
			return;
		}
		openEdit(r);
	}

	function openEdit(r: Route) {
		formMode = 'edit';
		editingId = r.id;
		// Step J.3: populate the pool from the stored route as-is.
		// A one-upstream route (e.g. migrated from Step I) shows a
		// single-row repeater; multi-upstream routes show every row.
		formData = {
			host: r.host,
			upstreams: r.upstreams.map((u) => ({ url: u.url, weight: u.weight })),
			lbPolicy: r.lbPolicy,
			tlsEnabled: r.tlsEnabled,
			redirectToHttps: r.redirectToHttps,
			aliases: [...(r.aliases ?? [])],
			authMode: r.authMode,
			basicAuth: {
				username: r.basicAuth?.username ?? '',
				password: ''
			},
			forwardAuth: {
				providerName: r.forwardAuth?.providerName ?? ''
			},
			requestHeaders: { ...(r.requestHeaders ?? {}) },
			responseHeaders: { ...(r.responseHeaders ?? {}) },
			wafMode: r.wafMode,
			// W.5 — clone the stored country-block config so
			// the form can mutate locally without touching
			// the loaded route reference. The list is
			// shallow-copied (string array; no nested refs).
			countryBlock: {
				mode: r.countryBlock.mode,
				countryList: [...r.countryBlock.countryList],
				statusCode: r.countryBlock.statusCode
			},
			// Step O: "inherited" is a server-derived value the
			// frontend never sends back. Reload it as "" (empty)
			// rather than "http-01" so the dropdown doesn't show
			// a misleading default if the operator opts out of
			// the wildcard via useDedicatedCert. The form state
			// is "no per-route challenge picked yet" — accurate
			// to what's stored.
			//
			// Per backlog #O.4-2: the onUseDedicatedCertToggle
			// handler ALSO clears acmeChallenge to "" on every
			// false → true transition, AND the Save button is
			// gated by dedicatedOptOutPendingChoice. So even if
			// a stored value sneaks through here (e.g. a covered
			// route with acmeChallenge="dns-01" in storage, which
			// shouldn't happen under D8.A but is defended against),
			// the operator must explicitly re-pick on opt-out.
			acmeChallenge:
				r.acmeChallenge === 'inherited' ? '' : r.acmeChallenge,
			useDedicatedCert: r.useDedicatedCert ?? false,
			// Step #R-PROXMOX-HTTPS-LOOP — load the persisted
			// value so the disclosure toggle reflects what the
			// route actually carries. Backend always emits a
			// definite bool (no omitempty on Route.insecure-
			// SkipVerify in the response), so the fallback to
			// false here is a safety net rather than the
			// expected path.
			insecureSkipVerify: r.insecureSkipVerify ?? false,
			// Phase 4.5 — load the persisted streaming-mode
			// state so the toggle on the form reflects what's
			// actually saved. The API response is non-omitempty
			// (false echoed explicitly), so the ?? false here is
			// purely defensive for very old pre-4.5 snapshots
			// that might have been restored without the field.
			uploadStreamingMode: r.uploadStreamingMode ?? false,
			// Step J.2: the server's HealthCheck is always present
			// on the wire (no omitempty). The form holds it as-is;
			// edit-mode shows explicit values (server materialised
			// defaults at original create), edit-mode users see
			// populated fields with no blanks to misinterpret.
			healthCheck: {
				enabled: r.healthCheck.enabled,
				uri: r.healthCheck.uri,
				method: r.healthCheck.method || HEALTH_CHECK_DEFAULTS.method,
				interval: r.healthCheck.interval,
				timeout: r.healthCheck.timeout,
				expectStatus: r.healthCheck.expectStatus,
				expectBody: r.healthCheck.expectBody,
				passes: r.healthCheck.passes,
				fails: r.healthCheck.fails
			}
		};
		basicAuthPasswordSet = r.basicAuth?.passwordSet ?? false;
		void loadDNSProvider();
		void loadForwardAuthProviders();
		// Step O.4: refresh managed-domains snapshot — see comment
		// on the create-form openCreate path.
		void loadManagedDomainsForRoutes();
		// Step J.2 preserve-or-replace: the user has not touched the
		// HC sub-form yet, so a submit without further interaction
		// omits the block and triggers the preserve path. Any
		// interaction with an HC input flips this to true (see
		// markHealthCheckTouched).
		healthCheckTouched = false;
		requestHeaderRows = recordToTuples(r.requestHeaders ?? {});
		responseHeaderRows = recordToTuples(r.responseHeaders ?? {});
		// W.7 follow-up — auto-open the country-block
		// section on edit IF the route already has a mode
		// set (allow / deny). The operator opening an
		// existing gated route should see the country list
		// immediately without a second click on the summary;
		// the off-state stays collapsed to match the create-
		// form default.
		cbSectionOpen = r.countryBlock.mode !== 'off';
		resetFormErrors();
		formOpen = true;
	}

	// Step J.2 preserve-or-replace: any user interaction with the
	// HC sub-form (the enabled checkbox or any sub-field) flips
	// healthCheckTouched to true, so the submit ships the complete
	// block. Without this, a PUT would omit `healthCheck` even
	// though the user intentionally changed something. The on:*
	// handlers in the markup call this.
	function markHealthCheckTouched() {
		healthCheckTouched = true;
	}

	function addAlias() {
		formData.aliases = [...formData.aliases, ''];
	}
	function removeAlias(i: number) {
		formData.aliases = formData.aliases.filter((_, idx) => idx !== i);
	}

	// Step I.7 hotfix (Finding #5): TLS off ⇒ no HTTP→HTTPS redirect.
	$effect(() => {
		if (!formData.tlsEnabled && formData.redirectToHttps) {
			formData.redirectToHttps = false;
		}
	});

	// Step J.4: DNS provider status (snapshot loaded on mount and
	// re-fetched whenever we open the form). The Routes page uses
	// this for three things:
	//   (1) the inline hint in the ACME challenge selector when the
	//       user picks "dns-01" without a configured provider;
	//   (2) the form-level disabled state on "dns-01" — keeps the
	//       backend's edit-time 400 from being the only signal;
	//   (3) the page-level (β) bandeau when any persisted route
	//       carries acmeChallenge="dns-01" while the provider is
	//       missing / incomplete (provider deleted AFTER routes
	//       were saved).
	let dnsProvider = $state<DNSProviderOVH | null>(null);
	let dnsProviderLoadError = $state<string | null>(null);

	async function loadDNSProvider() {
		try {
			dnsProvider = await settingsApi.getDNSProviderOVH();
			dnsProviderLoadError = null;
		} catch (err) {
			dnsProvider = null;
			dnsProviderLoadError = err instanceof ApiError ? err.message : String(err);
		}
	}

	// Step K.1: forward-auth providers snapshot, loaded on mount
	// and on form open. Drives the per-route forward_auth selector
	// (options = configured providers) and the inline hint when
	// the user picks forward_auth but no provider is configured.
	let forwardAuthProviders = $state<ForwardAuthProvider[]>([]);

	async function loadForwardAuthProviders() {
		try {
			forwardAuthProviders = await settingsApi.listForwardAuthProviders();
		} catch (_err) {
			forwardAuthProviders = [];
		}
	}

	// Step O.4 — managed-domains snapshot, loaded on mount + on
	// form open (same cadence as the DNS provider snapshot). Used
	// to drive (a) the route-list `effectiveCertSource` badge
	// already populated server-side and (b) the form's contextual
	// "host is covered by *.<apex>" hint + useDedicatedCert toggle.
	let managedDomains = $state<ManagedDomain[]>([]);

	async function loadManagedDomainsForRoutes() {
		try {
			const res = await settingsApi.listManagedDomains();
			managedDomains = res.domains;
		} catch (_err) {
			managedDomains = [];
		}
	}

	// Pure JS port of caddymgr.IsHostCoveredByManagedDomain (spec
	// §3.2 + RFC 6125 §6.4.3). Single-label wildcard, case-
	// insensitive, trailing dot canonicalised. Returns the matching
	// ManagedDomain or null. Kept in this file rather than a
	// shared util because it's the only frontend caller for now;
	// extract when a second caller lands (likely never — server
	// emits effectiveCertSource directly).
	function findCoveringManagedDomain(host: string): ManagedDomain | null {
		if (!host) return null;
		const h = host.toLowerCase().replace(/\.$/, '');
		if (h.startsWith('*.')) return null;
		for (const md of managedDomains) {
			const apex = md.apex.toLowerCase().replace(/\.$/, '');
			if (!apex) continue;
			if (h === apex) {
				if (md.includeApex) return md;
				continue;
			}
			const suffix = '.' + apex;
			if (!h.endsWith(suffix)) continue;
			const prefix = h.slice(0, -suffix.length);
			if (prefix === '' || prefix.includes('.')) continue;
			return md;
		}
		return null;
	}

	// (β) bandeau gate: any persisted route is on dns-01 while the
	// provider is not fully configured. Derived from the loaded
	// routes + provider snapshot; updates automatically when either
	// list changes after a refresh.
	const dns01Inconsistent = $derived.by(() => {
		if (!dnsProvider || dnsProvider.configured) return false;
		return routes.some((r) => r.acmeChallenge === 'dns-01');
	});

	// Step J.4 wildcard detection — mirrors the backend's
	// wildcardHostRE. Single-leading-`*` only; multi-wildcards are
	// rejected upstream as malformed hostnames.
	function isWildcardHost(h: string): boolean {
		return /^\*\.[A-Za-z0-9-.]+$/.test(h.trim());
	}

	// Step O.4 — derived covering managed domain for the form's
	// current host. When non-null, the per-route ACME selector is
	// hidden and an inheritance badge is shown (AC #11). Operator
	// can opt out via the useDedicatedCert checkbox to fall back
	// to the J-era per-route ACME path. Wildcard route-hosts
	// (`*.foo`) are never "covered" — the wildcard IS the cert,
	// not a consumer of one — so the predicate returns null and
	// the J-era acmeLockedToDNS01 path takes over.
	const coveringManagedDomain = $derived(findCoveringManagedDomain(formData.host));

	// Step O.4 backlog #O.4-2 — handler for the useDedicatedCert
	// checkbox. The plain bind:checked path would have silently
	// left the route's previous acmeChallenge value in place when
	// the operator toggles the opt-out on — but for routes that
	// were previously on a managed-domain wildcard, the form-load
	// path normalised acmeChallenge "inherited" → "http-01" as a
	// non-restorable default (the operator's original per-route
	// choice was lost at managed-domain-create time). Defaulting
	// the dropdown to http-01 on opt-out toggle would mean ANY
	// operator clicking the toggle accidentally provisions an
	// HTTP-01 cert with no explicit decision.
	//
	// Fix per backlog #O.4-2 Option B: when the toggle flips
	// false → true, clear acmeChallenge to "" so the dropdown
	// renders unselected. Submit is disabled until the operator
	// picks. Toggling back true → false re-engages the managed-
	// domain wildcard and the dropdown disappears, so we don't
	// need to restore anything.
	function onUseDedicatedCertToggle(next: boolean): void {
		const wasOptedOut = formData.useDedicatedCert;
		formData.useDedicatedCert = next;
		if (!wasOptedOut && next) {
			// false → true: force explicit choice. Empty
			// acmeChallenge is rejected by the backend
			// reconcile too, so this matches server contract.
			formData.acmeChallenge = '';
		}
	}

	// Step O.4 backlog #O.4-2 — submit guard. Covered + opted out
	// + no acmeChallenge picked = pending operator decision.
	// Button stays disabled until the dropdown resolves.
	const dedicatedOptOutPendingChoice = $derived(
		coveringManagedDomain !== null &&
			formData.useDedicatedCert &&
			(formData.acmeChallenge === '' || formData.acmeChallenge === 'inherited')
	);

	// Step J.4: when the host or any alias is a wildcard, the
	// challenge selector is LOCKED to "dns-01" (greyed). Used as
	// `disabled` on the selector AND to force-flip the formData
	// value if the user pastes a wildcard host into a form that
	// was previously on http-01.
	const acmeLockedToDNS01 = $derived.by(() => {
		if (isWildcardHost(formData.host)) return true;
		return formData.aliases.some(isWildcardHost);
	});

	$effect(() => {
		if (acmeLockedToDNS01 && formData.acmeChallenge !== 'dns-01') {
			formData.acmeChallenge = 'dns-01';
		}
	});

	// Step J.4: when TLS gets turned off the ACMEChallenge value is
	// irrelevant. We don't reset it (so the user can toggle TLS off
	// and back on without losing the choice), but the selector is
	// hidden — see the markup.
	// Step J.3: derive whether the LB-policy selector is visible.
	// Hidden when the pool has one upstream — selection is moot;
	// formData.lbPolicy is preserved across visibility flips so an
	// admin who picked weighted_round_robin, removed an upstream,
	// then re-added one keeps the choice.
	const lbSelectorVisible = $derived(formData.upstreams.length >= 2);

	// Step J.3: derive whether the weight column is visible.
	// Shown only for weighted_round_robin; per-row Weight value is
	// preserved across visibility flips (the form state isn't
	// touched when we hide the column).
	const weightVisible = $derived(formData.lbPolicy === 'weighted_round_robin');

	// Step #R-PROXMOX-HTTPS-LOOP — derived helpers for the
	// upstream-pool scheme + per-row UX hints. Mirror of the
	// storage `Route.PoolUsesHTTPS` predicate and the
	// `validateSameSchemePool` invariant, surfaced at form
	// time so the operator gets fast feedback instead of a
	// 400 on submit.
	//
	// poolScheme one of:
	//   - 'empty'  — no rows have a URL yet (form just opened)
	//   - 'http'   — every parseable row is http://
	//   - 'https'  — every parseable row is https://
	//   - 'mixed'  — at least one http and at least one https row
	//
	// Unparseable rows are ignored by the predicate (their own
	// per-row error already blocks submit). The "mixed" state
	// triggers a row-level error AND suppresses the TLS
	// advanced disclosure (the storage validator would reject
	// the submit anyway).
	type PoolScheme = 'empty' | 'http' | 'https' | 'mixed';
	function schemeOf(u: { url: string }): 'http' | 'https' | null {
		const s = u.url.trim().toLowerCase();
		if (s.startsWith('http://')) return 'http';
		if (s.startsWith('https://')) return 'https';
		return null;
	}
	const poolScheme = $derived.by<PoolScheme>(() => {
		let sawHTTP = false;
		let sawHTTPS = false;
		for (const u of formData.upstreams) {
			const sc = schemeOf(u);
			if (sc === 'http') sawHTTP = true;
			else if (sc === 'https') sawHTTPS = true;
		}
		if (sawHTTP && sawHTTPS) return 'mixed';
		if (sawHTTPS) return 'https';
		if (sawHTTP) return 'http';
		return 'empty';
	});

	// Disclosure visibility for the "Options avancées TLS"
	// block — visible ONLY on a clean all-https pool. When
	// the pool is mixed, the row error suppresses the
	// disclosure too (the operator can't make a meaningful
	// choice until the pool is consistent).
	const tlsAdvancedVisible = $derived(poolScheme === 'https');

	// Self-heal on https→http transition: reset the toggle
	// to false so the on-screen state and the storage state
	// stay aligned. Mirror of the backend self-heal at
	// internal/api/routes.go createRoute / updateRoute
	// (silent normalisation + warn-log). Without this
	// $effect the form would hide a still-true value when
	// the operator switched a Proxmox route's pool to an
	// http upstream, then re-expose it (checked) on a
	// re-flip — exactly the surprise the operator flagged
	// during plan review.
	$effect(() => {
		if (poolScheme !== 'https' && formData.insecureSkipVerify) {
			formData.insecureSkipVerify = false;
		}
	});

	// Per-row "private IP + https" hint. Recognises RFC 1918
	// (10/8, 172.16/12, 192.168/16), 127/8 loopback, and the
	// IPv6 ULA range fc00::/7 plus ::1. Hostnames are NOT
	// flagged (a homelab might use mDNS or a private DNS
	// suffix that the operator already trusts). The hint is
	// advisory only — it never blocks submit; the operator
	// might intentionally use a public-CA cert behind a
	// private network (split-horizon DNS), in which case
	// the hint is benign.
	const RFC1918_RE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/;
	const IPV6_PRIVATE_RE = /^(::1|f[cd][0-9a-f]{2}:)/i;
	function hasPrivateUpstreamHost(rawURL: string): boolean {
		const url = rawURL.trim();
		if (url === '') return false;
		let parsed: URL;
		try {
			parsed = new URL(url);
		} catch {
			return false;
		}
		// new URL() wraps bracketed IPv6 hostnames in [...]; strip
		// before matching the regex. IPv4 + hostnames are
		// untouched.
		const host = parsed.hostname.replace(/^\[|\]$/g, '');
		return RFC1918_RE.test(host) || IPV6_PRIVATE_RE.test(host);
	}
	function showPrivateIPHint(rawURL: string): boolean {
		return schemeOf({ url: rawURL }) === 'https' && hasPrivateUpstreamHost(rawURL);
	}

	// Per-row path warning. Caddy reverse_proxy targets the
	// upstream at host:port; any path component on the upstream
	// URL is silently dropped (the dial field never carries a
	// path). Operators routinely paste full URLs from a browser
	// address bar (e.g. https://pve.local:8006/api2/json) and
	// expect the path to be honoured — the warning surfaces the
	// truth without rejecting the value (they may want to keep
	// the input as a reminder of where the API root sits, then
	// configure path forwarding via request headers in a future
	// commit).
	function nonRootPath(rawURL: string): string | null {
		const url = rawURL.trim();
		if (url === '') return null;
		let parsed: URL;
		try {
			parsed = new URL(url);
		} catch {
			return null;
		}
		if (parsed.pathname === '' || parsed.pathname === '/') return null;
		return parsed.pathname;
	}

	// --- Client-side validation (Step J.3) -----------------------------------

	function parseDuration(s: string): number | null {
		if (!DURATION_RE.test(s)) return null;
		// We do not need the actual ns count — just whether it
		// parses. The "positive" check is done indirectly by
		// requiring at least one digit (the regex ensures \d+).
		// Comparison timeout < interval falls back on string
		// equality for the common case where the operator typed the
		// same value twice; rare edge cases (e.g. "60s" vs "1m")
		// are caught by the server validator.
		return s.length;
	}

	function validateBeforeSubmit(): boolean {
		const next: Record<string, string> = {};

		if (formData.host.trim() === '') {
			next['host'] = 'Host must not be empty';
		}

		// Step J.1: per-upstream URL + weight validation.
		if (formData.upstreams.length === 0) {
			next['upstreams'] = 'At least one upstream is required';
		}
		formData.upstreams.forEach((u, i) => {
			const url = u.url.trim();
			if (url === '') {
				next[`upstreams[${i}].url`] = 'URL must not be empty';
			} else {
				try {
					const parsed = new URL(url);
					if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
						next[`upstreams[${i}].url`] = 'URL must use http or https';
					}
				} catch {
					next[`upstreams[${i}].url`] = 'URL is malformed';
				}
			}
			if (weightVisible && u.weight < 1) {
				next[`upstreams[${i}].weight`] = 'Weight must be >= 1';
			}
		});
		// Step #R-PROXMOX-HTTPS-LOOP — same-scheme pool
		// invariant. Mirror of storage.validateSameSchemePool;
		// surfacing it at the form's submit boundary spares the
		// operator a 400 round-trip. Pool-level error rendered
		// under the pool header; individual rows keep their own
		// per-URL errors.
		if (poolScheme === 'mixed') {
			next['upstreams'] =
				'All upstreams must share the same scheme (http:// or https://) — mixed pools are not supported.';
		}

		// Step J.2: health-check sub-form validation, gated on enabled.
		if (formData.healthCheck.enabled) {
			const hc = formData.healthCheck;
			if (hc.uri.trim() === '') {
				next['healthCheck.uri'] = 'URI is required';
			} else if (!hc.uri.startsWith('/')) {
				next['healthCheck.uri'] = 'URI must start with /';
			}
			// method: a binary select bound to a fixed set, so
			// validation is unreachable through the UI; defensive
			// check kept anyway.
			if (hc.method !== 'GET' && hc.method !== 'HEAD') {
				next['healthCheck.method'] = 'Method must be GET or HEAD';
			}
			// Defaultable fields: blank passes through to the
			// server, which materialises defaults. Validate only
			// non-blank inputs.
			if (hc.interval !== '' && parseDuration(hc.interval) === null) {
				next['healthCheck.interval'] = 'Interval must be a duration (e.g. 30s)';
			}
			if (hc.timeout !== '' && parseDuration(hc.timeout) === null) {
				next['healthCheck.timeout'] = 'Timeout must be a duration (e.g. 5s)';
			}
			// timeout < interval: only checked when BOTH are
			// supplied (string equality catches the common typo).
			if (
				hc.interval !== '' &&
				hc.timeout !== '' &&
				parseDuration(hc.interval) !== null &&
				parseDuration(hc.timeout) !== null &&
				hc.timeout === hc.interval
			) {
				next['healthCheck.timeout'] = 'Timeout must be less than interval';
			}
			if (hc.expectStatus !== 0 && (hc.expectStatus < 100 || hc.expectStatus > 599)) {
				next['healthCheck.expectStatus'] = 'Expected status must be 0 or in 100..599';
			}
			if (hc.expectBody !== '') {
				try {
					// eslint-disable-next-line no-new
					new RegExp(hc.expectBody);
				} catch {
					next['healthCheck.expectBody'] = 'Expected body is not a valid regex';
				}
			}
			// passes / fails: 0 means "use default" → blank-equiv,
			// don't reject. Negative values are rejected.
			if (hc.passes < 0) {
				next['healthCheck.passes'] = 'Passes must be >= 1';
			}
			if (hc.fails < 0) {
				next['healthCheck.fails'] = 'Fails must be >= 1';
			}
		}

		errors = next;
		return Object.keys(next).length === 0;
	}

	// Step I.7 / J.3: server validation error → which field path
	// does it apply to? The server uses both camelCase ("upstreams[0]
	// .url", "healthCheck.method") and prefixes the message with the
	// field path verbatim, so we read up to the first colon or space.
	function fieldFromMessage(msg: string): string | null {
		// Patterns observed:
		//   "host must not be empty"
		//   "upstreams[1]: upstreamUrl must use http or https scheme"
		//   "upstreams[1].weight must be >= 1"
		//   "healthCheck.uri must not be empty when enabled"
		//   "healthCheck.timeout must be strictly less than interval"
		//   "lbPolicy "foo" is not a valid policy"
		const lower = msg.toLowerCase();
		if (lower.startsWith('host ')) return 'host';
		if (lower.startsWith('lbpolicy ')) return 'lbPolicy';
		// upstreams[N]:... or upstreams[N].field …
		const upstreamsMatch = /^upstreams\[(\d+)\]/.exec(msg);
		if (upstreamsMatch) {
			const idx = upstreamsMatch[1];
			if (msg.startsWith(`upstreams[${idx}].weight`)) {
				return `upstreams[${idx}].weight`;
			}
			return `upstreams[${idx}].url`;
		}
		if (lower.startsWith('upstreams ')) {
			return 'upstreams';
		}
		// healthCheck.<subfield>
		const hcMatch = /^healthCheck\.(\w+)/.exec(msg);
		if (hcMatch) {
			return `healthCheck.${hcMatch[1]}`;
		}
		return null;
	}

	async function submitForm() {
		submitting = true;
		resetFormErrors();
		if (!validateBeforeSubmit()) {
			submitting = false;
			return;
		}
		try {
			// Step J.3: build the payload from formData. The pool +
			// lbPolicy + healthCheck are shipped explicitly. lbPolicy
			// is sent as the empty string when the selector is
			// hidden (pool size == 1) so the server applies the
			// default round_robin on create / preserves on update.
			// Step K.1: zero out the inactive auth sub-shape based on
			// AuthMode. The server enforces mutual exclusion via
			// validateAuthFieldsMutex; the form mirrors the same
			// invariant on the way out so an in-place mode switch
			// in the radio group never ships stale fields.
			const basicAuth =
				formData.authMode === 'basic'
					? {
							username: formData.basicAuth.username,
							password: formData.basicAuth.password
						}
					: { username: '', password: '' };
			const forwardAuth =
				formData.authMode === 'forward_auth'
					? { providerName: formData.forwardAuth.providerName }
					: { providerName: '' };
			const payload: RouteRequest = {
				host: formData.host,
				upstreams: formData.upstreams.map((u) => ({ url: u.url.trim(), weight: u.weight })),
				lbPolicy: lbSelectorVisible ? (formData.lbPolicy as LBPolicy) : '',
				tlsEnabled: formData.tlsEnabled,
				redirectToHttps: formData.redirectToHttps,
				aliases: formData.aliases.map((a) => a.trim()).filter((a) => a.length > 0),
				authMode: formData.authMode,
				basicAuth,
				forwardAuth,
				requestHeaders: tuplesToRecord(requestHeaderRows),
				responseHeaders: tuplesToRecord(responseHeaderRows),
				wafMode: formData.wafMode,
				acmeChallenge: formData.acmeChallenge,
				// W.5 — country-block always shipped (POST and
				// PUT). Unlike healthCheck's preserve-or-replace
				// pattern, the form always shows the current
				// state and the operator's intent is explicit:
				// "off" is the canonical disabled state, NOT
				// "preserve previous". Mirrors wafMode's
				// always-shipped semantic (which the API maps
				// to preserve-on-empty for PUT, full set on
				// POST). The W.2 API tolerates both modes.
				countryBlock: {
					mode: formData.countryBlock.mode,
					countryList: [...formData.countryBlock.countryList],
					statusCode: formData.countryBlock.statusCode
				}
			};
			// Step #R-PROXMOX-HTTPS-LOOP — only ship
			// insecureSkipVerify when the pool is https. On an
			// http-only pool the field is meaningless (the
			// backend self-heals to false either way), and
			// omitting it on PUT triggers the preserve-previous
			// path which is the right shape for an unrelated
			// edit. On https pools ship the explicit boolean so
			// the operator's intent (true or freshly-unchecked
			// false) is full-replacement, mirroring the wafMode
			// always-ship pattern.
			if (poolScheme === 'https') {
				payload.insecureSkipVerify = formData.insecureSkipVerify;
			}
			// Phase 4.5 — always ship uploadStreamingMode. No
			// scheme-dependent self-heal applies (the toggle
			// affects WAF body inspection + Caddy buffering on
			// any pool), so the form's explicit value is the
			// authoritative one. On POST this captures the
			// strict-false default cleanly; on PUT it's a full
			// replacement aligned with the visible toggle state.
			payload.uploadStreamingMode = formData.uploadStreamingMode;
			// Step J.2 preserve-or-replace: ship the HC block only
			// if the user touched it. Otherwise omit, letting the
			// server preserve the previously stored value (on PUT)
			// or default to disabled (on POST — emptyFormData makes
			// the un-touched HC zero anyway, but omitting is
			// cleaner and symmetric with PUT).
			if (healthCheckTouched) {
				payload.healthCheck = {
					enabled: formData.healthCheck.enabled,
					uri: formData.healthCheck.uri,
					method: formData.healthCheck.method as 'GET' | 'HEAD',
					interval: formData.healthCheck.interval,
					timeout: formData.healthCheck.timeout,
					expectStatus: formData.healthCheck.expectStatus,
					expectBody: formData.healthCheck.expectBody,
					passes: formData.healthCheck.passes,
					fails: formData.healthCheck.fails
				};
			}
			if (formMode === 'create') {
				await createRoute(payload);
				pushToast('Route created', 'success');
			} else if (editingId) {
				await updateRoute(editingId, payload);
				pushToast('Route updated', 'success');
			}
			// Bug 1 fix (C11 Pack A polish round 3, 2026-06-06):
			// Save MUST clear editingId so the route-row-selected
			// highlight goes away — same symmetry Cancel has via
			// closePanel(). Previously this only flipped
			// formOpen=false, leaving editingId set and producing
			// a phantom-selected row with no panel open.
			closePanel();
			await loadRoutes();
		} catch (err) {
			if (err instanceof ApiError && err.kind === 'validation') {
				const field = fieldFromMessage(err.message);
				if (field) {
					errors = { ...errors, [field]: err.message };
				} else {
					formError = err.message;
				}
			} else if (auth.state === 'locked') {
				// Day 13 — #R-FRONTEND-PUT-NO-TIMEOUT layer B.
				// If the session lock fired while the save was in
				// flight (heartbeat 403 OR this very request's
				// 403), the LockScreen overlay already mounted on
				// top of the route panel. Suppress the toast — a
				// second alert on top of the unlock dialog is
				// noise + steals operator focus from the password
				// prompt. The 403 is still logged at info level
				// via the client interceptor; nothing is hidden,
				// just deduplicated for the operator.
			} else {
				const msg = err instanceof ApiError ? err.message : String(err);
				pushToast(msg, 'danger');
			}
		} finally {
			submitting = false;
		}
	}

	async function confirmDelete() {
		if (!confirmTarget) return;
		deleting = true;
		try {
			await deleteRoute(confirmTarget.id);
			pushToast('Route deleted', 'success');
			confirmTarget = null;
			await loadRoutes();
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : String(err);
			pushToast(msg, 'danger');
		} finally {
			deleting = false;
		}
	}

	async function loadRoutes() {
		loading = true;
		loadError = null;
		try {
			routes = await listRoutes();
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : String(err);
			loadError = msg;
			pushToast(msg, 'danger');
		} finally {
			loading = false;
		}
	}

	onMount(async () => {
		await Promise.all([
			loadRoutes(),
			loadDNSProvider(),
			loadForwardAuthProviders(),
			loadManagedDomainsForRoutes()
		]);
	});

	const stats = $derived({
		total: routes.length,
		active: routes.length,
		tls: routes.filter((r) => r.tlsEnabled).length,
		waf: routes.filter((r) => r.wafMode !== 'off').length
	});

	// Filtered list view. Two independent filters that AND
	// together: the search input (case-insensitive substring on
	// host / aliases / upstream URL) and the segmented Healthy /
	// Alerts tab (Critique 11 Pack A, 2026-06-05).
	//
	// Healthy / Alerts semantics:
	//   - 'all'     → no health filter; show every route
	//   - 'healthy' → only routes with aggregateStatus === 'healthy'
	//     (unknown does NOT count as healthy — gray ≠ green,
	//     consistent with the Topology C13 gate.)
	//   - 'alerts'  → routes in {degraded, down}. Unknown is also
	//     excluded from alerts: we don't have a confirmed problem.
	const filteredRoutes = $derived.by(() => {
		const q = listFilter.trim().toLowerCase();
		let pool = routes;
		if (listTab === 'healthy') {
			pool = pool.filter((r) => r.aggregateStatus === 'healthy');
		} else if (listTab === 'alerts') {
			pool = pool.filter(
				(r) => r.aggregateStatus === 'degraded' || r.aggregateStatus === 'down',
			);
		}
		if (!q) return pool;
		return pool.filter((r) => {
			if (r.host.toLowerCase().includes(q)) return true;
			for (const a of r.aliases ?? []) {
				if (a.toLowerCase().includes(q)) return true;
			}
			for (const u of r.upstreams ?? []) {
				if (u.url.toLowerCase().includes(q)) return true;
			}
			return false;
		});
	});

	// Map the wire-level aggregate health to a Badge presentation
	// (label + variant). The variant names map directly onto the
	// shared --status-* design tokens, the same ones Topology
	// UpstreamNode / BackendClusterNode + the TLS / Detect /
	// Block badges already in this table use. No inline colors —
	// a future theme change propagates everywhere automatically.
	//
	// Originally rendered as a StatusDot during C11 Pack A; the
	// operator's smoke surfaced the dot-alone was ambiguous to
	// scan, so the polish round swapped it for an explicit
	// uppercase text badge matching the existing pill style.
	function aggregateToBadge(s: Route['aggregateStatus']): {
		label: string;
		variant: 'status-up' | 'status-warn' | 'status-down' | 'neutral';
	} {
		switch (s) {
			case 'healthy':
				return { label: 'HEALTHY', variant: 'status-up' };
			case 'degraded':
				return { label: 'DEGRADED', variant: 'status-warn' };
			case 'down':
				return { label: 'DOWN', variant: 'status-down' };
			default:
				return { label: 'UNKNOWN', variant: 'neutral' };
		}
	}

	function fmtDate(iso: string): string {
		return new Date(iso).toLocaleString();
	}
</script>

<PageHeader
	eyebrow="Trafic · Routes"
	title="Routes"
	subtitle="Manage reverse proxy routes — hosts, upstreams, TLS, WAF, authentication."
>
	{#snippet actions()}
		<Button variant="ghost" disabled title="Phase 2 — Caddyfile import not yet wired"
			>Import Caddyfile</Button
		>
		<Button onclick={openCreate}>+ Add route</Button>
	{/snippet}
</PageHeader>

<!-- Step J.4 (β) bandeau: at least one persisted route uses
     DNS-01 ACME but the OVH DNS provider is not configured (or is
     partially configured). The (α) edit-time validation prevents
     creating new dns-01 routes in this state; this bandeau catches
     the case where the provider is removed AFTER routes were
     saved. Cert renewal will fail until the provider is
     re-completed. -->
{#if dns01Inconsistent}
	<div
		class="mt-4 mb-2 rounded border border-down/40 bg-down/10 px-4 py-3 text-sm text-down"
		role="alert"
	>
		<strong class="font-semibold">DNS-01 routes need a DNS provider.</strong>
		At least one route is configured for DNS-01 ACME, but the OVH DNS
		provider is missing or incomplete in
		<a href="/settings" class="underline">Settings</a>. Certificate
		renewals for these routes will fail until the provider is configured.
	</div>
{/if}

{#if loading}
	<div class="flex items-center gap-2 mt-12 text-secondary">
		<Spinner /> Loading routes…
	</div>
{:else if loadError}
	<div class="mt-12 text-down" role="alert">Failed to load routes: {loadError}</div>
{:else if routes.length === 0 && !formOpen}
	<!-- Empty-state CTA. Skipped when formOpen is true so the new-
	     route create flow drops directly into the split layout's
	     right panel (operator who clicked "+ Add route" expects to
	     see the form, not an empty-state encore). -->
	<div class="mt-16 flex flex-col items-center text-center gap-4">
		<div class="text-6xl text-muted">◉</div>
		<p class="text-secondary">No routes configured yet.</p>
		<Button onclick={openCreate}>+ Add your first route</Button>
	</div>
{:else}
	<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mt-6">
		<StatCard label="Total Routes" value={stats.total} />
		<StatCard label="Active" value={stats.active} />
		<StatCard label="With TLS" value={stats.tls} />
		<StatCard label="With WAF" value={stats.waf} />
	</div>

	<!-- Phase 1 split layout (2026-06-02) — replaces the Step I/J
	     DataTable + Modal-form combo with a 2-column grid: list on
	     the left, sticky edit panel on the right. The form contents
	     are unchanged; only the wrapping moved out of Modal into
	     the right-card.
	     Tests rely on the "+ Add route" button + form-field labels
	     being queryable AFTER an openCreate click — that contract
	     holds: openCreate() still flips formOpen=true and the
	     right-card renders the same Input/Checkbox/select fields. -->
	<div class="grid grid-cols-1 xl:grid-cols-[1.3fr_1fr] gap-4 mt-6 items-start">
		<!-- LEFT — routes list -->
		<div class="rounded-lg border border-border-subtle bg-elevated overflow-hidden">
			<div class="px-4 py-3 border-b border-border-subtle flex items-center gap-3 flex-wrap">
				<!-- Search input — filters host / aliases / upstream URL
				     substring via the filteredRoutes $derived. -->
				<div class="flex-1 min-w-[200px] flex items-center gap-2 px-2 py-1 rounded-md bg-surface border border-border-default">
					<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
						<circle cx="7" cy="7" r="5" />
						<path d="M11 11l3 3" />
					</svg>
					<input
						type="search"
						bind:value={listFilter}
						placeholder="Filter by host, alias, upstream…"
						aria-label="Filter routes"
						class="flex-1 bg-transparent outline-none text-sm text-primary placeholder-muted"
					/>
				</div>
				<!-- Segmented tabs. "All" is the only functional filter
				     in Phase 1; the other two are visual stubs pending
				     a per-route health field on the API surface.
				     TODO Phase 2: wire Healthy/Alerts. -->
				<div class="inline-flex gap-0.5 p-0.5 rounded-full bg-surface border border-border-default text-xs">
					<button
						type="button"
						onclick={() => (listTab = 'all')}
						class="px-3 py-1 rounded-full transition-colors"
						class:bg-hover={listTab === 'all'}
						class:text-primary={listTab === 'all'}
						class:text-secondary={listTab !== 'all'}
					>All</button>
					<button
						type="button"
						onclick={() => (listTab = 'healthy')}
						title="Phase 2 — needs per-route health field"
						class="px-3 py-1 rounded-full transition-colors"
						class:bg-hover={listTab === 'healthy'}
						class:text-primary={listTab === 'healthy'}
						class:text-secondary={listTab !== 'healthy'}
					>Healthy</button>
					<button
						type="button"
						onclick={() => (listTab = 'alerts')}
						title="Phase 2 — needs per-route health field"
						class="px-3 py-1 rounded-full transition-colors"
						class:bg-hover={listTab === 'alerts'}
						class:text-primary={listTab === 'alerts'}
						class:text-secondary={listTab !== 'alerts'}
					>Alerts</button>
				</div>
			</div>

			{#if filteredRoutes.length === 0}
				<div class="p-6 text-center text-sm text-secondary">
					{routes.length === 0
						? 'No routes configured yet.'
						: 'No routes match the current filter.'}
				</div>
			{:else}
				<table class="w-full text-sm" bind:this={tableEl}>
					<thead>
						<tr class="text-left text-xs uppercase tracking-wider text-secondary border-b border-border-subtle">
							<th class="px-4 py-3 font-medium">Host / path</th>
							<th class="px-4 py-3 font-medium">Upstream</th>
							<th class="px-4 py-3 font-medium">TLS</th>
							<th class="px-4 py-3 font-medium">WAF</th>
							<th class="px-4 py-3 font-medium text-right">État</th>
						</tr>
					</thead>
					<tbody>
						{#each filteredRoutes as r (r.id)}
							{@const selected = editingId === r.id}
							{@const statusBadge = aggregateToBadge(r.aggregateStatus)}
							<tr
								class="route-row border-b border-border-subtle last:border-b-0 cursor-pointer transition-colors hover:bg-hover"
								class:route-row-selected={selected}
								data-testid={selected ? 'route-row-selected' : 'route-row'}
								onclick={() => selectOrToggleRoute(r)}
								onkeydown={(e) => {
									if (e.key === 'Enter' || e.key === ' ') {
										e.preventDefault();
										selectOrToggleRoute(r);
									}
								}}
								tabindex="0"
								aria-current={selected ? 'true' : undefined}
								role="button"
							>
								<td class="px-4 py-3 font-mono">
									{r.host}
									{#if r.aliases && r.aliases.length > 0}
										<span
											class="ml-1.5 inline-flex items-center px-1.5 py-0.5 rounded text-xs font-sans text-secondary bg-elevated border border-border-subtle cursor-help"
											title={`Aliases:\n${r.aliases.join('\n')}`}
										>+{r.aliases.length}</span>
									{/if}
									{#if r.authMode === 'basic'}
										<span
											class="ml-1.5 inline-flex items-center text-muted cursor-help"
											title={`Basic Auth required (user: ${r.basicAuth?.username ?? ''})`}
											aria-label="Basic Auth required"
										>
											<svg
												xmlns="http://www.w3.org/2000/svg"
												class="w-3.5 h-3.5"
												viewBox="0 0 24 24"
												fill="none"
												stroke="currentColor"
												stroke-width="2"
												stroke-linecap="round"
												stroke-linejoin="round"
												aria-hidden="true"
											>
												<rect width="18" height="11" x="3" y="11" rx="2" />
												<path d="M7 11V7a5 5 0 0 1 10 0v4" />
											</svg>
										</span>
									{:else if r.authMode === 'forward_auth'}
										<span
											class="ml-1.5 inline-flex items-center text-muted cursor-help"
											title={`Forward-auth via ${r.forwardAuth?.providerName ?? ''}`}
											aria-label="Forward-auth required"
										>
											<svg
												xmlns="http://www.w3.org/2000/svg"
												class="w-3.5 h-3.5"
												viewBox="0 0 24 24"
												fill="none"
												stroke="currentColor"
												stroke-width="2"
												stroke-linecap="round"
												stroke-linejoin="round"
												aria-hidden="true"
											>
												<path d="M21 12H9" />
												<path d="m12 5 7 7-7 7" />
												<path d="M5 21V3" />
											</svg>
										</span>
									{/if}
								</td>
								<td
									class="px-4 py-3 font-mono text-secondary truncate max-w-[14rem]"
									title={r.upstreams[0]?.url ?? ''}
								>
									{r.upstreams[0]?.url ?? ''}{r.upstreams.length > 1
										? ` (+${r.upstreams.length - 1})`
										: ''}
									<!-- Critique 11 Pack A: "N/M sains" counter on
									     multi-upstream routes whose HC tracker has
									     a verdict. Hidden for single-upstream
									     pools (noise) and for unknown-status pools
									     (no verdict to count). -->
									{#if r.totalUpstreamCount > 1 && r.aggregateStatus !== 'unknown'}
										<span class="ml-1 text-xs text-muted"
											>· {r.healthyUpstreamCount}/{r.totalUpstreamCount}
											sains</span>
									{/if}
								</td>
								<td class="px-4 py-3">
									{#if r.tlsEnabled}
										<div class="flex flex-wrap items-center gap-1">
											<Badge variant="tls">TLS</Badge>
											{#if r.effectiveCertSource?.startsWith('managed-domain:')}
												<span
													title={`Inherits wildcard from *.${r.effectiveCertSource.slice('managed-domain:'.length)}`}
												>
													<Badge variant="current">wildcard</Badge>
												</span>
											{:else if r.effectiveCertSource === 'per-route-acme:dns-01'}
												<span title="Per-route DNS-01 ACME">
													<Badge variant="neutral">DNS-01</Badge>
												</span>
											{:else if r.effectiveCertSource === 'per-route-internal'}
												<span title="Internal CA (self-signed)">
													<Badge variant="neutral">internal</Badge>
												</span>
											{/if}
										</div>
									{:else}
										<span class="text-muted">—</span>
									{/if}
								</td>
								<td class="px-4 py-3">
									{#if r.wafMode === 'detect'}
										<Badge variant="status-warn">Detect</Badge>
									{:else if r.wafMode === 'block'}
										<Badge variant="status-down">Block</Badge>
									{:else}
										<span class="text-muted">—</span>
									{/if}
								</td>
								<td class="px-4 py-3 text-right">
									<!-- Critique 11 Pack A (2026-06-05): per-route
									     health rollup driven by the Stage B HC
									     tracker. aggregateToBadge maps the wire-
									     level enum to a Badge label + variant,
									     sharing the --status-* CSS tokens with
									     Topology AND the existing TLS / Detect /
									     Block badges in this same table. The
									     Healthy / Alerts segmented tabs above
									     filter on the same aggregateStatus.
									     Polish round (2026-06-06): removed the
									     redundant per-row "Edit" button — the
									     whole <tr> is the affordance (cursor-
									     pointer + hover tint + selected accent),
									     matching the mock and avoiding the
									     double-action anti-pattern. -->
									<Badge variant={statusBadge.variant}>{statusBadge.label}</Badge>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
		</div>

		<!-- RIGHT — route detail / edit panel. Sticky on wide
		     screens so it stays in view as the left list scrolls.
		     bind:this + use:clickOutsideToClose wire the
		     C11 Pack A polish round 3 dismiss-on-outside-click
		     behaviour: a document mousedown landing outside this
		     element AND outside the routes table closes the
		     panel. Clicks on the table are left to the row
		     onclick handlers (selectOrToggleRoute) so the toggle
		     semantic for the already-selected row works without
		     racing the outside listener. -->
		<div
			bind:this={panelEl}
			use:clickOutsideToClose
			class="relative rounded-lg border border-border-subtle bg-elevated xl:sticky xl:top-[calc(var(--tb-height)+14px)] xl:max-h-[calc(100vh-var(--tb-height)-40px)] overflow-auto"
		>
			{#if !formOpen}
				<!-- Empty state: nothing selected, not in create mode. -->
				<div class="p-10 text-center text-secondary text-sm">
					Select a route on the left to edit it, or click
					<span class="font-medium text-primary">+ Add route</span>
					to create a new one.
				</div>
			{:else}
				<!-- Panel header — pill + title + meta. The pill border
				     uses `border-cyan` (full opacity, same hue as the
				     text) instead of the previous `border-cyan/30`
				     which Tailwind v4 was resolving to a default-gray
				     fallback (reading as a white-ish outline on dark
				     mode and clashing visually with the cyan text). -->
				<div class="px-5 py-4 border-b border-border-subtle flex items-center gap-3">
					<span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] uppercase tracking-wider font-mono bg-accent-soft text-cyan border border-cyan">
						{formMode === 'create' ? 'new' : 'edit'}
					</span>
					<h3 class="text-base font-semibold text-primary truncate">
						{formMode === 'create' ? 'New route' : (formData.host || 'Edit route')}
					</h3>
					{#if formMode === 'edit' && editingId}
						<span class="ml-auto text-xs text-muted font-mono shrink-0">id <span class="text-secondary">{editingId.slice(0, 7)}</span></span>
					{/if}
				</div>

				<!-- D8 entry links (per-route observability + security
				     drill-downs). Visible only in edit mode — these
				     are sub-routes keyed by route id, so they're
				     meaningless for the create flow. The Delete
				     button moved here too: the per-row Delete action
				     of the prior DataTable layout is gone (clicking a
				     row now opens the panel, not the delete dialog),
				     so the delete trigger lives on the selected
				     route's own detail panel. -->
				{#if formMode === 'edit' && editingId}
					<div class="px-5 pt-4 flex flex-wrap gap-2">
						<a
							href={`/observability/${editingId}`}
							class="inline-flex items-center gap-1.5 rounded-md border border-border-default bg-surface px-2.5 py-1 text-xs text-secondary hover:text-primary hover:bg-hover transition-colors"
						>
							<svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
								<path d="M3 3v10h10" />
								<path d="M5 11l3-3 2 2 3-4" />
							</svg>
							Metrics for this route →
						</a>
						<a
							href={`/security/${editingId}`}
							class="inline-flex items-center gap-1.5 rounded-md border border-border-default bg-surface px-2.5 py-1 text-xs text-secondary hover:text-primary hover:bg-hover transition-colors"
						>
							<svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
								<rect x="3" y="7" width="10" height="7" rx="1" />
								<path d="M5 7V5a3 3 0 016 0v2" />
							</svg>
							Security for this route →
						</a>
						<Button
							variant="ghost"
							size="sm"
							onclick={() => {
								if (editingId) {
									const target = routes.find((r) => r.id === editingId);
									if (target) confirmTarget = target;
								}
							}}
						>Delete</Button>
					</div>
				{/if}

				<!-- Form body — moved verbatim out of the prior Modal
				     wrapper. All field bindings, validation, and
				     submit flow are unchanged. -->
				<form
					onsubmit={(e) => {
						e.preventDefault();
						submitForm();
					}}
					class="flex flex-col gap-4 p-5"
				>
					{#if formError}
						<p
							class="px-3 py-2 rounded bg-down/10 border border-down/40 text-sm text-down"
							role="alert"
						>
							{formError}
						</p>
					{/if}
					<Input
						label="Host"
						bind:value={formData.host}
						placeholder="example.local"
						error={errors['host'] ?? undefined}
					/>
					<!-- Step I.3: alias hostnames repeater. -->
					<div class="flex flex-col gap-2">
						<div class="flex items-center justify-between">
							<span class="text-sm text-secondary">Aliases (optional)</span>
							<Button variant="ghost" size="sm" onclick={addAlias} type="button">+ Add alias</Button>
						</div>
						{#each formData.aliases as _, i (i)}
							<div class="flex items-center gap-2">
								<Input bind:value={formData.aliases[i]} placeholder="alt.example.com" />
								<Button variant="ghost" size="sm" onclick={() => removeAlias(i)} type="button">×</Button>
							</div>
						{/each}
					</div>
			
					<!-- Step J.3: upstream pool repeater (replaces the Step I single
					     Upstream URL input). Each row binds to one pool element.
					     The weight column is hidden unless lbPolicy is
					     weighted_round_robin. Per-row state is preserved across
					     visibility flips. -->
					<div class="flex flex-col gap-2">
						<div class="flex items-center justify-between">
							<span class="text-sm font-medium text-secondary">Upstreams</span>
							<div class="flex items-center gap-2">
								<!--
									Step #R-PROXMOX-HTTPS-LOOP commit 3 — pool-level
									"Tester tous". Promise.all parallelise pool > 1.
									Disabled when every row's URL is empty.
								-->
								<Button
									variant="ghost"
									size="sm"
									onclick={runAllUpstreamTests}
									type="button"
									disabled={formData.upstreams.every((u) => u.url.trim() === '')}
									data-testid="test-all-upstreams"
								>
									Tester tous
								</Button>
								<Button variant="ghost" size="sm" onclick={addUpstream} type="button"
									>+ Add upstream</Button
								>
							</div>
						</div>
						{#if errors['upstreams']}
							<p class="text-xs text-down">{errors['upstreams']}</p>
						{/if}
						{#each formData.upstreams as _, i (i)}
							<div class="flex items-start gap-2">
								<div class="flex-1 flex flex-col gap-1">
									<Input
										bind:value={formData.upstreams[i].url}
										placeholder="http://127.0.0.1:8080"
										error={errors[`upstreams[${i}].url`] ?? undefined}
									/>
									<!--
										Step #R-PROXMOX-HTTPS-LOOP — per-row UX
										advisories. Path warning + private-IP
										hint are non-blocking; the URL value is
										preserved (operator may want to fix the
										URL themselves rather than have the form
										strip it).
									-->
									{#if nonRootPath(formData.upstreams[i].url)}
										<p
											class="text-xs text-amber-700 dark:text-amber-300"
											data-testid="upstream-path-warning"
										>
											Le chemin <code class="font-mono"
												>{nonRootPath(formData.upstreams[i].url)}</code
											> sera ignoré — Caddy proxyfie uniquement vers <code class="font-mono"
												>host:port</code
											>.
										</p>
									{/if}
									{#if showPrivateIPHint(formData.upstreams[i].url)}
										<p
											class="text-xs text-amber-700 dark:text-amber-300"
											data-testid="upstream-private-ip-hint"
										>
											IP privée + <code class="font-mono">https</code> détectés — le
											certificat upstream est probablement auto-signé. Pensez à
											« Options avancées TLS » si la connexion échoue.
										</p>
									{/if}
									<!--
										Step #R-PROXMOX-HTTPS-LOOP commit 3 — per-row
										probe result chip. Three states: hidden
										(undefined), spinner (running), outcome
										(reachable✓ or error✗). Outcome chip shows
										status code + latency for reachable, error
										text otherwise.
									-->
									{#if upstreamTests[i]}
										{@const ts = upstreamTests[i]}
										<div
											class="text-xs flex items-center gap-2 flex-wrap"
											data-testid="upstream-test-chip-{i}"
										>
											{#if ts.running}
												<span class="text-secondary">⏳ Test en cours…</span>
											{:else if ts.error}
												<span class="text-down">✗ {ts.error}</span>
											{:else if ts.result}
												{#if ts.result.reachable}
													<span class="text-up">
														✓ HTTP {ts.result.statusCode} ({ts.result.latencyMs}ms)
													</span>
													{#if ts.result.serverHeader}
														<span class="text-muted font-mono">
															{ts.result.serverHeader}
														</span>
													{/if}
													{#if ts.result.cert?.selfSigned}
														<span
															class="text-amber-700 dark:text-amber-300"
															title="Certificat auto-signé"
														>
															⚠ self-signed
														</span>
													{/if}
												{:else}
													<span class="text-down">
														✗ {ts.result.error || 'connexion échouée'}
													</span>
													{#if ts.result.cert?.commonName}
														<span class="text-muted font-mono">
															cert CN={ts.result.cert.commonName}
														</span>
													{/if}
												{/if}
											{/if}
										</div>
									{/if}
								</div>
								<!--
									Step #R-PROXMOX-HTTPS-LOOP commit 3 — per-row
									"Tester" button. Disabled when the URL is
									empty (no probe target) or while the row is
									already running. Spinner is in the chip below.
								-->
								<Button
									variant="ghost"
									size="sm"
									onclick={() => runUpstreamTest(i)}
									type="button"
									disabled={formData.upstreams[i].url.trim() === '' ||
										!!(upstreamTests[i] && (upstreamTests[i] as { running?: boolean }).running)}
									data-testid="test-upstream-{i}"
								>
									Tester
								</Button>
								{#if weightVisible}
									<div class="w-24 flex flex-col gap-1.5">
										<input
											type="number"
											min="1"
											bind:value={formData.upstreams[i].weight}
											placeholder="1"
											class="bg-surface border rounded-md px-3 py-2 text-sm text-primary focus:outline-none focus:ring-2 focus:ring-cyan focus:shadow-glow-cyan transition-shadow"
											class:border-down={!!errors[`upstreams[${i}].weight`]}
											class:border-border-default={!errors[`upstreams[${i}].weight`]}
										/>
										{#if errors[`upstreams[${i}].weight`]}
											<p class="text-xs text-down">{errors[`upstreams[${i}].weight`]}</p>
										{/if}
									</div>
								{/if}
								<Button
									variant="ghost"
									size="sm"
									onclick={() => removeUpstream(i)}
									disabled={formData.upstreams.length <= 1}
									type="button">×</Button
								>
							</div>
						{/each}
					</div>

					<!--
						Step #R-PROXMOX-HTTPS-LOOP — advanced TLS options
						disclosure. Mounted ONLY when the pool is a clean
						all-https; the entire block leaves the DOM on http
						/ mixed / empty pools so the operator can't set a
						meaningless flag. The scheme-transition $effect
						resets formData.insecureSkipVerify to false on
						https→http so the toggle state stays aligned with
						both the on-screen disclosure visibility and the
						storage row.
					-->
					{#if tlsAdvancedVisible}
						<details
							class="rounded-md border border-border-default bg-surface px-3 py-2"
							data-testid="tls-advanced-disclosure"
						>
							<summary class="text-sm font-medium text-secondary cursor-pointer">
								Options avancées TLS upstream
							</summary>
							<div class="mt-2 flex flex-col gap-1">
								<Checkbox
									label="Ignorer la vérification du certificat upstream"
									bind:checked={formData.insecureSkipVerify}
								/>
								<p class="text-xs text-muted ml-6">
									À cocher uniquement si l'upstream présente un certificat
									auto-signé (homelab Proxmox, Synology DSM, ESXi, UniFi).
									En production, préférez ajouter le CA à la trust store de
									l'hôte Arenet.
								</p>
							</div>
						</details>
					{/if}
			
					<!-- Step J.3: LB policy selector. Hidden when the pool has
					     one upstream (selection is moot). formData.lbPolicy is
					     preserved across visibility flips. -->
					{#if lbSelectorVisible}
						<div>
							<label
								for="route-lb-policy"
								class="text-sm font-medium text-secondary block mb-1"
							>
								Load balancing
							</label>
							<select
								id="route-lb-policy"
								bind:value={formData.lbPolicy}
								class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
							>
								<option value="round_robin">Round-robin (even distribution)</option>
								<option value="weighted_round_robin">Weighted round-robin</option>
								<option value="least_conn">Least connections</option>
								<option value="ip_hash">IP hash (client-IP affinity)</option>
								<option value="random">Random</option>
								<option value="first">First available (failover)</option>
							</select>
						</div>
					{/if}
			
					<div class="flex flex-col gap-1">
						<Checkbox label="Enable TLS" bind:checked={formData.tlsEnabled} />
						<p class="text-xs text-muted ml-6">
							Public domain required for Let's Encrypt; localhost / .local
							will fall back to internal CA.
						</p>
					</div>
					<Checkbox
						label="Redirect HTTP → HTTPS"
						bind:checked={formData.redirectToHttps}
						disabled={!formData.tlsEnabled}
						title={formData.tlsEnabled
							? 'Automatically redirects HTTP requests to HTTPS with a 301.'
							: 'Enable TLS to use HTTPS redirect.'}
					/>
			
					<!-- Step J.4 + O.4: ACME challenge selector. Visible only
					     when TLS is on. Locked to "dns-01" when host or any
					     alias is a wildcard. Step O.4 (AC #11 + #12): when the
					     host is covered by a managed domain AND the operator
					     hasn't opted out via useDedicatedCert, the selector
					     hides entirely and an inheritance badge takes its
					     place. When covered + opted out, the selector returns
					     and the operator picks http-01/dns-01 like J. -->
					{#if formData.tlsEnabled}
						{#if coveringManagedDomain && !formData.useDedicatedCert}
							<!-- AC #11: covered + inheriting. Show the wildcard
							     badge + the opt-out toggle. The selector is
							     gone — the wildcard cert serves this route. -->
							<div>
								<span class="text-sm font-medium text-secondary block mb-1"
									>Certificate</span
								>
								<div
									class="rounded border border-info/40 bg-info/10 px-3 py-2 text-sm"
								>
									<span class="font-medium">Inherits wildcard from</span>
									<code class="font-mono">*.{coveringManagedDomain.apex}</code>
									<span class="text-muted">
										(managed via <a href="/settings" class="text-cyan hover:underline"
											>SSL / Certificates</a
										>)
									</span>
								</div>
								<label class="inline-flex items-center gap-2 text-sm text-secondary mt-2 cursor-pointer">
									<input
										type="checkbox"
										checked={formData.useDedicatedCert}
										onchange={(e) =>
											onUseDedicatedCertToggle((e.target as HTMLInputElement).checked)}
									/>
									Use a dedicated cert for this route (opt out of the wildcard)
								</label>
								<p class="text-xs text-muted mt-1">
									Use this for routes that need a separate key (e.g. payments,
									staging) — the route will request its own ACME cert alongside
									the wildcard.
								</p>
							</div>
						{:else}
							<div>
								<label
									for="route-acme-challenge"
									class="text-sm font-medium text-secondary block mb-1"
								>
									ACME challenge
								</label>
								<select
									id="route-acme-challenge"
									bind:value={formData.acmeChallenge}
									disabled={acmeLockedToDNS01}
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary disabled:opacity-60 disabled:cursor-not-allowed"
								>
									{#if dedicatedOptOutPendingChoice}
										<!-- #O.4-2 force-explicit-choice — empty value
										     is the unselected state forced by the
										     toggle handler. The placeholder option
										     renders the empty selection clearly to
										     the operator (otherwise the browser
										     would silently render the first option
										     as visually selected without it being
										     the bound value). -->
										<option value="" disabled>— pick one —</option>
									{/if}
									<option value="http-01">HTTP-01 (default, port 80)</option>
									<option value="dns-01">DNS-01 (required for wildcards)</option>
								</select>
								{#if coveringManagedDomain && formData.useDedicatedCert}
									<!-- AC #11 opt-out path: show the per-route
									     selector AND the toggle (checked) so the
									     operator can flip back to inheritance. -->
									<label class="inline-flex items-center gap-2 text-sm text-secondary mt-2 cursor-pointer">
										<input
											type="checkbox"
											checked={formData.useDedicatedCert}
											onchange={(e) =>
												onUseDedicatedCertToggle(
													(e.target as HTMLInputElement).checked
												)}
										/>
										Use a dedicated cert (inherits <code class="font-mono"
											>*.{coveringManagedDomain.apex}</code
										> when unchecked)
									</label>
								{/if}
								{#if dedicatedOptOutPendingChoice}
									<!-- #O.4-2 force-explicit-choice — submit is
									     disabled until the operator picks. The
									     hint sits next to the now-unselected
									     dropdown so the cause is obvious. -->
									<p class="text-xs text-warn mt-1">
										Pick HTTP-01 or DNS-01 above — opting out of the wildcard
										requires an explicit per-route ACME challenge.
									</p>
								{/if}
								{#if acmeLockedToDNS01}
									<p class="text-xs text-muted mt-1">
										Wildcard hosts require DNS-01.
									</p>
								{:else if formData.acmeChallenge === 'dns-01' && (!dnsProvider || !dnsProvider.configured)}
									<p class="text-xs text-down mt-1">
										DNS-01 requires a configured DNS provider —
										<a href="/settings" class="text-cyan hover:underline"
											>configure it under Settings</a
										>.
									</p>
								{:else}
									<p class="text-xs text-muted mt-1">
										HTTP-01 proves control via port 80. DNS-01 proves it
										via a `_acme-challenge` TXT record and is the only
										option for wildcard certs.
									</p>
								{/if}
							</div>
						{/if}
					{/if}
			
					<!-- Step K.1 — per-route auth: radio group (none / basic /
					     forward_auth). Replaces the Step I.5 "Require Basic Auth"
					     checkbox with an explicit three-way choice. Mutual
					     exclusion enforced by the radio shape; the server
					     re-checks (validateAuthFieldsMutex) as defence in depth. -->
					<div class="flex flex-col gap-2">
						<span class="text-sm font-medium text-secondary">Authentication</span>
						<div class="flex flex-col gap-1 ml-1">
							<label class="inline-flex items-center gap-2 text-sm text-primary cursor-pointer">
								<input
									type="radio"
									name="route-auth-mode"
									value="none"
									bind:group={formData.authMode}
									class="accent-cyan"
								/>
								None
							</label>
							<label class="inline-flex items-center gap-2 text-sm text-primary cursor-pointer">
								<input
									type="radio"
									name="route-auth-mode"
									value="basic"
									bind:group={formData.authMode}
									class="accent-cyan"
								/>
								Basic auth (single shared credential)
							</label>
							<label class="inline-flex items-center gap-2 text-sm text-primary cursor-pointer">
								<input
									type="radio"
									name="route-auth-mode"
									value="forward_auth"
									bind:group={formData.authMode}
									class="accent-cyan"
								/>
								Forward auth (delegate to an IdP)
							</label>
						</div>
			
						{#if formData.authMode === 'basic'}
							<div class="ml-6 flex flex-col gap-2">
								<Input
									label="Username"
									bind:value={formData.basicAuth.username}
									placeholder="admin"
								/>
								<div>
									<label
										for="basic-auth-password"
										class="text-sm font-medium text-secondary block mb-1"
									>
										Password
									</label>
									<input
										id="basic-auth-password"
										type="password"
										bind:value={formData.basicAuth.password}
										placeholder={formMode === 'edit' && basicAuthPasswordSet
											? '••• set (leave blank to keep)'
											: ''}
										class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
									/>
								</div>
							</div>
						{:else if formData.authMode === 'forward_auth'}
							<div class="ml-6 flex flex-col gap-2">
								<label
									for="route-forward-auth-provider"
									class="text-sm font-medium text-secondary block"
								>
									Provider
								</label>
								{#if forwardAuthProviders.length === 0}
									<p class="text-xs text-down">
										No forward-auth provider configured —
										<a href="/settings" class="text-cyan hover:underline">configure one under Settings</a>.
									</p>
								{:else}
									<select
										id="route-forward-auth-provider"
										bind:value={formData.forwardAuth.providerName}
										class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
									>
										<option value="" disabled>— select a provider —</option>
										{#each forwardAuthProviders as p (p.name)}
											<option value={p.name}>{p.name} ({p.kind})</option>
										{/each}
									</select>
									<p class="text-xs text-muted">
										The route's auth gate delegates to the IdP at
										<code>{forwardAuthProviders.find((p) => p.name === formData.forwardAuth.providerName)?.verifyUrl ?? '...'}</code>
										via Caddy <code>forward_auth</code>.
									</p>
								{/if}
							</div>
						{/if}
					</div>
					<!-- Step I.4: WAF mode. -->
					<div>
						<label
							for="route-waf-mode"
							class="text-sm font-medium text-secondary block mb-1"
						>
							WAF (Coraza + OWASP CRS)
						</label>
						<select
							id="route-waf-mode"
							bind:value={formData.wafMode}
							class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
						>
							<option value="off">Off — no inspection</option>
							<option value="detect">Detect — log matches, let traffic through</option>
							<option value="block">Block — return 403 on match</option>
						</select>
						<p class="text-xs text-muted mt-1">
							Start with Detect to spot false positives before enforcing.
						</p>

						<!-- Phase 4.5 (#R-WAF-BUFFER-OOM-ON-LARGE-UPLOADS)
						     — upload-streaming toggle. Sits inside the
						     WAF block on purpose: it modulates the WAF
						     body-inspection behaviour, so the operator
						     reads it as a WAF-adjacent knob, not as an
						     advanced-TLS bolt-on. Independent of
						     wafMode — even with WAF=off the toggle
						     still controls Caddy's flush_interval. -->
						<label
							class="inline-flex items-start gap-2 text-sm text-secondary mt-3 cursor-pointer"
							data-testid="upload-streaming-toggle-label"
						>
							<input
								type="checkbox"
								bind:checked={formData.uploadStreamingMode}
								class="mt-0.5"
								data-testid="upload-streaming-toggle"
							/>
							<span>
								Mode upload streaming
								<span class="text-muted">(registry, file servers)</span>
							</span>
						</label>
						<p class="text-xs text-muted mt-1 max-w-prose">
							Désactive l'inspection WAF du <strong>request body</strong>
							<strong>ET</strong> le buffering Caddy en RAM. À activer pour
							les routes qui transitent des uploads volumineux (registry
							Docker, file servers, backups). Le WAF reste actif sur les
							<strong>headers</strong>, l'<strong>URL</strong> et la
							<strong>response</strong> — seul le body request n'est pas
							scanné. Garde ce toggle désactivé pour les routes API/web où
							l'analyse SQL/XSS du body est utile.
						</p>
					</div>

					<!-- W.5 — country-block per-route gate. Operator
					     picks mode + countries; the W.1 Caddy module
					     short-circuits at the edge before the request
					     reaches crowdsec/auth/waf. ALLOW mode + empty
					     list is rejected by the API (and surfaced here
					     as a red error) — it would block all
					     non-RFC1918 traffic. DENY mode + empty list is
					     accepted (legal no-op; server logs a Warn).
					     The "Add country" input takes ISO 3166-1
					     alpha-2 codes (2 uppercase letters); Enter or
					     comma adds the chip. -->
					<!-- W.7 polish: pill-style mode toggle (Off / Allow /
					     Deny) replaces the dropdown so operators see the
					     three states at a glance; the active button picks
					     up the mode-colored border (slate / green / red).
					     Chips recolor to match the active mode. Counter
					     "{N} pays autorisé(s) / bloqué(s)" surfaces the
					     count + mode-meaningful pluralization. Autocomplete
					     dropdown matches by alpha-2 code OR French name
					     prefix (Intl.DisplayNames) — operator types "russ"
					     to find RU/Russie. "+ Ajouter un pays" CTA improves
					     discoverability over the previous bare input. -->
					<details
						class="rounded border border-border-subtle cb-section cb-mode-{formData.countryBlock.mode}"
						bind:open={cbSectionOpen}
						data-testid="country-block-section"
					>
						<summary class="px-3 py-2 text-sm text-secondary cursor-pointer select-none">
							Pays bloqués
							{#if formData.countryBlock.mode !== 'off'}
								<span class="ml-1 text-xs text-muted">
									({formData.countryBlock.mode} · {formData.countryBlock.countryList.length})
								</span>
							{:else}
								<!-- W.7 follow-up: surface the "off" state in
								     the summary too, so when the operator
								     manually collapses the section after
								     picking Désactivé the closed-state
								     header isn't ambiguous. -->
								<span
									class="ml-1 text-xs text-muted"
									data-testid="country-block-summary-off"
								>
									(désactivé)
								</span>
							{/if}
						</summary>
						<div class="p-3 flex flex-col gap-3 border-t border-border-subtle">
							<!-- Mode pill toggle — 3 buttons in a segmented group.
							     The "Mode" caption is a <span> rather than a
							     <label> because the toggle has no single control
							     to bind to (group's aria-label carries the
							     accessible name). -->
							<div>
								<span class="text-sm font-medium text-secondary block mb-1">
									Mode
								</span>
								<div
									class="cb-mode-toggle"
									role="group"
									aria-label="Mode du gate pays"
									data-testid="country-block-mode-toggle"
								>
									<button
										type="button"
										class="cb-mode-btn cb-mode-btn--off"
										class:active={formData.countryBlock.mode === 'off'}
										data-testid="country-block-mode-off"
										aria-pressed={formData.countryBlock.mode === 'off'}
										onclick={() => cbPickMode('off')}
									>
										<span class="cb-mode-btn__label">Désactivé</span>
										<span class="cb-mode-btn__hint">pas de gate</span>
									</button>
									<button
										type="button"
										class="cb-mode-btn cb-mode-btn--allow"
										class:active={formData.countryBlock.mode === 'allow'}
										data-testid="country-block-mode-allow"
										aria-pressed={formData.countryBlock.mode === 'allow'}
										onclick={() => cbPickMode('allow')}
									>
										<span class="cb-mode-btn__label">Allow-list</span>
										<span class="cb-mode-btn__hint">refuse le reste</span>
									</button>
									<button
										type="button"
										class="cb-mode-btn cb-mode-btn--deny"
										class:active={formData.countryBlock.mode === 'deny'}
										data-testid="country-block-mode-deny"
										aria-pressed={formData.countryBlock.mode === 'deny'}
										onclick={() => cbPickMode('deny')}
									>
										<span class="cb-mode-btn__label">Deny-list</span>
										<span class="cb-mode-btn__hint">autorise le reste</span>
									</button>
								</div>
							</div>

							{#if formData.countryBlock.mode !== 'off'}
								<!-- Counter + autocomplete combo. The counter
								     uses mode-meaningful copy + plural agrees
								     with N; hidden when N=0 so the empty
								     state stays uncluttered. -->
								<div>
									<div class="flex items-baseline justify-between mb-1">
										<label
											for="route-country-block-list-input"
											class="text-sm font-medium text-secondary"
										>
											Pays
											<span class="text-xs text-muted font-normal">
												(code ISO ou nom)
											</span>
										</label>
										{#if cbCounterLabel}
											<span
												class="text-xs text-muted"
												data-testid="country-block-counter"
											>
												{cbCounterLabel}
											</span>
										{/if}
									</div>

									<!-- Chip list — rendered above the input so
									     the operator's "what's in" is the
									     primary visual focus, with the
									     "add more" affordance below. -->
									<div
										class="flex flex-wrap gap-2 mb-2"
										data-testid="country-block-chip-list"
									>
										{#each formData.countryBlock.countryList as code, i (code + i)}
											<span
												class="cb-chip"
												data-testid="country-block-chip"
												title={countryName(code)}
											>
												<span class="cb-chip__code">{code}</span>
												<span class="cb-chip__name">{countryName(code)}</span>
												<button
													type="button"
													class="cb-chip__remove"
													aria-label={`Retirer ${countryName(code)}`}
													onclick={() => cbRemoveCode(code)}
												>
													×
												</button>
											</span>
										{/each}
									</div>

									<!-- Input + CTA row. The input is wrapped in
									     a positioned container so the
									     suggestion dropdown can float below it
									     without disturbing the form layout. -->
									<div class="flex gap-2">
										<div class="cb-input-wrap flex-1">
											<input
												id="route-country-block-list-input"
												type="text"
												placeholder="Tapez FR, DE, Russie, États-Unis…"
												data-testid="country-block-input"
												autocomplete="off"
												bind:this={cbInputEl}
												value={cbInputValue}
												oninput={cbInputOnInput}
												onfocus={() => (cbDropdownOpen = true)}
												onblur={() => {
													// Defer close so a click on a
													// suggestion fires its onclick
													// BEFORE the dropdown unmounts.
													setTimeout(() => (cbDropdownOpen = false), 120);
												}}
												onkeydown={cbInputKeydown}
												class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
											/>
											{#if cbDropdownOpen && cbSuggestions.length > 0}
												<ul
													class="cb-dropdown"
													role="listbox"
													data-testid="country-block-dropdown"
												>
													{#each cbSuggestions as match, idx (match.code)}
														<li
															role="option"
															class="cb-dropdown__item"
															class:active={idx === cbActiveIndex}
															data-testid="country-block-suggestion"
															aria-selected={idx === cbActiveIndex}
															onmousedown={(e) => {
																// onmousedown (not onclick) so it
																// fires BEFORE the input's onblur
																// closes the dropdown.
																e.preventDefault();
																cbAddCode(match.code);
															}}
															onmouseenter={() => (cbActiveIndex = idx)}
														>
															<span class="cb-dropdown__code">
																{match.code}
															</span>
															<span class="cb-dropdown__name">
																{match.name}
															</span>
														</li>
													{/each}
												</ul>
											{/if}
										</div>
										<button
											type="button"
											class="cb-add-btn"
											data-testid="country-block-add-cta"
											aria-label="Ajouter un pays"
											onclick={cbOpenDropdown}
										>
											+ Ajouter
										</button>
									</div>

									{#if formData.countryBlock.mode === 'allow' && formData.countryBlock.countryList.length === 0}
										<p
											class="text-xs text-down mt-1"
											data-testid="country-block-allow-empty-error"
										>
											ALLOW exige au moins un pays — sinon tout le trafic
											public serait bloqué.
										</p>
									{/if}
								</div>
								<div>
									<label
										for="route-country-block-status"
										class="text-sm font-medium text-secondary block mb-1"
									>
										Code HTTP (0 = défaut env)
									</label>
									<select
										id="route-country-block-status"
										bind:value={formData.countryBlock.statusCode}
										class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
									>
										<option value={0}>Défaut (ARENET_COUNTRY_BLOCK_STATUS)</option>
										<option value={403}>403 Forbidden</option>
										<option value={451}>451 Unavailable For Legal Reasons</option>
										<option value={444}>444 (nginx — close sans réponse)</option>
									</select>
								</div>
							{:else}
								<!-- mode=off — muted hint so the operator
								     understands what happens when they pick
								     a mode (rather than seeing an empty
								     section that looks broken). -->
								<p
									class="text-xs text-muted"
									data-testid="country-block-off-hint"
								>
									Aucun gate par pays. Choisissez Allow-list ou Deny-list
									pour activer.
								</p>
							{/if}
						</div>
					</details>

					<!-- Step J.3: active health-check sub-form. Gated by the
					     enabled checkbox. Sub-fields disabled when off; their
					     state is PRESERVED across the toggle so a user who
					     flips off-and-on keeps their typed values.
					     Any interaction marks healthCheckTouched so submit ships
					     the complete 9-field block (J.2 preserve-or-replace). -->
					<details
						class="rounded border border-border-subtle"
						open={formData.healthCheck.enabled}
					>
						<summary
							class="px-3 py-2 text-sm text-secondary cursor-pointer select-none"
							onclick={markHealthCheckTouched}
						>
							Active health check
							{#if formData.healthCheck.enabled}
								<span class="ml-1 text-xs text-muted">(on)</span>
							{/if}
						</summary>
						<div class="p-3 flex flex-col gap-3 border-t border-border-subtle">
							<!-- Capture click on the wrapper so toggling the
							     checkbox marks the HC block as touched (drives
							     the J.2 preserve-or-replace decision). Checkbox
							     does not expose an onchange prop; the wrapper
							     handler runs whether the user clicks the box or
							     its label. -->
							<div onclick={markHealthCheckTouched} onkeydown={markHealthCheckTouched} role="none">
								<Checkbox
									label="Enable active health checks"
									bind:checked={formData.healthCheck.enabled}
								/>
							</div>
							<div>
								<label
									for="hc-uri"
									class="text-sm font-medium text-secondary block mb-1"
								>
									URI <span class="text-down" aria-hidden="true">*</span>
								</label>
								<input
									id="hc-uri"
									type="text"
									bind:value={formData.healthCheck.uri}
									placeholder="/healthz"
									disabled={!formData.healthCheck.enabled}
									aria-required="true"
									oninput={markHealthCheckTouched}
									class="w-full bg-surface border rounded-md px-3 py-2 text-sm text-primary disabled:opacity-50 disabled:cursor-not-allowed"
									class:border-down={!!errors['healthCheck.uri']}
									class:border-border-default={!errors['healthCheck.uri']}
								/>
								{#if errors['healthCheck.uri']}
									<p class="text-xs text-down mt-1">{errors['healthCheck.uri']}</p>
								{/if}
							</div>
							<div>
								<label
									for="hc-method"
									class="text-sm font-medium text-secondary block mb-1"
								>
									Method
								</label>
								<select
									id="hc-method"
									bind:value={formData.healthCheck.method}
									disabled={!formData.healthCheck.enabled}
									onchange={markHealthCheckTouched}
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary disabled:opacity-50 disabled:cursor-not-allowed"
								>
									<option value="GET">GET</option>
									<option value="HEAD">HEAD</option>
								</select>
								{#if errors['healthCheck.method']}
									<p class="text-xs text-down mt-1">{errors['healthCheck.method']}</p>
								{/if}
							</div>
							<div class="grid grid-cols-2 gap-3">
								<Input
									label="Interval"
									bind:value={formData.healthCheck.interval}
									placeholder={HEALTH_CHECK_DEFAULTS.interval}
									disabled={!formData.healthCheck.enabled}
									oninput={markHealthCheckTouched}
									error={errors['healthCheck.interval'] ?? undefined}
								/>
								<Input
									label="Timeout"
									bind:value={formData.healthCheck.timeout}
									placeholder={HEALTH_CHECK_DEFAULTS.timeout}
									disabled={!formData.healthCheck.enabled}
									oninput={markHealthCheckTouched}
									error={errors['healthCheck.timeout'] ?? undefined}
								/>
							</div>
							<div class="grid grid-cols-2 gap-3">
								<div class="flex flex-col gap-1.5">
									<label
										for="hc-passes"
										class="text-sm font-medium text-secondary">Passes</label
									>
									<input
										id="hc-passes"
										type="number"
										min="1"
										bind:value={formData.healthCheck.passes}
										placeholder={String(HEALTH_CHECK_DEFAULTS.passes)}
										disabled={!formData.healthCheck.enabled}
										oninput={markHealthCheckTouched}
										class="bg-surface border rounded-md px-3 py-2 text-sm text-primary disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-cyan focus:shadow-glow-cyan transition-shadow"
										class:border-down={!!errors['healthCheck.passes']}
										class:border-border-default={!errors['healthCheck.passes']}
									/>
									{#if errors['healthCheck.passes']}
										<p class="text-xs text-down">{errors['healthCheck.passes']}</p>
									{/if}
								</div>
								<div class="flex flex-col gap-1.5">
									<label
										for="hc-fails"
										class="text-sm font-medium text-secondary">Fails</label
									>
									<input
										id="hc-fails"
										type="number"
										min="1"
										bind:value={formData.healthCheck.fails}
										placeholder={String(HEALTH_CHECK_DEFAULTS.fails)}
										disabled={!formData.healthCheck.enabled}
										oninput={markHealthCheckTouched}
										class="bg-surface border rounded-md px-3 py-2 text-sm text-primary disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-cyan focus:shadow-glow-cyan transition-shadow"
										class:border-down={!!errors['healthCheck.fails']}
										class:border-border-default={!errors['healthCheck.fails']}
									/>
									{#if errors['healthCheck.fails']}
										<p class="text-xs text-down">{errors['healthCheck.fails']}</p>
									{/if}
								</div>
							</div>
							<div class="flex flex-col gap-1.5">
								<label
									for="hc-expect-status"
									class="text-sm font-medium text-secondary">Expected status</label
								>
								<input
									id="hc-expect-status"
									type="number"
									min="0"
									max="599"
									bind:value={formData.healthCheck.expectStatus}
									placeholder="200"
									disabled={!formData.healthCheck.enabled}
									oninput={markHealthCheckTouched}
									class="bg-surface border rounded-md px-3 py-2 text-sm text-primary disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-cyan focus:shadow-glow-cyan transition-shadow"
									class:border-down={!!errors['healthCheck.expectStatus']}
									class:border-border-default={!errors['healthCheck.expectStatus']}
								/>
								{#if errors['healthCheck.expectStatus']}
									<p class="text-xs text-down">{errors['healthCheck.expectStatus']}</p>
								{/if}
							</div>
							<Input
								label="Expected body (regex)"
								bind:value={formData.healthCheck.expectBody}
								disabled={!formData.healthCheck.enabled}
								oninput={markHealthCheckTouched}
								error={errors['healthCheck.expectBody'] ?? undefined}
							/>
							<p class="text-xs text-muted">
								Leave a field blank to use the server default
								({HEALTH_CHECK_DEFAULTS.method} / {HEALTH_CHECK_DEFAULTS.interval}
								/ {HEALTH_CHECK_DEFAULTS.timeout} / passes={HEALTH_CHECK_DEFAULTS.passes}
								/ fails={HEALTH_CHECK_DEFAULTS.fails}). URI is required.
							</p>
						</div>
					</details>
			
					<!-- Step I.6: custom request / response headers. -->
					<details class="rounded border border-border-subtle">
						<summary class="px-3 py-2 text-sm text-secondary cursor-pointer select-none">
							Request headers
							{#if requestHeaderRows.length > 0}
								<span class="ml-1 text-xs text-muted">({requestHeaderRows.length})</span>
							{/if}
						</summary>
						<div class="p-3 flex flex-col gap-2 border-t border-border-subtle">
							{#each requestHeaderRows as _, i (i)}
								<div class="flex items-center gap-2">
									<Input bind:value={requestHeaderRows[i][0]} placeholder="X-Custom-Header" />
									<Input bind:value={requestHeaderRows[i][1]} placeholder="value" />
									<Button
										variant="ghost"
										size="sm"
										onclick={() => removeRequestHeader(i)}
										type="button">×</Button
									>
								</div>
							{/each}
							<Button variant="ghost" size="sm" onclick={addRequestHeader} type="button"
								>+ Add request header</Button
							>
						</div>
					</details>
					<details class="rounded border border-border-subtle">
						<summary class="px-3 py-2 text-sm text-secondary cursor-pointer select-none">
							Response headers
							{#if responseHeaderRows.length > 0}
								<span class="ml-1 text-xs text-muted">({responseHeaderRows.length})</span>
							{/if}
						</summary>
						<div class="p-3 flex flex-col gap-2 border-t border-border-subtle">
							{#each responseHeaderRows as _, i (i)}
								<div class="flex items-center gap-2">
									<Input bind:value={responseHeaderRows[i][0]} placeholder="X-Custom-Header" />
									<Input bind:value={responseHeaderRows[i][1]} placeholder="value" />
									<Button
										variant="ghost"
										size="sm"
										onclick={() => removeResponseHeader(i)}
										type="button">×</Button
									>
								</div>
							{/each}
							<Button variant="ghost" size="sm" onclick={addResponseHeader} type="button"
								>+ Add response header</Button
							>
						</div>
					</details>
					<button type="submit" class="hidden" aria-hidden="true"></button>
				</form>

				<!-- Panel footer — Cancel + Save. Cancel calls
				     closePanel() (drops selection + form state, back
				     to empty state). Save reuses the existing
				     submitForm() flow. On success submitForm clears
				     formOpen via the existing path; on validation
				     errors the panel stays open with field-level
				     messages. -->
				<div class="px-5 pb-5 pt-2 flex justify-end gap-2 border-t border-border-subtle">
					<Button variant="ghost" onclick={closePanel}>Cancel</Button>
					<Button
						onclick={submitForm}
						loading={submitting}
						disabled={dedicatedOptOutPendingChoice}
					>
						{formMode === 'create' ? 'Create' : 'Save'}
					</Button>
				</div>
			{/if}

			<!--
				Phase 5 follow-up — Caddy-reload overlay (T2). Sits
				on top of the form/footer while submitForm() is
				awaiting the PUT/POST. Mirrors the spinner on the
				Save button but at panel-scale so the operator
				perceives the ~5s wait as "Caddy is being reloaded",
				not as "the UI is frozen". The veil also blocks
				accidental input edits during the in-flight save —
				clicks pass through to the veil, not to the form
				underneath.
			-->
			{#if submitting}
				<div
					class="absolute inset-0 z-10 flex items-center justify-center bg-elevated/85 backdrop-blur-sm rounded-lg"
					role="status"
					aria-live="polite"
					aria-busy="true"
					data-testid="route-save-overlay"
				>
					<div class="flex flex-col items-center gap-3 px-4 py-3 rounded-md">
						<Spinner size="md" />
						<p class="text-sm text-secondary">
							Application des modifications Caddy…
						</p>
					</div>
				</div>
			{/if}
		</div>
	</div>
{/if}

<Modal
	open={confirmTarget !== null}
	title="Delete route"
	onClose={() => (confirmTarget = null)}
>
	{#if confirmTarget}
		<p class="text-sm">
			Are you sure you want to delete the route for
			<code class="font-mono text-cyan">{confirmTarget.host}</code>?
		</p>
		<p class="text-xs text-secondary mt-2">
			Caddy will be reloaded immediately. This action cannot be undone.
		</p>
	{/if}
	{#snippet footer()}
		<Button variant="ghost" onclick={() => (confirmTarget = null)}>Cancel</Button>
		<Button variant="danger" loading={deleting} onclick={confirmDelete}>Delete</Button>
	{/snippet}
</Modal>

<style>
	/* Selected-row visual state for the Routes table (C11 Pack A
	   polish, 2026-06-06). The Tailwind classes on the row carry
	   the base + hover styles; this block layers the
	   selected-when-editing affordance on top.

	   The brief calls for "subtle accent tint + left-border
	   accent" — using the shared --accent token (same as the
	   .nav-item.active state and Topology's hub border) so a
	   future theme change propagates everywhere. Inset
	   box-shadow gives the left edge a 3px solid accent stripe
	   without requiring a layout-shifting border. */
	:global(tr.route-row-selected) {
		background: color-mix(in oklch, var(--accent) 10%, transparent);
		box-shadow: inset 3px 0 0 0 var(--accent);
	}
	/* Slightly stronger hover on the selected row so the click
	   target still feels "live", not visually frozen. */
	:global(tr.route-row-selected:hover) {
		background: color-mix(in oklch, var(--accent) 16%, transparent);
	}

	/* W.5 + W.7 — country-block UI styles.
	   W.5 introduced the chip; W.7 polishes the surface:
	   - Mode-colored section border (slate / green / red).
	   - 3-button pill toggle replaces the mode dropdown.
	   - Chips recolor to the active mode + show resolved
	     country name next to the code.
	   - Autocomplete dropdown styled to match the form's
	     existing select aesthetic.
	   Color tokens reused from styles/tokens.css: --status-up
	   (success green), --status-down (danger red),
	   --status-meta (neutral slate). Spec brief mentioned
	   --status-success / --status-danger which don't exist
	   in the design system — using the canonical *-up / *-down
	   tokens instead (same hues; the project already maps
	   them to success/danger semantics via the --badge-*
	   derived tokens). */

	/* Section border tinted by active mode so the operator's
	   choice radiates outward from the toggle to the whole
	   panel. cb-mode-off is the default border-subtle. */
	.cb-section.cb-mode-allow {
		border-color: color-mix(in oklch, var(--status-up) 50%, var(--border-subtle));
	}
	.cb-section.cb-mode-deny {
		border-color: color-mix(in oklch, var(--status-down) 50%, var(--border-subtle));
	}

	/* Mode toggle — 3 segmented buttons. Active button picks
	   up the mode color; inactive buttons stay neutral. */
	.cb-mode-toggle {
		display: grid;
		grid-template-columns: repeat(3, minmax(0, 1fr));
		gap: 6px;
	}
	.cb-mode-btn {
		appearance: none;
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 2px;
		padding: 8px 10px;
		background: var(--bg-surface);
		border: 1px solid var(--border-subtle);
		border-radius: 6px;
		color: var(--text-secondary);
		cursor: pointer;
		font-size: 12px;
		font-weight: 500;
		text-align: left;
		transition: border-color 80ms ease-out, background 80ms ease-out;
	}
	.cb-mode-btn:hover {
		background: color-mix(in oklch, var(--accent) 6%, var(--bg-surface));
	}
	.cb-mode-btn__label {
		font-size: 12.5px;
		font-weight: 600;
		color: var(--text-primary);
	}
	.cb-mode-btn__hint {
		font-size: 10.5px;
		color: var(--text-muted);
	}
	.cb-mode-btn.active.cb-mode-btn--off {
		border-color: var(--status-meta);
		background: color-mix(in oklch, var(--status-meta) 12%, var(--bg-surface));
	}
	.cb-mode-btn.active.cb-mode-btn--allow {
		border-color: var(--status-up);
		background: color-mix(in oklch, var(--status-up) 12%, var(--bg-surface));
	}
	.cb-mode-btn.active.cb-mode-btn--allow .cb-mode-btn__label {
		color: var(--status-up);
	}
	.cb-mode-btn.active.cb-mode-btn--deny {
		border-color: var(--status-down);
		background: color-mix(in oklch, var(--status-down) 12%, var(--bg-surface));
	}
	.cb-mode-btn.active.cb-mode-btn--deny .cb-mode-btn__label {
		color: var(--status-down);
	}

	/* Chip — recolors based on the section's mode class.
	   Default (off / no mode) keeps the original slate tint
	   in case a chip is rendered outside an active section
	   (shouldn't happen today, but defensive). */
	.cb-chip {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 3px 4px 3px 8px;
		font-family: var(--font-mono);
		font-size: 11px;
		font-weight: 600;
		letter-spacing: 0.04em;
		color: var(--text-secondary);
		background: color-mix(in oklch, var(--status-meta) 14%, transparent);
		border: 1px solid color-mix(in oklch, var(--status-meta) 40%, var(--border-subtle));
		border-radius: 999px;
	}
	.cb-mode-allow .cb-chip {
		background: color-mix(in oklch, var(--status-up) 12%, transparent);
		border-color: color-mix(in oklch, var(--status-up) 45%, var(--border-subtle));
		color: var(--status-up);
	}
	.cb-mode-deny .cb-chip {
		background: color-mix(in oklch, var(--status-down) 12%, transparent);
		border-color: color-mix(in oklch, var(--status-down) 45%, var(--border-subtle));
		color: var(--status-down);
	}
	.cb-chip__code {
		font-weight: 700;
	}
	.cb-chip__name {
		font-family: var(--font-sans);
		font-weight: 400;
		letter-spacing: 0;
		font-size: 11.5px;
		color: var(--text-secondary);
		max-width: 140px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	/* In allow/deny modes the chip text picks up the mode
	   color; let the name follow too (slightly muted via
	   color-mix so it doesn't compete with the code). */
	.cb-mode-allow .cb-chip__name {
		color: color-mix(in oklch, var(--status-up) 75%, var(--text-secondary));
	}
	.cb-mode-deny .cb-chip__name {
		color: color-mix(in oklch, var(--status-down) 75%, var(--text-secondary));
	}
	.cb-chip__remove {
		appearance: none;
		background: none;
		border: 0;
		color: currentColor;
		opacity: 0.6;
		cursor: pointer;
		font-size: 14px;
		line-height: 1;
		padding: 0 4px;
		border-radius: 999px;
		transition: opacity 80ms ease-out, background 80ms ease-out;
	}
	.cb-chip__remove:hover {
		opacity: 1;
		background: color-mix(in oklch, currentColor 15%, transparent);
	}

	/* Autocomplete dropdown — absolute-positioned under
	   the input. Uses surface bg + subtle shadow for
	   focal weight; mirrors the form's existing select
	   panels. */
	.cb-input-wrap {
		position: relative;
	}
	.cb-dropdown {
		position: absolute;
		top: calc(100% + 4px);
		left: 0;
		right: 0;
		max-height: 240px;
		overflow-y: auto;
		background: var(--bg-surface);
		border: 1px solid var(--border-default);
		border-radius: 6px;
		box-shadow: 0 6px 18px color-mix(in oklch, var(--bg-base) 30%, transparent);
		z-index: 10;
		list-style: none;
		margin: 0;
		padding: 4px 0;
	}
	.cb-dropdown__item {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 6px 10px;
		cursor: pointer;
		font-size: 12.5px;
		color: var(--text-secondary);
	}
	.cb-dropdown__item.active,
	.cb-dropdown__item:hover {
		background: color-mix(in oklch, var(--accent) 12%, transparent);
		color: var(--text-primary);
	}
	.cb-dropdown__code {
		font-family: var(--font-mono);
		font-size: 11px;
		font-weight: 700;
		padding: 1px 6px;
		border-radius: 4px;
		background: color-mix(in oklch, var(--status-meta) 16%, transparent);
		color: var(--text-primary);
		min-width: 26px;
		text-align: center;
	}
	.cb-dropdown__name {
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	/* "+ Ajouter un pays" CTA — pill-shaped accent button
	   that opens the dropdown + focuses the input. */
	.cb-add-btn {
		appearance: none;
		padding: 6px 12px;
		background: color-mix(in oklch, var(--accent) 14%, transparent);
		border: 1px solid color-mix(in oklch, var(--accent) 40%, var(--border-subtle));
		border-radius: 6px;
		color: var(--accent);
		font-size: 12px;
		font-weight: 600;
		cursor: pointer;
		white-space: nowrap;
		transition: background 80ms ease-out;
	}
	.cb-add-btn:hover {
		background: color-mix(in oklch, var(--accent) 22%, transparent);
	}
</style>
