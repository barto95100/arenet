// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step §5.3 — Extended frontend test suite for the Routes page.
// Promoted to BLOCKING BEFORE THE `v0.6.0-step-j` tag during J.7
// (see docs/backlog-step-j.md). The J.3 Routes-page rewrite
// shipped without these tests; this file is the catch-up.
//
// Test taxonomy (mirrors §5.3 bullets):
//   - Upstream-pool repeater add / remove / last-row guard
//   - LB-selector visibility flip — preserved across flips
//   - Weight-column visibility flip — preserved across flips
//   - Health-check sub-form gating + state preservation
//   - Client-side validation rules (§5.2 — each rule)
//   - Error map round-trip (server 400 → errors[<field>])
//   - openEdit → submit-unchanged round-trip pinning all 9
//     HealthCheck fields (the J.3 review's manual audit, now
//     automated)
//
// Harness notes:
//   - `@testing-library/svelte` v5.3.1 + jsdom (Step F infra).
//   - The page imports the API client wrappers, not raw `fetch`;
//     we mock `$lib/api/client` + `$lib/api/settings` so no HTTP
//     traffic leaves the test process.
//   - The page uses Svelte 5 runes ($state/$effect/$derived) —
//     `render(Page)` mounts it normally; reactivity ticks run
//     synchronously enough for click → assertion sequences.
//   - jsdom does not run a real layout engine, but the form's
//     visibility logic is rune-driven ({#if lbSelectorVisible})
//     so it's testable by `queryByLabelText` returning null /
//     non-null rather than by computed style.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen, fireEvent } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';

// --- Mocks. vi.mock + the supporting references both go through
// vi.hoisted so they end up above the page import the bundler
// hoists into place. See client.test.ts for the same pattern
// (it works because that file deferred its import; we use the
// vi.hoisted form so we can keep the static `import Page from`
// at the top of this file).

const { toastMock, apiMock, settingsMock, authMock } = vi.hoisted(() => ({
	toastMock: { pushToast: vi.fn() },
	apiMock: {
		listRoutes: vi.fn(),
		createRoute: vi.fn(),
		updateRoute: vi.fn(),
		deleteRoute: vi.fn(),
		// Step #R-PROXMOX-HTTPS-LOOP commit 3 — operator-
		// triggered upstream probe. Per-test rebinds the
		// resolve / reject to drive the result chip states.
		testUpstream: vi.fn()
	},
	settingsMock: {
		getDNSProviderOVH: vi.fn()
	},
	// Day 13 — #R-FRONTEND-PUT-NO-TIMEOUT layer B. submitForm
	// reads auth.state to decide whether to suppress the
	// danger toast on lock-screen overlap; tests flip
	// authMock.state to drive the branch.
	authMock: {
		user: null as null | { id: string; role: 'admin' | 'viewer' },
		state: 'authenticated' as 'authenticated' | 'anonymous' | 'locked' | 'unknown',
		clear: vi.fn(),
		setLocked: vi.fn()
	}
}));

// $app/navigation: only reached if the page redirects (it doesn't
// here). Stub to avoid the SvelteKit runtime dependency.
vi.mock('$app/navigation', () => ({
	goto: vi.fn()
}));

// $lib/stores/toast: pushToast is called on success / failure
// paths. We capture invocations so success-path tests can assert
// "Route updated" / "Route created" reached the toast layer.
vi.mock('$lib/stores/toast', () => ({
	pushToast: toastMock.pushToast
}));

// $lib/api/client: the Routes page calls listRoutes on mount and
// {create,update,delete}Route from the form submit. Each test
// rebinds the impl via the exported references below.
vi.mock('$lib/api/client', () => ({
	listRoutes: (...args: unknown[]) => apiMock.listRoutes(...args),
	createRoute: (...args: unknown[]) => apiMock.createRoute(...args),
	updateRoute: (...args: unknown[]) => apiMock.updateRoute(...args),
	deleteRoute: (...args: unknown[]) => apiMock.deleteRoute(...args),
	testUpstream: (...args: unknown[]) => apiMock.testUpstream(...args)
}));

// $lib/api/settings: getDNSProviderOVH is called in openCreate /
// openEdit and on mount (via the DNS provider snapshot). Default
// to a "not configured" shape; tests touching the DNS-01 path
// rebind for that scenario.
vi.mock('$lib/api/settings', () => ({
	settingsApi: {
		getDNSProviderOVH: () => settingsMock.getDNSProviderOVH()
	}
}));

// Day 13 — #R-FRONTEND-PUT-NO-TIMEOUT layer B. The page now
// reads auth.state to decide whether to suppress the danger
// toast on session-locked-during-save. Mock the store so tests
// can flip the state.
vi.mock('$lib/stores/auth.svelte', () => ({
	auth: authMock
}));

import { ApiError } from '$lib/api/types';
import Page from './+page.svelte';
import type { Route } from '$lib/api/types';

// Helper: build a server Route response in the wire shape the
// page consumes (camelCase, healthCheck non-optional, etc.).
function makeRoute(overrides: Partial<Route> = {}): Route {
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
		countryBlock: { mode: 'off', countryList: [], statusCode: 0 },
		// Step #R-PROXMOX-HTTPS-LOOP — strict default. Tests
		// exercising the disclosure / toggle override via the
		// partial Route overrides.
		insecureSkipVerify: false,
		// Phase 4.5 — strict default; tests that exercise the
		// streaming toggle override via the partial Route
		// overrides parameter.
		uploadStreamingMode: false,
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
		// Step Q — strict default no rate limit ; tests
		// exercising the rate-limit section override via the
		// partial Route overrides parameter set a non-null
		// value to populate the form.
		rateLimit: null,
		...overrides
	};
}

beforeEach(() => {
	toastMock.pushToast.mockReset();
	apiMock.listRoutes.mockReset();
	apiMock.createRoute.mockReset();
	apiMock.updateRoute.mockReset();
	apiMock.deleteRoute.mockReset();
	apiMock.testUpstream.mockReset();
	settingsMock.getDNSProviderOVH.mockReset();
	// Day 13 — auth store defaults: every test starts in
	// authenticated state. Tests exercising the lock-screen-
	// during-save branch flip authMock.state = 'locked' before
	// the submit fires.
	authMock.state = 'authenticated';
	authMock.clear.mockReset();
	authMock.setLocked.mockReset();

	// Sensible defaults so tests that don't override see an empty
	// page (no routes) and a not-configured DNS provider.
	apiMock.listRoutes.mockResolvedValue([]);
	settingsMock.getDNSProviderOVH.mockResolvedValue({
		endpoint: '',
		applicationKey: '',
		applicationSecret: '',
		consumerKey: '',
		configured: false
	});
});

// Opens the create form (clicks "+ Add route") and returns after
// the modal is mounted. Tests that don't need the empty-state CTA
// path go through this helper.
async function openCreateForm(): Promise<void> {
	// Two "+ Add route" buttons exist in the markup: PageHeader's
	// actions snippet ("+ Add route") and the empty-state CTA
	// ("+ Add your first route"). When routes is empty (the
	// default in beforeEach), only the empty-state CTA renders the
	// "+ Add your first route" label; the header button reads
	// "+ Add route". Either opens the modal; pick the header one
	// so the test works whether the page has data or not.
	const btn = await screen.findByRole('button', { name: /^\+\s*Add route$/i });
	await userEvent.click(btn);
	await tick();
}

// Reaches into the modal: returns the "Host" Input (label match
// is the deterministic anchor — the input gets an id assigned at
// render so role=textbox + accessible name is the right query).
function hostInput(): HTMLInputElement {
	return screen.getByLabelText('Host') as HTMLInputElement;
}

// Returns the LB-policy <select>. Returns null when the selector
// is hidden (pool size 1 → {#if lbSelectorVisible} suppresses it).
function lbSelect(): HTMLSelectElement | null {
	return screen.queryByLabelText('Load balancing') as HTMLSelectElement | null;
}

// Returns all upstream URL inputs in repeater order. They share
// the placeholder text but no label; pick by placeholder.
function upstreamURLInputs(): HTMLInputElement[] {
	return screen.getAllByPlaceholderText('http://127.0.0.1:8080') as HTMLInputElement[];
}

// --- 1. Upstream-pool repeater ------------------------------------

describe('Routes page — upstream-pool repeater', () => {
	it('starts with one upstream row on a fresh create', async () => {
		render(Page);
		await openCreateForm();
		expect(upstreamURLInputs()).toHaveLength(1);
	});

	it('adds a row when "+ Add upstream" is clicked', async () => {
		render(Page);
		await openCreateForm();
		const addBtn = screen.getByRole('button', { name: /\+\s*Add upstream/i });
		await userEvent.click(addBtn);
		await tick();
		expect(upstreamURLInputs()).toHaveLength(2);
		await userEvent.click(addBtn);
		await tick();
		expect(upstreamURLInputs()).toHaveLength(3);
	});

	it('removes a row when "×" is clicked on a non-last row', async () => {
		render(Page);
		await openCreateForm();
		const addBtn = screen.getByRole('button', { name: /\+\s*Add upstream/i });
		await userEvent.click(addBtn);
		await tick();
		await userEvent.click(addBtn);
		await tick();
		expect(upstreamURLInputs()).toHaveLength(3);

		// Type identifying URLs so we can verify which row got removed.
		const inputs = upstreamURLInputs();
		await userEvent.type(inputs[0], 'http://a.test');
		await userEvent.type(inputs[1], 'http://b.test');
		await userEvent.type(inputs[2], 'http://c.test');

		// Remove the middle row. The × buttons in the upstream rows
		// are the ones in the same flex container as the URL Input;
		// by role name they all match /^×$/, so pick by index.
		const removeButtons = screen
			.getAllByRole('button', { name: '×' })
			// Aliases also render × buttons in this test — filter to
			// the upstream removers by their proximity to an upstream URL input.
			.filter((b) => {
				const row = b.closest('.flex.items-start');
				return row?.querySelector('input[placeholder="http://127.0.0.1:8080"]') != null;
			});
		expect(removeButtons).toHaveLength(3);
		await userEvent.click(removeButtons[1]);
		await tick();

		const remaining = upstreamURLInputs();
		expect(remaining).toHaveLength(2);
		expect(remaining[0].value).toBe('http://a.test');
		expect(remaining[1].value).toBe('http://c.test');
	});

	it('disables the remove "×" button when only one row remains (last-row guard)', async () => {
		render(Page);
		await openCreateForm();
		expect(upstreamURLInputs()).toHaveLength(1);
		// Pick the upstream's × — same proximity heuristic.
		const removeBtn = screen
			.getAllByRole('button', { name: '×' })
			.find((b) => {
				const row = b.closest('.flex.items-start');
				return row?.querySelector('input[placeholder="http://127.0.0.1:8080"]') != null;
			});
		expect(removeBtn).toBeDefined();
		// `disabled` attribute on the button (the page passes
		// disabled={formData.upstreams.length <= 1} to <Button>).
		expect(removeBtn).toBeDisabled();
	});
});

// --- 2. LB-selector visibility flip -------------------------------

describe('Routes page — LB selector visibility', () => {
	it('is hidden with one upstream, shown with two, preserves state across flips', async () => {
		render(Page);
		await openCreateForm();
		// One upstream → hidden.
		expect(lbSelect()).toBeNull();

		// Add second upstream → shown, default round_robin.
		const addBtn = screen.getByRole('button', { name: /\+\s*Add upstream/i });
		await userEvent.click(addBtn);
		await tick();
		let sel = lbSelect();
		expect(sel).not.toBeNull();
		expect(sel!.value).toBe('round_robin');

		// Change the LB policy.
		await userEvent.selectOptions(sel!, 'least_conn');
		await tick();
		expect(lbSelect()!.value).toBe('least_conn');

		// Remove the second upstream → selector hides again.
		const removeBtn = screen
			.getAllByRole('button', { name: '×' })
			.find((b) => {
				const row = b.closest('.flex.items-start');
				return (
					row?.querySelector('input[placeholder="http://127.0.0.1:8080"]') != null &&
					!(b as HTMLButtonElement).disabled
				);
			});
		await userEvent.click(removeBtn!);
		await tick();
		expect(lbSelect()).toBeNull();

		// Re-add a second upstream → selector reappears with the
		// previously-chosen policy preserved (formData.lbPolicy
		// was never reset).
		await userEvent.click(addBtn);
		await tick();
		sel = lbSelect();
		expect(sel).not.toBeNull();
		expect(sel!.value).toBe('least_conn');
	});
});

// --- 3. Weight column visibility flip -----------------------------

describe('Routes page — weight column visibility', () => {
	// Returns only the upstream WEIGHT inputs (not the HC passes /
	// fails inputs, which also use placeholder="1"). Identifies
	// them by proximity to an upstream URL input inside the same
	// flex container.
	function weightInputs(): HTMLInputElement[] {
		return Array.from(
			document.querySelectorAll<HTMLInputElement>('input[type="number"][placeholder="1"]')
		).filter((el) => {
			const row = el.closest('.flex.items-start');
			return row?.querySelector('input[placeholder="http://127.0.0.1:8080"]') != null;
		});
	}

	it('is hidden for round_robin, shown for weighted_round_robin, preserves values across flips', async () => {
		render(Page);
		await openCreateForm();

		// Need a 2-upstream pool to see the LB selector.
		const addBtn = screen.getByRole('button', { name: /\+\s*Add upstream/i });
		await userEvent.click(addBtn);
		await tick();

		// Weight column hidden for the default round_robin.
		expect(weightInputs().length).toBe(0);

		// Flip to weighted_round_robin.
		await userEvent.selectOptions(lbSelect()!, 'weighted_round_robin');
		await tick();

		// Two weight inputs now (one per upstream row).
		let weights = weightInputs();
		expect(weights.length).toBe(2);

		// Set distinct values.
		await userEvent.clear(weights[0]);
		await userEvent.type(weights[0], '5');
		await userEvent.clear(weights[1]);
		await userEvent.type(weights[1], '7');
		await tick();
		weights = weightInputs();
		expect(weights[0].value).toBe('5');
		expect(weights[1].value).toBe('7');

		// Flip back to round_robin → column hides.
		await userEvent.selectOptions(lbSelect()!, 'round_robin');
		await tick();
		expect(weightInputs().length).toBe(0);

		// Flip back to weighted_round_robin → column reappears
		// with the values preserved (formData.upstreams[i].weight
		// was never touched).
		await userEvent.selectOptions(lbSelect()!, 'weighted_round_robin');
		await tick();
		weights = weightInputs();
		expect(weights.length).toBe(2);
		expect(weights[0].value).toBe('5');
		expect(weights[1].value).toBe('7');
	});
});

// --- 4. Health-check sub-form gating + state preservation ---------

describe('Routes page — health-check gating', () => {
	it('sub-fields are disabled when enabled=false, enabled when true, state preserved across the toggle', async () => {
		render(Page);
		await openCreateForm();

		// HC URI input by id (the field is `<input id="hc-uri">`).
		const uri = document.getElementById('hc-uri') as HTMLInputElement;
		const method = document.getElementById('hc-method') as HTMLSelectElement;
		const passes = document.getElementById('hc-passes') as HTMLInputElement;
		const fails = document.getElementById('hc-fails') as HTMLInputElement;
		const expectStatus = document.getElementById('hc-expect-status') as HTMLInputElement;
		expect(uri).not.toBeNull();
		expect(method).not.toBeNull();

		// Initial: enabled=false → every sub-field disabled.
		expect(uri.disabled).toBe(true);
		expect(method.disabled).toBe(true);
		expect(passes.disabled).toBe(true);
		expect(fails.disabled).toBe(true);
		expect(expectStatus.disabled).toBe(true);

		// Flip the HC checkbox on. The Checkbox component hides the
		// native input visually; click the label text.
		const hcCheckbox = screen.getByLabelText('Enable active health checks') as HTMLInputElement;
		await userEvent.click(hcCheckbox);
		await tick();

		// Sub-fields now enabled.
		expect(uri.disabled).toBe(false);
		expect(method.disabled).toBe(false);
		expect(passes.disabled).toBe(false);

		// Type identifying values.
		await userEvent.type(uri, '/probe');
		await userEvent.selectOptions(method, 'HEAD');
		await tick();
		expect(uri.value).toBe('/probe');
		expect(method.value).toBe('HEAD');

		// Toggle OFF.
		await userEvent.click(hcCheckbox);
		await tick();
		expect(uri.disabled).toBe(true);
		expect(method.disabled).toBe(true);
		// State preserved (the page never clears the sub-fields).
		expect(uri.value).toBe('/probe');
		expect(method.value).toBe('HEAD');

		// Toggle ON again — values still there, fields editable.
		await userEvent.click(hcCheckbox);
		await tick();
		expect(uri.disabled).toBe(false);
		expect(uri.value).toBe('/probe');
		expect(method.value).toBe('HEAD');
	});
});

// --- 5. Client-side validation rules ------------------------------
//
// The submit path runs validateBeforeSubmit() which writes the
// `errors` map keyed by field path. Each failing rule below
// triggers a submit and asserts the matching error message
// surfaces. We never let the submit reach the API mocks — when
// validation rejects, no createRoute() call is made.

describe('Routes page — validation rules (§5.2)', () => {
	async function submitForm() {
		// The submit button is the only "Save" / "Create" button
		// inside the Modal; the form's onsubmit handler runs the
		// validation. fireEvent.submit on the form keeps the
		// preventDefault contract.
		const form = document.querySelector('form');
		expect(form).not.toBeNull();
		await fireEvent.submit(form!);
		await tick();
	}

	it('rejects empty host', async () => {
		render(Page);
		await openCreateForm();
		await submitForm();
		// The Input renders the error under the field as a <p>.
		// validateBeforeSubmit writes errors['host'] = "Host must
		// not be empty".
		expect(screen.getByText('Host must not be empty')).toBeInTheDocument();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});

	it('rejects malformed upstream URL (missing http:// scheme)', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'just-a-host');
		await submitForm();
		// "URL must use http or https" comes from the URL parse +
		// protocol check in validateBeforeSubmit.
		expect(
			screen.getByText(/URL must use http or https|URL is malformed/i)
		).toBeInTheDocument();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});

	it('rejects HC enabled with empty URI', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		const hcCheckbox = screen.getByLabelText('Enable active health checks');
		await userEvent.click(hcCheckbox);
		await tick();
		await submitForm();
		expect(screen.getByText('URI is required')).toBeInTheDocument();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});

	it('rejects HC URI that does not start with /', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, 'probe');
		await submitForm();
		expect(screen.getByText('URI must start with /')).toBeInTheDocument();
	});

	it('rejects HC interval with malformed duration shape', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/p');
		// Interval Input has label "Interval" so we can query by label.
		await userEvent.type(screen.getByLabelText('Interval'), 'nope');
		await submitForm();
		expect(
			screen.getByText('Interval must be a duration (e.g. 30s)')
		).toBeInTheDocument();
	});

	it('rejects HC timeout equal to interval (timeout < interval rule)', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/p');
		await userEvent.type(screen.getByLabelText('Interval'), '30s');
		await userEvent.type(screen.getByLabelText('Timeout'), '30s');
		await submitForm();
		expect(
			screen.getByText('Timeout must be less than interval')
		).toBeInTheDocument();
	});

	it('rejects HC expectStatus outside 100..599', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/p');
		const expectStatusInput = document.getElementById('hc-expect-status') as HTMLInputElement;
		await userEvent.clear(expectStatusInput);
		await userEvent.type(expectStatusInput, '700');
		await submitForm();
		expect(
			screen.getByText('Expected status must be 0 or in 100..599')
		).toBeInTheDocument();
	});

	it('rejects HC expectBody that is not a valid regex', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/p');
		await userEvent.type(screen.getByLabelText('Expected body (regex)'), '(unbalanced');
		await submitForm();
		expect(
			screen.getByText('Expected body is not a valid regex')
		).toBeInTheDocument();
	});

	// §5.1 / J.1 weight rule. The client check is gated on
	// `weightVisible` (only fires when the weighted_round_robin
	// policy is selected) — so the test must arrange both a
	// 2-upstream pool AND that policy before typing a < 1 weight.
	// The HTML5 `min="1"` attribute is a soft hint that jsdom (and
	// most browsers prior to form-submit) do not enforce on input,
	// so a user typing "0" in the field still reaches the JS
	// validator, which is what we pin here.
	it('rejects upstream weight < 1 when weighted_round_robin is selected', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		// Add a second upstream so the LB selector + weight column
		// become reachable.
		await userEvent.click(screen.getByRole('button', { name: /\+\s*Add upstream/i }));
		await tick();
		await userEvent.type(upstreamURLInputs()[1], 'http://127.0.0.1:9001');
		await userEvent.selectOptions(
			screen.getByLabelText('Load balancing') as HTMLSelectElement,
			'weighted_round_robin'
		);
		await tick();

		// Reach the second weight input (the first carries the
		// default 1 — leave it valid so the rejection names the
		// row we deliberately broke).
		const weightInputs = Array.from(
			document.querySelectorAll<HTMLInputElement>('input[type="number"][placeholder="1"]')
		).filter((el) => {
			const row = el.closest('.flex.items-start');
			return row?.querySelector('input[placeholder="http://127.0.0.1:8080"]') != null;
		});
		expect(weightInputs.length).toBe(2);
		await userEvent.clear(weightInputs[1]);
		await userEvent.type(weightInputs[1], '0');
		await submitForm();
		expect(screen.getByText('Weight must be >= 1')).toBeInTheDocument();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});

	// §5.2 #9 / J.2 passes rule. The client relaxes the server's
	// `>= 1` to `>= 0` (intentional — passes=0 means "use the
	// server default", per the inline comment in
	// validateBeforeSubmit). Only NEGATIVE values are rejected
	// client-side; the HTML5 min="1" hint is not enforced before
	// submit, so the test types a negative value to reach the JS
	// rule.
	it('rejects negative HC passes', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/p');
		const passesInput = document.getElementById('hc-passes') as HTMLInputElement;
		await userEvent.clear(passesInput);
		// userEvent.type with a leading minus on a number input
		// produces a negative numeric value in the bound state.
		await userEvent.type(passesInput, '-2');
		await submitForm();
		expect(screen.getByText('Passes must be >= 1')).toBeInTheDocument();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});

	// §5.2 #10 / J.2 fails rule. Same shape as the passes rule
	// above. Both negative-value tests share the same client-side
	// "0 ⇒ use default, < 0 ⇒ reject" semantic; the server enforces
	// the strict >= 1 boundary on top.
	it('rejects negative HC fails', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/p');
		const failsInput = document.getElementById('hc-fails') as HTMLInputElement;
		await userEvent.clear(failsInput);
		await userEvent.type(failsInput, '-3');
		await submitForm();
		expect(screen.getByText('Fails must be >= 1')).toBeInTheDocument();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});
});

// --- 6. Error map round-trip (server 400 → errors[<field>]) ------
//
// On a successful client-validate-pass but a server 400, the
// page's submitForm catches the ApiError, runs fieldFromMessage
// on the message, and writes the error onto errors[field]. We
// inject a controlled ApiError on createRoute and assert the
// right field renders the message.

describe('Routes page — server error map round-trip', () => {
	it('routes "upstreams[0].weight must be >= 1" to errors[upstreams[0].weight]', async () => {
		// Two-upstream pool with weighted_round_robin so the weight
		// inputs are visible AND the rejection message has a real
		// target field to render under.
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByRole('button', { name: /\+\s*Add upstream/i }));
		await tick();
		await userEvent.type(upstreamURLInputs()[1], 'http://127.0.0.1:9001');
		await userEvent.selectOptions(lbSelect()!, 'weighted_round_robin');
		await tick();

		apiMock.createRoute.mockRejectedValueOnce(
			new ApiError('upstreams[0].weight must be >= 1', 400, 'validation')
		);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick(); // submitForm awaits the API call resolution

		// fieldFromMessage maps the message to errors['upstreams[0].weight'];
		// the markup renders it under the second weight input.
		expect(
			screen.getByText('upstreams[0].weight must be >= 1')
		).toBeInTheDocument();
	});

	it('routes "host must be a valid hostname" to errors[host]', async () => {
		render(Page);
		await openCreateForm();
		// The client passes the empty-host gate first; supply a value
		// that the CLIENT accepts (non-empty) but trigger the server
		// rejection by mocking it.
		await userEvent.type(hostInput(), 'something');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		apiMock.createRoute.mockRejectedValueOnce(
			new ApiError('host must be a valid hostname', 400, 'validation')
		);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		// Assert against the Input's <p> error element. By
		// fieldFromMessage's "host " prefix rule, the message is
		// keyed to errors['host'].
		expect(
			screen.getByText('host must be a valid hostname')
		).toBeInTheDocument();
	});

	it('routes "healthCheck.timeout must be strictly less than interval" to errors[healthCheck.timeout]', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/p');
		// Client-side rule would reject equal durations, so supply
		// values the CLIENT accepts (timeout < interval by string,
		// but the server semantics catches "1m vs 60s"). We're
		// asserting the server-rejection wiring, not the rule.
		await userEvent.type(screen.getByLabelText('Interval'), '60s');
		await userEvent.type(screen.getByLabelText('Timeout'), '5s');

		apiMock.createRoute.mockRejectedValueOnce(
			new ApiError(
				'healthCheck.timeout must be strictly less than interval',
				400,
				'validation'
			)
		);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		expect(
			screen.getByText('healthCheck.timeout must be strictly less than interval')
		).toBeInTheDocument();
	});
});

// --- 7. openEdit round-trip (THE pivot test) ----------------------
//
// Spec §5.3 / J.3 review: a route with a complete HealthCheck
// (all 9 fields in non-default values) must round-trip through
// openEdit → submit-unchanged → updateRoute payload without
// losing any field. Failure mode being guarded: a regression
// where openEdit forgets to copy one of the 9 fields would let
// the form keep the zero value, the user wouldn't notice (the
// form has been touched: healthCheckTouched=true so the block
// ships in the payload), and the storage would silently overwrite
// the field with the form's zero. This test pins the property.

describe('Routes page — openEdit round-trip preserves HealthCheck', () => {
	it('all 9 HealthCheck fields survive openEdit → submit-unchanged → updateRoute payload', async () => {
		// Distinct non-default values per field so a regression
		// that swaps two fields would also be caught.
		const seededHC = {
			enabled: true,
			uri: '/probe-path',
			method: 'HEAD' as const,
			interval: '12s',
			timeout: '3s',
			expectStatus: 204,
			expectBody: '^pong$',
			passes: 4,
			fails: 7
		};
		const seededRoute = makeRoute({
			id: 'edit-fixture',
			host: 'edit.example.com',
			upstreams: [{ url: 'http://127.0.0.1:9100', weight: 1 }],
			healthCheck: seededHC
		});
		apiMock.listRoutes.mockResolvedValue([seededRoute]);
		// updateRoute returns the (unchanged) route; the page only
		// reads it via toResponse-equivalent for the toast/redirect.
		apiMock.updateRoute.mockResolvedValue(seededRoute);

		render(Page);

		// Wait for listRoutes to settle and the table to render the
		// row. Polish round 2026-06-06 dropped the per-row "Edit"
		// button — the whole <tr> is the affordance now, so we
		// open the edit panel by clicking the row itself. Find by
		// the host cell text and walk up to the row.
		const hostCell = await screen.findByText('edit.example.com');
		const row = hostCell.closest('tr')!;

		// IMPORTANT: this test is meaningful only if the HC sub-form
		// is actually mounted by openEdit. We assert against the
		// payload sent to updateRoute, NOT against the DOM-typed
		// values — the test must catch a regression where openEdit
		// silently drops a field. If we re-read each field from the
		// DOM and used it to build the payload, a missing-field
		// regression would be invisible. We do NOT do that.
		await userEvent.click(row);
		await tick();

		// Mark HC touched (the wrapper onclick / oninput in the
		// sub-form does this when the user interacts; the test
		// simulates a no-edit save where the user opened the edit,
		// looked at the form, then clicked Save).
		//
		// The PUT path on the page omits the HC block if
		// healthCheckTouched is false. To pin the round-trip
		// property of openEdit→submit specifically, we MUST set
		// touched=true; otherwise we're testing the "preserve
		// previous on omit" path which is exercised server-side,
		// not the openEdit field-by-field copy.
		//
		// We trigger touched by re-typing the same URI value back
		// into itself — this fires oninput → markHealthCheckTouched
		// without changing any value. (A no-op click on the summary
		// also flips it, but we want the touched flag without
		// risking a checkbox toggle.)
		const uri = document.getElementById('hc-uri') as HTMLInputElement;
		expect(uri.value).toBe(seededHC.uri); // openEdit copied it
		// Trigger oninput by dispatching an input event that does
		// not change the value (avoids userEvent.clear() which would
		// blank the field before the round-trip is verified).
		uri.dispatchEvent(new Event('input', { bubbles: true }));
		await tick();

		// Submit.
		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		// updateRoute must have been called exactly once.
		expect(apiMock.updateRoute).toHaveBeenCalledTimes(1);
		const [id, payload] = apiMock.updateRoute.mock.calls[0];
		expect(id).toBe('edit-fixture');

		// THE assertion: every HC field on the payload matches the
		// seeded value byte for byte. If openEdit drops a field, the
		// formData zero-value would land in the payload and one of
		// these assertions would fail with a clear "got 0 / '' /
		// false" diff.
		expect(payload.healthCheck).toBeDefined();
		expect(payload.healthCheck.enabled).toBe(seededHC.enabled);
		expect(payload.healthCheck.uri).toBe(seededHC.uri);
		expect(payload.healthCheck.method).toBe(seededHC.method);
		expect(payload.healthCheck.interval).toBe(seededHC.interval);
		expect(payload.healthCheck.timeout).toBe(seededHC.timeout);
		expect(payload.healthCheck.expectStatus).toBe(seededHC.expectStatus);
		expect(payload.healthCheck.expectBody).toBe(seededHC.expectBody);
		expect(payload.healthCheck.passes).toBe(seededHC.passes);
		expect(payload.healthCheck.fails).toBe(seededHC.fails);
	});
});

// --- 2026-06-25 — double-PUT guard (operator empirical report) -----
//
// Empirical observation : journalctl on the operator's homelab
// showed 2 PUT /api/v1/routes/X calls 47ms apart for a single
// Save click. The 2nd PUT carried "config is unchanged" in the
// Caddy reload log (idempotent) but still consumed a server
// round-trip + grace-period cycle on the 1st PUT.
//
// v2.9.6 added `disabled={submitting}` on the Save button but the
// double-PUT persisted post-deploy. Root cause analysis : Svelte
// 5 reactivity → DOM commit window has a microtask gap where a
// queued 2nd click event (OS-level double-click setting, mouse
// hardware bounce, accessibility tool) can pass through before
// the disabled attribute actually lands on the <button>.
//
// v2.9.7 adds a `if (submitting) return` guard at the start of
// submitForm() itself — bulletproof against any click event
// volume, regardless of DOM commit timing.
describe('Routes page — submitForm double-PUT guard', () => {
	it('fires updateRoute exactly once when the form is submitted twice in rapid succession', async () => {
		const seeded = makeRoute({
			id: 'guard-fixture',
			host: 'guard.example.com',
			upstreams: [{ url: 'http://10.0.0.1:80', weight: 1 }],
			healthCheck: {
				enabled: true,
				uri: '/healthz',
				method: 'GET',
				interval: '30s',
				timeout: '5s',
				expectStatus: 0,
				expectBody: '',
				passes: 1,
				fails: 1
			}
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);

		// Slow the updateRoute response so the 2nd submit fires
		// while the 1st is still in flight — mirrors the empirical
		// 47ms-apart double-PUT the operator captured.
		let resolveUpdate: (r: Route) => void;
		apiMock.updateRoute.mockReturnValue(
			new Promise<Route>((resolve) => {
				resolveUpdate = resolve;
			})
		);

		render(Page);

		// Open edit panel for the route.
		const row = await screen.findByText('guard.example.com');
		await userEvent.click(row.closest('tr')!);
		await tick();

		// Fire submit twice within the same microtask. tick() is
		// NOT called between them — that's the point. We mirror
		// the OS-level double-click event delivery where both
		// clicks land before Svelte's reactivity commits the
		// disabled attribute.
		const form = document.querySelector('form')!;
		fireEvent.submit(form);
		fireEvent.submit(form);
		await tick();
		await tick();

		// Now resolve the in-flight updateRoute so the test cleans up.
		resolveUpdate!(seeded);
		await tick();
		await tick();

		// THE assertion : exactly ONE updateRoute call, no matter
		// how many submit events fired before the resolve.
		expect(apiMock.updateRoute).toHaveBeenCalledTimes(1);
	});
});

// --- C11 Pack A — aggregate health badge + filter tabs --------------
//
// Operator's Pack A smoke caught the original "static green dot"
// mendacity; the polish round (this commit, amended a8a4723)
// replaced the dot with an explicit uppercase Badge. These tests
// pin the badge → variant mapping AND the segmented-tab filter
// semantics so a future regression on either gets caught
// immediately.
describe('Routes page — aggregate health badges + filter tabs', () => {
	const mkRoute = (
		id: string,
		host: string,
		aggregateStatus: Route['aggregateStatus'],
		healthy: number,
		total: number,
	): Route =>
		makeRoute({
			id,
			host,
			aggregateStatus,
			healthyUpstreamCount: healthy,
			totalUpstreamCount: total,
			upstreams: Array.from({ length: total }, (_, i) => ({
				url: `http://10.0.0.${i + 1}:80`,
				weight: 1,
			})),
		});

	it('renders one badge per route with the label matching aggregateStatus', async () => {
		apiMock.listRoutes.mockResolvedValue([
			mkRoute('r-h', 'healthy.example', 'healthy', 1, 1),
			mkRoute('r-d', 'degraded.example', 'degraded', 1, 2),
			mkRoute('r-down', 'down.example', 'down', 0, 1),
			mkRoute('r-u', 'unknown.example', 'unknown', 0, 1),
		]);
		render(Page);

		expect(await screen.findByText('HEALTHY')).toBeInTheDocument();
		expect(screen.getByText('DEGRADED')).toBeInTheDocument();
		expect(screen.getByText('DOWN')).toBeInTheDocument();
		expect(screen.getByText('UNKNOWN')).toBeInTheDocument();
	});

	it('Healthy tab filters to aggregateStatus === healthy only', async () => {
		apiMock.listRoutes.mockResolvedValue([
			mkRoute('r-h', 'healthy.example', 'healthy', 1, 1),
			mkRoute('r-d', 'degraded.example', 'degraded', 1, 2),
			mkRoute('r-u', 'unknown.example', 'unknown', 0, 1),
		]);
		render(Page);

		// Wait for the initial render — the Healthy badge being
		// in the DOM is a reliable readiness signal that listRoutes
		// resolved.
		await screen.findByText('HEALTHY');

		await userEvent.click(screen.getByRole('button', { name: 'Healthy' }));
		await tick();

		// Strict: unknown must NOT pass the Healthy filter. The
		// gray-≠-green contract from the C13 Topology gate.
		expect(screen.getByText('HEALTHY')).toBeInTheDocument();
		expect(screen.queryByText('DEGRADED')).not.toBeInTheDocument();
		expect(screen.queryByText('UNKNOWN')).not.toBeInTheDocument();
	});

	it('renders "HC INACTIF" distinct badge for not_monitored aggregateStatus (2026-06-25 UX split)', async () => {
		// Pre-2026-06-25 : routes with HealthCheck.Enabled=false
		// rendered the same "UNKNOWN" badge as HC-enabled-but-warm-up
		// routes, making the operator unable to tell whether the
		// gray badge meant "I chose not to monitor" or "I monitor
		// but I don't know yet". The split adds 'not_monitored' as
		// a distinct aggregateStatus with its own label.
		apiMock.listRoutes.mockResolvedValue([
			mkRoute('r-nm', 'unmonitored.example', 'not_monitored', 0, 1),
			mkRoute('r-u', 'warmup.example', 'unknown', 0, 1),
		]);
		render(Page);

		expect(await screen.findByText('HC INACTIF')).toBeInTheDocument();
		expect(screen.getByText('UNKNOWN')).toBeInTheDocument();
	});

	it('Alerts tab filters to degraded OR down; unknown excluded', async () => {
		apiMock.listRoutes.mockResolvedValue([
			mkRoute('r-h', 'healthy.example', 'healthy', 1, 1),
			mkRoute('r-d', 'degraded.example', 'degraded', 1, 2),
			mkRoute('r-down', 'down.example', 'down', 0, 1),
			mkRoute('r-u', 'unknown.example', 'unknown', 0, 1),
		]);
		render(Page);

		await screen.findByText('HEALTHY');

		await userEvent.click(screen.getByRole('button', { name: 'Alerts' }));
		await tick();

		expect(screen.getByText('DEGRADED')).toBeInTheDocument();
		expect(screen.getByText('DOWN')).toBeInTheDocument();
		expect(screen.queryByText('HEALTHY')).not.toBeInTheDocument();
		// "Unknown ≠ alert" — operator can't get false-positive
		// noise from warm-up routes in the alerts list.
		expect(screen.queryByText('UNKNOWN')).not.toBeInTheDocument();
	});

	it('multi-upstream "N/M sains" appears only for routes with a verdict', async () => {
		apiMock.listRoutes.mockResolvedValue([
			// Two upstreams, degraded → counter visible.
			mkRoute('r-d', 'degraded.example', 'degraded', 1, 2),
			// Single upstream, healthy → counter hidden (noise).
			mkRoute('r-h1', 'single.example', 'healthy', 1, 1),
			// Two upstreams, unknown → counter hidden (no verdict).
			mkRoute('r-u2', 'warmup.example', 'unknown', 0, 2),
		]);
		render(Page);

		await screen.findByText('DEGRADED');

		// v2.9.14 i18n Phase 3 batch 1 — counter copy migrated
		// from hardcoded FR "N/M sains" to t('routes.list.healthyCounter')
		// which resolves to "N/M healthy" in EN (test default boot).
		expect(screen.getByText(/1\/2 healthy/)).toBeInTheDocument();
		expect(screen.queryByText(/0\/2 healthy/)).not.toBeInTheDocument();
		expect(screen.queryByText(/1\/1 healthy/)).not.toBeInTheDocument();
	});
});

// --- C11 Pack A polish — table-row affordance ---------------------
//
// Operator's smoke after the badge polish caught two more UX
// gaps: (1) the per-row "Edit" button was redundant noise next
// to the whole-row click target, and (2) the selected row had
// no visual indication, which is a real footgun when multiple
// routes share similar URLs (operator's test2 + arenet-test
// both point at 192.168.99.10:8080). This commit drops the
// button entirely and adds a route-row-selected class on the
// active row. These tests pin the new contract.
describe('Routes page — table row interaction affordance', () => {
	const mk = (id: string, host: string): Route =>
		makeRoute({ id, host, upstreams: [{ url: 'http://127.0.0.1:9000', weight: 1 }] });

	it('renders no per-row "Edit" button (whole-row affordance instead)', async () => {
		apiMock.listRoutes.mockResolvedValue([
			mk('r-a', 'alpha.example'),
			mk('r-b', 'beta.example'),
		]);
		render(Page);

		// Wait for the rows to render.
		await screen.findByText('alpha.example');

		// No button anywhere in the document with the accessible
		// name "Edit" — the polish round explicitly removed it.
		expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
	});

	it('clicking a row opens the edit panel', async () => {
		apiMock.listRoutes.mockResolvedValue([mk('r-a', 'alpha.example')]);
		render(Page);

		const hostCell = await screen.findByText('alpha.example');
		const row = hostCell.closest('tr')!;

		// Before click: the edit-panel form is not mounted. The
		// most stable anchor is the host input — it's only in the
		// DOM when the form is open. (createForm path also mounts
		// it, but here we haven't opened the create form either.)
		expect(screen.queryByLabelText('Host')).not.toBeInTheDocument();

		await userEvent.click(row);
		await tick();

		// After click: the edit form is mounted and pre-populated
		// with the clicked route's host.
		const hostInput = screen.getByLabelText('Host') as HTMLInputElement;
		expect(hostInput.value).toBe('alpha.example');
	});

	it('selected row gets the route-row-selected class; deselects when another row opens', async () => {
		apiMock.listRoutes.mockResolvedValue([
			mk('r-a', 'alpha.example'),
			mk('r-b', 'beta.example'),
		]);
		render(Page);

		const alphaCell = await screen.findByText('alpha.example');
		const betaCell = screen.getByText('beta.example');
		const alphaRow = alphaCell.closest('tr')!;
		const betaRow = betaCell.closest('tr')!;

		// Initial: no row selected.
		expect(alphaRow.classList.contains('route-row-selected')).toBe(false);
		expect(betaRow.classList.contains('route-row-selected')).toBe(false);

		// Click alpha → alpha gets the selected class.
		await userEvent.click(alphaRow);
		await tick();
		expect(alphaRow.classList.contains('route-row-selected')).toBe(true);
		expect(betaRow.classList.contains('route-row-selected')).toBe(false);

		// Click beta → beta selected, alpha deselected. The
		// highlight follows the active editing route — critical
		// for the operator-footgun scenario (similar URLs across
		// routes).
		await userEvent.click(betaRow);
		await tick();
		expect(alphaRow.classList.contains('route-row-selected')).toBe(false);
		expect(betaRow.classList.contains('route-row-selected')).toBe(true);
	});

	// --- Polish round 3 (2026-06-06) — close paths -------------
	// Operator caught two regressions in 5a07275: Save left the
	// row highlighted (phantom selection with no panel), and
	// click-outside did nothing. These tests pin the three
	// close paths (Save / Cancel / outside-click) and the
	// click-same-row toggle so the next refactor can't regress.

	it('Save closes the panel AND deselects the row', async () => {
		const route = mk('r-a', 'alpha.example');
		apiMock.listRoutes.mockResolvedValue([route]);
		apiMock.updateRoute.mockResolvedValue(route);

		render(Page);

		const hostCell = await screen.findByText('alpha.example');
		const row = hostCell.closest('tr')!;
		await userEvent.click(row);
		await tick();

		// Sanity: row is selected before Save.
		expect(row.classList.contains('route-row-selected')).toBe(true);

		// Submit. Re-using the same pattern as the validation
		// suite — fireEvent.submit on the panel's form.
		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick(); // closePanel + loadRoutes both schedule

		// After Save: row is deselected (Bug 1 fix). The route is
		// still rendered (loadRoutes ran), but no row carries the
		// route-row-selected class.
		const rowAfter = (await screen.findByText('alpha.example')).closest('tr')!;
		expect(rowAfter.classList.contains('route-row-selected')).toBe(false);
		// Form mount anchor is gone too — the panel closed.
		expect(screen.queryByLabelText('Host')).not.toBeInTheDocument();
	});

	it('clicking outside the panel closes it and deselects the row', async () => {
		apiMock.listRoutes.mockResolvedValue([mk('r-a', 'alpha.example')]);
		render(Page);

		const hostCell = await screen.findByText('alpha.example');
		const row = hostCell.closest('tr')!;
		await userEvent.click(row);
		await tick();
		expect(row.classList.contains('route-row-selected')).toBe(true);

		// Click on the page <h1> heading — outside the panel
		// AND outside the table. The mousedown listener should
		// fire closePanel.
		const heading = screen.getByRole('heading', { name: /Routes/i });
		await fireEvent.mouseDown(heading);
		await tick();

		expect(row.classList.contains('route-row-selected')).toBe(false);
		expect(screen.queryByLabelText('Host')).not.toBeInTheDocument();
	});

	it('clicking inside the panel does NOT close it', async () => {
		apiMock.listRoutes.mockResolvedValue([mk('r-a', 'alpha.example')]);
		render(Page);

		const hostCell = await screen.findByText('alpha.example');
		const row = hostCell.closest('tr')!;
		await userEvent.click(row);
		await tick();

		// Click on a form input inside the panel — must not
		// trigger closePanel. The host input is the most reliable
		// in-panel anchor.
		const hostInput = screen.getByLabelText('Host') as HTMLInputElement;
		await fireEvent.mouseDown(hostInput);
		await tick();

		// Panel still open, row still selected.
		expect(row.classList.contains('route-row-selected')).toBe(true);
		expect(screen.getByLabelText('Host')).toBeInTheDocument();
	});

	it('clicking the same selected row toggles the panel closed', async () => {
		apiMock.listRoutes.mockResolvedValue([mk('r-a', 'alpha.example')]);
		render(Page);

		const hostCell = await screen.findByText('alpha.example');
		const row = hostCell.closest('tr')!;
		await userEvent.click(row);
		await tick();
		expect(row.classList.contains('route-row-selected')).toBe(true);

		// Click the same row again — toggle close (macOS Finder
		// list inspector behaviour). The row's onclick calls
		// selectOrToggleRoute which detects editingId === r.id
		// and invokes closePanel instead of re-opening.
		await userEvent.click(row);
		await tick();

		expect(row.classList.contains('route-row-selected')).toBe(false);
		expect(screen.queryByLabelText('Host')).not.toBeInTheDocument();
	});
});

// W.5 — country-block form section. The section lives in
// the route create/edit modal between WAF mode and the
// HealthCheck details block. Mode="off" hides the country
// list + status-code sub-fields; mode="allow" with an
// empty list surfaces a reactive footgun error (the W.2 API
// rejects with 400; client-side message is the
// pre-submit UX nudge).
describe('Routes page — W.5 country-block form section', () => {
	it('shows the country-block details block in the create form', async () => {
		render(Page);
		await openCreateForm();
		// The <summary> for the country-block <details> is
		// the canonical anchor.
		expect(screen.getByText('Pays bloqués')).toBeInTheDocument();
	});

	it('mode=off hides the country-list + status-code sub-fields', async () => {
		render(Page);
		await openCreateForm();
		// Default mode is 'off' → the sub-fields don't render.
		expect(screen.queryByTestId('country-block-input')).not.toBeInTheDocument();
		expect(
			screen.queryByLabelText(/Code HTTP/i)
		).not.toBeInTheDocument();
	});

	it('mode=deny reveals the country-list + status-code sub-fields', async () => {
		render(Page);
		await openCreateForm();
		// W.7 — Mode is now a 3-button toggle, not a dropdown.
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		expect(screen.getByTestId('country-block-input')).toBeInTheDocument();
		expect(screen.getByLabelText(/Code HTTP/i)).toBeInTheDocument();
	});

	it('typing FR + Enter adds a chip to the country list', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();

		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'FR{enter}');
		await tick();

		const chips = screen.getAllByTestId('country-block-chip');
		expect(chips).toHaveLength(1);
		// W.7 — chip carries the alpha-2 code in the
		// .cb-chip__code span; the resolved French name
		// also renders in .cb-chip__name. Both should be
		// findable.
		expect(chips[0].textContent).toContain('FR');
		// "France" comes from Intl.DisplayNames(fr) which
		// jsdom + Node ICU both ship.
		expect(chips[0].textContent).toContain('France');
	});

	it('mode=allow + empty list shows the footgun error', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-allow'));
		await tick();

		// Reactive paragraph with testid country-block-allow-empty-error
		// renders immediately on mode change while the list is empty.
		expect(
			screen.getByTestId('country-block-allow-empty-error')
		).toBeInTheDocument();
	});

	it('mode=allow + non-empty list clears the footgun error', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-allow'));
		await tick();
		// Error visible.
		expect(
			screen.getByTestId('country-block-allow-empty-error')
		).toBeInTheDocument();
		// Add a country — error clears.
		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'FR{enter}');
		await tick();
		expect(
			screen.queryByTestId('country-block-allow-empty-error')
		).not.toBeInTheDocument();
	});
});

// W.7 polish — autocomplete + mode-color + counter +
// CTA tests. These layer on top of the W.5 tests above
// without replacing them; the W.5 contracts (mode → input
// visibility, footgun error, payload shape) all still hold.
describe('Routes page — W.7 country-block polish', () => {
	it('renders the 3-button mode toggle (Off / Allow / Deny)', async () => {
		render(Page);
		await openCreateForm();
		expect(screen.getByTestId('country-block-mode-off')).toBeInTheDocument();
		expect(screen.getByTestId('country-block-mode-allow')).toBeInTheDocument();
		expect(screen.getByTestId('country-block-mode-deny')).toBeInTheDocument();
	});

	it('mode=off shows the muted off-hint instead of the input', async () => {
		render(Page);
		await openCreateForm();
		// Default state is off → hint visible, no input.
		expect(screen.getByTestId('country-block-off-hint')).toBeInTheDocument();
		expect(
			screen.queryByTestId('country-block-input')
		).not.toBeInTheDocument();
	});

	it('clicking the Allow button activates it (aria-pressed=true)', async () => {
		render(Page);
		await openCreateForm();
		const allowBtn = screen.getByTestId('country-block-mode-allow');
		expect(allowBtn).toHaveAttribute('aria-pressed', 'false');
		await userEvent.click(allowBtn);
		await tick();
		expect(allowBtn).toHaveAttribute('aria-pressed', 'true');
		expect(allowBtn).toHaveClass('active');
	});

	it('section root gets the mode-allow class when allow is selected', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-allow'));
		await tick();
		// CSS hook for chip + section recoloring.
		expect(screen.getByTestId('country-block-section')).toHaveClass(
			'cb-mode-allow'
		);
	});

	it('section root gets the mode-deny class when deny is selected', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		expect(screen.getByTestId('country-block-section')).toHaveClass(
			'cb-mode-deny'
		);
	});

	it('typing into the input opens the dropdown with matching suggestions', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'ru');
		await tick();
		// Suggestion list opens.
		expect(screen.getByTestId('country-block-dropdown')).toBeInTheDocument();
		// "RU" is one of the suggestions (prefix-matched on
		// the alpha-2 code).
		const suggestions = screen.getAllByTestId('country-block-suggestion');
		const codes = suggestions.map(
			(el) => el.querySelector('.cb-dropdown__code')?.textContent
		);
		expect(codes).toContain('RU');
	});

	it('typing a French name prefix matches the country (russie → RU)', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'russ');
		await tick();
		const suggestions = screen.getAllByTestId('country-block-suggestion');
		const codes = suggestions.map(
			(el) => el.querySelector('.cb-dropdown__code')?.textContent
		);
		expect(codes).toContain('RU');
	});

	it('clicking a suggestion adds it as a chip with the French name', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'fr');
		await tick();
		const suggestion = screen
			.getAllByTestId('country-block-suggestion')
			.find((el) => el.querySelector('.cb-dropdown__code')?.textContent === 'FR');
		expect(suggestion).toBeDefined();
		// mousedown (not click) because that's what the
		// onmousedown handler fires on — picked over click
		// so it runs BEFORE the input's blur closes the
		// dropdown.
		await fireEvent.mouseDown(suggestion!);
		await tick();
		const chips = screen.getAllByTestId('country-block-chip');
		expect(chips).toHaveLength(1);
		expect(chips[0].textContent).toContain('FR');
		expect(chips[0].textContent).toContain('France');
	});

	it('counter shows "{N} pays bloqué(s)" in deny mode + agrees with N', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'FR{enter}');
		await tick();
		expect(screen.getByTestId('country-block-counter')).toHaveTextContent(
			'1 pays bloqué'
		);
		// Second country → plural.
		await userEvent.type(input, 'DE{enter}');
		await tick();
		expect(screen.getByTestId('country-block-counter')).toHaveTextContent(
			'2 pays bloqués'
		);
	});

	it('counter shows "{N} pays autorisé(s)" in allow mode', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-allow'));
		await tick();
		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'FR{enter}');
		await tick();
		expect(screen.getByTestId('country-block-counter')).toHaveTextContent(
			'1 pays autorisé'
		);
	});

	it('counter is hidden when N=0 (even in allow/deny mode)', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		expect(
			screen.queryByTestId('country-block-counter')
		).not.toBeInTheDocument();
	});

	it('"+ Ajouter" CTA button is present in allow/deny mode', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		expect(screen.getByTestId('country-block-add-cta')).toBeInTheDocument();
	});

	it('chip removes itself when the × button is clicked', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'FR{enter}');
		await tick();
		const removeBtn = screen
			.getByTestId('country-block-chip')
			.querySelector('.cb-chip__remove');
		expect(removeBtn).not.toBeNull();
		await fireEvent.click(removeBtn!);
		await tick();
		expect(
			screen.queryByTestId('country-block-chip')
		).not.toBeInTheDocument();
	});

	it('comma separator adds the buffered code (paste-chain UX)', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'FR,');
		await tick();
		const chips = screen.getAllByTestId('country-block-chip');
		expect(chips).toHaveLength(1);
		expect(chips[0].textContent).toContain('FR');
	});
});

// W.7 follow-up — pinning the collapse-on-off UX fix.
// Before the fix, the <details> element's `open`
// attribute was reactively bound to (mode !== 'off') —
// so clicking "Désactivé" collapsed the entire section
// out of view, hiding the muted hint operators needed
// to confirm their choice. Fix: cbSectionOpen $state
// holds the open/closed intent independently of mode;
// switching to off keeps the section open + reveals
// the muted hint where the input used to live.
describe('Routes page — W.7 follow-up: section visibility on mode=off', () => {
	async function openSection(): Promise<void> {
		// New create-form path: section starts closed
		// (matches the create-form discipline for other
		// detail blocks like HealthCheck). Operator opens
		// it by clicking the summary.
		await openCreateForm();
		const summary = screen
			.getByTestId('country-block-section')
			.querySelector('summary');
		expect(summary).not.toBeNull();
		await fireEvent.click(summary!);
		await tick();
	}

	it('section starts closed on a fresh create form', async () => {
		render(Page);
		await openCreateForm();
		const section = screen.getByTestId(
			'country-block-section'
		) as HTMLDetailsElement;
		expect(section.open).toBe(false);
	});

	it('summary shows "(désactivé)" tag when collapsed in off-state', async () => {
		render(Page);
		await openCreateForm();
		// Summary visible (always rendered in jsdom — the
		// <summary> element isn't hidden by details.open=false).
		expect(
			screen.getByTestId('country-block-summary-off')
		).toBeInTheDocument();
	});

	it('clicking Allow opens the section AND reveals the input', async () => {
		render(Page);
		await openCreateForm();
		const section = screen.getByTestId(
			'country-block-section'
		) as HTMLDetailsElement;
		expect(section.open).toBe(false);
		// Picking Allow auto-opens — operator's "I want to
		// configure this" intent unmistakable.
		await userEvent.click(screen.getByTestId('country-block-mode-allow'));
		await tick();
		expect(section.open).toBe(true);
		expect(screen.getByTestId('country-block-input')).toBeInTheDocument();
	});

	it('clicking Désactivé from an open Allow state KEEPS section open + shows the muted hint', async () => {
		render(Page);
		await openSection();
		// Pick Allow first (configured state).
		await userEvent.click(screen.getByTestId('country-block-mode-allow'));
		await tick();
		const section = screen.getByTestId(
			'country-block-section'
		) as HTMLDetailsElement;
		expect(section.open).toBe(true);
		expect(screen.getByTestId('country-block-input')).toBeInTheDocument();

		// Now pick Off — the brief's UX-feedback regression.
		// Before the fix, this collapsed the whole section.
		// After the fix, section stays open + the muted
		// hint takes over where the input was.
		await userEvent.click(screen.getByTestId('country-block-mode-off'));
		await tick();
		expect(section.open).toBe(true);
		expect(screen.getByTestId('country-block-off-hint')).toBeInTheDocument();
		// Input + chips no longer rendered (the {#if mode
		// !== 'off'} branch evaporates), but the toggle
		// + the muted hint stay visible — operator can
		// see what they just picked.
		expect(
			screen.queryByTestId('country-block-input')
		).not.toBeInTheDocument();
		// All 3 mode buttons still on screen.
		expect(
			screen.getByTestId('country-block-mode-off')
		).toBeInTheDocument();
		expect(
			screen.getByTestId('country-block-mode-allow')
		).toBeInTheDocument();
		expect(
			screen.getByTestId('country-block-mode-deny')
		).toBeInTheDocument();
	});

	it('the off-state muted hint message reads the canonical Step W copy', async () => {
		render(Page);
		await openSection();
		// Verbatim string the brief specified — operator-
		// visible nudge "Choose Allow-list or Deny-list to
		// activate." Future copy changes should reach this
		// test before reaching production.
		const hint = screen.getByTestId('country-block-off-hint');
		expect(hint.textContent).toContain('Aucun gate par pays');
		expect(hint.textContent).toContain('Allow-list');
		expect(hint.textContent).toContain('Deny-list');
	});

	it('operator can still manually collapse the section via the summary', async () => {
		render(Page);
		await openSection();
		const section = screen.getByTestId(
			'country-block-section'
		) as HTMLDetailsElement;
		expect(section.open).toBe(true);
		// Manual summary click toggles open/closed — the
		// fix's "section.open is not mode-reactive" rule
		// must NOT lock the section into an always-open
		// state.
		const summary = section.querySelector('summary');
		await fireEvent.click(summary!);
		await tick();
		expect(section.open).toBe(false);
	});
});

// --- 9. #R-PROXMOX-HTTPS-LOOP commit 2 — TLS advanced disclosure +
// per-row hints + scheme-transition self-heal -----------------------

describe('Routes page — TLS advanced disclosure + UX hints (#R-PROXMOX-HTTPS-LOOP)', () => {
	// Reaches the first upstream URL input directly via the
	// placeholder selector (helper from §1 above).
	function firstURL(): HTMLInputElement {
		return upstreamURLInputs()[0];
	}

	it('hides the TLS advanced disclosure on an http-only pool', async () => {
		render(Page);
		await openCreateForm();
		// Initial state: row is empty → poolScheme === "empty" →
		// disclosure absent.
		expect(screen.queryByTestId('tls-advanced-disclosure')).toBeNull();
		// Type http URL — disclosure stays absent.
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'http://10.0.0.10:8123');
		await tick();
		expect(screen.queryByTestId('tls-advanced-disclosure')).toBeNull();
	});

	it('shows the TLS advanced disclosure on an https-only pool', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://192.168.1.60:8006');
		await tick();
		expect(screen.queryByTestId('tls-advanced-disclosure')).not.toBeNull();
	});

	it('hides the disclosure AND clears the toggle on https→http scheme transition (self-heal)', async () => {
		render(Page);
		await openCreateForm();
		// 1. Type https — disclosure appears.
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://192.168.1.60:8006');
		await tick();
		const disclosure = screen.getByTestId('tls-advanced-disclosure');
		// 2. Tick the toggle — would persist a true on submit.
		const toggle = screen.getByLabelText(
			'Ignorer la vérification du certificat upstream'
		) as HTMLInputElement;
		await userEvent.click(toggle);
		await tick();
		expect(toggle.checked).toBe(true);
		// 3. Flip the URL to http — disclosure must leave the DOM
		// AND the $effect must reset insecureSkipVerify to false.
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'http://10.0.0.10:8123');
		await tick();
		expect(screen.queryByTestId('tls-advanced-disclosure')).toBeNull();
		// 4. Re-flip to https — toggle must re-appear UNCHECKED
		// (the $effect cleared it on the transition, so the
		// operator's stale intent doesn't leak back).
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://192.168.1.60:8006');
		await tick();
		const reborn = screen.getByLabelText(
			'Ignorer la vérification du certificat upstream'
		) as HTMLInputElement;
		expect(reborn.checked).toBe(false);
		// touch the disclosure so the previous binding is held
		// (no-op assertion to keep TS happy on the reference).
		expect(disclosure).toBeTruthy();
	});

	it('shows the path warning when the upstream URL carries a non-root path', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://1.2.3.4:8006/api2/json');
		await tick();
		const warning = screen.getByTestId('upstream-path-warning');
		expect(warning.textContent).toContain('/api2/json');
		expect(warning.textContent).toMatch(/ignoré/i);
		// And the value is preserved (no auto-strip — the operator
		// has to decide).
		expect(firstURL().value).toBe('https://1.2.3.4:8006/api2/json');
	});

	it('shows the private-IP hint on https + RFC 1918 host', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://192.168.1.60:8006');
		await tick();
		const hint = screen.getByTestId('upstream-private-ip-hint');
		expect(hint.textContent).toMatch(/IP privée/i);
		// Negative case: http + RFC 1918 → hint absent.
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'http://192.168.1.60:8006');
		await tick();
		expect(screen.queryByTestId('upstream-private-ip-hint')).toBeNull();
		// Negative case: https + public IP → hint absent.
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://1.1.1.1');
		await tick();
		expect(screen.queryByTestId('upstream-private-ip-hint')).toBeNull();
	});

	it('blocks submit on a mixed-scheme pool with a pool-level error', async () => {
		render(Page);
		await openCreateForm();
		// Fill a usable host so the host validator doesn't shadow
		// the mixed-scheme error.
		await userEvent.type(hostInput(), 'mixed.example.com');
		// Row 0: http. Row 1: https.
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'http://10.0.0.10:8000');
		const addBtn = screen.getByRole('button', { name: /\+\s*Add upstream/i });
		await userEvent.click(addBtn);
		await tick();
		const row1 = upstreamURLInputs()[1];
		await userEvent.type(row1, 'https://10.0.0.11:8000');
		await tick();
		// Submit — backend should NOT be reached; the form's
		// validateBeforeSubmit short-circuits with the mixed-pool
		// error rendered under the pool header. Create-mode button
		// label is "Create" (Edit-mode would read "Save").
		const submitBtn = screen.getByRole('button', { name: /^Create$/i });
		await userEvent.click(submitBtn);
		await tick();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
		// Error copy exact phrase pinned (a future copy change
		// should reach this test, not production).
		expect(
			screen.getByText(/All upstreams must share the same scheme/i)
		).not.toBeNull();
	});

	it('serialises insecureSkipVerify=true into the POST payload on an https pool', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute({
			host: 'pve.example.com',
			upstreams: [{ url: 'https://192.168.1.60:8006', weight: 1 }],
			insecureSkipVerify: true
		}));
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'pve.example.com');
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://192.168.1.60:8006');
		await tick();
		const toggle = screen.getByLabelText(
			'Ignorer la vérification du certificat upstream'
		) as HTMLInputElement;
		await userEvent.click(toggle);
		await tick();
		const submitBtn = screen.getByRole('button', { name: /^Create$/i });
		await userEvent.click(submitBtn);
		await tick();
		expect(apiMock.createRoute).toHaveBeenCalledTimes(1);
		const payload = apiMock.createRoute.mock.calls[0][0] as Record<string, unknown>;
		expect(payload.insecureSkipVerify).toBe(true);
	});

	it('OMITS insecureSkipVerify from the PUT payload on an http-only pool (preserve-on-omit)', async () => {
		// openEdit a route that's currently http+true (a stale
		// row from before a manual scheme switch). The form's
		// scheme-transition $effect already self-healed
		// formData.insecureSkipVerify to false in the
		// openEdit→render path; the submit pipeline OMITS the
		// field on an http pool so the backend's preserve-
		// previous path runs (the backend will then itself
		// self-heal the stored true → false with a warn-log on
		// the next PUT that DOES touch the flag).
		const fixture = makeRoute({
			id: 'route-http-stale',
			host: 'ha.example.com',
			upstreams: [{ url: 'http://10.0.0.10:8123', weight: 1 }],
			insecureSkipVerify: false
		});
		apiMock.listRoutes.mockResolvedValue([fixture]);
		apiMock.updateRoute.mockResolvedValue(fixture);
		render(Page);
		// Wait for the route row, then click it to enter edit.
		const row = await screen.findByText('ha.example.com');
		await userEvent.click(row);
		await tick();
		// Submit unchanged.
		const saveBtn = screen.getByRole('button', { name: /^Save$/i });
		await userEvent.click(saveBtn);
		await tick();
		expect(apiMock.updateRoute).toHaveBeenCalledTimes(1);
		const payload = apiMock.updateRoute.mock.calls[0][1] as Record<string, unknown>;
		// Pin the OMISSION — preserve-on-omit path. The backend
		// will preserve whatever was stored (false here).
		expect('insecureSkipVerify' in payload).toBe(false);
	});
});

// --- 10. #R-PROXMOX-HTTPS-LOOP commit 3 — Test-upstream UI ---------

describe('Routes page — Test upstream button + chip (#R-PROXMOX-HTTPS-LOOP commit 3)', () => {
	function firstURL(): HTMLInputElement {
		return upstreamURLInputs()[0];
	}

	it('renders one "Tester" button per upstream row, disabled while URL empty', async () => {
		render(Page);
		await openCreateForm();
		const btn0 = screen.getByTestId('test-upstream-0') as HTMLButtonElement;
		expect(btn0.disabled).toBe(true);
		// Type a URL, disabled flips off.
		await userEvent.type(firstURL(), 'http://10.0.0.10:8080');
		await tick();
		expect(btn0.disabled).toBe(false);
	});

	it('sends the URL to the API and renders the reachable chip on success', async () => {
		apiMock.testUpstream.mockResolvedValue({
			reachable: true,
			statusCode: 200,
			latencyMs: 42,
			serverHeader: 'nginx/1.24.0'
		});
		render(Page);
		await openCreateForm();
		await userEvent.type(firstURL(), 'http://10.0.0.10:8080');
		await tick();
		const btn = screen.getByTestId('test-upstream-0');
		await userEvent.click(btn);
		await tick();
		expect(apiMock.testUpstream).toHaveBeenCalledTimes(1);
		const args = apiMock.testUpstream.mock.calls[0][0] as {
			url: string;
			insecureSkipVerify?: boolean;
		};
		expect(args.url).toBe('http://10.0.0.10:8080');
		// http pool → insecureSkipVerify must be false on
		// the wire, never the form's stale state.
		expect(args.insecureSkipVerify).toBe(false);
		const chip = screen.getByTestId('upstream-test-chip-0');
		expect(chip.textContent).toMatch(/HTTP 200/);
		expect(chip.textContent).toMatch(/42ms/);
		expect(chip.textContent).toContain('nginx/1.24.0');
	});

	it('renders the error chip on a backend error result', async () => {
		apiMock.testUpstream.mockResolvedValue({
			reachable: false,
			error: 'connection refused'
		});
		render(Page);
		await openCreateForm();
		await userEvent.type(firstURL(), 'http://10.0.0.10:8080');
		await tick();
		await userEvent.click(screen.getByTestId('test-upstream-0'));
		await tick();
		const chip = screen.getByTestId('upstream-test-chip-0');
		expect(chip.textContent).toMatch(/✗/);
		expect(chip.textContent).toMatch(/connection refused/i);
	});

	it('renders an error chip when the request itself throws (network down)', async () => {
		apiMock.testUpstream.mockRejectedValue(new Error('network down'));
		render(Page);
		await openCreateForm();
		await userEvent.type(firstURL(), 'http://10.0.0.10:8080');
		await tick();
		await userEvent.click(screen.getByTestId('test-upstream-0'));
		await tick();
		const chip = screen.getByTestId('upstream-test-chip-0');
		expect(chip.textContent).toContain('network down');
	});

	it('forwards insecureSkipVerify on an https pool with the toggle checked', async () => {
		apiMock.testUpstream.mockResolvedValue({
			reachable: true,
			statusCode: 200,
			latencyMs: 50,
			cert: { commonName: 'pve.local', issuer: 'CN=pve.local', selfSigned: true }
		});
		render(Page);
		await openCreateForm();
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://192.168.1.60:8006');
		await tick();
		// Tick the toggle so the request carries true.
		const toggle = screen.getByLabelText(
			'Ignorer la vérification du certificat upstream'
		) as HTMLInputElement;
		await userEvent.click(toggle);
		await tick();
		await userEvent.click(screen.getByTestId('test-upstream-0'));
		await tick();
		expect(apiMock.testUpstream).toHaveBeenCalledTimes(1);
		const args = apiMock.testUpstream.mock.calls[0][0] as {
			insecureSkipVerify?: boolean;
		};
		expect(args.insecureSkipVerify).toBe(true);
		const chip = screen.getByTestId('upstream-test-chip-0');
		// self-signed warning rendered on the chip.
		expect(chip.textContent).toMatch(/self-signed/i);
	});

	it('"Tester tous" parallelises the probe across every non-empty row', async () => {
		apiMock.testUpstream.mockImplementation(async (req: { url: string }) => ({
			reachable: true,
			statusCode: 200,
			latencyMs: 10,
			serverHeader: `fake-for-${req.url}`
		}));
		render(Page);
		await openCreateForm();
		await userEvent.type(firstURL(), 'http://10.0.0.10:8080');
		const addBtn = screen.getByRole('button', { name: /\+\s*Add upstream/i });
		await userEvent.click(addBtn);
		await tick();
		await userEvent.click(addBtn);
		await tick();
		await userEvent.type(upstreamURLInputs()[1], 'http://10.0.0.11:8080');
		// Leave row 2 empty — "Tester tous" should skip it.
		const testAllBtn = screen.getByTestId('test-all-upstreams');
		await userEvent.click(testAllBtn);
		await tick();
		await tick();
		// Two probes fired: rows 0 and 1 (row 2 skipped).
		expect(apiMock.testUpstream).toHaveBeenCalledTimes(2);
		// Both chips rendered.
		expect(screen.getByTestId('upstream-test-chip-0').textContent).toMatch(
			/10\.0\.0\.10/
		);
		expect(screen.getByTestId('upstream-test-chip-1').textContent).toMatch(
			/10\.0\.0\.11/
		);
		expect(screen.queryByTestId('upstream-test-chip-2')).toBeNull();
	});

	it('removing a tested row shifts the surviving chip indices', async () => {
		// Pin the splice cleanup in removeUpstream — without
		// it, removing row 0 would leave chip-0 attached to
		// the old result, and the row that was at index 1
		// (now at 0) would have no chip.
		apiMock.testUpstream.mockResolvedValue({
			reachable: true,
			statusCode: 200,
			latencyMs: 7,
			serverHeader: 'row-1'
		});
		render(Page);
		await openCreateForm();
		await userEvent.type(firstURL(), 'http://10.0.0.10:8080');
		const addBtn = screen.getByRole('button', { name: /\+\s*Add upstream/i });
		await userEvent.click(addBtn);
		await tick();
		await userEvent.type(upstreamURLInputs()[1], 'http://10.0.0.11:8080');
		// Test row 1 only.
		await userEvent.click(screen.getByTestId('test-upstream-1'));
		await tick();
		expect(screen.getByTestId('upstream-test-chip-1').textContent).toContain('row-1');
		expect(screen.queryByTestId('upstream-test-chip-0')).toBeNull();
		// Remove row 0 — the tested row should now be at
		// index 0; chip-1 should be gone, chip-0 should
		// carry the old row-1 result.
		const removeButtons = screen
			.getAllByRole('button')
			.filter((b) => b.textContent?.trim() === '×');
		await userEvent.click(removeButtons[0]);
		await tick();
		expect(screen.queryByTestId('upstream-test-chip-1')).toBeNull();
		expect(screen.getByTestId('upstream-test-chip-0').textContent).toContain('row-1');
	});
});

// --- Phase 4.5 — uploadStreamingMode toggle ----------------------------
//
// The toggle lives inside the WAF settings block (modulates WAF body
// inspection + Caddy buffering — coupling it with the WAF knob it
// affects is the clearer mental model than burying it under
// "advanced TLS"). These tests pin:
//   1. Toggle is rendered + defaults to unchecked on create
//   2. Helper text is present and surfaces the operative invariants
//      (body skipped, headers still scanned)
//   3. Form ships uploadStreamingMode=false by default on POST
//   4. Form ships uploadStreamingMode=true when operator ticks the
//      toggle
//   5. openEdit loads the persisted value (true) onto the toggle
//   6. The toggle works independently of wafMode (no constraint
//      between the two)

describe('Routes page — Phase 4.5 uploadStreamingMode toggle', () => {
	it('renders the toggle unchecked by default on create', async () => {
		render(Page);
		await openCreateForm();

		const toggle = screen.getByTestId('upload-streaming-toggle') as HTMLInputElement;
		expect(toggle).toBeInTheDocument();
		expect(toggle.checked).toBe(false);
	});

	it('renders helper text describing the body-skip / header-still-scanned invariants', async () => {
		render(Page);
		await openCreateForm();

		const label = screen.getByTestId('upload-streaming-toggle-label');
		expect(label.textContent).toMatch(/Mode upload streaming/);

		// The helper paragraph follows the label. Walk the parent
		// to find it without coupling to exact DOM structure.
		const wafSection = label.closest('div')!;
		const helperText = wafSection.textContent ?? '';
		expect(helperText).toMatch(/headers/);
		expect(helperText).toMatch(/URL/);
		expect(helperText).toMatch(/response/);
		expect(helperText).toMatch(/registry/i);
	});

	it('ships uploadStreamingMode=false by default in the create payload', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'plain.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		expect(apiMock.createRoute).toHaveBeenCalledTimes(1);
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.uploadStreamingMode).toBe(false);
	});

	it('ships uploadStreamingMode=true when operator ticks the toggle', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute({ uploadStreamingMode: true }));
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'registry.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:5000');

		const toggle = screen.getByTestId('upload-streaming-toggle') as HTMLInputElement;
		await userEvent.click(toggle);
		expect(toggle.checked).toBe(true);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		expect(apiMock.createRoute).toHaveBeenCalledTimes(1);
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.uploadStreamingMode).toBe(true);
	});

	it('loads the persisted uploadStreamingMode=true value into the toggle on edit', async () => {
		const seeded = makeRoute({
			id: 'edit-streaming',
			host: 'registry.edit.example.com',
			uploadStreamingMode: true
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);

		render(Page);
		const hostCell = await screen.findByText('registry.edit.example.com');
		const row = hostCell.closest('tr')!;
		await userEvent.click(row);
		await tick();

		const toggle = screen.getByTestId('upload-streaming-toggle') as HTMLInputElement;
		expect(toggle.checked).toBe(true);
	});

	it('persists toggle state across wafMode changes (no cross-coupling)', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute({ uploadStreamingMode: true }));
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'files.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:8081');

		// Operator ticks the toggle FIRST, then sets WAF=block.
		// Streaming-mode state must survive the wafMode change —
		// no coupling between the two.
		const toggle = screen.getByTestId('upload-streaming-toggle') as HTMLInputElement;
		await userEvent.click(toggle);
		expect(toggle.checked).toBe(true);

		const wafSelect = document.getElementById('route-waf-mode') as HTMLSelectElement;
		await userEvent.selectOptions(wafSelect, 'block');
		// Toggle still checked after WAF dropdown interaction.
		expect(toggle.checked).toBe(true);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.uploadStreamingMode).toBe(true);
		expect(payload.wafMode).toBe('block');
	});
});

// --- Day 13 #R-FRONTEND-PUT-NO-TIMEOUT — submitForm error
// handling. Two pins:
//   1. Timeout (system-kind ApiError) → spinner clears + danger
//      toast surfaces the actionable message.
//   2. Locked state after the await → spinner clears + NO
//      toast (LockScreen overlay already informs the operator).
//
// Both branches go through the same try/catch/finally —
// regressions would either leave the spinner running (worst
// case, the operator-reported symptom) or double-notify on
// lock (LockScreen + danger toast competing for focus).

describe('Routes page — submitForm error handling (#R-FRONTEND-PUT-NO-TIMEOUT)', () => {
	it('shows danger toast + closes spinner when backend stalls past the timeout', async () => {
		// updateRoute rejects with the exact ApiError shape the
		// request() helper throws on AbortController timeout.
		apiMock.updateRoute.mockRejectedValue(
			new ApiError('request timed out after 30s', 0, 'system')
		);
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({ id: 'r-timeout', host: 'timeout.example.com' })
		]);

		render(Page);
		const hostCell = await screen.findByText('timeout.example.com');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		// Toast surfaces the timeout message verbatim — operator
		// reads "request timed out after 30s" and knows the
		// backend was unresponsive, not that they did something
		// wrong.
		expect(toastMock.pushToast).toHaveBeenCalledWith(
			'request timed out after 30s',
			'danger'
		);
		// Spinner gone: the Save button is no longer in its
		// loading state. We assert via the overlay test-id
		// which only mounts while submitting=true.
		expect(screen.queryByTestId('route-save-overlay')).toBeNull();
	});

	it('suppresses the danger toast when auth.state is "locked" after the await', async () => {
		// The PUT returned a 403 session-locked; the client
		// interceptor called auth.setLocked() (which flipped the
		// store to 'locked') and threw ApiError(403, forbidden).
		// submitForm must see auth.state==='locked' in its catch
		// and skip the toast — the LockScreen overlay is the
		// authoritative operator signal.
		authMock.state = 'locked';
		apiMock.updateRoute.mockRejectedValue(
			new ApiError('session locked', 403, 'forbidden')
		);
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({ id: 'r-lock', host: 'lock.example.com' })
		]);

		render(Page);
		const hostCell = await screen.findByText('lock.example.com');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		// No double-notify: pushToast not called for the lock
		// case. (The LockScreen overlay is layout-level, not
		// asserted here — its mounting is covered by
		// auth.test.ts + layout tests.)
		expect(toastMock.pushToast).not.toHaveBeenCalled();
		// Spinner still cleared — finally ran even on the
		// suppressed-toast branch.
		expect(screen.queryByTestId('route-save-overlay')).toBeNull();
	});
});

// --- Step X.2 — wafDisableCRS toggle + confirm dialog ----------------
//
// The toggle lives in the WAF settings block alongside wafMode +
// uploadStreamingMode. Two operator-visible contracts :
//   1. Enabling the toggle (false → true) opens an ADR-D4 confirm
//      dialog before the form state mutates. Cancelling leaves
//      the toggle unticked and the formData at false ; confirming
//      commits the true.
//   2. Disabling the toggle (true → false) flips immediately. No
//      dialog : re-enabling CRS is a security-improving action,
//      always safe.
//
// Wire contract :
//   3. Payload ships wafDisableCRS=false by default on POST
//      (zero-value byte-equivalent to pre-X.1 routes).
//   4. Payload ships wafDisableCRS=true after the operator
//      confirms via the dialog.
//   5. Edit loads the persisted value (true) so the toggle
//      reflects the stored state on re-open.
//   6. Toggle is independent of wafMode (same independence as
//      uploadStreamingMode, mirror of the Phase 4.5 invariant).

describe('Routes page — Step X.2 wafDisableCRS toggle + confirm dialog', () => {
	it('renders the toggle unchecked by default on create', async () => {
		render(Page);
		await openCreateForm();
		const toggle = screen.getByTestId('waf-disable-crs-toggle') as HTMLInputElement;
		expect(toggle).toBeInTheDocument();
		expect(toggle.checked).toBe(false);
	});

	it('ticking the toggle opens the ADR-D4 confirm dialog and DOES NOT mutate the toggle state', async () => {
		render(Page);
		await openCreateForm();
		const toggle = screen.getByTestId('waf-disable-crs-toggle') as HTMLInputElement;
		await userEvent.click(toggle);
		// v2.9.14 i18n Phase 3 batch 1 — dialog title resolves via
		// t('routes.wafCRSDialog.title'). Test boot has no cookie/
		// localStorage in jsdom → EN bundle wins.
		expect(screen.getByText('Disable the OWASP CRS rules?')).toBeInTheDocument();
		// Toggle visual state stays at false until the operator
		// confirms via the dialog.
		expect(toggle.checked).toBe(false);
	});

	it('cancelling the dialog keeps the toggle unchecked and the form value at false', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'cancel.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		const toggle = screen.getByTestId('waf-disable-crs-toggle') as HTMLInputElement;
		await userEvent.click(toggle);
		// Cancel via the ConfirmDialog cancel button (EN: "Cancel").
		// v2.9.14 — multiple "Cancel" buttons exist now (form +
		// dialog); scope the lookup to a role+name match that
		// finds the dialog's cancel since the dialog is the only
		// currently-visible button-named "Cancel" in modal scope.
		const cancelBtns = screen.getAllByRole('button', { name: 'Cancel' });
		// The CRS confirm dialog cancel is the most-recently-mounted
		// "Cancel" button (Modal portals to body end). Click the last.
		await userEvent.click(cancelBtns[cancelBtns.length - 1]);
		await tick();

		expect(toggle.checked).toBe(false);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.wafDisableCRS).toBe(false);
	});

	it('confirming the dialog flips formData true and ships wafDisableCRS=true in the create payload', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute({ wafDisableCRS: true }));
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'nas.lan');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:8080');

		const toggle = screen.getByTestId('waf-disable-crs-toggle') as HTMLInputElement;
		await userEvent.click(toggle);
		// Confirm the dialog — the affirmative button reads
		// "Disable CRS" (EN bundle, test boot default).
		const confirmBtn = screen.getByText('Disable CRS');
		await userEvent.click(confirmBtn);
		await tick();
		expect(toggle.checked).toBe(true);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.wafDisableCRS).toBe(true);
	});

	it('unticking an already-true toggle DOES NOT open the dialog (re-enable CRS is always safe)', async () => {
		// Seed a stored route with wafDisableCRS=true so the
		// edit form opens with the toggle checked. The operator
		// then unticks ; no dialog should appear, the formData
		// flips immediately, and the next save ships false.
		const seeded = makeRoute({
			id: 'edit-disable-crs',
			host: 'edit.nas.lan',
			wafDisableCRS: true
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue({ ...seeded, wafDisableCRS: false });

		render(Page);
		const hostCell = await screen.findByText('edit.nas.lan');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		const toggle = screen.getByTestId('waf-disable-crs-toggle') as HTMLInputElement;
		expect(toggle.checked).toBe(true);

		await userEvent.click(toggle);
		// NO dialog on un-tick path. v2.9.14 i18n Phase 3 batch 1
		// flipped the title to t('routes.wafCRSDialog.title') →
		// "Disable the OWASP CRS rules?" in the EN bundle.
		expect(screen.queryByText('Disable the OWASP CRS rules?')).toBeNull();
		expect(toggle.checked).toBe(false);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.updateRoute.mock.calls[0][1];
		expect(payload.wafDisableCRS).toBe(false);
	});

	it('loads the persisted wafDisableCRS=true value into the toggle on edit', async () => {
		const seeded = makeRoute({
			id: 'edit-disable-crs-load',
			host: 'load.nas.lan',
			wafDisableCRS: true
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		const hostCell = await screen.findByText('load.nas.lan');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();
		const toggle = screen.getByTestId('waf-disable-crs-toggle') as HTMLInputElement;
		expect(toggle.checked).toBe(true);
	});

	it('toggle is independent of wafMode (no cross-coupling, mirror of streaming-mode invariant)', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute({ wafDisableCRS: true }));
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'independent.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:8000');

		// Tick + confirm BEFORE changing wafMode.
		const toggle = screen.getByTestId('waf-disable-crs-toggle') as HTMLInputElement;
		await userEvent.click(toggle);
		await userEvent.click(screen.getByText('Disable CRS'));
		await tick();
		expect(toggle.checked).toBe(true);

		const wafSelect = document.getElementById('route-waf-mode') as HTMLSelectElement;
		await userEvent.selectOptions(wafSelect, 'block');
		// Toggle survives the dropdown change.
		expect(toggle.checked).toBe(true);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.wafDisableCRS).toBe(true);
		expect(payload.wafMode).toBe('block');
	});
});

// --- Step X Option (c) — wafExcludeRules textarea ----------------
//
// The textarea lives below the wafDisableCRS toggle in the WAF block.
// Operator types a comma-separated list of 6-digit CRS rule IDs ;
// frontend parses, validates (range + reserved-Arenet check),
// dedupes + sorts, and ships the canonical number[] in the payload.
//
// Operator-visible contracts pinned :
//   1. Empty input on create ships [] (no exclusions).
//   2. Valid 6-digit IDs parse into number[] payload.
//   3. Non-numeric input surfaces a frontend error and blocks
//      submit.
//   4. Out-of-range IDs (< 100000, > 999999) surface a frontend
//      error.
//   5. Arenet-reserved range [100000, 199999] surfaces a
//      frontend error.
//   6. Edit loads the persisted list back into the textarea.
//   7. Textarea is disabled when wafDisableCRS is true (the
//      stored list is preserved, just gated).
//   8. /security/{routeId} link is present in edit mode for rule
//      ID discovery.

describe('Routes page — Step X Option (c) wafExcludeRules textarea', () => {
	it('ships empty wafExcludeRules in the create payload when textarea is empty', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'empty.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.wafExcludeRules).toEqual([]);
	});

	it('parses comma-separated 6-digit IDs into the create payload', async () => {
		apiMock.createRoute.mockResolvedValue(
			makeRoute({ wafExcludeRules: [920280, 941390, 942100] })
		);
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'parse.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		const textarea = screen.getByTestId('waf-exclude-rules-input') as HTMLTextAreaElement;
		// Type out of order to verify the frontend canonicalises
		// (ascending sort + dedup) before sending.
		await userEvent.type(textarea, '942100, 941390, 920280');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.wafExcludeRules).toEqual([920280, 941390, 942100]);
	});

	it('surfaces a frontend error on non-numeric input and blocks submit', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'bad.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		const textarea = screen.getByTestId('waf-exclude-rules-input') as HTMLTextAreaElement;
		await userEvent.type(textarea, 'abc, 942100');

		const errorNode = screen.getByTestId('waf-exclude-rules-error');
		expect(errorNode.textContent ?? '').toContain('abc');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});

	it('rejects IDs in the Arenet-reserved range [100000, 199999]', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'reserved.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		const textarea = screen.getByTestId('waf-exclude-rules-input') as HTMLTextAreaElement;
		await userEvent.type(textarea, '150000');

		const errorNode = screen.getByTestId('waf-exclude-rules-error');
		expect(errorNode.textContent ?? '').toMatch(/réservée|reserved/i);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});

	it('rejects IDs out of the 6-digit range', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'oor.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		const textarea = screen.getByTestId('waf-exclude-rules-input') as HTMLTextAreaElement;
		await userEvent.type(textarea, '99999');

		const errorNode = screen.getByTestId('waf-exclude-rules-error');
		expect(errorNode.textContent ?? '').toMatch(/6 chiffres|range/i);
	});

	it('loads the persisted exclusion list into the textarea on edit', async () => {
		const seeded = makeRoute({
			id: 'edit-exclude',
			host: 'edit.exclude.local',
			wafExcludeRules: [920280, 941390, 942100]
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		const hostCell = await screen.findByText('edit.exclude.local');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		const textarea = screen.getByTestId('waf-exclude-rules-input') as HTMLTextAreaElement;
		// Canonical comma-separated form ; openEdit calls
		// formatExcludeRulesInput on the stored slice.
		expect(textarea.value).toBe('920280, 941390, 942100');
	});

	it('disables the textarea when wafDisableCRS is true', async () => {
		const seeded = makeRoute({
			id: 'edit-disable',
			host: 'edit.disable.local',
			wafDisableCRS: true,
			wafExcludeRules: [942100]
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		const hostCell = await screen.findByText('edit.disable.local');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		const textarea = screen.getByTestId('waf-exclude-rules-input') as HTMLTextAreaElement;
		// Disabled but NOT cleared — the operator may toggle CRS
		// back on later and expect the list to still apply.
		expect(textarea.disabled).toBe(true);
		expect(textarea.value).toBe('942100');
	});

	it('surfaces the /security/{routeId} discovery link in edit mode', async () => {
		const seeded = makeRoute({
			id: 'discover-link',
			host: 'discover.local'
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		const hostCell = await screen.findByText('discover.local');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		const link = screen.getByTestId('waf-exclude-rules-security-link') as HTMLAnchorElement;
		expect(link.getAttribute('href')).toBe('/security/discover-link');
	});
});

// --- Step X Option (e) — wafExcludeTags textarea + datalist --------
//
// Sibling of (c). Same operator-visible contracts :
//   1. Empty input → ships [] (no exclusions).
//   2. Comma-separated tags parse + canonicalise (lowercase,
//      dedup, sort) into the payload.
//   3. Invalid characters (comma inside a tag, whitespace
//      inside a tag, double-quote) surface a frontend error
//      and block submit.
//   4. Edit loads the persisted list back into the textarea.
//   5. Datalist exposes the curated CRS tag catalog (24 entries).
//   6. Textarea is disabled when wafDisableCRS is true.

describe('Routes page — Step X Option (e) wafExcludeTags textarea', () => {
	it('ships empty wafExcludeTags in the create payload when textarea is empty', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'empty-tags.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.wafExcludeTags).toEqual([]);
	});

	it('parses comma-separated tags into the canonicalised create payload', async () => {
		apiMock.createRoute.mockResolvedValue(
			makeRoute({ wafExcludeTags: ['attack-protocol', 'attack-sqli', 'paranoia-level/3'] })
		);
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'parse-tags.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		const textarea = screen.getByTestId('waf-exclude-tags-input') as HTMLTextAreaElement;
		// Type out-of-order + mixed-case + duplicate to verify
		// the frontend canonicalises (lowercase, dedup, sort).
		await userEvent.type(textarea, 'Paranoia-Level/3, attack-sqli, ATTACK-PROTOCOL, attack-sqli');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.wafExcludeTags).toEqual(['attack-protocol', 'attack-sqli', 'paranoia-level/3']);
	});

	it('surfaces a frontend error on a comma-smuggling tag and blocks submit', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'bad-tag.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		// Note : the parser splits on `,`, so the way to land
		// a comma-inside-a-tag here is to use a token that the
		// split already produced and that still contains an
		// invalid character. Double-quote is the cleanest signal.
		const textarea = screen.getByTestId('waf-exclude-tags-input') as HTMLTextAreaElement;
		await userEvent.type(textarea, 'attack-sqli"');

		const errorNode = screen.getByTestId('waf-exclude-tags-error');
		expect(errorNode.textContent ?? '').toContain('SecAction');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});

	it('reloads the persisted tag list into the textarea on edit', async () => {
		const seeded = makeRoute({
			id: 'tag-edit',
			host: 'tag-edit.local',
			wafExcludeTags: ['attack-protocol', 'paranoia-level/3']
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		const hostCell = await screen.findByText('tag-edit.local');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		const textarea = screen.getByTestId('waf-exclude-tags-input') as HTMLTextAreaElement;
		expect(textarea.value).toBe('attack-protocol, paranoia-level/3');
	});

	it('exposes the curated CRS tag catalog via <datalist>', async () => {
		render(Page);
		await openCreateForm();
		const datalist = document.getElementById('waf-exclude-tags-catalog') as HTMLDataListElement;
		expect(datalist).not.toBeNull();
		// 24 curated tags — the catalog is hardcoded so this
		// is a stable assertion across CRS upstream updates.
		expect(datalist.options.length).toBe(24);
		// Spot-check a high-traffic tag is present.
		const values = Array.from(datalist.options).map((o) => o.value);
		expect(values).toContain('attack-protocol');
		expect(values).toContain('paranoia-level/3');
	});

	it('disables the textarea when wafDisableCRS is true', async () => {
		render(Page);
		await openCreateForm();
		const crsToggle = screen.getByTestId('waf-disable-crs-toggle') as HTMLInputElement;
		await userEvent.click(crsToggle);
		// The confirm dialog gates the flip ; click the confirm
		// button by label (the ConfirmDialog component doesn't
		// carry a stable testid on the action button — finding
		// the visible label is the operator-equivalent path).
		// v2.9.14 i18n Phase 3 batch 1 — EN default in test boot.
		const confirmBtn = await screen.findByRole('button', { name: 'Disable CRS' });
		await userEvent.click(confirmBtn);
		await tick();

		const textarea = screen.getByTestId('waf-exclude-tags-input') as HTMLTextAreaElement;
		expect(textarea.disabled).toBe(true);
	});
});

// --- Step Q — rate-limit section -------------------------------

describe('Routes page — Step Q rate-limit toggle + payload', () => {
	it('renders the toggle unchecked on create + hides the inputs when off', async () => {
		render(Page);
		await openCreateForm();
		const toggle = screen.getByTestId('rate-limit-toggle') as HTMLInputElement;
		expect(toggle.checked).toBe(false);
		// Inputs only render when the toggle is on.
		expect(screen.queryByTestId('rate-limit-events-input')).toBeNull();
		expect(screen.queryByTestId('rate-limit-window-input')).toBeNull();
		expect(screen.queryByTestId('rate-limit-key-input')).toBeNull();
	});

	it('toggling on seeds the inputs with operator-meaningful defaults', async () => {
		render(Page);
		await openCreateForm();
		const toggle = screen.getByTestId('rate-limit-toggle') as HTMLInputElement;
		await userEvent.click(toggle);
		await tick();
		const events = screen.getByTestId('rate-limit-events-input') as HTMLInputElement;
		const window = screen.getByTestId('rate-limit-window-input') as HTMLInputElement;
		const key = screen.getByTestId('rate-limit-key-input') as HTMLInputElement;
		expect(events.value).toBe('60');
		expect(window.value).toBe('1m');
		expect(key.value).toBe('{http.request.remote.host}');
	});

	it('ships rateLimit object in the create payload when the toggle is on', async () => {
		apiMock.createRoute.mockResolvedValue(
			makeRoute({ rateLimit: { events: 5, window: '10s', key: '{http.request.remote.host}' } })
		);
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'rate.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		await userEvent.click(screen.getByTestId('rate-limit-toggle'));
		const events = screen.getByTestId('rate-limit-events-input') as HTMLInputElement;
		const window = screen.getByTestId('rate-limit-window-input') as HTMLInputElement;
		await userEvent.clear(events);
		await userEvent.type(events, '5');
		await userEvent.clear(window);
		await userEvent.type(window, '10s');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.rateLimit).toMatchObject({ events: 5, window: '10s' });
		// v2.9.13 Phase Q.2 — when the toggle is ON, clearRateLimit
		// MUST stay absent (or false). Otherwise the sentinel would
		// wipe the rateLimit body the operator just typed.
		expect(payload.clearRateLimit).toBeFalsy();
	});

	it('omits rateLimit but sends clearRateLimit:true when toggle is off (v2.9.13 Phase Q.2)', async () => {
		// Pre-v2.9.13 the OFF case omitted both fields. The backend
		// treated that as preserve-on-omit, so the UI toggle OFF
		// appeared to succeed but a previously-stored rate-limit
		// stuck around (operator-reported 2026-06-26). The frontend
		// now signals the OFF intent via clearRateLimit:true so the
		// backend handler actively clears the stored value.
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'noRate.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.rateLimit).toBeUndefined();
		expect(payload.clearRateLimit).toBe(true);
	});

	it('loads the persisted rateLimit into the toggle + inputs on edit', async () => {
		const seeded = makeRoute({
			id: 'edit-rate',
			host: 'edit.rate.example.com',
			rateLimit: { events: 100, window: '5m', key: '{http.request.remote.host}' }
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		const hostCell = await screen.findByText('edit.rate.example.com');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();
		const toggle = screen.getByTestId('rate-limit-toggle') as HTMLInputElement;
		expect(toggle.checked).toBe(true);
		const events = screen.getByTestId('rate-limit-events-input') as HTMLInputElement;
		expect(events.value).toBe('100');
	});
});
