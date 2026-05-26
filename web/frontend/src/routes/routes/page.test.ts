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

const { toastMock, apiMock, settingsMock } = vi.hoisted(() => ({
	toastMock: { pushToast: vi.fn() },
	apiMock: {
		listRoutes: vi.fn(),
		createRoute: vi.fn(),
		updateRoute: vi.fn(),
		deleteRoute: vi.fn()
	},
	settingsMock: {
		getDNSProviderOVH: vi.fn()
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
	deleteRoute: (...args: unknown[]) => apiMock.deleteRoute(...args)
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
		...overrides
	};
}

beforeEach(() => {
	toastMock.pushToast.mockReset();
	apiMock.listRoutes.mockReset();
	apiMock.createRoute.mockReset();
	apiMock.updateRoute.mockReset();
	apiMock.deleteRoute.mockReset();
	settingsMock.getDNSProviderOVH.mockReset();

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
		// row + Edit button.
		const editBtn = await screen.findByRole('button', { name: 'Edit' });

		// IMPORTANT: this test is meaningful only if the HC sub-form
		// is actually mounted by openEdit. We assert against the
		// payload sent to updateRoute, NOT against the DOM-typed
		// values — the test must catch a regression where openEdit
		// silently drops a field. If we re-read each field from the
		// DOM and used it to build the payload, a missing-field
		// regression would be invisible. We do NOT do that.
		await userEvent.click(editBtn);
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
