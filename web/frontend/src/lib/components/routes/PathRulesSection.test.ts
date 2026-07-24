// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// PathRulesSection component tests (Task 8, path-based-rules). Behavior-based
// per the project's Toggle-neighbor test convention: render + simulate user
// interaction + assert observable outcome, no internal state peeking.

import { describe, it, expect } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import PathRulesSection from './PathRulesSection.svelte';
import type { PathRule } from '$lib/api/types';

describe('PathRulesSection', () => {
	it('is collapsed by default and adds a rule card on demand', async () => {
		const { getByTestId, queryAllByTestId } = render(PathRulesSection, { value: [] });
		expect(queryAllByTestId('path-rule-card').length).toBe(0);
		await fireEvent.click(getByTestId('path-rules-add'));
		expect(queryAllByTestId('path-rule-card').length).toBe(1);
	});

	it('renders one card per existing rule', () => {
		const value: PathRule[] = [{ pathPrefix: '/docs' }, { pathPrefix: '/api' }];
		const { queryAllByTestId } = render(PathRulesSection, { value });
		expect(queryAllByTestId('path-rule-card').length).toBe(2);
	});

	it('removes a rule card on demand', async () => {
		const value: PathRule[] = [{ pathPrefix: '/docs' }];
		const { getByTestId, queryAllByTestId } = render(PathRulesSection, { value });
		expect(queryAllByTestId('path-rule-card').length).toBe(1);
		await fireEvent.click(getByTestId('path-rule-remove-0'));
		expect(queryAllByTestId('path-rule-card').length).toBe(0);
	});

	// Task 8: path-rule basic auth takes a PLAIN password on the wire
	// (hashed server-side), matching route-level basicAuth. Typing into
	// the password field must land in `basicAuth.password` — binding it
	// to `passwordHash` was the bug this fix corrects (an operator's
	// plaintext password would've been stored verbatim as a "hash").
	// Rule starts with basicAuth already present (mirrors the existing
	// 'renders one card per existing rule' convention) so the test
	// exercises the input binding directly rather than the checkbox's
	// cross-render reactivity plumbing.
	it('binds the password field to basicAuth.password (plain), not passwordHash', async () => {
		const value: PathRule[] = [{ pathPrefix: '/admin', basicAuth: { username: 'admin' } }];
		const { getByTestId } = render(PathRulesSection, { value });

		const passwordInput = getByTestId('path-rule-basicauth-password-0') as HTMLInputElement;
		expect(passwordInput.type).toBe('password');

		await fireEvent.input(passwordInput, { target: { value: 'somePlainPassword' } });

		expect(value[0].basicAuth?.password).toBe('somePlainPassword');
		expect((value[0].basicAuth as unknown as Record<string, unknown>).passwordHash).toBeUndefined();
	});

	// Task 6 (path-based-rules, per-path upstream routing) — the
	// "Upstream spécifique" disclosure is collapsed by default: the
	// <details> exists per rule, but its inner fields (url repeater,
	// add-backend button) are not rendered/visible until the
	// disclosure is opened, mirroring the route-level health-check
	// <details> idiom (open={...}, collapsed unless there's already
	// content).
	it('renders a collapsed "Upstream spécifique" disclosure per rule', async () => {
		const value: PathRule[] = [{ pathPrefix: '/docs' }];
		const { getByTestId, queryByTestId } = render(PathRulesSection, { value });

		const disclosure = getByTestId('path-rule-upstream-disclosure-0') as HTMLDetailsElement;
		expect(disclosure).toBeTruthy();
		expect(disclosure.open).toBe(false);
		// No backends badge yet — pool is empty.
		expect(queryByTestId('path-rule-backends-badge-0')).toBeNull();
	});

	it('adding a backend materialises the pool and shows the "→ N backends" badge', async () => {
		const value: PathRule[] = [{ pathPrefix: '/docs' }];
		const { getByTestId } = render(PathRulesSection, { value });

		await fireEvent.click(getByTestId('path-rule-upstream-add-0'));
		expect(value[0].upstreams?.length).toBe(1);
		expect(getByTestId('path-rule-backends-badge-0').textContent).toContain('1');

		// Second interaction: asserted purely via the DOM. The bare
		// `value` array literal this test passes to render() is not a
		// reactive ($state) host — Svelte's $bindable only write-backs
		// to that exact outer reference on its first prop replacement
		// (empirically verified), so a second round-trip read of the
		// `value` variable here would be stale even though the
		// component's own internal state (and therefore the real app,
		// where the parent's pathRules IS $state) is correct.
		await fireEvent.click(getByTestId('path-rule-upstream-add-0'));
		expect(getByTestId('path-rule-backends-badge-0').textContent).toContain('2');
	});

	it('shows a "→ N backends" badge on mount when the rule already has a non-empty pool', () => {
		const value: PathRule[] = [
			{
				pathPrefix: '/api',
				upstreams: [
					{ url: 'http://a:8080', weight: 1 },
					{ url: 'http://b:8080', weight: 1 }
				]
			}
		];
		const { getByTestId } = render(PathRulesSection, { value });
		expect(getByTestId('path-rule-backends-badge-0').textContent).toContain('2');
	});

	it('removing a backend updates the pool and the input is gone', async () => {
		const value: PathRule[] = [
			{ pathPrefix: '/api', upstreams: [{ url: 'http://a:8080', weight: 1 }] }
		];
		const { getByTestId, queryByTestId } = render(PathRulesSection, { value });

		expect(getByTestId('path-rule-upstream-url-0-0')).toBeTruthy();
		await fireEvent.click(getByTestId('path-rule-upstream-remove-0-0'));

		expect(value[0].upstreams?.length).toBe(0);
		expect(queryByTestId('path-rule-upstream-url-0-0')).toBeNull();
		expect(queryByTestId('path-rule-backends-badge-0')).toBeNull();
	});

	it('typing a backend url updates the bound rule', async () => {
		const value: PathRule[] = [
			{ pathPrefix: '/api', upstreams: [{ url: '', weight: 1 }] }
		];
		const { getByTestId } = render(PathRulesSection, { value });

		const urlInput = getByTestId('path-rule-upstream-url-0-0') as HTMLInputElement;
		await fireEvent.input(urlInput, { target: { value: 'http://backend:9090' } });
		expect(value[0].upstreams?.[0].url).toBe('http://backend:9090');
	});

	it('typing a backend weight updates the DOM value', async () => {
		// Second interaction on a freshly rendered instance, asserted
		// via the DOM element's own `.value` rather than the outer
		// `value` array — see the note in the "adding a backend..."
		// test above re: bare-array $bindable props in this harness.
		const value: PathRule[] = [
			{ pathPrefix: '/api', upstreams: [{ url: 'http://backend:9090', weight: 1 }] }
		];
		const { getByTestId } = render(PathRulesSection, { value });

		const weightInput = getByTestId('path-rule-upstream-weight-0-0') as HTMLInputElement;
		await fireEvent.input(weightInput, { target: { value: '5' } });
		expect(weightInput.value).toBe('5');
	});

	it('enabling the health-check materialises a full HealthCheck object with the uri field visible', async () => {
		const value: PathRule[] = [{ pathPrefix: '/api' }];
		const { getByTestId, queryByTestId } = render(PathRulesSection, { value });

		expect(queryByTestId('path-rule-hc-uri-0')).toBeNull();
		await fireEvent.click(getByTestId('path-rule-hc-toggle-0'));

		expect(value[0].healthCheck?.enabled).toBe(true);
		expect(value[0].healthCheck?.method).toBe('GET');
		expect(getByTestId('path-rule-hc-uri-0')).toBeTruthy();
	});

	it('disabling the health-check hides the uri field', async () => {
		// Fresh instance starting already-enabled, so disabling it is
		// the FIRST interaction against this render — keeps the
		// assertion on the outer `value` reference valid (see note
		// above re: bare-array $bindable props only write-back once).
		const value: PathRule[] = [
			{
				pathPrefix: '/api',
				healthCheck: {
					enabled: true,
					uri: '/health',
					method: 'GET',
					interval: '10s',
					timeout: '5s',
					expectStatus: 0,
					expectBody: '',
					passes: 1,
					fails: 1
				}
			}
		];
		const { getByTestId, queryByTestId } = render(PathRulesSection, { value });

		expect(getByTestId('path-rule-hc-uri-0')).toBeTruthy();
		await fireEvent.click(getByTestId('path-rule-hc-toggle-0'));

		expect(value[0].healthCheck).toBeUndefined();
		expect(queryByTestId('path-rule-hc-uri-0')).toBeNull();
	});
});
