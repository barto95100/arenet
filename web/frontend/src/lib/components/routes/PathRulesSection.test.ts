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
});
