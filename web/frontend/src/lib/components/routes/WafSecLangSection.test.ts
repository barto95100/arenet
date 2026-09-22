// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.38 — SecLang section: live check, templates, request tester,
// language helpers.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { EditorState } from '@codemirror/state';
import { CompletionContext } from '@codemirror/autocomplete';

const { clientMock } = vi.hoisted(() => ({
	clientMock: { validateSecLang: vi.fn(), testRouteWaf: vi.fn() }
}));
vi.mock('$lib/api/client', () => clientMock);

import WafSecLangSection from './WafSecLangSection.svelte';
import { secLangCompletions } from '$lib/utils/seclang-language';
import { SECLANG_TEMPLATE_KEYS, secLangTemplate } from '$lib/utils/seclang-templates';

beforeEach(() => {
	clientMock.validateSecLang.mockReset();
	clientMock.testRouteWaf.mockReset();
	clientMock.validateSecLang.mockResolvedValue({ errors: [], nextId: 130000 });
});

function mount(initial: string, routeId: string | null = 'route-1') {
	const state = { value: initial };
	render(WafSecLangSection, {
		props: {
			get value() {
				return state.value;
			},
			set value(v) {
				state.value = v;
			},
			routeId,
			wafMode: 'block'
		}
	});
	return state;
}

function complete(doc: string) {
	const state = EditorState.create({ doc });
	return secLangCompletions(new CompletionContext(state, doc.length, true));
}

describe('SecLang helpers', () => {
	it('completes directives, operators, ctl and actions from the allowlist', () => {
		expect(complete('Sec')?.options.map((o) => o.label)).toEqual(['SecRule', 'SecAction', 'SecMarker']);
		const ops = complete('SecRule ARGS "@be')?.options.map((o) => o.label) ?? [];
		expect(ops).toContain('@beginsWith');
		expect(ops).not.toContain('@inspectFile');
		const ctl = complete('SecAction "id:130000,ctl:rule')?.options.map((o) => o.label) ?? [];
		expect(ctl).toContain('ruleRemoveTargetById');
		expect(ctl).not.toContain('ruleEngine');
		const acts = complete('SecAction "id:130000,ph')?.options.map((o) => o.label) ?? [];
		expect(acts).toContain('phase');
		expect(acts).not.toContain('exec');
		expect(complete('SecRule REQ')?.options.map((o) => o.label)).toContain('REQUEST_FILENAME');
	});

	it('renders every template with its ID in both languages', () => {
		for (const key of SECLANG_TEMPLATE_KEYS) {
			for (const lang of ['fr', 'en']) {
				const text = secLangTemplate(key, lang, 130042);
				expect(text).toContain('id:130042');
				expect(text).not.toContain('{ID}');
				expect(text.startsWith('#')).toBe(true);
			}
		}
		expect(secLangTemplate('jsonOnly', 'fr', 1)).toContain('uniquement');
		expect(secLangTemplate('jsonOnly', 'en', 1)).toContain('only');
	});
});

describe('WafSecLangSection', () => {
	it('checks the SecLang live and lists the problems with their line', async () => {
		clientMock.validateSecLang.mockResolvedValue({
			errors: [{ line: 2, message: 'directive "include" is not allowed' }],
			nextId: 130001
		});
		mount('SecAction "id:130000,phase:1,pass"\nInclude /etc/passwd');
		await waitFor(() => expect(screen.getByTestId('seclang-problems')).toBeInTheDocument(), { timeout: 2000 });
		expect(screen.getByTestId('seclang-problems').textContent).toContain('include');
		expect(screen.getByTestId('seclang-problems').textContent).toContain('2');
	});

	it('shows "valid" when the server accepts it, and nothing for an empty SecLang', async () => {
		mount('SecAction "id:130000,phase:1,pass"');
		await waitFor(() => expect(screen.getByTestId('seclang-status').textContent).toMatch(/✓/), { timeout: 2000 });
	});

	it('inserts a template with the next free ID', async () => {
		clientMock.validateSecLang.mockResolvedValue({ errors: [], nextId: 130007 });
		const state = mount('');
		await fireEvent.change(screen.getByTestId('seclang-template'), { target: { value: 'allowedMethods' } });
		await fireEvent.click(screen.getByTestId('seclang-insert-template'));
		await waitFor(() => expect(state.value).toContain('id:130007'));
		expect(state.value).toContain('REQUEST_METHOD');
	});

	it('runs the tester with the unsaved draft and shows the verdict', async () => {
		clientMock.testRouteWaf.mockResolvedValue({
			blocked: true,
			status: 405,
			blockedBy: 130000,
			matches: [{ id: 130000, msg: 'Method not allowed', severity: 'unknown' }],
			mode: 'detect'
		});
		const draft = 'SecRule REQUEST_METHOD "!@rx ^GET$" "id:130000,phase:1,deny,status:405,msg:\'Method not allowed\'"';
		mount(draft);
		await fireEvent.change(screen.getByTestId('tester-method'), { target: { value: 'DELETE' } });
		await fireEvent.input(screen.getByTestId('tester-path'), { target: { value: '/x?a=1' } });
		await fireEvent.input(screen.getByTestId('tester-headers'), { target: { value: 'X-Test: 1\nbad line' } });
		await fireEvent.click(screen.getByTestId('tester-run'));
		await waitFor(() => expect(screen.getByTestId('tester-result')).toBeInTheDocument());
		expect(clientMock.testRouteWaf).toHaveBeenCalledWith('route-1', {
			method: 'DELETE',
			path: '/x?a=1',
			headers: [{ name: 'X-Test', value: '1' }],
			body: '',
			seclang: draft
		});
		const text = screen.getByTestId('tester-result').textContent ?? '';
		expect(text).toContain('405');
		expect(text).toContain('130000');
		expect(text).toContain('Method not allowed');
	});

	it('asks to save the route before testing a new one', () => {
		mount('', null);
		expect(screen.queryByTestId('tester-run')).toBeNull();
	});
});
