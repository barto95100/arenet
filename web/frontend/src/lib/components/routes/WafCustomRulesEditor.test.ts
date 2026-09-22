// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.37 — guided WAF rules: helpers + route-form editor.

import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import type { WafCustomRule } from '$lib/api/types';
import WafCustomRulesEditor from './WafCustomRulesEditor.svelte';
import { describeRule, parseValues, preset, ruleError } from '$lib/utils/waf-custom-rule';

function mount(initial: WafCustomRule[], wafMode = 'block') {
	const state = { value: initial };
	const utils = render(WafCustomRulesEditor, {
		props: {
			get value() {
				return state.value;
			},
			set value(v) {
				state.value = v;
			},
			wafMode
		}
	});
	return { state, ...utils };
}

const loginRule: WafCustomRule = {
	id: 120000,
	name: 'Login bots',
	conditions: [
		{ field: 'method', operator: 'is', values: ['POST'] },
		{ field: 'path', operator: 'begins_with', values: ['/login', '/wp-login.php'] },
		{ field: 'user_agent', operator: 'missing' }
	]
};

describe('waf-custom-rule helpers', () => {
	it('describes a rule in one sentence', () => {
		const s = describeRule(loginRule);
		expect(s).toContain('POST');
		expect(s).toContain('/login');
		expect(s).toContain('/wp-login.php');
		expect(s).toMatch(/User-Agent/);
	});

	it('parses one value per line, upper-casing methods', () => {
		expect(parseValues(' get\n\npost \n', 'method')).toEqual(['GET', 'POST']);
		expect(parseValues('/a\n /b ', 'path')).toEqual(['/a', '/b']);
	});

	it('flags invalid rules', () => {
		expect(ruleError(loginRule)).toBeNull();
		expect(ruleError({ ...loginRule, name: ' ' })).toBe('wafRules.errors.name');
		expect(ruleError({ ...loginRule, conditions: [] })).toBe('wafRules.errors.noCondition');
		expect(ruleError({ id: 0, name: 'x', conditions: [{ field: 'path', operator: 'is', values: ['admin'] }] })).toBe(
			'wafRules.errors.path'
		);
		expect(ruleError({ id: 0, name: 'x', conditions: [{ field: 'path', operator: 'contains', values: [] }] })).toBe(
			'wafRules.errors.noValue'
		);
		expect(ruleError({ id: 0, name: 'x', conditions: [{ field: 'user_agent', operator: 'contains', values: ['a"b'] }] })).toBe(
			'wafRules.errors.value'
		);
		expect(ruleError({ id: 0, name: 'x', conditions: [{ field: 'header', header: 'X Bad', operator: 'present' }] })).toBe(
			'wafRules.errors.headerName'
		);
		expect(ruleError({ id: 0, name: 'x', conditions: [{ field: 'method', operator: 'is', values: ['GET1'] }] })).toBe(
			'wafRules.errors.method'
		);
	});

	it('presets are valid new rules', () => {
		for (const key of ['sensitiveFiles', 'scanners', 'methods'] as const) {
			const r = preset(key);
			expect(r.id).toBe(0);
			expect(ruleError(r)).toBeNull();
		}
	});
});

describe('WafCustomRulesEditor', () => {
	it('lists rules as sentences and warns when the WAF is off', () => {
		mount([loginRule], 'off');
		expect(screen.getAllByTestId('waf-rule-row')).toHaveLength(1);
		expect(screen.getByTestId('waf-rule-sentence').textContent).toContain('/login');
		expect(screen.getByTestId('waf-rules-off')).toBeInTheDocument();
	});

	it('adds a rule from a preset', async () => {
		const { state } = mount([]);
		await fireEvent.click(screen.getByTestId('waf-rule-preset-sensitiveFiles'));
		expect(screen.getByTestId('waf-rule-preview').textContent).toContain('/.env');
		await fireEvent.click(screen.getByTestId('waf-rule-ok'));
		expect(state.value).toHaveLength(1);
		expect(state.value[0].id).toBe(0);
		expect(state.value[0].conditions[0].values).toContain('/.git');
	});

	it('builds a rule by hand and refuses it while invalid', async () => {
		const { state } = mount([]);
		await fireEvent.click(screen.getByTestId('waf-rule-add'));
		await fireEvent.click(screen.getByTestId('waf-rule-ok'));
		expect(screen.getByTestId('waf-rule-error')).toBeInTheDocument();
		expect(state.value).toHaveLength(0);

		await fireEvent.input(screen.getByTestId('waf-rule-name'), { target: { value: 'Admin' } });
		await fireEvent.input(screen.getByTestId('waf-rule-values'), { target: { value: '/admin' } });
		await fireEvent.click(screen.getByTestId('waf-rule-add-condition'));
		const fields = screen.getAllByTestId('waf-rule-field');
		await fireEvent.change(fields[1], { target: { value: 'header' } });
		await fireEvent.input(screen.getByTestId('waf-rule-header'), { target: { value: 'X-Admin-Token' } });
		await fireEvent.click(screen.getByTestId('waf-rule-ok'));
		expect(state.value).toEqual([
			{
				id: 0,
				name: 'Admin',
				conditions: [
					{ field: 'path', operator: 'begins_with', values: ['/admin'] },
					{ field: 'header', header: 'X-Admin-Token', operator: 'absent' }
				]
			}
		]);
	});

	it('edits a rule keeping its id, toggles and deletes', async () => {
		const { state } = mount([loginRule]);
		await fireEvent.click(screen.getByTestId('waf-rule-edit'));
		await fireEvent.input(screen.getByTestId('waf-rule-name'), { target: { value: 'Login bots v2' } });
		await fireEvent.click(screen.getByTestId('waf-rule-ok'));
		expect(state.value[0].id).toBe(120000);
		expect(state.value[0].name).toBe('Login bots v2');
		expect(state.value[0].conditions).toEqual(loginRule.conditions);

		await fireEvent.click(screen.getByTestId('waf-rule-toggle'));
		expect(state.value[0].disabled).toBe(true);
		await fireEvent.click(screen.getByTestId('waf-rule-toggle'));
		expect(state.value[0].disabled).toBeFalsy();

		await fireEvent.click(screen.getByTestId('waf-rule-delete'));
		expect(state.value).toEqual([]);
	});
});
