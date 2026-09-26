// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

// v2.37 — guided WAF rules: operators per field, readable sentence,
// starter presets and client-side checks mirroring the backend
// (internal/api/waf_custom_rules.go, authoritative).

import type { WafCustomRule, WafRuleCondition } from '$lib/api/types';
import { t } from '$lib/i18n';

type Field = WafRuleCondition['field'];
type Operator = WafRuleCondition['operator'];

/** Operators offered per field, in display order. */
export const OPERATORS_BY_FIELD: Record<Field, Operator[]> = {
	path: ['begins_with', 'is', 'contains'],
	method: ['is', 'is_not'],
	user_agent: ['contains', 'is', 'missing'],
	header: ['absent', 'present', 'contains', 'is']
};

export const FIELDS: Field[] = ['path', 'method', 'user_agent', 'header'];

export const MAX_CONDITIONS = 8;

/** Whether an operator compares with values. */
export function takesValues(op: Operator): boolean {
	return op !== 'missing' && op !== 'present' && op !== 'absent';
}

/** A fresh condition for a field (its first operator, no value). */
export function newCondition(field: Field = 'path'): WafRuleCondition {
	const c: WafRuleCondition = { field, operator: OPERATORS_BY_FIELD[field][0], values: [] };
	if (field === 'header') c.header = '';
	return c;
}

/** "the path begins with /login or /admin" — one condition in words. */
export function describeCondition(c: WafRuleCondition): string {
	const values = (c.values ?? []).join(` ${t('wafRules.or')} `);
	return t(`wafRules.sentence.${c.field}.${c.operator}`, { values, header: c.header ?? '' });
}

/** "Block when … and …" — the whole rule in words. */
export function describeRule(rule: Pick<WafCustomRule, 'conditions'>): string {
	const parts = rule.conditions.map(describeCondition);
	return t('wafRules.sentence.block', { conditions: parts.join(` ${t('wafRules.and')} `) });
}

const HEADER_NAME = /^[A-Za-z0-9_-]{1,64}$/;
const METHOD = /^[A-Z]{1,16}$/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;

/** First problem of a rule as an i18n key, or null when valid. */
export function ruleError(rule: WafCustomRule): string | null {
	const name = rule.name.trim();
	if (name === '' || name.length > 64 || /["'\\]/.test(name) || CONTROL.test(name)) return 'wafRules.errors.name';
	if (rule.conditions.length === 0) return 'wafRules.errors.noCondition';
	if (rule.conditions.length > MAX_CONDITIONS) return 'wafRules.errors.tooManyConditions';
	for (const c of rule.conditions) {
		if (c.field === 'header' && !HEADER_NAME.test((c.header ?? '').trim())) return 'wafRules.errors.headerName';
		if (!takesValues(c.operator)) continue;
		const values = c.values ?? [];
		if (values.length === 0) return 'wafRules.errors.noValue';
		if (values.length > (c.field === 'method' ? 10 : 20)) return 'wafRules.errors.tooManyValues';
		for (const v of values) {
			if (v.length > 256 || /["\\]/.test(v) || CONTROL.test(v)) return 'wafRules.errors.value';
			if (c.field === 'method' && !METHOD.test(v)) return 'wafRules.errors.method';
			if (c.field === 'path' && c.operator !== 'contains' && !v.startsWith('/')) return 'wafRules.errors.path';
		}
	}
	return null;
}

/** Splits a textarea (one value per line) into trimmed values. */
export function parseValues(text: string, field: Field): string[] {
	return text
		.split('\n')
		.map((v) => v.trim())
		.filter((v) => v !== '')
		.map((v) => (field === 'method' ? v.toUpperCase() : v));
}

/** Starter rules offered as "presets" (prefill the editor). */
export type PresetKey = 'sensitiveFiles' | 'scanners' | 'methods';

export function preset(key: PresetKey): WafCustomRule {
	switch (key) {
		case 'sensitiveFiles':
			return {
				id: 0,
				name: t('wafRules.presets.sensitiveFiles'),
				conditions: [
					{
						field: 'path',
						operator: 'contains',
						values: ['/.env', '/.git', '/.svn', '/.htaccess', '/.DS_Store', '/.aws', '/wp-config.php']
					}
				]
			};
		case 'scanners':
			return {
				id: 0,
				name: t('wafRules.presets.scanners'),
				conditions: [
					{
						field: 'user_agent',
						operator: 'contains',
						values: ['sqlmap', 'nikto', 'masscan', 'nmap', 'zgrab', 'nuclei', 'wpscan', 'gobuster', 'dirbuster']
					}
				]
			};
		case 'methods':
			return {
				id: 0,
				name: t('wafRules.presets.methods'),
				conditions: [{ field: 'method', operator: 'is_not', values: ['GET', 'HEAD', 'POST', 'OPTIONS'] }]
			};
	}
}
