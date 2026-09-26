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

// v2.38 — SecLang for CodeMirror: a small stream tokenizer (comments,
// directives, variables, @operators, action names, quoted text) and a
// completion source limited to what Arenet's allowlist accepts
// (internal/waf/seclang.go is authoritative).

import { StreamLanguage, HighlightStyle, type StringStream } from '@codemirror/language';
import type { CompletionContext, CompletionResult } from '@codemirror/autocomplete';
import { tags } from '@lezer/highlight';

export const SECLANG_DIRECTIVES = ['SecRule', 'SecAction', 'SecMarker'];

export const SECLANG_OPERATORS = [
	'@rx', '@streq', '@beginsWith', '@endsWith', '@contains', '@pm', '@within',
	'@eq', '@ge', '@gt', '@le', '@lt', '@ipMatch', '@detectSQLi', '@detectXSS',
	'@validateByteRange', '@validateUrlEncoding', '@validateUtf8Encoding',
	'@strmatch', '@unconditionalMatch', '@noMatch'
];

export const SECLANG_ACTIONS = [
	'id', 'phase', 'chain', 'deny', 'block', 'drop', 'pass', 'allow', 'status',
	'redirect', 'log', 'nolog', 'auditlog', 'noauditlog', 'msg', 'logdata', 'tag',
	'severity', 'rev', 'ver', 'maturity', 'capture', 'multiMatch', 'setvar',
	'expirevar', 'skip', 'skipAfter', 't', 'ctl'
];

export const SECLANG_CTL = [
	'ruleRemoveById', 'ruleRemoveByTag', 'ruleRemoveByMsg', 'ruleRemoveTargetById',
	'ruleRemoveTargetByTag', 'ruleRemoveTargetByMsg', 'requestBodyProcessor',
	'forceRequestBodyVariable'
];

export const SECLANG_TRANSFORMS = [
	'none', 'lowercase', 'urlDecode', 'urlDecodeUni', 'htmlEntityDecode', 'base64Decode',
	'compressWhitespace', 'removeWhitespace', 'removeNulls', 'normalizePath', 'trim',
	'length', 'cmdLine', 'jsDecode', 'cssDecode', 'hexDecode', 'utf8toUnicode', 'sha1', 'md5'
];

export const SECLANG_VARIABLES = [
	'ARGS', 'ARGS_GET', 'ARGS_POST', 'ARGS_NAMES', 'ARGS_GET_NAMES', 'ARGS_POST_NAMES',
	'REQUEST_METHOD', 'REQUEST_URI', 'REQUEST_URI_RAW', 'REQUEST_FILENAME', 'REQUEST_BASENAME',
	'REQUEST_LINE', 'REQUEST_PROTOCOL', 'QUERY_STRING', 'REQUEST_HEADERS', 'REQUEST_HEADERS_NAMES',
	'REQUEST_COOKIES', 'REQUEST_COOKIES_NAMES', 'REQUEST_BODY', 'REQUEST_BODY_LENGTH',
	'REQUEST_CONTENT_TYPE', 'FILES', 'FILES_NAMES', 'FILES_SIZES', 'FILES_COMBINED_SIZE',
	'REMOTE_ADDR', 'REMOTE_PORT', 'SERVER_NAME', 'SERVER_PORT', 'XML', 'TX', 'MATCHED_VAR',
	'MATCHED_VAR_NAME', 'MATCHED_VARS', 'GEO', 'UNIQUE_ID', 'RESPONSE_STATUS',
	'RESPONSE_HEADERS', 'RESPONSE_BODY', 'REQBODY_ERROR', 'REQBODY_PROCESSOR_ERROR'
];

interface State {
	inQuote: boolean;
	lineStart: boolean;
}

function token(stream: StringStream, state: State): string | null {
	if (stream.sol()) state.lineStart = true;
	if (stream.eatSpace()) return null;
	if (!state.inQuote && state.lineStart && stream.peek() === '#') {
		stream.skipToEnd();
		return 'comment';
	}
	if (state.inQuote) {
		const ch = stream.peek();
		if (ch === '"') {
			stream.next();
			state.inQuote = false;
			return 'string';
		}
		if (ch === '\\') {
			stream.next();
			stream.next();
			return 'string';
		}
		if (ch === "'") {
			stream.next();
			while (!stream.eol()) {
				const c = stream.next();
				if (c === '\\') stream.next();
				else if (c === "'") break;
			}
			return 'string';
		}
		if (stream.match(/^!?@[A-Za-z0-9]+/)) return 'keyword';
		if (stream.match(/^[A-Za-z]+(?=:)/)) return 'propertyName';
		if (stream.match(/^[A-Za-z]+(?=[,"])/)) return 'propertyName';
		stream.next();
		return 'string';
	}
	state.lineStart = false;
	if (stream.peek() === '"') {
		stream.next();
		state.inQuote = true;
		return 'string';
	}
	if (stream.match(/^Sec[A-Za-z]+/)) return 'typeName';
	if (stream.match(/^[!&]?[A-Z_]+(:[^\s|]+)?/)) return 'variableName';
	stream.next();
	return null;
}

/** The SecLang stream language for CodeMirror. */
export const secLang = StreamLanguage.define<State>({
	name: 'seclang',
	startState: () => ({ inQuote: false, lineStart: true }),
	token,
	languageData: { commentTokens: { line: '#' } }
});

/** Theme-aware colours (Arenet CSS tokens). */
export const secLangHighlight = HighlightStyle.define([
	{ tag: tags.comment, color: 'var(--text-muted)', fontStyle: 'italic' },
	{ tag: tags.typeName, color: 'var(--accent-cyan)', fontWeight: '600' },
	{ tag: tags.variableName, color: 'var(--status-warn)' },
	{ tag: tags.keyword, color: 'var(--status-down)' },
	{ tag: tags.propertyName, color: 'var(--status-up)' },
	{ tag: tags.string, color: 'var(--text-primary)' }
]);

function options(labels: string[], type: string) {
	return labels.map((label) => ({ label, type }));
}

/** Completion: directives at line start, @operators, actions (and
 *  ctl: / t: values) inside quotes, variables elsewhere. */
export function secLangCompletions(ctx: CompletionContext): CompletionResult | null {
	const line = ctx.state.doc.lineAt(ctx.pos);
	const before = line.text.slice(0, ctx.pos - line.from);
	const quotes = (before.match(/(?<!\\)"/g) ?? []).length;
	const inQuote = quotes % 2 === 1;

	const op = ctx.matchBefore(/!?@[A-Za-z0-9]*/);
	if (op && inQuote) {
		return { from: op.from + (op.text.startsWith('!') ? 1 : 0), options: options(SECLANG_OPERATORS, 'keyword') };
	}
	const ctl = ctx.matchBefore(/ctl:[A-Za-z]*/i);
	if (ctl && inQuote) return { from: ctl.from + 4, options: options(SECLANG_CTL, 'function') };
	const tr = ctx.matchBefore(/(?:^|[,"])t:[A-Za-z0-9]*/);
	if (tr && inQuote) {
		const at = tr.text.indexOf('t:') + 2;
		return { from: tr.from + at, options: options(SECLANG_TRANSFORMS, 'function') };
	}
	const word = ctx.matchBefore(/[A-Za-z_]+/);
	if (!word && !ctx.explicit) return null;
	const from = word ? word.from : ctx.pos;
	if (!inQuote && /^\s*[A-Za-z]*$/.test(before)) return { from, options: options(SECLANG_DIRECTIVES, 'keyword') };
	if (inQuote) return { from, options: options(SECLANG_ACTIONS, 'property') };
	return { from, options: options(SECLANG_VARIABLES, 'variable') };
}
