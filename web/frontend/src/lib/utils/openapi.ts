// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
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

// v2.39 — helpers for the in-app OpenAPI viewer (/api-docs): list the
// operations by tag, resolve local $refs, build example payloads.
// Only what Arenet's own document uses (OpenAPI 3.1, local refs).

/* eslint-disable @typescript-eslint/no-explicit-any */
export type OpenAPIDoc = Record<string, any>;
export type Schema = Record<string, any>;

export const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete'] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

/** One operation of the document. */
export interface Operation {
	key: string;
	method: HttpMethod;
	path: string;
	/** Path as sent by the browser (servers override applied). */
	fullPath: string;
	tag: string;
	summary: string;
	description: string;
	role: string;
	parameters: Schema[];
	requestBody?: Schema;
	responses: Record<string, Schema>;
}

/** Follows a local "#/a/b" reference; returns the input when not a ref. */
export function resolve(doc: OpenAPIDoc, node: any): any {
	let cur = node;
	for (let guard = 0; cur && typeof cur === 'object' && typeof cur.$ref === 'string' && guard < 20; guard++) {
		const ref: string = cur.$ref;
		if (!ref.startsWith('#/')) return cur;
		cur = ref
			.slice(2)
			.split('/')
			.reduce<any>((acc, part) => (acc && typeof acc === 'object' ? acc[part] : undefined), doc);
	}
	return cur;
}

/** The name of a "#/components/schemas/X" reference, or "". */
export function refName(node: any): string {
	const ref: unknown = node?.$ref;
	return typeof ref === 'string' ? ref.split('/').pop() ?? '' : '';
}

/** Every operation, in tag order then path order. */
export function listOperations(doc: OpenAPIDoc): Operation[] {
	const base: string = doc?.servers?.[0]?.url ?? '';
	const tagOrder: string[] = (doc.tags ?? []).map((t: { name: string }) => t.name);
	const ops: Operation[] = [];
	for (const [path, rawItem] of Object.entries<any>(doc.paths ?? {})) {
		const item = resolve(doc, rawItem) ?? {};
		const prefix = item.servers?.[0]?.url === '/' ? '' : base;
		for (const method of HTTP_METHODS) {
			const op = item[method];
			if (!op) continue;
			ops.push({
				key: `${method} ${path}`,
				method,
				path,
				fullPath: prefix + path,
				tag: op.tags?.[0] ?? 'Other',
				summary: op.summary ?? '',
				description: op.description ?? '',
				role: op['x-arenet-role'] ?? '',
				parameters: [...(item.parameters ?? []), ...(op.parameters ?? [])].map((p: any) => resolve(doc, p)),
				requestBody: op.requestBody ? resolve(doc, op.requestBody) : undefined,
				responses: Object.fromEntries(
					Object.entries<any>(op.responses ?? {}).map(([code, r]) => [code, resolve(doc, r)])
				)
			});
		}
	}
	const rank = (tag: string) => {
		const i = tagOrder.indexOf(tag);
		return i < 0 ? tagOrder.length : i;
	};
	return ops.sort((a, b) => rank(a.tag) - rank(b.tag) || a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
}

/** Groups operations by tag, keeping order. */
export function groupByTag(ops: Operation[]): { tag: string; ops: Operation[] }[] {
	const groups: { tag: string; ops: Operation[] }[] = [];
	for (const op of ops) {
		const last = groups[groups.length - 1];
		if (last && last.tag === op.tag) last.ops.push(op);
		else groups.push({ tag: op.tag, ops: [op] });
	}
	return groups;
}

/** Case-insensitive match on method, path, summary and tag. */
export function matches(op: Operation, query: string): boolean {
	const q = query.trim().toLowerCase();
	if (q === '') return true;
	return `${op.method} ${op.fullPath} ${op.summary} ${op.tag}`.toLowerCase().includes(q);
}

/** The JSON schema of a request body or response, if any. */
export function jsonSchema(doc: OpenAPIDoc, bodyOrResponse: Schema | undefined): Schema | undefined {
	const content = bodyOrResponse?.content;
	if (!content) return undefined;
	const media = content['application/json'] ?? Object.values<any>(content)[0];
	return media?.schema ? resolve(doc, media.schema) : undefined;
}

/** An explicit example of a request body / response, if the document has one. */
export function explicitExample(bodyOrResponse: Schema | undefined): unknown {
	const content = bodyOrResponse?.content;
	if (!content) return undefined;
	const media = content['application/json'] ?? Object.values<any>(content)[0];
	if (!media) return undefined;
	if (media.example !== undefined) return media.example;
	const first = media.examples && Object.values<any>(media.examples)[0];
	return first?.value;
}

/** The main type of a schema ("string", "array"…), ignoring "null". */
export function schemaType(schema: Schema | undefined): string {
	if (!schema) return '';
	const t = schema.type;
	if (Array.isArray(t)) return t.find((x: string) => x !== 'null') ?? t[0] ?? '';
	if (t) return t;
	if (schema.properties) return 'object';
	if (schema.items) return 'array';
	return '';
}

/** Builds an example value from a schema (explicit example first). */
export function sampleFromSchema(doc: OpenAPIDoc, node: any, depth = 0): unknown {
	const schema = resolve(doc, node);
	if (!schema || depth > 6) return null;
	if (schema.example !== undefined) return schema.example;
	if (Array.isArray(schema.examples) && schema.examples.length > 0) return schema.examples[0];
	if (schema.default !== undefined) return schema.default;
	if (Array.isArray(schema.enum) && schema.enum.length > 0) return schema.enum[0];
	for (const combo of ['oneOf', 'anyOf'] as const) {
		if (Array.isArray(schema[combo]) && schema[combo].length > 0) return sampleFromSchema(doc, schema[combo][0], depth + 1);
	}
	if (Array.isArray(schema.allOf)) {
		return Object.assign({}, ...schema.allOf.map((s: any) => sampleFromSchema(doc, s, depth + 1) ?? {}));
	}
	switch (schemaType(schema)) {
		case 'object': {
			const out: Record<string, unknown> = {};
			for (const [k, v] of Object.entries<any>(schema.properties ?? {})) {
				if (resolve(doc, v)?.readOnly) continue;
				out[k] = sampleFromSchema(doc, v, depth + 1);
			}
			return out;
		}
		case 'array':
			return [sampleFromSchema(doc, schema.items, depth + 1)];
		case 'integer':
		case 'number':
			return schema.minimum ?? 0;
		case 'boolean':
			return false;
		case 'string':
			return schema.format === 'date-time' ? '2026-01-01T00:00:00Z' : '';
	}
	return null;
}

/** Whether a method changes state (the "try it" asks for confirmation). */
export function isMutating(method: HttpMethod): boolean {
	return method !== 'get';
}

/** Fills {param} placeholders; missing values stay as-is. */
export function fillPath(path: string, values: Record<string, string>): string {
	return path.replace(/\{([^}]+)\}/g, (m, name: string) =>
		values[name] ? encodeURIComponent(values[name]) : m
	);
}
