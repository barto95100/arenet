// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.39 — API docs viewer: helpers + page (list, search, detail,
// "Try it" with confirmation for changing methods).

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';

const { clientMock } = vi.hoisted(() => ({
	clientMock: { getOpenAPI: vi.fn(), rawRequest: vi.fn() }
}));
vi.mock('$lib/api/client', () => clientMock);

import Page from './+page.svelte';
import { fillPath, groupByTag, listOperations, matches, resolve, sampleFromSchema } from '$lib/utils/openapi';

const DOC = {
	openapi: '3.1.0',
	info: { title: 'Arenet admin API', version: 'v2.39.0', description: 'Intro text.' },
	servers: [{ url: '/api/v1' }],
	tags: [{ name: 'Routes' }, { name: 'System' }],
	paths: {
		'/routes': {
			get: { summary: 'List routes', tags: ['Routes'], 'x-arenet-role': 'viewer', responses: { '200': { description: 'OK' } } },
			post: {
				summary: 'Create a route',
				tags: ['Routes'],
				'x-arenet-role': 'admin',
				requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/RouteRequest' } } } },
				responses: { '201': { description: 'Created' }, '400': { $ref: '#/components/responses/BadRequest' } }
			}
		},
		'/routes/{id}': {
			parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
			get: { summary: 'Get a route', tags: ['Routes'], 'x-arenet-role': 'viewer', responses: { '200': { description: 'OK' } } }
		},
		'/healthz': {
			servers: [{ url: '/' }],
			get: { summary: 'Liveness', tags: ['System'], 'x-arenet-role': 'public', security: [], responses: { '200': { description: 'OK' } } }
		}
	},
	components: {
		schemas: {
			RouteRequest: {
				type: 'object',
				required: ['host'],
				properties: {
					host: { type: 'string', example: 'app.example.com' },
					wafMode: { type: 'string', enum: ['off', 'detect', 'block'] },
					id: { type: 'string', readOnly: true },
					upstreams: { type: 'array', items: { $ref: '#/components/schemas/Upstream' } }
				}
			},
			Upstream: { type: 'object', properties: { url: { type: 'string' }, weight: { type: 'integer', minimum: 1 } } }
		},
		responses: { BadRequest: { description: 'Invalid input.' } }
	}
};

beforeEach(() => {
	clientMock.getOpenAPI.mockReset();
	clientMock.rawRequest.mockReset();
	clientMock.getOpenAPI.mockResolvedValue(DOC);
});

describe('openapi helpers', () => {
	it('lists operations by tag with full paths', () => {
		const ops = listOperations(DOC);
		expect(ops.map((o) => `${o.method} ${o.fullPath}`)).toEqual([
			'get /api/v1/routes',
			'post /api/v1/routes',
			'get /api/v1/routes/{id}',
			'get /healthz'
		]);
		expect(ops[2].parameters[0].name).toBe('id');
		expect(ops[1].responses['400'].description).toBe('Invalid input.');
		expect(groupByTag(ops).map((g) => g.tag)).toEqual(['Routes', 'System']);
		expect(matches(ops[1], 'create')).toBe(true);
		expect(matches(ops[1], 'healthz')).toBe(false);
	});

	it('builds examples from schemas, skipping read-only fields', () => {
		const sample = sampleFromSchema(DOC, { $ref: '#/components/schemas/RouteRequest' });
		expect(sample).toEqual({ host: 'app.example.com', wafMode: 'off', upstreams: [{ url: '', weight: 1 }] });
		expect(resolve(DOC, { $ref: '#/components/schemas/Upstream' }).type).toBe('object');
		expect(fillPath('/api/v1/routes/{id}', { id: 'a b' })).toBe('/api/v1/routes/a%20b');
	});
});

describe('/api-docs page', () => {
	it('shows the intro, filters, and opens an operation', async () => {
		render(Page);
		await waitFor(() => expect(screen.getByTestId('api-intro')).toBeInTheDocument());
		expect(screen.getAllByTestId('api-op-link')).toHaveLength(4);

		await fireEvent.input(screen.getByTestId('api-search'), { target: { value: 'health' } });
		expect(screen.getAllByTestId('api-op-link')).toHaveLength(1);
		await fireEvent.input(screen.getByTestId('api-search'), { target: { value: '' } });

		await fireEvent.click(screen.getAllByTestId('api-op-link')[1]);
		const op = screen.getByTestId('api-op');
		expect(op.textContent).toContain('/api/v1/routes');
		expect(op.textContent).toContain('Create a route');
		expect(op.textContent).toContain('host');
		expect(op.textContent).toContain('wafMode');
	});

	it('asks for confirmation before sending a changing request', async () => {
		clientMock.rawRequest.mockResolvedValue({ status: 201, body: '{"id":"r1"}', contentType: 'application/json' });
		render(Page);
		await waitFor(() => expect(screen.getAllByTestId('api-op-link')).toHaveLength(4));
		await fireEvent.click(screen.getAllByTestId('api-op-link')[1]);
		await fireEvent.click(screen.getByTestId('api-try-open'));
		expect((screen.getByTestId('api-body') as HTMLTextAreaElement).value).toContain('app.example.com');

		await fireEvent.click(screen.getByTestId('api-send'));
		expect(screen.getByTestId('api-confirm')).toBeInTheDocument();
		expect(clientMock.rawRequest).not.toHaveBeenCalled();

		await fireEvent.click(screen.getByTestId('api-send'));
		await waitFor(() => expect(screen.getByTestId('api-result')).toBeInTheDocument());
		expect(clientMock.rawRequest).toHaveBeenCalledWith('post', '/api/v1/routes', expect.stringContaining('app.example.com'));
		expect(screen.getByTestId('api-result').textContent).toContain('201');
	});

	it('sends a GET directly once the path parameters are filled', async () => {
		clientMock.rawRequest.mockResolvedValue({ status: 404, body: '{"error":"route not found"}', contentType: 'application/json' });
		render(Page);
		await waitFor(() => expect(screen.getAllByTestId('api-op-link')).toHaveLength(4));
		await fireEvent.click(screen.getAllByTestId('api-op-link')[2]);
		await fireEvent.click(screen.getByTestId('api-try-open'));
		expect((screen.getByTestId('api-send') as HTMLButtonElement).disabled).toBe(true);
		await fireEvent.input(screen.getByTestId('api-param-id'), { target: { value: 'r1' } });
		await fireEvent.click(screen.getByTestId('api-send'));
		await waitFor(() => expect(screen.getByTestId('api-result')).toBeInTheDocument());
		expect(clientMock.rawRequest).toHaveBeenCalledWith('get', '/api/v1/routes/r1', undefined);
		expect(screen.getByTestId('api-result').textContent).toContain('route not found');
	});
});
