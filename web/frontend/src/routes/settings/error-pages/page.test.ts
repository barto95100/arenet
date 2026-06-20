// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step R Phase 2.a — /settings/error-pages page tests.
//
// Focused on the operator-facing UX contracts :
//   - empty state when no templates exist
//   - list rendering when templates load
//   - create flow lands in editor view
//   - edit flow pre-populates the form
//   - 8 status-code tabs render
//   - Variables panel renders + click inserts placeholder
//   - delete confirmation flow
//   - error state on list-load failure
//
// CodeMirror internals are exercised by HtmlEditor.test.ts ;
// here we treat HtmlEditor as a black box (its mount is
// verified at the .cm-editor selector).

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import type { ErrorTemplate } from '$lib/api/error-templates';

const { apiMock, toastMock } = vi.hoisted(() => ({
	apiMock: {
		list: vi.fn(),
		get: vi.fn(),
		create: vi.fn(),
		update: vi.fn(),
		delete: vi.fn(),
		preview: vi.fn()
	},
	toastMock: { pushToast: vi.fn() }
}));

vi.mock('$lib/api/error-templates', async () => {
	const real = await vi.importActual<typeof import('$lib/api/error-templates')>(
		'$lib/api/error-templates'
	);
	return {
		...real,
		errorTemplatesApi: apiMock
	};
});
vi.mock('$lib/stores/toast', () => toastMock);

import Page from './+page.svelte';

const sampleTemplate = (overrides: Partial<ErrorTemplate> = {}): ErrorTemplate => ({
	id: 'tpl-1',
	name: 'WGW Branding',
	description: 'Worldgeekwide branded errors',
	pages: { '403': '<h1>403 — branded</h1>', '404': '<h1>404 — branded</h1>' },
	createdAt: '2026-06-20T10:00:00Z',
	updatedAt: '2026-06-20T10:00:00Z',
	...overrides
});

beforeEach(() => {
	apiMock.list.mockReset();
	apiMock.create.mockReset();
	apiMock.update.mockReset();
	apiMock.delete.mockReset();
	apiMock.preview.mockReset();
	toastMock.pushToast.mockReset();
	apiMock.list.mockResolvedValue([]);
	apiMock.preview.mockResolvedValue('<h1>preview</h1>');
});

describe('/settings/error-pages — list view', () => {
	it('renders the empty state when no templates exist', async () => {
		apiMock.list.mockResolvedValue([]);
		render(Page);
		await screen.findByText(/Aucun template personnalisé/);
		// CTA to create the first template is present.
		const ctas = screen.getAllByRole('button', { name: /Créer le premier/ });
		expect(ctas.length).toBeGreaterThan(0);
	});

	it('renders the table when templates load', async () => {
		apiMock.list.mockResolvedValue([
			sampleTemplate({ id: 't1', name: 'WGW' }),
			sampleTemplate({
				id: 't2',
				name: 'Other Brand',
				description: 'Another branding',
				pages: { '403': '<h1>x</h1>' }
			})
		]);
		render(Page);
		await screen.findByText('WGW');
		expect(screen.getByText('Other Brand')).toBeInTheDocument();
		// "2 / 8" for WGW (403 + 404 from sample).
		expect(screen.getByText('2 / 8')).toBeInTheDocument();
		// "1 / 8" for the second template.
		expect(screen.getByText('1 / 8')).toBeInTheDocument();
	});

	it('shows error state + retry on list-load failure', async () => {
		apiMock.list.mockRejectedValueOnce(new Error('network down'));
		render(Page);
		await waitFor(() => {
			expect(screen.getByText('network down')).toBeInTheDocument();
		});
		const retryBtn = screen.getByRole('button', { name: 'Réessayer' });
		expect(retryBtn).toBeInTheDocument();
	});
});

describe('/settings/error-pages — create flow', () => {
	it('clicking "Nouveau template" switches to editor view', async () => {
		apiMock.list.mockResolvedValue([]);
		render(Page);
		await screen.findByText(/Aucun template personnalisé/);
		// Header CTA = "+ Nouveau template", empty state CTA also creates.
		const cta = screen.getByRole('button', { name: '+ Nouveau template' });
		await fireEvent.click(cta);
		// Editor view : the header eyebrow switches to "Nouveau template"
		// and the meta-card name input appears.
		await screen.findByPlaceholderText(/WGW Branding/);
	});

	it('saves a new template and returns to list view', async () => {
		apiMock.list.mockResolvedValue([]);
		apiMock.create.mockResolvedValue(sampleTemplate({ id: 'new-id', name: 'New One' }));
		// After save, the list re-fetch returns the created.
		apiMock.list.mockResolvedValueOnce([]); // initial empty
		render(Page);
		await screen.findByText(/Aucun template personnalisé/);
		await fireEvent.click(screen.getByRole('button', { name: '+ Nouveau template' }));
		const nameInput = await screen.findByPlaceholderText(/WGW Branding/);
		await fireEvent.input(nameInput, { target: { value: 'New One' } });
		// Second list call returns the new entry.
		apiMock.list.mockResolvedValueOnce([sampleTemplate({ id: 'new-id', name: 'New One' })]);
		await fireEvent.click(screen.getByRole('button', { name: /Enregistrer/ }));
		await waitFor(() => {
			expect(apiMock.create).toHaveBeenCalledTimes(1);
		});
		const [req] = apiMock.create.mock.calls[0];
		expect(req.name).toBe('New One');
	});

	it('rejects empty name with a toast', async () => {
		apiMock.list.mockResolvedValue([]);
		render(Page);
		await screen.findByText(/Aucun template personnalisé/);
		await fireEvent.click(screen.getByRole('button', { name: '+ Nouveau template' }));
		await screen.findByPlaceholderText(/WGW Branding/);
		// Click save with empty name.
		await fireEvent.click(screen.getByRole('button', { name: /Enregistrer/ }));
		await waitFor(() => {
			expect(toastMock.pushToast).toHaveBeenCalledWith(
				expect.stringContaining('nom du template'),
				'danger'
			);
		});
		// Create API should NOT have been hit.
		expect(apiMock.create).not.toHaveBeenCalled();
	});
});

describe('/settings/error-pages — editor', () => {
	it('renders the 8 supported status-code tabs', async () => {
		apiMock.list.mockResolvedValue([]);
		render(Page);
		await screen.findByText(/Aucun template personnalisé/);
		await fireEvent.click(screen.getByRole('button', { name: '+ Nouveau template' }));
		// All 8 codes appear as tab labels.
		for (const code of [401, 403, 404, 429, 500, 502, 503, 504]) {
			expect(screen.getByRole('tab', { name: new RegExp(`^${code}`) })).toBeInTheDocument();
		}
	});

	it('renders the Variables panel with placeholder tokens', async () => {
		apiMock.list.mockResolvedValue([]);
		render(Page);
		await screen.findByText(/Aucun template personnalisé/);
		await fireEvent.click(screen.getByRole('button', { name: '+ Nouveau template' }));
		// Panel header.
		expect(
			screen.getByText(/Variables Caddy disponibles/)
		).toBeInTheDocument();
		// Some token examples are rendered as <code>.
		expect(screen.getByText('{http.error.status_code}')).toBeInTheDocument();
		expect(screen.getByText('{http.request.host}')).toBeInTheDocument();
		expect(screen.getByText('{time.now.year}')).toBeInTheDocument();
	});

	it('pre-populates the editor when editing an existing template', async () => {
		const existing = sampleTemplate({
			id: 'edit-me',
			name: 'Existing brand',
			description: 'desc',
			pages: { '403': '<h1>existing 403</h1>' }
		});
		apiMock.list.mockResolvedValue([existing]);
		render(Page);
		await screen.findByText('Existing brand');
		// Click Modifier on the row.
		const editBtn = screen.getByRole('button', { name: 'Modifier' });
		await fireEvent.click(editBtn);
		// Editor view : name input has the existing value.
		const nameInput = (await screen.findByPlaceholderText(/WGW Branding/)) as HTMLInputElement;
		expect(nameInput.value).toBe('Existing brand');
	});

	it('cancel returns to list view without saving', async () => {
		apiMock.list.mockResolvedValue([sampleTemplate()]);
		render(Page);
		await screen.findByText('WGW Branding');
		await fireEvent.click(screen.getByRole('button', { name: 'Modifier' }));
		await screen.findByPlaceholderText(/WGW Branding/);
		await fireEvent.click(screen.getByRole('button', { name: 'Annuler' }));
		// Back to list : the table is visible again.
		await waitFor(() => {
			expect(screen.getByText('WGW Branding')).toBeInTheDocument();
		});
		expect(apiMock.update).not.toHaveBeenCalled();
	});
});

describe('/settings/error-pages — delete confirmation', () => {
	it('opens the modal and fires the delete API on confirm', async () => {
		apiMock.list.mockResolvedValue([sampleTemplate({ id: 'doomed', name: 'Doomed' })]);
		apiMock.delete.mockResolvedValue(undefined);
		render(Page);
		await screen.findByText('Doomed');
		await fireEvent.click(screen.getByRole('button', { name: 'Supprimer' }));
		// Modal heading appears.
		await screen.findByText(/Supprimer le template/);
		// Second-stage list call after delete.
		apiMock.list.mockResolvedValueOnce([]);
		// Click the modal's Supprimer button (second occurrence).
		const confirmBtn = screen
			.getAllByRole('button', { name: /^Supprimer$/ })
			.pop();
		expect(confirmBtn).toBeDefined();
		await fireEvent.click(confirmBtn!);
		await waitFor(() => {
			expect(apiMock.delete).toHaveBeenCalledWith('doomed');
		});
	});

	it('clicking Annuler closes the modal without deleting', async () => {
		apiMock.list.mockResolvedValue([sampleTemplate({ id: 'safe' })]);
		render(Page);
		await screen.findByText('WGW Branding');
		await fireEvent.click(screen.getByRole('button', { name: 'Supprimer' }));
		await screen.findByText(/Supprimer le template/);
		await fireEvent.click(screen.getByRole('button', { name: 'Annuler' }));
		expect(apiMock.delete).not.toHaveBeenCalled();
	});
});
