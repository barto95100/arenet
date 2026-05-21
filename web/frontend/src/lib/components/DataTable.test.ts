// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// DataTable component tests (Step F Chunk 7.2, spec §11.3 — 3 tests).
// Behavior-based per §11.2.
//
// DataTable is `generics="T extends { id: string }"`. The row + expanded
// snippets receive the item as parameter, so createRawSnippet's render
// callback takes the typed parameter and returns the markup string.
// testing-library handles the HTML strings; we read the rendered <td>
// content as the assertion surface.

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { createRawSnippet, type Snippet } from 'svelte';
import DataTable from './DataTable.svelte';

interface Item {
	id: string;
	label: string;
}

const items: Item[] = [
	{ id: 'r1', label: 'route one' },
	{ id: 'r2', label: 'route two' }
];

// Snippets that read the row item parameter. The double cast widens
// the snippet's parameter type from Item to the generic `{id: string}`
// that svelte-check infers from the DataTable's generic signature in
// a non-TSX context. The runtime contract is intact (Svelte calls
// the snippet with the actual Item at render time).
function rowSnippet(): Snippet<[{ id: string }]> {
	return createRawSnippet((getItem: () => Item) => ({
		render: () => {
			const item = getItem();
			return `<td class="px-4 py-3">${item.label}</td>`;
		}
	})) as unknown as Snippet<[{ id: string }]>;
}

function expandedSnippet(): Snippet<[{ id: string }]> {
	return createRawSnippet((getItem: () => Item) => ({
		render: () => {
			const item = getItem();
			return `<div data-testid="expanded-${item.id}">expanded: ${item.label}</div>`;
		}
	})) as unknown as Snippet<[{ id: string }]>;
}

describe('DataTable', () => {
	it('renders all headers + a row per item', () => {
		render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet()
		});

		// Headers in <th>.
		expect(screen.getByRole('columnheader', { name: 'Label' })).toBeInTheDocument();
		// One <td> per item via the row snippet.
		expect(screen.getByText('route one')).toBeInTheDocument();
		expect(screen.getByText('route two')).toBeInTheDocument();
	});

	it('reveals the expanded snippet when a row is clicked, then collapses on second click', async () => {
		const user = userEvent.setup();
		render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			expanded: expandedSnippet()
		});

		// Pre-click: expanded panel is not rendered (activeId === null,
		// the `{#if expanded && activeId === item.id}` branch is false).
		expect(screen.queryByTestId('expanded-r1')).not.toBeInTheDocument();

		// Click on the first row's <tr> (role="button" via DataTable's
		// markup). We target by accessible name composed of the inner
		// <td> text, since each <tr> is role="button".
		const rows = screen.getAllByRole('button');
		const firstRow = rows[0];
		await user.click(firstRow);
		expect(screen.getByTestId('expanded-r1')).toBeInTheDocument();

		// Second click on the same row collapses it (activeId returns
		// to null per the toggle() logic).
		await user.click(firstRow);
		expect(screen.queryByTestId('expanded-r1')).not.toBeInTheDocument();
	});

	it('shows a fallback empty-state message when items is empty', () => {
		render(DataTable, {
			headers: ['Label'],
			items: [] as Item[],
			row: rowSnippet()
		});

		// DataTable renders a single fallback row with "No items." text
		// inside a colspan'd <td>. Asserting on the text is enough; the
		// surrounding markup is a defensive scaffold.
		expect(screen.getByText('No items.')).toBeInTheDocument();
	});

	it('drops row interactivity when interactive=false (Step G G.3)', () => {
		// Sessions table use case: caller passes no expanded snippet and
		// wants read-only rows. The pre-G.3 component left cursor-pointer
		// + role=button + tabindex + hover-rail on every row regardless,
		// causing the parasite-cursor cosmetic bug documented in smoke
		// doc Step F §5 dette #1.
		const { container } = render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			interactive: false
		});

		// No role=button on rows → screen.queryAllByRole returns 0 for
		// the row layer (the columnheader role is still there for <th>).
		expect(screen.queryAllByRole('button')).toHaveLength(0);

		// Rows render but without tabindex and without the .interactive
		// class that drives cursor + hover-rail + focus-ring in CSS.
		const rows = container.querySelectorAll('tr.data-row');
		expect(rows).toHaveLength(items.length);
		for (const r of rows) {
			expect(r.getAttribute('tabindex')).toBeNull();
			expect(r.getAttribute('role')).toBeNull();
			expect(r.classList.contains('interactive')).toBe(false);
		}
	});

	it('defaults to interactive=true (rétrocompat Routes/Audit)', () => {
		// Without an explicit interactive prop, behavior must match the
		// pre-G.3 component: rows are role=button, tabindex=0, .interactive
		// class is set. Guarantees that Routes + Audit callers (which
		// don't pass the prop) keep their existing click-to-expand
		// behavior wired to the same row markup.
		const { container } = render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			expanded: expandedSnippet()
		});

		const rows = container.querySelectorAll('tr.data-row');
		expect(rows).toHaveLength(items.length);
		for (const r of rows) {
			expect(r.getAttribute('tabindex')).toBe('0');
			expect(r.getAttribute('role')).toBe('button');
			expect(r.classList.contains('interactive')).toBe(true);
		}
	});
});
